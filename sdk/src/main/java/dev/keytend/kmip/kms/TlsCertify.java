/*
 * Copyright 2026 Jeremiah Jordan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dev.keytend.kmip.kms;

import static dev.keytend.kmip.model.Tag.*;

import dev.keytend.kmip.client.Request;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.Attributes;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Ttlv;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.security.auth.x500.X500Principal;

/**
 * What an issue or reissue of a TLS identity asks the KMS to issue with KMIP Certify ({@link
 * TlsIssue}), and the checks of what it issued. A first issue asks for the subject, the subject
 * alternative names and the key type given; a reissue asks for those of the certificate it
 * replaces, with that certificate's key or a new key. The issuer is the {@link TlsIssuer} given, a
 * reissue's default being the issuer the replaced certificate links to; none means the server's
 * own CA. One instance serves one call.
 */
final class TlsCertify {
  /**
   * How far the issued certificate's notBefore may be after this client's clock, and its notAfter
   * from the Deactivation Date asked: clocks differ, and servers round.
   */
  static final Duration TOLERANCE = Duration.ofMinutes(5);

  /** The serverAuth, clientAuth and anyExtendedKeyUsage purposes (RFC 5280 4.2.1.12). */
  private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1",
      CLIENT_AUTH = "1.3.6.1.5.5.7.3.2",
      ANY_PURPOSE = "2.5.29.37.0";

  /** Why the issued certificate is refused, and whether the reason is its validity. */
  record Problem(String why, boolean validity) {}

  private final boolean first;
  private final KeyPairSpec askedSpec;
  private final Duration validFor;
  private final TlsIssuer issuer;

  private X500Principal subject;
  private List<Pkcs10.AltName> names;
  private KeyPairSpec spec;
  private PublicKey currentKey;
  private List<String> issuerIds = List.of();
  private List<X509Certificate> issuerChain = List.of();
  private boolean prepared;
  private RuntimeException unprepared;

  private TlsCertify(
      boolean first,
      X500Principal subject,
      List<Pkcs10.AltName> names,
      KeyPairSpec spec,
      Duration validFor,
      TlsIssuer issuer) {
    this.first = first;
    this.subject = subject;
    this.names = names;
    this.askedSpec = spec;
    this.validFor = validFor;
    this.issuer = issuer;
  }

  /** A first issue: {@code issuer} null for the server's own CA. */
  static TlsCertify issue(
      X500Principal subject,
      List<Pkcs10.AltName> names,
      KeyPairSpec spec,
      Duration validFor,
      TlsIssuer issuer) {
    return new TlsCertify(true, subject, List.copyOf(names), spec, validFor, issuer);
  }

  /**
   * A reissue, with a new key of {@code spec} (null: the current key's algorithm and size, or for
   * a same-key reissue, which {@link TlsIssue.Kind} says, that key); {@code issuer} null for the
   * issuer the current certificate links to.
   */
  static TlsCertify reissue(KeyPairSpec spec, Duration validFor, TlsIssuer issuer) {
    return new TlsCertify(false, null, null, spec, validFor, issuer);
  }

  /**
   * Reads what the call asks for (one Get per certificate): for a reissue, the subject, names and
   * key of {@code expected}, the certificate it replaces, and its issuers; then the issuer's chain.
   * A reissue whose certificate cannot be read stays unprepared, and {@link #requirePrepared}
   * throws why, after the call's own checks.
   */
  void prepare(KmsKeys keys, TlsIssue.Kind kind, String expected, Map<String, KeyAttributes> read) {
    if (prepared) return;
    String operation = kind.operation;
    List<String> ids;
    if (first) {
      spec = askedSpec;
      ids = issuer == null ? List.of() : idsOf(issuer.chain());
    } else {
      X509Certificate current;
      KeyAttributes a;
      try {
        a = TlsIdentities.attributes(keys, read, expected);
        current = a == null ? null : TlsIdentities.certificate(keys.kms(), expected);
      } catch (NotFoundException | StateConflictException gone) {
        unprepared = gone;
        return;
      }
      if (current == null) {
        unprepared =
            new NotFoundException(
                operation + ": the certificate " + expected + " does not exist",
                null,
                operation,
                expected,
                null,
                null);
        return;
      }
      subject = current.getSubjectX500Principal();
      List<String> other = new ArrayList<>();
      names = altNames(current, other);
      if (!other.isEmpty()) {
        unprepared =
            new UnsupportedException(
                operation
                    + ": the certificate "
                    + expected
                    + " has subject alternative names of kinds a"
                    + " reissue does not request ("
                    + String.join(", ", other)
                    + "; it requests DNS names, IP addresses, URIs and email addresses): issue a"
                    + " new identity with the names it should have",
                null,
                operation,
                expected,
                null,
                null);
        return;
      }
      currentKey = current.getPublicKey();
      spec = askedSpec != null ? askedSpec : specOf(currentKey, operation);
      if (issuer != null) ids = idsOf(issuer.chain());
      else {
        List<String> chain = TlsIdentities.chainIds(keys, a, read);
        ids = chain.subList(1, chain.size());
      }
    }
    if (spec != null) checkSpec(spec, operation);
    issuerIds = List.copyOf(ids);
    List<X509Certificate> certificates = new ArrayList<>();
    for (String id : issuerIds) certificates.add(TlsIdentities.certificate(keys.kms(), id));
    issuerChain = List.copyOf(certificates);
    prepared = true;
  }

  /** Throws why {@link #prepare} could not prepare a reissue. */
  void requirePrepared(String operation) {
    if (unprepared != null) throw unprepared;
    if (!prepared) throw new IllegalStateException(operation + ": the request is not prepared");
  }

  private static List<String> idsOf(List<KeyHandle> handles) {
    return handles.stream().map(KeyHandle::id).toList();
  }

  X500Principal subject() {
    return subject;
  }

  List<Pkcs10.AltName> names() {
    return names;
  }

  /** The new key pair's spec; for a same-key reissue, the current key's. */
  KeyPairSpec spec() {
    return spec;
  }

  /** The key of the certificate a reissue replaces; null for a first issue. */
  PublicKey currentKey() {
    return currentKey;
  }

  /** The issuers in the KMS, the issuing CA's certificate first; empty for the server's own CA. */
  List<String> issuerIds() {
    return issuerIds;
  }

  /** The Deactivation Date to ask for, from {@code now}, to the second; null for none. */
  Instant deactivation(Instant now) {
    return validFor == null ? null : now.plus(validFor).truncatedTo(ChronoUnit.SECONDS);
  }

  /** The validity asked for; null for the server's default. */
  Duration validFor() {
    return validFor;
  }

  /**
   * The issuing CA certificate's notAfter, when the issuer is in the KMS and was read by {@link
   * #prepare}; null for the server's own CA.
   */
  Instant issuerNotAfter() {
    return issuerChain.isEmpty() ? null : issuerChain.get(0).getNotAfter().toInstant();
  }

  /**
   * Refuses, before anything is sent, a validity shorter than {@code shortest} ({@link
   * TlsIssue#shortestValidity}): the issued certificate must outlast the safety margin at each
   * change of the identity, which such a validity leaves no room for.
   */
  void checkShortest(String operation, Duration shortest) {
    if (validFor == null || validFor.compareTo(shortest) >= 0) return;
    throw new InvalidRequestException(
        operation
            + ": the validity asked ("
            + validFor
            + ") is shorter than "
            + shortest
            + ": ten minutes plus three times the call timeout of the Kms the call runs on. Each"
            + " change of the identity needs the certificate valid for more than a safety margin"
            + " of five minutes plus twice the call timeout, after a call that may take up to its"
            + " call timeout, and a notAfter may be up to five minutes before the date asked. Ask"
            + " for a longer validity, or call through a Kms with a shorter call timeout. Nothing"
            + " was changed",
        null,
        operation,
        null,
        null,
        null);
  }

  /**
   * Refuses, before anything is changed, a validity that would end after the issuing CA's notAfter:
   * keytend-kmip-server refuses such a Deactivation Date with Invalid Field and never cuts it
   * short, and the SDK refuses a certificate cut short by another server. Nothing for the server's
   * own CA, whose notAfter the client does not know, or without a validity.
   */
  void checkValidity(String operation, Instant now) {
    Instant until = deactivation(now), caEnd = issuerNotAfter();
    if (until == null || caEnd == null || !until.isAfter(caEnd)) return;
    throw new InvalidRequestException(
        operation
            + ": the validity asked ("
            + validFor
            + ") would end at "
            + until
            + ", after the issuing CA's notAfter ("
            + caEnd
            + "). A KMS cannot issue past its CA's expiry: ask for a validity that ends by then,"
            + " or reissue the CA first. Nothing was changed",
        null,
        operation,
        null,
        null,
        null);
  }

  /**
   * The Certify request: the public key object {@code publicId}, the PKCS#10 request {@code csr}
   * (Certificate Request Type PKCS#10; the value in Certificate Request on KMIP 1.x, Certificate
   * Request Value from 2.0), and the new certificate's attributes, which the client layer sends as
   * a Template-Attribute on 1.x and Attributes from 2.0: the temporary name, the custom attributes,
   * a Certificate link to {@code issuerId} (none for the server's own CA), and a Deactivation Date
   * {@code until} (none for the server's default validity). No Activation Date is sent: one at or
   * before now would make the certificate Active at once, before the call's switch. A server that
   * takes the dates as the validity (keytend-kmip-server) then issues from now to
   * {@code until} and keeps the certificate Pre-Active.
   */
  Request certify(
      KmsKeys keys,
      String publicId,
      byte[] csr,
      String temporary,
      Map<CustomAttribute, Object> custom,
      Instant until,
      String issuerId) {
    List<Ttlv> attributes = new ArrayList<>();
    attributes.add(Attributes.name(temporary));
    for (var e : custom.entrySet()) attributes.add(keys.custom(e.getKey(), e.getValue()));
    if (issuerId != null)
      attributes.add(Attributes.link(Enums.LinkType.CERTIFICATE_LINK, issuerId));
    if (until != null)
      attributes.add(
          Attributes.attribute("Deactivation Date", Ttlv.dateTime(DEACTIVATION_DATE, until)));
    boolean legacy = keys.kms().protocolVersion().legacyAttributes();
    return Requests.certify()
        .uniqueIdentifier(publicId)
        .add(Ttlv.enumeration(CERTIFICATE_REQUEST_TYPE, Enums.CertificateRequestType.PKCS_10))
        .add(Ttlv.bytes(legacy ? CERTIFICATE_REQUEST : CERTIFICATE_REQUEST_VALUE, csr))
        .template(attributes.toArray(Ttlv[]::new))
        .build();
  }

  /**
   * Why {@code issued} is not what was asked, or null when it is: it is for {@code requested}; its
   * subject and subject alternative names are exactly those asked; it chains to the issuer's
   * certificate, when there is one; it is not a CA certificate; its key usages permit TLS at both
   * ends ({@link #tlsUseProblem}); {@code now} is within its validity, give or take {@link
   * #TOLERANCE} at its start; and its notAfter is {@code until}, give or take {@link #TOLERANCE},
   * when a Deactivation Date was asked. The rest of the chain is checked once it is known ({@link
   * TlsIdentities#chainBreak}).
   */
  Problem problem(X509Certificate issued, PublicKey requested, Instant until, Instant now) {
    if (!sameKey(issued.getPublicKey(), requested))
      return new Problem("it is not for the public key requested", false);
    if (!sameSubject(issued.getSubjectX500Principal(), subject))
      return new Problem(
          "its subject is \"" + issued.getSubjectX500Principal() + "\", not \"" + subject + "\"",
          false);
    List<String> other = new ArrayList<>();
    List<Pkcs10.AltName> got = altNames(issued, other);
    if (!other.isEmpty() || !sameNames(got, names))
      return new Problem(
          "its subject alternative names are "
              + describe(got)
              + (other.isEmpty() ? "" : " and " + other)
              + ", not "
              + describe(names),
          false);
    if (!issuerChain.isEmpty() && !issuedBy(issued, issuerChain.get(0)))
      return new Problem(
          "it is not issued by the issuer's certificate ("
              + issuerChain.get(0).getSubjectX500Principal()
              + ")",
          false);
    boolean[] usage = issued.getKeyUsage();
    if (issued.getBasicConstraints() != -1 || (usage != null && usage.length > 5 && usage[5]))
      return new Problem("it is a CA certificate", false);
    String tls = tlsUseProblem(issued);
    if (tls != null) return new Problem(tls, false);
    Instant notBefore = issued.getNotBefore().toInstant();
    Instant notAfter = issued.getNotAfter().toInstant();
    if (notBefore.isAfter(now.plus(TOLERANCE)) || !notAfter.isAfter(now))
      return new Problem(
          "it is valid from " + notBefore + " to " + notAfter + ", which does not include now",
          false);
    if (until != null && Duration.between(notAfter, until).abs().compareTo(TOLERANCE) > 0)
      return new Problem(
          "its notAfter is "
              + notAfter
              + ", not the requested Deactivation Date "
              + until
              + " (the server does not honor the requested validity)",
          true);
    return null;
  }

  /**
   * Whether {@code issued}, read from a leaf an earlier call's switch made, is what this call asks
   * for: the subject and names asked, the issuer's certificate its issuer, and for {@code kept}
   * the key of the certificate it replaces; otherwise a key of the spec asked, not that one.
   */
  boolean holds(X509Certificate issued, boolean kept) {
    if (!prepared) return false;
    if (!sameSubject(issued.getSubjectX500Principal(), subject)) return false;
    List<String> other = new ArrayList<>();
    if (!sameNames(altNames(issued, other), names) || !other.isEmpty()) return false;
    if (!issuerChain.isEmpty() && !issuedBy(issued, issuerChain.get(0))) return false;
    PublicKey key = issued.getPublicKey();
    if (kept) return currentKey != null && sameKey(key, currentKey);
    if (currentKey != null && sameKey(key, currentKey)) return false;
    return spec != null && fits(key, spec);
  }

  /**
   * The new chain, leaf first: {@code leaf}, then the certificates {@code ids} names, the issuer's
   * as read by {@link #prepare}, or for the server's own CA read now (one Get each).
   */
  List<X509Certificate> chain(KmsKeys keys, X509Certificate leaf, List<String> ids) {
    List<X509Certificate> out = new ArrayList<>(List.of(leaf));
    if (ids.equals(issuerIds)) out.addAll(issuerChain);
    else for (String id : ids) out.add(TlsIdentities.certificate(keys.kms(), id));
    return List.copyOf(out);
  }

  /** The key type of {@code key}, for a reissue with a new key of the same type. */
  private static KeyPairSpec specOf(PublicKey key, String operation) {
    if (key instanceof RSAPublicKey rsa) return KeyPairSpec.rsa(rsa.getModulus().bitLength());
    if (key instanceof ECPublicKey ec)
      return KeyPairSpec.ec(ec.getParams().getCurve().getField().getFieldSize());
    throw new UnsupportedException(
        operation + ": a key of type " + key.getAlgorithm() + " is not reissued",
        null,
        operation,
        null,
        null,
        null);
  }

  /** Refuses a key type Certify servers do not certify: RSA below 2048 bits. */
  static void checkSpec(KeyPairSpec spec, String operation) {
    if (spec.algorithm() == Algorithm.RSA && spec.bits() < 2048)
      throw new IllegalArgumentException(
          operation + ": an issued TLS key is RSA of at least 2048 bits, or EC; not " + spec);
  }

  /** Whether {@code key} is of {@code spec}'s algorithm and size. */
  private static boolean fits(PublicKey key, KeyPairSpec spec) {
    if (key instanceof RSAPublicKey rsa)
      return spec.algorithm() == Algorithm.RSA && rsa.getModulus().bitLength() == spec.bits();
    if (key instanceof ECPublicKey ec)
      return spec.algorithm() == Algorithm.EC
          && ec.getParams().getCurve().getField().getFieldSize() == spec.bits();
    return false;
  }

  /** Whether two public keys are the same key, whatever their encodings. */
  static boolean sameKey(PublicKey a, PublicKey b) {
    if (a instanceof RSAPublicKey x && b instanceof RSAPublicKey y)
      return x.getModulus().equals(y.getModulus())
          && x.getPublicExponent().equals(y.getPublicExponent());
    if (a instanceof ECPublicKey x && b instanceof ECPublicKey y)
      return x.getW().equals(y.getW()) && x.getParams().getCurve().equals(y.getParams().getCurve());
    return Arrays.equals(a.getEncoded(), b.getEncoded());
  }

  /** The same DER, or the same RFC 2253 text (a server that re-encodes the attribute values). */
  private static boolean sameSubject(X500Principal issued, X500Principal asked) {
    return Arrays.equals(issued.getEncoded(), asked.getEncoded())
        || issued.getName(X500Principal.RFC2253).equals(asked.getName(X500Principal.RFC2253));
  }

  private static boolean issuedBy(X509Certificate leaf, X509Certificate ca) {
    return TlsIdentities.chainBreak(List.of(leaf, ca)) == null;
  }

  /**
   * Why {@code issued} cannot be presented by both ends of a TLS connection, or null when it can.
   * A node presents its identity when it accepts a connection and when it makes one, so:
   *
   * <ul>
   *   <li>a Key Usage extension must have digitalSignature, whatever the key type: TLS 1.3 signs
   *       the handshake with the key, and so does TLS 1.2 in client authentication and in an
   *       ECDHE key exchange. A certificate with only keyEncipherment (RSA key transport) or only
   *       keyAgreement (static ECDH) serves neither;
   *   <li>an Extended Key Usage extension must have serverAuth and clientAuth, or
   *       anyExtendedKeyUsage: peers refuse a server certificate without serverAuth and a client
   *       certificate without clientAuth.
   * </ul>
   *
   * Without these extensions the certificate is not restricted.
   */
  static String tlsUseProblem(X509Certificate issued) {
    boolean[] usage = issued.getKeyUsage();
    if (usage != null && (usage.length == 0 || !usage[0]))
      return "its Key Usage has no digitalSignature, which TLS needs to sign with the key";
    List<String> purposes;
    try {
      purposes = issued.getExtendedKeyUsage();
    } catch (CertificateParsingException e) {
      return "its Extended Key Usage cannot be read: " + e.getMessage();
    }
    if (purposes == null || purposes.contains(ANY_PURPOSE)) return null;
    if (!purposes.contains(SERVER_AUTH) || !purposes.contains(CLIENT_AUTH))
      return "its Extended Key Usage "
          + purposes
          + " does not have both serverAuth and clientAuth: a node presents its identity both"
          + " when it accepts a connection and when it makes one";
    return null;
  }

  /**
   * {@code c}'s subject alternative names of the kinds a request carries; the others are added to
   * {@code other}, by their RFC 5280 choice number.
   */
  static List<Pkcs10.AltName> altNames(X509Certificate c, List<String> other) {
    Collection<List<?>> all;
    try {
      all = c.getSubjectAlternativeNames();
    } catch (CertificateParsingException e) {
      other.add("unreadable: " + e.getMessage());
      return List.of();
    }
    List<Pkcs10.AltName> out = new ArrayList<>();
    if (all == null) return out;
    for (List<?> n : all) {
      int type = (Integer) n.get(0);
      if (type == Pkcs10.AltName.EMAIL
          || type == Pkcs10.AltName.DNS
          || type == Pkcs10.AltName.URI
          || type == Pkcs10.AltName.IP) out.add(new Pkcs10.AltName(type, (String) n.get(1)));
      else other.add("GeneralName " + type);
    }
    return out;
  }

  /** Whether two lists hold the same names, in any order; IP addresses compared by their octets. */
  static boolean sameNames(List<Pkcs10.AltName> a, List<Pkcs10.AltName> b) {
    return sorted(a).equals(sorted(b));
  }

  private static List<String> sorted(List<Pkcs10.AltName> names) {
    List<String> out = new ArrayList<>();
    for (Pkcs10.AltName n : names)
      out.add(
          n.type()
              + ":"
              + (n.type() == Pkcs10.AltName.IP
                  ? HexFormat.of().formatHex(Pkcs10.ipAddress(n.value()))
                  : n.value()));
    out.sort(null);
    return out;
  }

  private static String describe(List<Pkcs10.AltName> names) {
    if (names.isEmpty()) return "none";
    List<String> out = new ArrayList<>();
    for (Pkcs10.AltName n : names)
      out.add(
          switch (n.type()) {
                case Pkcs10.AltName.DNS -> "DNS:";
                case Pkcs10.AltName.IP -> "IP:";
                case Pkcs10.AltName.URI -> "URI:";
                default -> "email:";
              }
              + n.value());
    return "[" + String.join(", ", out) + "]";
  }

  @Override
  public String toString() {
    return "TlsCertify[" + Objects.toString(subject) + "]";
  }
}
