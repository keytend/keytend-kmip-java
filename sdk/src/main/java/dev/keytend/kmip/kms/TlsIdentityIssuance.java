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

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

/**
 * Issues a TLS identity from the KMS ({@link KmsTls#issue}): the KMS creates the key pair, and
 * signs the certificate with KMIP Certify.
 *
 * <pre>{@code
 * TlsIdentityHandle node = kms.tls().issue("cassandra/node1")
 *     .keyPair(KeyPairSpec.ec(Curve.P_256))
 *     .subject("CN=node1,O=cluster1")
 *     .dnsNames("node1.cluster1.internal")
 *     .ipAddresses("10.0.0.11")
 *     .validFor(Duration.ofDays(30))
 *     .issuedBy(ca)
 *     .custom(TLS_ROLE, "cluster1:identity")
 *     .issue();
 * }</pre>
 *
 * <p>{@code ca} is a {@link TlsIssuer}, and {@code TLS_ROLE} a {@link CustomAttribute}. Give a
 * subject, subject alternative names, or both. Not thread-safe.
 *
 * @since 0.10.0
 */
public final class TlsIdentityIssuance {
  private final KmsTls tls;
  private final String name;
  private final Map<CustomAttribute, Object> custom = new LinkedHashMap<>();
  private final Set<Pkcs10.AltName> names = new LinkedHashSet<>();
  private KeyPairSpec spec = KeyPairSpec.ec(Curve.P_256);
  private X500Principal subject = new X500Principal("");
  private Duration validFor;
  private TlsIssuer issuer;

  TlsIdentityIssuance(KmsTls tls, String name) {
    this.tls = tls;
    this.name = name;
  }

  /**
   * The key pair the KMS creates: RSA of at least 2048 bits, or EC on P-256, P-384 or P-521. EC
   * P-256 by default.
   *
   * @param spec the key pair's algorithm and size
   * @return this builder
   * @throws IllegalArgumentException for RSA below 2048 bits
   * @since 0.10.0
   */
  public TlsIdentityIssuance keyPair(KeyPairSpec spec) {
    Objects.requireNonNull(spec, "spec");
    TlsCertify.checkSpec(spec, "issue");
    this.spec = spec;
    return this;
  }

  /**
   * The certificate's subject, a distinguished name in RFC 2253 or RFC 1779 form, such as {@code
   * "CN=node1,O=cluster1"}. Empty by default, which needs subject alternative names.
   *
   * @param distinguishedName the subject
   * @return this builder
   * @throws IllegalArgumentException when it is not a distinguished name
   * @since 0.10.0
   */
  public TlsIdentityIssuance subject(String distinguishedName) {
    Objects.requireNonNull(distinguishedName, "distinguishedName");
    this.subject = new X500Principal(distinguishedName);
    return this;
  }

  /**
   * DNS names for the subject alternative name extension, added to those already given.
   *
   * @param dnsNames the names, such as {@code node1.cluster1.internal}
   * @return this builder
   * @throws IllegalArgumentException when a name is empty or not ASCII
   * @since 0.10.0
   */
  public TlsIdentityIssuance dnsNames(String... dnsNames) {
    for (String n : dnsNames) {
      ascii(Objects.requireNonNull(n, "dnsName"), "DNS name");
      names.add(new Pkcs10.AltName(Pkcs10.AltName.DNS, n));
    }
    return this;
  }

  /**
   * IP addresses for the subject alternative name extension, added to those already given. Only
   * literal IPv4 and IPv6 addresses are taken, so that no name is looked up.
   *
   * @param addresses the addresses, such as {@code 10.0.0.11} or {@code fd00::11}
   * @return this builder
   * @throws IllegalArgumentException when one is not an IP address literal
   * @since 0.10.0
   */
  public TlsIdentityIssuance ipAddresses(String... addresses) {
    for (String a : addresses) {
      Pkcs10.ipAddress(Objects.requireNonNull(a, "address"));
      names.add(new Pkcs10.AltName(Pkcs10.AltName.IP, a));
    }
    return this;
  }

  /**
   * URIs for the subject alternative name extension, added to those already given, such as a
   * SPIFFE ID.
   *
   * @param uris the URIs, absolute
   * @return this builder
   * @throws IllegalArgumentException when one is not an absolute ASCII URI
   * @since 0.10.0
   */
  public TlsIdentityIssuance uris(String... uris) {
    for (String u : uris) {
      ascii(Objects.requireNonNull(u, "uri"), "URI");
      if (!java.net.URI.create(u).isAbsolute())
        throw new IllegalArgumentException("Not an absolute URI: " + u);
      names.add(new Pkcs10.AltName(Pkcs10.AltName.URI, u));
    }
    return this;
  }

  /**
   * Email addresses for the subject alternative name extension, added to those already given.
   *
   * @param emails the addresses
   * @return this builder
   * @throws IllegalArgumentException when one is not an ASCII address with an {@code @}
   * @since 0.10.0
   */
  public TlsIdentityIssuance emails(String... emails) {
    for (String e : emails) {
      ascii(Objects.requireNonNull(e, "email"), "email address");
      if (e.indexOf('@') <= 0) throw new IllegalArgumentException("Not an email address: " + e);
      names.add(new Pkcs10.AltName(Pkcs10.AltName.EMAIL, e));
    }
    return this;
  }

  /**
   * How long the certificate is valid from now. The call asks for it as the certificate's
   * Deactivation Date, and refuses a certificate whose notAfter is not that date, give or take a
   * few minutes. keytend-kmip-server issues to that date. A server that ignores
   * the date (earlier keytend-kmip-server builds issue for 365 days, capped at the CA's notAfter)
   * makes the call fail ({@link UnsupportedException}). A validity that would end after the issuing
   * CA's notAfter is refused ({@link InvalidRequestException}): before anything is changed when the
   * issuer is in the KMS, otherwise when the server refuses it. So is one shorter than ten minutes
   * plus three times the call timeout of the {@code Kms} the call runs on, before anything is sent
   * ({@link InvalidRequestException}): the certificate must outlast a safety margin at each change
   * of the identity ({@link #issue()}). By default none is asked, and the server's own validity
   * applies.
   *
   * @param validFor how long, positive
   * @return this builder
   * @throws IllegalArgumentException when it is not positive
   * @since 0.10.0
   */
  public TlsIdentityIssuance validFor(Duration validFor) {
    Objects.requireNonNull(validFor, "validFor");
    if (validFor.isNegative() || validFor.isZero())
      throw new IllegalArgumentException("validFor must be positive: " + validFor);
    this.validFor = validFor;
    return this;
  }

  /**
   * The CA in the KMS that signs the certificate. Without one, the server's own CA signs, on
   * servers that have one (keytend-kmip-server needs an issuer).
   *
   * @param issuer the issuer
   * @return this builder
   * @since 0.10.0
   */
  public TlsIdentityIssuance issuedBy(TlsIssuer issuer) {
    this.issuer = Objects.requireNonNull(issuer, "issuer");
    return this;
  }

  /**
   * Sets a custom attribute on the leaf certificate, as {@link
   * TlsIdentityRegistration#custom(CustomAttribute, Object)} does. Reissues copy it.
   *
   * @param attribute the attribute
   * @param value its value, of a type {@link KeyAttributes} lists; a {@code byte[]} is copied here
   * @return this builder
   * @since 0.10.0
   */
  public TlsIdentityIssuance custom(CustomAttribute attribute, Object value) {
    Objects.requireNonNull(attribute, "attribute");
    AttributeReader.encode(Objects.requireNonNull(value, "value"));
    custom.put(attribute, value instanceof byte[] b ? b.clone() : value);
    return this;
  }

  /**
   * Issues the identity. The steps:
   *
   * <ol>
   *   <li>The KMS creates the key pair (Create Key Pair), Pre-Active, under a temporary name that
   *       only this call uses.
   *   <li>The call activates the new private key, since KMIP lets no Pre-Active key be used and
   *       servers lease no Pre-Active object. No certificate certifies it yet, and nothing of the
   *       identity links to it. The call retrieves it, with a lease where it states a Lease Time,
   *       signs a PKCS#10 request with it locally (SHA-256 with RSA PKCS#1 v1.5, or ECDSA), and
   *       wipes the copy.
   *   <li>Certify: the KMS issues the certificate for the public key, Pre-Active, under the
   *       temporary name, with the custom attributes and a Certificate link to the issuer.
   *   <li>The call checks the certificate: it is for the public key, has exactly the subject and
   *       subject alternative names asked, is issued by the issuer's certificate, and its chain
   *       verifies (each certificate issued and signed by the next; without {@link #issuedBy},
   *       the chain is what the leaf's Certificate links lead to). It is not a CA certificate,
   *       and a node can present it at both ends of a TLS connection: a Key Usage extension has
   *       digitalSignature, whatever the key type, and an Extended Key Usage extension has both
   *       serverAuth and clientAuth, or anyExtendedKeyUsage. It is valid now, ends at the
   *       validity asked, and is still Pre-Active in the KMS. Otherwise the call stops with
   *       {@link KeyMismatchException}, or {@link UnsupportedException} for the validity, and
   *       leaves its objects over, none of them activated but the new private key.
   *   <li>Then the steps of {@link TlsIdentityRegistration#register()}: the objects are linked,
   *       the leaf gets the name (the switch), and they are activated, the leaf last.
   * </ol>
   *
   * <p>Each change from the switch on is a request of its own, and is sent only while the
   * certificate is valid for more than a safety margin by the {@code Kms}'s clock: five minutes
   * plus twice the call timeout of the {@code Kms} the call runs on ({@link Kms#callTimeout()}, a
   * {@link Kms#withTimeout} view's for a call through one). The call checks just before each
   * request goes out, after the {@link KmsListener#started} callbacks. The call's requests share
   * one deadline, so the client waits at most one call timeout for that request's reply; the
   * margin also allows for a server that processes a request late, and for a peer whose clock
   * runs ahead. A certificate that does not outlast the margin at the switch is refused, with
   * nothing of the identity changed; after the switch the call stops before it activates the
   * certificate. So an issued certificate must live longer than the margin, and a {@link
   * #validFor} shorter than ten minutes plus three times the call timeout is refused before
   * anything is sent.
   *
   * <p>When the call stops part-way ({@link PartialCompletionException}) or its outcome is unknown,
   * repeat it with the same arguments. Before the name, a repeat starts over, and what the stopped
   * call made is left over. After the name, a repeat activates the objects and returns the
   * identity, but only when the leaf has the subject, names, issuer and key type asked, and its
   * chain verifies. So does a repeat after success. How to find and clean up what a stopped call
   * leaves is in <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/tls-identities.md#what-a-stopped-call-leaves">TLS
   * identities</a>.
   *
   * @return the identity
   * @throws IllegalStateException when neither a subject nor a subject alternative name was given;
   *     nothing is sent
   * @throws AlreadyExistsException as {@link TlsIdentityRegistration#register()}; nothing was made
   * @throws KeyMismatchException when the certificate the KMS issued is not what was asked, other
   *     than its validity, its chain does not verify, its key usages do not permit TLS at both
   *     ends, or it does not outlast the safety margin at the switch; nothing of the identity
   *     changed, and the message lists the objects left over. Also
   *     when a repeat finds the leaf an earlier call's switch made with a chain that does not
   *     verify; then nothing was changed
   * @throws UnsupportedException when the certificate's notAfter is not the validity asked (the
   *     server ignores it); nothing of the identity changed, and the message lists the objects
   *     left over
   * @throws InvalidRequestException when the validity asked is shorter than ten minutes plus three
   *     times the call timeout, before anything is sent; when it would end after the issuing CA's
   *     notAfter, before anything is changed when the issuer is in the KMS; or when the server
   *     refuses Certify with Invalid Field while a validity was asked, which names the validity as
   *     the likely cause and keeps the server's message: then nothing of the identity changed, and
   *     the message lists the objects left over
   * @throws StateConflictException as {@link TlsIdentityRegistration#register()} for a repeat;
   *     and when the certificate no longer outlasts the safety margin after the switch: the call
   *     stops before it activates it, and the message says how to undo the switch
   * @throws PartialCompletionException when a step after the key pair's creation failed, such as a
   *     Certify the server refuses (one that does not implement Certify, or an issuer the
   *     credentials do not own): repeat, or see the cause
   * @since 0.10.0
   */
  public TlsIdentityHandle issue() {
    if (subject.getEncoded().length <= 2 && names.isEmpty())
      throw new IllegalStateException("issue: give a subject, subject alternative names, or both");
    TlsCertify request = TlsCertify.issue(subject, List.copyOf(names), spec, validFor, issuer);
    return new TlsIssue(tls, TlsIssue.Kind.ISSUE, name, request, new LinkedHashMap<>(custom), null)
        .run();
  }

  private static void ascii(String value, String what) {
    if (value.isEmpty() || !value.chars().allMatch(c -> c > 0x20 && c < 0x7f))
      throw new IllegalArgumentException("Not an ASCII " + what + ": " + value);
  }

  @Override
  public String toString() {
    return "TlsIdentityIssuance[" + name + ", " + names.size() + " names]";
  }
}
