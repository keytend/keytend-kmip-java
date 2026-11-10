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

import dev.keytend.kmip.client.KmipException;
import dev.keytend.kmip.client.Messages;
import dev.keytend.kmip.client.ObjectViews;
import dev.keytend.kmip.client.ProtocolException;
import dev.keytend.kmip.client.Request;
import dev.keytend.kmip.client.RequestOptions;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.client.Response;
import dev.keytend.kmip.client.Result;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Ttlv;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * What the TLS identity calls share: what a name leads to, and reading an identity's certificates
 * and private key. An identity is a leaf certificate that has the name, whose Private Key link
 * names its private key, which names it back with a Certificate link; the leaf's Certificate link
 * names the next certificate of its chain, and so on. A renewal or re-key links the new leaf to
 * the old one with Replaced Object and Replacement Object links, as Re-key links keys.
 */
final class TlsIdentities {
  private TlsIdentities() {}

  /** Replacement steps a walk follows forward from the certificate a name leads to. */
  static final int WALK = 16;

  /**
   * Lookups of a name, each followed by a lookup of the record of the name being moved, before it
   * is taken for gone: a move that finishes between the two lookups of a round is found by the next.
   */
  static final int ROUNDS = 3;

  /** The certificates of a chain read from the KMS, the leaf included, at most. */
  static final int CHAIN = 8;

  /** What a name leads to: the certificates from the one found to its newest replacement. */
  static final class Found {
    /** From the certificate found, by replacement steps both certificates confirm. */
    final List<KeyAttributes> path;

    /** Found through the record of the name being moved, or through the held certificate's links. */
    final boolean moving;

    /** Everything read on the way, by identifier. */
    final Map<String, KeyAttributes> read;

    Found(List<KeyAttributes> path, boolean moving, Map<String, KeyAttributes> read) {
      this.path = List.copyOf(path);
      this.moving = moving;
      this.read = read;
    }

    /** The last certificate of the path. */
    KeyAttributes newest() {
      return path.get(path.size() - 1);
    }

    /**
     * The identity's current certificate: the newest of the path that has been activated (not
     * Pre-Active); a newer one that is still Pre-Active is a replacement not yet made current. The
     * newest when all are Pre-Active.
     */
    KeyAttributes current() {
      for (int i = path.size() - 1; i >= 0; i--)
        if (path.get(i).state() != KeyState.PRE_ACTIVE) return path.get(i);
      return newest();
    }

    /** Whether a replacement is in progress: the name is moving, or a newer certificate is not Active yet. */
    boolean replacing() {
      return moving || newest() != current();
    }
  }

  /**
   * What {@code name} leads to, or empty when nothing does after {@link #ROUNDS} rounds. A round:
   * the certificates with the name (one Locate) are read with {@code alsoRead} (one batched Get
   * Attributes); one of them is chosen as {@link KmsKeys#findByName} chooses, and the walk goes
   * forward from it. When no certificate has the name, the certificates that record it as a name
   * being moved to them (where names are unique the name is on no object while it moves); then,
   * when {@code held} names a certificate with a replacement, the walk from it.
   */
  static Optional<Found> find(KmsKeys keys, String name, Collection<String> alsoRead, String held) {
    return find(keys, name, alsoRead, held, new HashMap<>());
  }

  /** {@link #find(KmsKeys, String, Collection, String)}, keeping what it reads in {@code read}. */
  static Optional<Found> find(
      KmsKeys keys,
      String name,
      Collection<String> alsoRead,
      String held,
      Map<String, KeyAttributes> read) {
    for (int round = 1; round <= ROUNDS; round++) {
      List<String> holders =
          keys.locate(KeyQuery.byName(name).kind(ObjectKind.CERTIFICATE))
              .map(KeyHandle::id)
              .distinct()
              .toList();
      // The held pair first: when a read fails part-way, what it read of them is kept in read.
      Set<String> batch = new LinkedHashSet<>();
      if (round == 1) for (String id : alsoRead) if (id != null) batch.add(id);
      batch.addAll(holders);
      readAll(keys, new ArrayList<>(batch), read);
      List<KeyAttributes> named = new ArrayList<>();
      for (String id : holders) {
        KeyAttributes a = read.get(id);
        // Moved off it since the Locate: not a holder.
        if (a != null && a.kind() == ObjectKind.CERTIFICATE && a.names().contains(name))
          named.add(a);
      }
      if (!named.isEmpty()) {
        KeyAttributes start =
            named.size() == 1
                ? named.get(0)
                : read.get(keys.chooseAmongRead(named).orElseThrow().id());
        return Optional.of(walk(keys, start, false, read));
      }
      List<KeyAttributes> moving = new ArrayList<>();
      for (String id : keys.pendingName(name)) {
        KeyAttributes a = attributes(keys, read, id);
        if (a != null && a.kind() == ObjectKind.CERTIFICATE) moving.add(a);
      }
      if (!moving.isEmpty())
        return Optional.of(walk(keys, moving.stream().min(Lineage.TIPS).orElseThrow(), true, read));
      if (held != null) {
        KeyAttributes h = attributes(keys, read, held);
        if (h != null && h.kind() == ObjectKind.CERTIFICATE) {
          Found f = walk(keys, h, true, read);
          if (f.path.size() > 1) return Optional.of(f);
        }
      }
    }
    return Optional.empty();
  }

  /**
   * The path from {@code start} forward: each step to a certificate that names the last one as
   * replaced and that it names as its replacement (both links), the first in {@link Lineage#TIPS}
   * order when there are several, at most {@link #WALK} steps.
   */
  static Found walk(
      KmsKeys keys, KeyAttributes start, boolean moving, Map<String, KeyAttributes> read) {
    List<KeyAttributes> path = new ArrayList<>(List.of(start));
    Set<String> seen = new HashSet<>(Set.of(start.id()));
    KeyAttributes c = start;
    for (int step = 0; step < WALK; step++) {
      List<String> targets = c.links(LinkKind.REPLACEMENT);
      KeyAttributes next = null;
      for (String t : targets.subList(0, Math.min(targets.size(), Lineage.FANOUT))) {
        if (seen.contains(t)) continue;
        KeyAttributes r = attributes(keys, read, t);
        if (r == null || r.kind() != ObjectKind.CERTIFICATE || !Lineage.replaced(r, c)) continue;
        if (next == null || Lineage.TIPS.compare(r, next) < 0) next = r;
      }
      if (next == null) break;
      path.add(next);
      seen.add(next.id());
      c = next;
    }
    return new Found(path, moving, read);
  }

  /**
   * Reads the attributes of {@code ids} into {@code read} (objects that do not exist map to
   * null): one batched Get Attributes, retaining each successful item or absence even if another fails; when
   * that fails, one each in order, so a later failure leaves the earlier observations intact.
   */
  static void readAll(KmsKeys keys, List<String> ids, Map<String, KeyAttributes> read) {
    if (ids.isEmpty()) return;
    try {
      keys.attributesOf(ids, read::put);
    } catch (KmsException batchFailed) {
      for (String id : ids) read.put(id, keys.read(id).orElse(null));
      return;
    }
  }

  /**
   * Whether {@code a} matches what {@code query} asks of its name, group, state, kind,
   * algorithm, custom attributes and links, checked here rather than trusted to the server (some
   * servers ignore filters on client attributes); its date ranges are left to the server.
   */
  static boolean matches(KeyAttributes a, KeyQuery query) {
    if (query.name != null && !a.names().contains(query.name)) return false;
    if (query.group != null && !a.groups().contains(query.group)) return false;
    if (query.state != null && a.state() != query.state) return false;
    if (query.kind != null && a.kind() != query.kind) return false;
    if (query.algorithm != null && !a.algorithm().map(query.algorithm::equals).orElse(false))
      return false;
    if (!query.matchesCustom(a)) return false;
    for (KeyQuery.LinkFilter l : query.links)
      if (!a.links(l.kind()).contains(l.targetId())) return false;
    return true;
  }

  /**
   * The certificates {@code query} matches: one Locate, one batched Get Attributes of what it
   * found, each checked against the query here ({@link #matches}), in the server's order.
   */
  static List<String> located(KmsKeys keys, KeyQuery query) {
    return locatedAttributes(keys, query).stream().map(KeyAttributes::id).toList();
  }

  /** {@link #located}, with the attributes read of each. */
  static List<KeyAttributes> locatedAttributes(KmsKeys keys, KeyQuery query) {
    List<String> ids = keys.locate(query).map(KeyHandle::id).distinct().toList();
    if (ids.isEmpty()) return List.of();
    List<KeyAttributes> out = new ArrayList<>();
    for (KeyAttributes a : keys.attributesOf(ids)) if (matches(a, query)) out.add(a);
    return out;
  }

  /** {@code id}'s attributes, from {@code read} or read now (and kept there); null when it does not exist. */
  static KeyAttributes attributes(KmsKeys keys, Map<String, KeyAttributes> read, String id) {
    KeyAttributes a = read.get(id);
    if (a != null) return a;
    a = keys.read(id).orElse(null);
    read.put(id, a);
    return a;
  }

  /**
   * The private key of {@code certificate}: the one its Private Key link names that names it back
   * with a Certificate link; null when there is none. A key taken from {@code read} without that
   * link is read again: it may have been read before the certificate, and before a renewal that
   * ran meanwhile linked it to the certificate (which it does before activating the certificate).
   */
  static KeyAttributes keyOf(
      KmsKeys keys, KeyAttributes certificate, Map<String, KeyAttributes> read) {
    for (String id : certificate.links(LinkKind.PRIVATE_KEY)) {
      boolean earlier = read.get(id) != null;
      KeyAttributes k = attributes(keys, read, id);
      if (earlier
          && k.kind() == ObjectKind.PRIVATE_KEY
          && !k.links(LinkKind.CERTIFICATE).contains(certificate.id())) {
        k = keys.read(id).orElse(null);
        read.put(id, k);
      }
      if (k != null
          && k.kind() == ObjectKind.PRIVATE_KEY
          && k.links(LinkKind.CERTIFICATE).contains(certificate.id())) return k;
    }
    return null;
  }

  /**
   * The identifiers of {@code leaf}'s chain, the leaf first: each certificate's first Certificate
   * link to a certificate, at most {@link #CHAIN}; a link to an object that does not exist, or that
   * is not a certificate, ends it.
   */
  static List<String> chainIds(KmsKeys keys, KeyAttributes leaf, Map<String, KeyAttributes> read) {
    List<String> ids = new ArrayList<>(List.of(leaf.id()));
    KeyAttributes c = leaf;
    while (ids.size() < CHAIN) {
      KeyAttributes parent = null;
      for (String id : c.links(LinkKind.CERTIFICATE)) {
        if (ids.contains(id)) continue;
        KeyAttributes p = attributes(keys, read, id);
        if (p != null && p.kind() == ObjectKind.CERTIFICATE) {
          parent = p;
          break;
        }
      }
      if (parent == null) break;
      ids.add(parent.id());
      c = parent;
    }
    return ids;
  }

  /**
   * {@code leaf}'s chain as certificates, the leaf first, following {@link #chainIds}; a
   * certificate that does not exist any more, or is not the issuer of the one before it, ends it.
   * Certificates are taken from {@code cache} or read (one Get each) and kept there.
   */
  static List<X509Certificate> chain(
      KmsKeys keys,
      KeyAttributes leaf,
      X509Certificate leafCertificate,
      Map<String, X509Certificate> cache,
      Map<String, KeyAttributes> read) {
    List<X509Certificate> chain = new ArrayList<>(List.of(leafCertificate));
    List<String> ids = chainIds(keys, leaf, read);
    for (String id : ids.subList(1, ids.size())) {
      X509Certificate parent;
      try {
        parent = cached(keys.kms(), cache, id);
      } catch (NotFoundException | StateConflictException gone) {
        break;
      }
      X509Certificate child = chain.get(chain.size() - 1);
      if (!parent.getSubjectX500Principal().equals(child.getIssuerX500Principal())) break;
      chain.add(parent);
    }
    return chain;
  }

  /** The certificate {@code id}, from {@code cache} or read with one Get (and kept there). */
  static X509Certificate cached(Kms kms, Map<String, X509Certificate> cache, String id) {
    X509Certificate c = cache.get(id);
    if (c == null) {
      c = certificate(kms, id);
      cache.put(id, c);
    }
    return c;
  }

  /** The certificate {@code id}, with one Get and no state check: the caller has read its state. */
  static X509Certificate certificate(Kms kms, String id) {
    Request request = Requests.get().uniqueIdentifier(id).build();
    return kms.execute(
        "asCertificate",
        Kms.Kind.READ,
        id,
        s -> ObjectViews.certificate(payload(s.call(request)), id));
  }

  /**
   * The certificates {@code ids} name, by identifier, in their order: one batched Get per {@link
   * Messages#MAX_BATCH_ITEMS} (one Get each from servers that do not take batches). One that does
   * not exist any more is left out.
   */
  static Map<String, X509Certificate> certificates(Kms kms, List<String> ids) {
    Map<String, X509Certificate> out = new LinkedHashMap<>();
    List<String> unique = new ArrayList<>(new LinkedHashSet<>(ids));
    for (int from = 0; from < unique.size(); from += Messages.MAX_BATCH_ITEMS) {
      List<String> chunk =
          unique.subList(from, Math.min(unique.size(), from + Messages.MAX_BATCH_ITEMS));
      if (chunk.size() > 1)
        try {
          out.putAll(batch(kms, chunk));
          continue;
        } catch (UnsupportedException
            | InvalidRequestException
            | ServerFailureException
            | ProtocolViolationException e) {
          // A server that does not process batches, or a batch it could not: one Get each.
        }
      for (String id : chunk)
        try {
          out.put(id, certificate(kms, id));
        } catch (NotFoundException gone) {
          // destroyed since it was found
        }
    }
    return out;
  }

  private static Map<String, X509Certificate> batch(Kms kms, List<String> ids) {
    List<Request> requests =
        ids.stream().map(id -> Requests.get().uniqueIdentifier(id).build()).toList();
    return kms.execute(
        "certificates",
        Kms.Kind.READ,
        null,
        s -> {
          Response response =
              s.batch(
                  requests,
                  RequestOptions.DEFAULT.batching(true, Enums.BatchErrorContinuation.CONTINUE));
          Map<String, X509Certificate> read = new LinkedHashMap<>();
          for (int i = 0; i < requests.size(); i++) {
            Result r =
                response
                    .resultFor(i)
                    .orElseThrow(
                        () -> new ProtocolException("Batch item without a result", null, null));
            if (!r.successful()) {
              if (r.hasReason(Enums.ResultReason.ITEM_NOT_FOUND)
                  || r.hasReason(Enums.ResultReason.OBJECT_NOT_FOUND)
                  || r.hasReason(Enums.ResultReason.OBJECT_DESTROYED)) continue;
              throw new KmipException(r);
            }
            read.put(ids.get(i), ObjectViews.certificate(payload(r), ids.get(i)));
          }
          return read;
        });
  }

  private static Ttlv payload(Result result) throws ProtocolException {
    try {
      return result.requirePayload();
    } catch (IllegalStateException e) {
      throw new ProtocolException("Get response has no payload", result.batchItem(), null);
    }
  }

  /** What to expect of the private key of a certificate whose public key is {@code key}. */
  static Expect expect(PublicKey key) {
    if (key instanceof RSAPublicKey rsa) return Expect.rsa(rsa.getModulus().bitLength());
    if (key instanceof ECPublicKey ec)
      return Expect.ec(ec.getParams().getCurve().getField().getFieldSize());
    throw new IllegalArgumentException(
        "Only RSA and EC keys are supported, not " + key.getAlgorithm());
  }

  /** Refuses SDK-owned signing with a key whose latest observed State is not Active. */
  static void requireActiveSigningKey(KeyAttributes attributes, String operation) {
    if (attributes.state() != KeyState.ACTIVE)
      throw new StateConflictException(
              operation
                  + ": private key "
                  + attributes.id()
                  + " is "
                  + attributes.state()
                  + "; signing requires Active",
              null,
              operation,
              attributes.id(),
              null,
              null)
          .observed(attributes.state());
  }

  /** A signing policy the SDK cannot obey without refusing the key; null when signing is permitted. */
  static UnsupportedException signingRefusal(KeyAttributes attributes, String operation) {
    String detail =
        attributes.usageLimited()
            ? " has Usage Limits; the SDK cannot obtain or enforce usage allocations"
            : !attributes.usages().contains(KeyUsage.SIGN)
                ? " does not permit SIGN in its Cryptographic Usage Mask"
                : null;
    return detail == null
        ? null
        : new UnsupportedException(
            "TLS private key " + attributes.id() + detail,
            null,
            operation,
            attributes.id(),
            null,
            null);
  }

  /** Whether {@code key} is the private half of {@code certificateKey} (it signs, the other verifies). */
  static boolean matches(PrivateKey key, PublicKey certificateKey) {
    try {
      return PemIdentity.matches(key, certificateKey, null);
    } catch (IllegalArgumentException unusable) {
      return false;
    }
  }

  /**
   * Checks a chain given to register, renew or re-key: not empty, without repeats, each
   * certificate issued (and signed) by the next.
   *
   * @throws IllegalArgumentException otherwise
   */
  static List<X509Certificate> checkedChain(String operation, X509Certificate... chain) {
    Objects.requireNonNull(chain, "chain");
    if (chain.length == 0)
      throw new IllegalArgumentException(operation + ": the certificate chain is empty");
    if (chain.length > CHAIN)
      throw new IllegalArgumentException(
          operation + ": a chain of more than " + CHAIN + " certificates");
    for (X509Certificate c : chain) Objects.requireNonNull(c, "certificate");
    Set<String> seen = new HashSet<>();
    for (X509Certificate c : chain)
      if (!seen.add(fingerprint(c)))
        throw new IllegalArgumentException(
            operation + ": the chain holds " + c.getSubjectX500Principal() + " twice");
    String broken = chainBreak(List.of(chain));
    if (broken != null)
      throw new IllegalArgumentException(
          operation
              + ": "
              + broken
              + ": give the chain leaf first, each certificate followed by its issuer");
    expect(chain[0].getPublicKey());
    return List.of(chain);
  }

  /**
   * Where {@code chain}, leaf first, breaks: why the first certificate that is not issued by the
   * next one (its issuer name the next one's subject, and its signature verified with the next
   * one's key) is not; null when each is.
   */
  static String chainBreak(List<X509Certificate> chain) {
    for (int i = 0; i + 1 < chain.size(); i++) {
      X509Certificate c = chain.get(i), next = chain.get(i + 1);
      boolean issued = c.getIssuerX500Principal().equals(next.getSubjectX500Principal());
      try {
        if (issued) c.verify(next.getPublicKey());
      } catch (java.security.GeneralSecurityException e) {
        issued = false;
      }
      if (!issued)
        return "certificate "
            + i
            + " of the chain ("
            + c.getSubjectX500Principal()
            + ") is not issued by the next one ("
            + next.getSubjectX500Principal()
            + ")";
    }
    return null;
  }

  /** The SHA-256 of a certificate's DER encoding, in lower-case hex. */
  static String fingerprint(X509Certificate certificate) {
    try {
      return HexFormat.of()
          .formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
    } catch (NoSuchAlgorithmException | java.security.cert.CertificateEncodingException e) {
      throw new IllegalStateException(e);
    }
  }

  /** How the temporary names of a call for the identity {@code name} begin. */
  static String temporaryPrefix(String name) {
    return name + ".issuing-";
  }

  /**
   * A temporary name for the objects of one call that makes a new leaf certificate the identity
   * {@code name}: {@link #temporaryPrefix}, then a random part, so that no other call uses it.
   */
  static String temporaryName(String name) {
    return temporaryPrefix(name) + java.util.UUID.randomUUID();
  }
}
