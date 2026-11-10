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

import dev.keytend.kmip.model.*;
import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * A managed object's attributes in one shape for every protocol version: read from KMIP 1.x
 * {@code Attribute} structures, 2.x {@code Attributes}, and the 3.0 draft's text names and
 * per-type link attributes alike.
 *
 * <p>Custom and vendor attributes are keyed by {@link CustomAttribute}; their values are {@link
 * String}, {@link Integer} (Integer and Enumeration), {@link Long}, {@link BigInteger}, {@link
 * Boolean}, {@link Instant} (DateTime), {@code byte[]} or, for structures, the raw {@link Ttlv}.
 *
 * <p>Immutable, so thread-safe: a snapshot of what the server returned when it was read, never
 * refreshed (read the object again for its attributes now). Nothing it returns changes it: the
 * collections cannot be modified, and each {@link #custom()} call returns its own copies of
 * {@code byte[]} values, as the constructor keeps its own.
 *
 * @since 0.10.0
 */
public final class KeyAttributes {
  private final String id;
  private final int objectType, state, usageMask;
  private final List<String> names, groups;
  private final int algorithm;
  private final Integer length;
  private final Instant created, activated, deactivated, compromised, destroyed;
  private final List<Link> links;
  private final Map<CustomAttribute, Object> custom;

  /** Whether {@link #custom} holds a {@code byte[]}, which {@link #custom()} copies. */
  private final boolean customArrays;

  private final List<Ttlv> raw;

  /** Extractable and Sensitive (KMIP 1.4 §3.50, §3.48); null when the server did not state them. */
  private final Boolean extractable, sensitive;

  /** Lease Time in seconds (KMIP 1.4 §3.20); null when the server did not state one. */
  private final Long leaseSeconds;

  private final boolean malformedLease;

  /** Process Start, Protect Stop and Compromise Occurrence Dates; null when the server gave none. */
  private final Instant processStart, protectStop, compromiseOccurred;

  KeyAttributes(
      String id,
      int objectType,
      int state,
      int usageMask,
      List<String> names,
      List<String> groups,
      int algorithm,
      Integer length,
      Instant created,
      Instant activated,
      Instant deactivated,
      Instant compromised,
      Instant destroyed,
      List<Link> links,
      Map<CustomAttribute, Object> custom,
      List<Ttlv> raw) {
    this.id = id;
    this.objectType = objectType;
    this.state = state;
    this.usageMask = usageMask;
    this.names = List.copyOf(names);
    this.groups = List.copyOf(groups);
    this.algorithm = algorithm;
    this.length = length;
    this.created = created;
    this.activated = activated;
    this.deactivated = deactivated;
    this.compromised = compromised;
    this.destroyed = destroyed;
    this.links = List.copyOf(links);
    this.custom = copy(custom);
    this.customArrays = this.custom.values().stream().anyMatch(byte[].class::isInstance);
    this.raw = List.copyOf(raw);
    Boolean x = null, s = null;
    Long lease = null;
    boolean malformed = false;
    Instant start = null, stop = null, occurred = null;
    for (Ttlv a : this.raw) {
      boolean date = a.type() == Ttlv.Type.DATE_TIME || a.type() == Ttlv.Type.DATE_TIME_EXTENDED;
      if (date && a.tag() == Tag.PROCESS_START_DATE.code() && start == null)
        start = a.instantValue();
      else if (date && a.tag() == Tag.PROTECT_STOP_DATE.code() && stop == null)
        stop = a.instantValue();
      else if (date && a.tag() == Tag.COMPROMISE_OCCURRENCE_DATE.code() && occurred == null)
        occurred = a.instantValue();
      else if (a.tag() == Tag.EXTRACTABLE.code() && a.type() == Ttlv.Type.BOOLEAN && x == null)
        x = a.booleanValue();
      else if (a.tag() == Tag.SENSITIVE.code() && a.type() == Ttlv.Type.BOOLEAN && s == null)
        s = a.booleanValue();
      else if (a.tag() == Tag.LEASE_TIME.code()) {
        if (a.type() != Ttlv.Type.INTERVAL || lease != null) malformed = true;
        else {
          lease = a.longValue();
          if (lease < 0 || lease > 0xffff_ffffL) malformed = true;
        }
      }
    }
    this.extractable = x;
    this.sensitive = s;
    this.leaseSeconds = lease;
    this.malformedLease = malformed;
    this.processStart = start;
    this.protectStop = stop;
    this.compromiseOccurred = occurred;
  }

  /**
   * The object's Unique Identifier.
   *
   * @return the identifier
   */
  public String id() {
    return id;
  }

  /**
   * The KMIP Object Type; {@link ObjectKind#OTHER} for a type this API does not name, or none.
   *
   * @return the kind
   */
  public ObjectKind kind() {
    return ObjectKind.of(objectType);
  }

  /**
   * The KMIP Object Type code (0 when the server did not return it).
   *
   * @return the code, or 0
   */
  public int rawObjectType() {
    return objectType;
  }

  /**
   * The KMIP State; {@link KeyState#UNKNOWN} for a state this API does not name, or none.
   *
   * @return the state
   */
  public KeyState state() {
    return KeyState.of(state);
  }

  /**
   * The KMIP State code (0 when the server did not return it).
   *
   * @return the code, or 0
   */
  public int rawState() {
    return state;
  }

  /**
   * The Name values, in the server's order.
   *
   * @return the names, unmodifiable; empty when the object has none
   */
  public List<String> names() {
    return names;
  }

  /**
   * The Cryptographic Algorithm; {@link Algorithm#OTHER} for one this API does not name.
   *
   * @return the algorithm; empty when the server did not return one
   */
  public Optional<Algorithm> algorithm() {
    return algorithm == 0 ? Optional.empty() : Optional.of(Algorithm.of(algorithm));
  }

  /**
   * The KMIP Cryptographic Algorithm code (0 when the server did not return it).
   *
   * @return the code, or 0
   */
  public int rawAlgorithm() {
    return algorithm;
  }

  /**
   * Cryptographic Length in bits.
   *
   * @return the length; empty when the server did not return one
   */
  public OptionalInt length() {
    return length == null ? OptionalInt.empty() : OptionalInt.of(length);
  }

  /**
   * The usages this API names; {@link #rawUsageMask()} keeps every bit.
   *
   * @return the usages, unmodifiable
   */
  public Set<KeyUsage> usages() {
    return KeyUsage.of(usageMask);
  }

  /**
   * The KMIP Cryptographic Usage Mask, every bit (0 when the server did not return it).
   *
   * @return the mask
   */
  public int rawUsageMask() {
    return usageMask;
  }

  /**
   * Initial Date: when the object was created or registered.
   *
   * @return the date; empty when the server did not return one
   */
  public Optional<Instant> creationDate() {
    return Optional.ofNullable(created);
  }

  /**
   * Activation Date: when the object became Active, or will. A key made by a KMIP Re-key without an
   * Offset ({@link KeyHandle#rotate()}) has the Activation Date of the key it replaced (KMIP 1.4
   * §4.4, 2.1 §6.1.46), which may be its lineage's first; its {@link #creationDate()} is when it was
   * made.
   *
   * @return the date; empty when the server did not return one
   */
  public Optional<Instant> activationDate() {
    return Optional.ofNullable(activated);
  }

  /**
   * Deactivation Date: when the object was or will be deactivated.
   *
   * @return the date; empty when the server did not return one
   */
  public Optional<Instant> deactivationDate() {
    return Optional.ofNullable(deactivated);
  }

  /**
   * Process Start Date: when the key may begin to process (decrypt, unwrap, verify) data. Servers
   * usually set it from a cryptoperiod policy.
   *
   * @return the date; empty when the server did not return one
   * @since 0.10.0
   */
  public Optional<Instant> processStartDate() {
    return Optional.ofNullable(processStart);
  }

  /**
   * Protect Stop Date: when the key stops protecting (encrypting, wrapping, signing) data, though it
   * may still process it. Servers usually set it from a cryptoperiod policy. A Re-key without an
   * Offset copies it ({@link KeyHandle#rotate()}); with one ({@link RotationDates#SHIFTED}) the
   * server moves it.
   *
   * @return the date; empty when the server did not return one
   * @since 0.10.0
   */
  public Optional<Instant> protectStopDate() {
    return Optional.ofNullable(protectStop);
  }

  /**
   * Compromise Date: when the object was revoked as compromised, as the server recorded it.
   *
   * @return the date; empty when the server did not return one
   */
  public Optional<Instant> compromiseDate() {
    return Optional.ofNullable(compromised);
  }

  /**
   * Compromise Occurrence Date: when the compromise happened, as the revocation stated it ({@link
   * RevocationReason#compromiseOccurred()}). It may be earlier than {@link #compromiseDate()}.
   *
   * @return the date; empty when the server did not return one
   * @since 0.10.0
   */
  public Optional<Instant> compromiseOccurrenceDate() {
    return Optional.ofNullable(compromiseOccurred);
  }

  /**
   * Destroy Date: when the object was destroyed.
   *
   * @return the date; empty when the server did not return one
   */
  public Optional<Instant> destroyDate() {
    return Optional.ofNullable(destroyed);
  }

  /**
   * Every Link, in the server's order.
   *
   * @return the links, unmodifiable
   */
  public List<Link> links() {
    return links;
  }

  /**
   * The target of the first link of {@code kind}, as the server returns it. KMIP allows a Managed
   * Object one replacement object (and the 3.0 draft one link of most kinds); a server that re-keys
   * a key twice, or lets a client add a second link, breaks that rule and can return several, which
   * {@link #links(LinkKind)} returns.
   *
   * @param kind the link kind
   * @return the first link's target; empty when there is none
   */
  public Optional<String> link(LinkKind kind) {
    return links.stream().filter(l -> l.kind() == kind).map(Link::targetId).findFirst();
  }

  /**
   * The targets of every link of {@code kind}, in the server's order, without repeats.
   *
   * @param kind the link kind
   * @return the targets, unmodifiable
   */
  public List<String> links(LinkKind kind) {
    return links.stream().filter(l -> l.kind() == kind).map(Link::targetId).distinct().toList();
  }

  /**
   * This key's first Replacement Object link: a raw, one-sided link, as the server returns it.
   * Whoever controls this key can set it, so it proves nothing about the lineage: {@link
   * KeyHandle#latest()}, {@link KeyHandle#reconcile()} and the other walks count a rotation step
   * only when both keys name each other, and treat a replacement that does not name this key back
   * as outside the lineage. Only a server that breaks KMIP's one-replacement rule gives a key
   * several ({@link #links(LinkKind)}). {@link LineageKey#replacedBy()} gives the confirmed steps.
   *
   * @return the target; empty when there is none
   */
  public Optional<String> replacementLink() {
    return link(LinkKind.REPLACEMENT);
  }

  /**
   * This key's first Replaced Object link: a raw, one-sided link, as the server returns it. Whoever
   * controls this key can set it, so a key that names another here is not in that key's lineage
   * unless the other names it back with its Replacement Object link ({@link KeyHandle#latest()},
   * {@link KeyHandle#compromisedPredecessors()}). {@link LineageKey#replaced()} gives the
   * confirmed steps.
   *
   * @return the target; empty when there is none
   */
  public Optional<String> replacedLink() {
    return link(LinkKind.REPLACED);
  }

  /**
   * The KMIP Extractable attribute (1.4 §3.50, 2.1 §4.23): {@code false} means the server must refuse
   * to return the key's value with Get, wrapped or not ({@link KeyHandle#asSecretKey} and the other
   * retrieval methods are refused with a {@link PermissionDeniedException} whose reason is {@link
   * KmsReason#NOT_EXTRACTABLE}). KMIP 1.4 introduced it and requires a value on every object (True
   * unless the client set it); empty when the server did not state it, which is always the case below
   * KMIP 1.4, and also a server that omits it: then whether the key can be extracted is unknown, not
   * {@code true}. A snapshot: on KMIP 1.4 to 2.1 a client allowed to modify the key can change it
   * either way (the 3.0 draft allows only True to False).
   *
   * @return the value the server stated; never null
   * @since 0.10.0
   */
  public Optional<Boolean> extractable() {
    return Optional.ofNullable(extractable);
  }

  /**
   * The KMIP Sensitive attribute (1.4 §3.48, 2.1 §4.55): {@code true} means the server must refuse
   * to return the key's value with Get unless it is wrapped by another key, so {@link
   * KeyHandle#asSecretKey} and the other retrieval methods, which ask for it unwrapped, are refused
   * ({@link PermissionDeniedException}, reason {@link KmsReason#NOT_EXTRACTABLE}). KMIP 1.4
   * introduced it and requires a value on every object (False unless the client set it); empty when
   * the server did not state it (always below KMIP 1.4). A snapshot, as {@link #extractable()}.
   *
   * @return the value the server stated; never null
   * @since 0.10.0
   */
  public Optional<Boolean> sensitive() {
    return Optional.ofNullable(sensitive);
  }

  /**
   * The KMIP Lease Time (1.4 §3.20, 2.1 §4.30): how long a client may use the object, once it has
   * a lease, before it "SHALL NOT use the object without obtaining another lease" (Obtain Lease). The
   * maximum the server will grant, not the time left. Empty when the server set none, which is
   * KMIP's default (it need not have a value) and means no lease obligation; read on every version.
   * A key with one is not for a cache that keeps it indefinitely (see <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/local-keys.md#keys-taken-out-of-the-kms">Keys taken out of the KMS</a>).
   *
   * @return the server's Lease Time, whole seconds; never null
   * @throws ProtocolViolationException when a stated Lease Time has the wrong type or value, or is repeated
   * @since 0.10.0
   */
  public Optional<Duration> leaseTime() {
    if (malformedLease)
      throw new ProtocolViolationException(
          "Malformed Lease Time for " + id, null, "getAttributes", id, null, null);
    return leaseSeconds == null ? Optional.empty() : Optional.of(Duration.ofSeconds(leaseSeconds));
  }

  /** A malformed obligation still requires Obtain Lease; its maximum is unknown until the answer. */
  Duration leaseToObtain() {
    return malformedLease ? Duration.ZERO : leaseTime().orElse(null);
  }

  /** Presence alone requires a usage allocation before applying protection, irrespective of its value. */
  boolean usageLimited() {
    return raw.stream().anyMatch(a -> a.tag() == Tag.USAGE_LIMITS.code());
  }

  /**
   * Object Group values (KMIP 1.x and 2.x).
   *
   * @return the groups, unmodifiable
   */
  public List<String> groups() {
    return groups;
  }

  /**
   * Custom and vendor attributes (see the class description for the value types). A {@code
   * byte[]} value is a copy made for this call: changing it changes neither this snapshot nor what
   * the next call returns.
   *
   * @return the attributes, unmodifiable
   */
  public Map<CustomAttribute, Object> custom() {
    return customArrays ? copy(custom) : custom;
  }

  /** An unmodifiable copy of {@code values}, in order, with its own copy of each {@code byte[]}. */
  private static Map<CustomAttribute, Object> copy(Map<CustomAttribute, Object> values) {
    Map<CustomAttribute, Object> out = new LinkedHashMap<>(values);
    out.replaceAll((name, value) -> value instanceof byte[] b ? b.clone() : value);
    return Collections.unmodifiableMap(out);
  }

  /**
   * Protocol-layer escape hatch: every attribute in the KMIP 2.x form (each tagged with the
   * attribute; vendor attributes as {@code Attribute} structures), for attributes this record does
   * not model.
   *
   * @return the attributes, unmodifiable
   */
  public List<Ttlv> protocolAttributes() {
    return raw;
  }

  @Override
  public String toString() {
    return "KeyAttributes[" + id + ", " + kind() + ", " + state() + ", names=" + names + "]";
  }
}
