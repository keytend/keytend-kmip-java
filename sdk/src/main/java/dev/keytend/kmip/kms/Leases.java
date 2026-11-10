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
import dev.keytend.kmip.client.ProtocolException;
import dev.keytend.kmip.client.Request;
import dev.keytend.kmip.client.RequestOptions;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.client.Response;
import dev.keytend.kmip.client.Result;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * The KMIP leases of the objects a TLS follower keeps for use (KMIP 1.4 §3.20 and §4.17, 2.1 §4.30
 * and §6.1.35): a client "SHALL NOT use the object without obtaining another lease" once its lease
 * has run out. An object whose Get Attributes states a Lease Time is usable only while a lease that
 * Obtain Lease granted runs: from the local time the request was sent (never its answer, nor a
 * retry), for the interval returned, zero meaning no limit. An object without a Lease Time needs no
 * lease and is asked for none. Get, Get Attributes and Locate never grant or renew one. Each grant
 * is told to {@link KmsListener#leaseGranted} by {@link #tell}, once the follower's lock is
 * released.
 *
 * <p>{@link #usable} is what a handshake asks: a map lookup and a clock read, never a request or a
 * lock, so a stalled refresh or executor cannot extend a lease. {@link #obtain} runs under the
 * follower's lock, within the refresh's deadline. A refusal (the server's definite answer: Permission
 * Denied, Operation Not Supported, not found, a state or request refusal) ends the object's lease
 * at once; another failure (no answer, a malformed one, a server failure) keeps the lease it had
 * until that runs out, and grants nothing new.
 */
final class Leases {
  /** Renewals are never planned sooner than this after a refresh. */
  static final long FLOOR_NANOS = TimeUnit.SECONDS.toNanos(1);

  /** Usable with no limit: the object states no Lease Time, so it needs no lease. */
  private static final Lease NOT_LEASED = new Lease(0, Long.MAX_VALUE, 0);

  /** Usable with no limit: Obtain Lease returned zero. */
  private static final Lease UNLIMITED = new Lease(1, Long.MAX_VALUE, 0);

  /**
   * A lease granted at {@code sent} (the clock's value) for {@code nanos}: none when zero (refused,
   * or never granted). {@code maximum}: the object's Lease Time, in nanoseconds (0: zero).
   */
  private record Lease(long sent, long nanos, long maximum) {
    boolean runs(long now) {
      return nanos == Long.MAX_VALUE || (nanos > 0 && now - sent < nanos);
    }
  }

  /** What one {@link #obtain} found: the first refusal, and the first other failure; null when none. */
  record Outcome(KmsException refused, RuntimeException failed) {
    static final Outcome OK = new Outcome(null, null);
  }

  /** The monotonic clock leases are measured on (nanoseconds); tests set it. */
  volatile LongSupplier clock = System::nanoTime;

  private final Map<String, Lease> leases = new ConcurrentHashMap<>();

  /** The objects Obtain Lease granted at least once, for {@link KmsListener#leaseGranted}'s renewal flag. */
  private final Set<String> granted = ConcurrentHashMap.newKeySet();

  /** One grant {@link #tell} has yet to tell, as {@link KmsListener#leaseGranted} hears it. */
  private record Grant(String id, Duration lease, boolean renewal) {}

  /** The grants {@link #obtain} made that {@link #tell} has not told yet, in order. */
  private final java.util.Queue<Grant> untold = new java.util.concurrent.ConcurrentLinkedQueue<>();

  /** Whether {@code id} may be used now: it needs no lease, or its lease runs. Unknown: no. */
  boolean usable(String id) {
    Lease l = leases.get(id);
    return l != null && l.runs(clock.getAsLong());
  }

  /** Whether each of {@code ids} may be used now. */
  boolean usable(Collection<String> ids) {
    long now = clock.getAsLong();
    for (String id : ids) {
      Lease l = leases.get(id);
      if (l == null || !l.runs(now)) return false;
    }
    return true;
  }

  /**
   * How long each of {@code ids} may still be used, at least: the shortest time left of their
   * leases, in nanoseconds; {@link Long#MAX_VALUE} when none of them has a limited lease; 0 when
   * one of them is not usable now. A diagnostic, read from memory.
   */
  long remaining(Collection<String> ids) {
    long now = clock.getAsLong(), left = Long.MAX_VALUE;
    for (String id : ids) {
      Lease l = leases.get(id);
      if (l == null || !l.runs(now)) return 0;
      if (l.nanos != Long.MAX_VALUE) left = Math.min(left, l.nanos - (now - l.sent));
    }
    return left;
  }

  /** {@link #remaining} as a diagnostic: empty for no limit. */
  static java.util.Optional<Duration> usableFor(long remaining) {
    return remaining == Long.MAX_VALUE
        ? java.util.Optional.empty()
        : java.util.Optional.of(Duration.ofNanos(Math.max(0, remaining)));
  }

  /** Forgets every object but {@code ids}. */
  void retain(Collection<String> ids) {
    Set<String> keep = new HashSet<>(ids);
    leases.keySet().retainAll(keep);
    granted.retainAll(keep);
  }

  /** Forgets every object. */
  void clear() {
    leases.clear();
    granted.clear();
  }

  /**
   * Tells {@code config}'s listeners of each lease {@link #obtain} granted since the last call
   * ({@link KmsListener#leaseGranted}), in order. The follower calls it after it releases its lock,
   * on the thread that obtained them.
   */
  void tell(KmsConfig config) {
    for (Grant g; (g = untold.poll()) != null; ) {
      Grant grant = g;
      Kms.leaseGranted(config, grant.id, grant.lease, grant.renewal);
    }
  }

  /**
   * How long after now a renewal is due: half the shortest time left of a lease running among
   * {@code ids}, or half the Lease Time of one that needs a lease and has none running (so a KMS
   * back after an outage grants it again), at least {@link #FLOOR_NANOS}; {@link Long#MAX_VALUE}
   * when none of them has a limited lease.
   */
  long renewalDelay(Collection<String> ids) {
    long now = clock.getAsLong(), shortest = Long.MAX_VALUE;
    for (String id : ids) {
      Lease l = leases.get(id);
      if (l == null || l.nanos == Long.MAX_VALUE) continue;
      if (l.runs(now)) shortest = Math.min(shortest, l.nanos - (now - l.sent));
      else if (l.maximum > 0) shortest = Math.min(shortest, l.maximum);
    }
    return shortest == Long.MAX_VALUE ? Long.MAX_VALUE : Math.max(FLOOR_NANOS, shortest / 2);
  }

  /**
   * Under the follower's lock: records which of {@code objects} need a lease (each one's Lease Time
   * as last read; null when it states none), and sends Obtain Lease for those that do (one batched
   * request per {@link Messages#MAX_BATCH_ITEMS}), all of them when {@code renew}, else only those
   * whose lease does not run now. Never throws for the KMS.
   */
  Outcome obtain(Kms kms, Map<String, Duration> objects, boolean renew) {
    List<String> ask = new ArrayList<>();
    long now = clock.getAsLong();
    for (Map.Entry<String, Duration> o : objects.entrySet()) {
      String id = o.getKey();
      Lease held = leases.get(id);
      if (o.getValue() == null) {
        if (held != UNLIMITED) leases.put(id, NOT_LEASED);
        continue;
      }
      // An object that stated no Lease Time and now states one needs a lease from now on.
      if (held == NOT_LEASED) leases.remove(id);
      else if (!renew && held != null && held.runs(now)) continue;
      ask.add(id);
    }
    if (ask.isEmpty()) return Outcome.OK;
    KmsException refused = null;
    RuntimeException failed = null;
    for (int from = 0; from < ask.size(); from += Messages.MAX_BATCH_ITEMS) {
      List<String> chunk = ask.subList(from, Math.min(ask.size(), from + Messages.MAX_BATCH_ITEMS));
      // Before the first attempt: a retry, or a late answer, never lengthens the lease.
      long sent = clock.getAsLong();
      Map<String, Object> answers = request(kms, chunk);
      for (String id : chunk) {
        Object a = answers.get(id);
        long maximum = nanos(objects.get(id).toSeconds());
        long bound =
            a instanceof KmsException k ? unsupportedBound(kms, k, id, objects.get(id)) : -1;
        if (a instanceof Long seconds) {
          leases.put(id, lease(sent, seconds, maximum));
          untold.add(new Grant(id, Duration.ofSeconds(seconds), !granted.add(id)));
        } else if (bound > 0) {
          // A server that does not implement Obtain Lease, under HONOR_IF_SUPPORTED.
          leases.put(id, lease(sent, bound, maximum));
        } else if (a instanceof KmsException k && refusal(k)) {
          leases.put(id, new Lease(0, 0, maximum));
          if (refused == null) refused = settled(kms, k, id);
        } else {
          // No new lease: the one held, if any, runs out as granted.
          leases.putIfAbsent(id, new Lease(0, 0, maximum));
          if (failed == null) failed = (RuntimeException) a;
        }
      }
    }
    return new Outcome(refused, failed);
  }

  /**
   * The first refusal {@link #obtain} reports, {@code k} for {@code id}: when the State the server
   * reports now (read once) is a known state other than Active, the refusal is about the object's
   * lifecycle and is reported by that state ({@link #refused(KmsException, String, String,
   * KeyState)}, STATE); otherwise, and when that read fails (suppressed on it), {@code k} itself.
   */
  private static KmsException settled(Kms kms, KmsException k, String id) {
    if (k instanceof NotFoundException) return k;
    KeyState now;
    try {
      now = stateNow(kms, id);
    } catch (KmsException | IllegalStateException unread) {
      k.addSuppressed(unread);
      return k;
    }
    if (now == KeyState.ACTIVE || now == KeyState.UNKNOWN) return k;
    return refused(k, id, Kms.named("obtainLease"), now, false);
  }

  /**
   * The lease a grant of {@code seconds} sent at {@code sent} gives: zero is no limit; a grant
   * longer than the object's own Lease Time ({@code maximum}, the most the server serves, 1.4
   * §3.20) is held to that.
   */
  private static Lease lease(long sent, long seconds, long maximum) {
    if (seconds == 0) return UNLIMITED;
    long nanos = nanos(seconds);
    return new Lease(sent, maximum > 0 ? Math.min(nanos, maximum) : nanos, maximum);
  }

  /** Seconds of an Interval (at most 2^32 - 1, so this never overflows) in nanoseconds; 0 for a negative. */
  private static long nanos(long seconds) {
    return seconds <= 0 ? 0 : TimeUnit.SECONDS.toNanos(Math.min(seconds, 0xffff_ffffL));
  }

  /**
   * A definite answer that the server will not lease the object now: its lease ends at once. A
   * failure without the server's reason (not sent, no answer) is not one, nor a server failure.
   */
  static boolean refusal(KmsException e) {
    if (e instanceof UnsupportedException) return true;
    boolean answer =
        e instanceof PermissionDeniedException
            || e instanceof NotFoundException
            || e instanceof StateConflictException
            || e instanceof InvalidRequestException;
    return answer && e.serverReason().isPresent();
  }

  /**
   * What a refused lease is reported as, by every SDK path that leases: {@code f}, the
   * server's {@link #refusal} of Obtain Lease for {@code id}, when it is to be used for {@code
   * purpose}. When the attributes read just before showed the object other than Active ({@code
   * state}), the cause is its lifecycle, not access: a {@link StateConflictException} (STATE) whose
   * {@link StateConflictException#observedState()} is that state. Otherwise {@code f}'s own type.
   * Either way {@link KmsException#operation()} is {@code obtainLease}, the server's reason,
   * message and result are kept, and the message names the lease, the reason and (sanitized) the
   * server's message, so a lease refusal never reads as a plain authorization failure.
   */
  static KmsException refused(KmsException f, String id, String purpose, KeyState state) {
    return refused(f, id, purpose, state, false);
  }

  /**
   * {@link #refused(KmsException, String, String, KeyState)} with a lifecycle race settled: when the
   * attributes read just before the Obtain Lease showed the object Active ({@code state}), and the
   * refusal is not Item Not Found, the object's State is read once more (one Get Attributes, in the
   * call's deadline). An object deactivated, revoked or destroyed between that read and the Obtain
   * Lease is then reported by the state it is in now, a {@link StateConflictException} (STATE), not
   * as a refusal of access. When the State read again is still Active (or unknown), or the read fails
   * (added to the result as suppressed), the refusal is reported as before, by its own type.
   */
  static KmsException refused(Kms kms, KmsException f, String id, String purpose, KeyState state) {
    if (state != KeyState.ACTIVE || f instanceof NotFoundException)
      return refused(f, id, purpose, state, false);
    KeyState now;
    try {
      now = stateNow(kms, id);
    } catch (KmsException | IllegalStateException unread) {
      KmsException out = refused(f, id, purpose, state, false);
      out.addSuppressed(unread);
      return out;
    }
    return now == KeyState.ACTIVE || now == KeyState.UNKNOWN
        ? refused(f, id, purpose, state, false)
        : refused(f, id, purpose, now, true);
  }

  /** {@code id}'s State as the server reports it now: one Get Attributes, part of the call open. */
  private static KeyState stateNow(Kms kms, String id) {
    Request request = Requests.getAttributes().uniqueIdentifier(id).build();
    return kms.execute(
        "attributes", Kms.Kind.READ, id, s -> KeyHandle.readAttributes(s.call(request)).state());
  }

  /** {@code reread}: {@code state} was read again after the refusal, and changed. */
  private static KmsException refused(
      KmsException f, String id, String purpose, KeyState state, boolean reread) {
    String reason = f.serverReason().map(Object::toString).orElse("");
    String said =
        f.serverMessage()
            .map(KmsException::sanitized)
            .filter(m -> !m.isEmpty())
            .map(m -> "\"" + m + "\"")
            .orElse("");
    String server =
        reason.isEmpty() && said.isEmpty()
            ? ""
            : " (" + reason + (reason.isEmpty() || said.isEmpty() ? "" : ": ") + said + ")";
    var result = f.result().orElse(null);
    var response = f.response().orElse(null);
    String operation = "obtainLease";
    if (state != null && state != KeyState.ACTIVE && !(f instanceof NotFoundException))
      return new StateConflictException(
              purpose
                  + ": "
                  + id
                  + " is "
                  + state
                  + (reread ? " (read again after the refusal: it was Active when first read)" : "")
                  + ", and the server refused to lease it"
                  + server
                  + "; servers lease only some states (keytend-kmip-server: Active, and Deactivated unless --lease-states"
                  + " active; never Compromised): keep a key in a state the server leases while data under it is still read",
              f,
              operation,
              id,
              result,
              response)
          .observed(state);
    String message = purpose + ": the server refused to lease " + id + server;
    if (f instanceof PermissionDeniedException)
      return new PermissionDeniedException(message, f, operation, id, result, response);
    if (f instanceof NotFoundException)
      return new NotFoundException(message, f, operation, id, result, response);
    if (f instanceof StateConflictException)
      return new StateConflictException(message, f, operation, id, result, response);
    if (f instanceof InvalidRequestException)
      return new InvalidRequestException(message, f, operation, id, result, response);
    return new UnsupportedException(message, f, operation, id, result, response);
  }

  /**
   * Under {@link LeasePolicy#HONOR_IF_SUPPORTED}: the seconds {@code id} (stating {@code stated})
   * may be used without a granted lease, because {@code f}, its Obtain Lease's failure, shows a
   * server that does not implement Obtain Lease: Operation Not Supported, or a message-level
   * Invalid Message, confirmed by the server's Query Operations not listing it. The stated Lease
   * Time; -1 otherwise (the policy is {@link LeasePolicy#REQUIRE}, the server refused for another
   * reason or lists Obtain Lease, or the stated time is zero or malformed, which bounds nothing).
   */
  static long unsupportedBound(Kms kms, KmsException f, String id, Duration stated) {
    if (kms.config.leases != LeasePolicy.HONOR_IF_SUPPORTED
        || stated == null
        || stated.isZero()
        || stated.isNegative()) return -1;
    Result r = f.result().orElse(null);
    if (r == null) return -1;
    Enums.ResultReason reason = r.reasonEnum().orElse(null);
    boolean messageLevel = r.operation() == null && r.operationCode().isEmpty();
    boolean unsupported =
        reason == Enums.ResultReason.OPERATION_NOT_SUPPORTED
            || (reason == Enums.ResultReason.INVALID_MESSAGE && messageLevel);
    if (!unsupported || kms.listsObtainLease()) return -1;
    kms.leaseNotGranted(id, stated);
    return Math.min(stated.toSeconds(), 0xffff_ffffL);
  }

  /** Obtain Lease for each of {@code ids}: by identifier, the seconds granted (a Long) or the failure. */
  private static Map<String, Object> request(Kms kms, List<String> ids) {
    Map<String, Object> out = new LinkedHashMap<>();
    if (ids.size() > 1)
      try {
        return batch(kms, ids);
      } catch (UnsupportedException
          | InvalidRequestException
          | ServerFailureException
          | ProtocolViolationException e) {
        // A server that does not process batches, or a batch it could not: one each.
      } catch (KmsException | IllegalStateException e) {
        for (String id : ids) out.put(id, e);
        return out;
      }
    for (String id : ids)
      try {
        Request request = Requests.obtainLease().uniqueIdentifier(id).build();
        out.put(
            id, kms.execute("obtainLease", Kms.Kind.READ, id, s -> granted(s.call(request), id)));
      } catch (KmsException | IllegalStateException e) {
        out.put(id, e);
      }
    return out;
  }

  private static Map<String, Object> batch(Kms kms, List<String> ids) {
    List<Request> requests =
        ids.stream().map(id -> Requests.obtainLease().uniqueIdentifier(id).build()).toList();
    Map<String, Object> items =
        kms.execute(
            "obtainLease",
            Kms.Kind.READ,
            null,
            s -> {
              Response response =
                  s.batch(
                      requests,
                      RequestOptions.DEFAULT.batching(true, Enums.BatchErrorContinuation.CONTINUE));
              Map<String, Object> read = new LinkedHashMap<>();
              for (int i = 0; i < requests.size(); i++) {
                String id = ids.get(i);
                Result r = response.resultFor(i).orElse(null);
                if (r == null)
                  read.put(id, new ProtocolException("Batch item without a result", null, null));
                else if (!r.successful()) read.put(id, new KmipException(r));
                else
                  try {
                    read.put(id, granted(r, id));
                  } catch (ProtocolException malformed) {
                    read.put(id, malformed);
                  }
              }
              return read;
            });
    Map<String, Object> out = new LinkedHashMap<>();
    for (String id : ids) {
      Object a = items.get(id);
      if (a instanceof Exception e && !(a instanceof KmsException))
        a =
            Failures.classify(
                new Failures.Call(Kms.named("obtainLease"), true, id, false),
                kms.protocolVersion(),
                e);
      out.put(id, a);
    }
    return out;
  }

  /**
   * The seconds an Obtain Lease response grants {@code id}: it must name {@code id} and state one
   * Lease Time; anything else is malformed and grants nothing.
   */
  static long granted(Result result, String id) throws ProtocolException {
    Ttlv payload;
    try {
      payload = result.requirePayload();
    } catch (IllegalStateException e) {
      throw new ProtocolException("Obtain Lease response has no payload", result.batchItem(), null);
    }
    List<Ttlv> named = payload.children(Tag.UNIQUE_IDENTIFIER),
        lease = payload.children(Tag.LEASE_TIME);
    String name = named.size() == 1 ? text(named.get(0)) : null;
    if (!id.equals(name))
      throw new ProtocolException(
          "Obtain Lease response for " + id + " names " + (name != null ? name : "no one object"),
          result.batchItem(),
          null);
    if (lease.size() != 1 || lease.get(0).type() != Ttlv.Type.INTERVAL)
      throw new ProtocolException(
          "Obtain Lease response for " + id + " states no one Lease Time",
          result.batchItem(),
          null);
    long seconds = lease.get(0).longValue();
    if (seconds < 0 || seconds > 0xffff_ffffL)
      throw new ProtocolException(
          "Obtain Lease response for " + id + " states Lease Time " + seconds,
          result.batchItem(),
          null);
    return seconds;
  }

  /**
   * A Unique Identifier's text: a Text String, or the 3.0 draft's Identifier or Reference type (as
   * the protocol layer takes a concrete identifier); null for another type.
   */
  private static String text(Ttlv field) {
    Ttlv.Type t = field.type();
    return t == Ttlv.Type.TEXT_STRING || t == Ttlv.Type.IDENTIFIER || t == Ttlv.Type.REFERENCE
        ? field.textValue()
        : null;
  }
}
