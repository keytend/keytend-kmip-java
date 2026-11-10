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
import java.time.Instant;
import java.util.List;

/**
 * Observability callbacks for metrics, tracing and alerts. Implement the methods you need and add
 * the listener with {@link KmsConfig.Builder#addListener}. The {@code keytend-kmip-micrometer} and
 * {@code keytend-kmip-opentelemetry} modules have listeners that turn these events into meters and
 * spans.
 *
 * <ul>
 *   <li>A configuration has any number of listeners, called in the order added. The SDK's own
 *       logging runs beside them (<a
 *       href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/production.md#logging">Logging</a>).
 *   <li>Listeners run on the thread that does the work. Keep them quick.
 *   <li>Whatever a listener throws, an {@link Error} included, is ignored, and the next listener is
 *       still called. A listener cannot change the outcome of an operation.
 * </ul>
 *
 * <p>A listener may call a {@link Kms}, and that call gets its own call deadline. It must not call
 * {@link KeyCreation#findOrCreate()} for the key the observed call is finding or creating, through
 * the same {@code Kms} or one of its views. That throws {@link IllegalStateException}, because it
 * would wait for itself.
 *
 * <p>Every method has a default that does nothing. Later releases may add methods with such
 * defaults.
 *
 * @since 0.10.0
 */
public interface KmsListener {
  /**
   * A listener that calls each of {@code listeners} in turn, isolated from each other: what one
   * throws is ignored and the next is still called. A listener given twice, also inside another
   * {@code all}, is called once per event.
   *
   * @param listeners the listeners, in calling order
   * @return a listener calling all of them
   */
  static KmsListener all(KmsListener... listeners) {
    return new KmsListeners(List.of(listeners));
  }

  /**
   * An application call started: its first attempt is about to be sent.
   *
   * <p>A call is one method the application called through a {@link Kms}, or through an SDK object
   * that uses one. It covers every step, attempt, retry and failover the method takes on the
   * calling thread, under one deadline ({@link KmsConfig.Builder#callTimeout}). {@link
   * KmsEvent#callId()} is the same in the call's events and in its attempts' events.
   *
   * <p><b>When it fires.</b> Once per call, just before its first {@link #started}.
   *
   * <ul>
   *   <li>A call that sends no request, because a cache served it or the SDK refused it first,
   *       fires neither this nor {@link #callFinished}.
   *   <li>A call a listener makes from any callback is a call of its own.
   *   <li>When a call's attempts go through {@code Kms} instances of different configurations, such
   *       as {@link KeyHandle#rewrapTo} to another server, each of their listeners hears of the
   *       call once. That includes a listener added to several of them, and the SDK's own logging.
   * </ul>
   *
   * <p><b>Names.</b> {@link KmsEvent#operation()} is the name of the public method called, and
   * every attempt of the call carries it. {@link KmsEvent#step()} says which step an attempt
   * serves.
   *
   * <ul>
   *   <li>A method has its own name: {@code "findOrCreate"}, {@code "register"}, {@code
   *       "asSecretKey"}, a {@link CurrentKey}'s {@code "seal"} or {@code "rewrapTo"}. Overloads
   *       share it. A {@code CurrentKey}'s {@code "seal"} whose check is due starts with the step
   *       {@code "attributes"}.
   *   <li>A {@code ...Result} form has its method's name: {@code rotateResult} is {@code "rotate"},
   *       {@code findOrCreateResult} is {@code "findOrCreate"}.
   *   <li>A {@link LocalKeys} use or load is {@code "localKeys"}.
   *   <li>Each page of a lazy stream ({@link KmsKeys#locate}) is a call of its own, named after the
   *       method.
   *   <li>A TLS follower's calls are named after the method that made the follower, {@code
   *       "follow"} or {@code "trustAnchors"}: its start with its read and decision, its {@code
   *       refresh()}, and each scheduled refresh or check of an unknown peer.
   * </ul>
   *
   * <p><b>Background work</b> is a call of its own, on the thread that runs it: a {@link LocalKeys}
   * refresh ({@code "localKeys"}), a scheduled {@link CurrentKey} check ({@code "refresh"}), a TLS
   * follower's scheduled refreshes and checks.
   *
   * <p>The event's {@link KmsEvent#endpoint()} is the first attempt's, {@link KmsEvent#attempt()}
   * is 0, and {@link KmsEvent#objectId()} is the object the first attempt names, if any.
   *
   * @param call the call, of {@link KmsEvent#kind()} {@link KmsEvent.Kind#CALL} and outcome {@link
   *     KmsEvent.Outcome#STARTED}
   * @since 0.10.0
   */
  default void callStarted(KmsEvent call) {}

  /**
   * An application call finished: it is returning or throwing, after its last {@link #finished}.
   *
   * <ul>
   *   <li>{@link KmsEvent#latency()} runs from {@link #callStarted} to now, with every attempt,
   *       back-off and the SDK's work between steps.
   *   <li>{@link KmsEvent#attempt()} is the number of attempts made. {@link KmsEvent#endpoint()}
   *       and {@link KmsEvent#version()} are the last attempt's. {@link KmsEvent#objectId()} is the
   *       first object its attempts named.
   * </ul>
   *
   * <p>The outcome is what the application saw:
   *
   * <ul>
   *   <li>{@link KmsEvent.Outcome#SUCCEEDED} when the method returned. That includes a call whose
   *       failed attempts or steps were retried or handled, such as a lookup that returns empty
   *       after a Not Found.
   *   <li>{@link KmsEvent.Outcome#FAILED} when it threw. {@link KmsEvent#failure()} is what it
   *       threw when that is a {@link KmsException}, the SDK's own refusals included, such as a
   *       key that does not match what was expected. Anything else, such as an {@link
   *       IllegalStateException} for a misuse, gives no failure.
   *   <li>For background work, {@code FAILED} when the work failed, such as a check of an unknown
   *       peer that could not read the KMS, or read it past the check's timeout.
   * </ul>
   *
   * <p>The attempt events keep each request's own outcome.
   *
   * @param call the call, of {@link KmsEvent#kind()} {@link KmsEvent.Kind#CALL}
   * @since 0.10.0
   */
  default void callFinished(KmsEvent call) {}

  /**
   * An attempt is about to be sent.
   *
   * @param event the attempt, of outcome {@link KmsEvent.Outcome#STARTED}
   */
  default void started(KmsEvent event) {}

  /**
   * An attempt finished, successfully or not.
   *
   * @param event the attempt, of outcome {@link KmsEvent.Outcome#SUCCEEDED} or {@link
   *     KmsEvent.Outcome#FAILED}
   */
  default void finished(KmsEvent event) {}

  /**
   * A retryable failure will be retried after {@code delay}.
   *
   * @param failed the failed attempt
   * @param delay the back-off before the next attempt
   */
  default void retrying(KmsEvent failed, Duration delay) {}

  /**
   * An endpoint was marked unavailable: it refused a connection; did not answer within the {@link
   * RetryPolicy#attemptTimeout() attempt timeout}, whether a read or the Discover Versions at
   * connect or before its first request; or offers another KMIP version.
   *
   * @param endpoint the endpoint's {@code host:port}
   * @param why what happened, for logs
   */
  default void endpointUnavailable(String endpoint, String why) {}

  /**
   * An endpoint {@link #endpointUnavailable} was told of answered again: it sent a valid response
   * to a request, a successful one or a failure result such as Not Found (an answer shows it
   * serves). Fired once for each recovery, by the first answer after the endpoint was told
   * unavailable, on the thread whose request it answered, before that attempt's {@link #finished}.
   * An answer to a request sent before the endpoint was told unavailable may also count. Paired
   * with {@code endpointUnavailable} per {@link Kms} (each {@code Kms} keeps its own endpoints): an
   * up/down gauge per endpoint is 1 after this, 0 after that.
   *
   * @param endpoint the endpoint's {@code host:port}
   * @since 0.10.0
   */
  default void endpointAvailable(String endpoint) {}

  /**
   * A handle's own key was read and found replaced: it names {@code replacements} (Replacement
   * Object links), so another instance has rotated it and data encrypted or sealed through this
   * handle goes under an old key. Refresh the handle ({@code key = key.latest()}). Fired by {@link
   * KeyHandle#isLatest()} and whenever an operation reads the handle's key anyway: decrypting,
   * unwrapping and opening through the handle, its first encrypt or seal, and an encrypt, seal,
   * sign or MAC the server refused because the key is no longer Active (Deactivated after a
   * rotation's grace period, say). Encrypting and sealing that succeed read nothing after the
   * first, so poll {@code isLatest()} to notice a rotation by another instance.
   * Also fired by {@link KeyHandle#isLatest()} on a newest key that is not the one {@link
   * KeyHandle#latest()} chooses (callers rotated one key at the same time), with the chosen key as
   * {@code replacements}. Not called again for calls this method itself makes (an {@code isLatest()}
   * here).
   *
   * @param keyId the handle's key
   * @param replacements the identifiers its Replacement Object links name
   */
  default void staleHandle(String keyId, List<String> replacements) {}

  /**
   * {@code keyId} was replaced at the same time as this call replaced it, or instead. Two cases,
   * which {@code replacements.size()} tells apart: two or more replacements mean several newest
   * keys, which {@link KeyHandle#reconcile()} joins; one is another caller's replacement, made
   * instead of this call's, to use with {@link KeyHandle#latest()} (nothing to reconcile).
   *
   * <p>Several: {@code keyId} has more than one confirmed replacement, {@code replacements}
   * (created first first): callers rotated or replaced it at the same time, so its lineage has
   * several newest keys. Every record still opens through any key of the lineage. New data may
   * spread across them until {@link KeyHandle#reconcile()} joins them. Run rotation from one place
   * ({@link KeyHandle#rotate()}). Fired by {@link
   * KeyHandle#rotate()} and {@link KeyHandle#replaceCompromised} (and so {@code
   * findOrCreate().replacingCompromised()}) when they see the other replacements after making their
   * own; a caller that finished first may not.
   *
   * <p>One: fired, with the other caller's replacement as {@code replacements}, when the server
   * refused a call's Re-key because another caller had replaced {@code keyId} meanwhile (servers
   * that refuse a second Re-key, which never fork the lineage), and when {@code replaceCompromised}
   * finds, after the server refused its Revoke because another caller had compromised {@code keyId}
   * meanwhile, a replacement linked to it since the call read it.
   *
   * @param keyId the replaced key
   * @param replacements its confirmed replacements, created first first
   */
  default void concurrentReplacement(String keyId, List<String> replacements) {}

  /**
   * A {@link CurrentKey}'s check for a newer key failed: it goes on sealing under {@code keyId},
   * the key it holds, and checks again an interval later. Called at most once per check interval
   * for each {@code CurrentKey} (its checks are that far apart); {@code failuresInARow} counts the
   * checks in a row that failed (1 for the first, back to 1 after one succeeds), so an alert can
   * pass over a single failure and fire on a check that keeps failing (a predecessor that can no
   * longer be read, a purged link): until it succeeds, instances that hold this {@code
   * CurrentKey} do not follow a rotation by another instance, and keep sealing under {@code keyId}
   * while the server accepts it. A seal the server refuses still checks at once, and a failure
   * there is thrown with the call ({@link CurrentKey}, "How it follows").
   *
   * @param keyId the key the {@code CurrentKey} holds and goes on using
   * @param failuresInARow the number of checks in a row that failed, from 1
   * @param failure the failure of this check
   */
  default void currentKeyCheckFailed(String keyId, int failuresInARow, KmsException failure) {}

  /**
   * A follower read an object it uses in a different state from the one it read before: {@code id}
   * went from {@code from} to {@code to} (Active to Compromised or Deactivated, say), so a
   * revocation of a key or certificate in use is heard of without polling. Told by:
   *
   * <ul>
   *   <li>a {@link CurrentKey}, for the key it holds, when a check reads it (a scheduled or due
   *       check, the refresh after a refused call, {@link CurrentKey#refresh()}); a key it moves
   *       away from is told when the check that moves read the change;
   *   <li>a {@link TlsIdentityFollower}, for its identity's current certificate and private key,
   *       at each refresh (also the old pair a renewal deactivated, when the refresh that finds the
   *       renewal reads it).
   * </ul>
   *
   * {@code from} is never null: the first state a follower reads of an object is its reference and
   * is not told (a {@code CurrentKey} found by name starts from Active; one given a handle, or moved
   * to a key by a rotation or {@link CurrentKey#moveTo}, from its next check). A change and its
   * reversal between two reads, and an object that no longer exists (destroyed and purged), are
   * not told. Called on the thread that read the change (the executor's, for a follower that
   * refreshes in the background), outside the follower's lock, once for each change read. The
   * anchors and peers of a {@link TlsTrustFollower} are not told here: its {@code onChange} hears
   * of each change of the set it trusts.
   *
   * @param id the object's identifier
   * @param from the state read before
   * @param to the state read now
   * @since 0.10.0
   */
  default void keyStateChanged(String id, KeyState from, KeyState to) {}

  /**
   * A {@link LocalKeys} cache committed a write selection for {@code name}: the first one it
   * validated and published ({@code previousId} null), or a change from {@code previousId} to
   * {@code newId}. Called once for each committed change, never for a load that was superseded
   * or discarded, nor when a revalidation keeps the same key. A diagnostic: it says what this
   * cache selected on this process, not that the selection still holds (TTL, a lease or a
   * refusal may end it) nor that other processes switched. Called on the thread that committed
   * the selection (an application thread, or the cache's refresh executor), outside the cache's
   * locks, with no call deadline of the cache's. It must not block, and must not use the cache
   * that calls it; an exception it throws is ignored and changes nothing the cache does.
   *
   * @param name the write key name the cache selects by
   * @param previousId the identifier selected before; null for the first selection
   * @param newId the identifier now selected, never null
   * @since 0.10.0
   */
  default void localKeySelected(String name, String previousId, String newId) {}

  /**
   * Under {@link LeasePolicy#HONOR_IF_SUPPORTED}, the key {@code keyId} states a Lease Time and
   * its server does not implement Obtain Lease, so its material is used without a lease the server
   * granted, under the stated Lease Time as a local bound. Told once per key and {@link Kms}, on the
   * thread that read the key, outside its call deadline; it must not block, and an exception it
   * throws is ignored.
   *
   * @param keyId the key used without a granted lease
   * @param bound its stated Lease Time, the longest a copy is used before the next attempt
   * @since 0.10.0
   */
  default void leaseNotGranted(String keyId, Duration bound) {}

  /**
   * The server granted a lease on {@code keyId} (Obtain Lease): for a {@link LocalKeys} cache's key,
   * a certificate or the private key of a {@link TlsIdentityFollower}'s identity, or a certificate
   * a {@link TlsTrustFollower} trusts. {@code renewal} is true when the cache or
   * follower still holds an earlier grant it obtained for the object, false otherwise: for the
   * first grant, and again for an object it stopped holding (a cache's evicted or invalidated
   * entry, an object a follower stopped using) and then obtains again. A server that does not implement Obtain Lease grants
   * nothing ({@link #leaseNotGranted}). Called on the thread that obtained it, outside the cache's
   * or follower's locks; it must not block, and an exception it throws is ignored.
   *
   * @param keyId the key leased
   * @param lease the Lease Time granted, as the server stated it; zero for no limit
   * @param renewal whether an earlier grant for the key is being renewed
   * @since 0.10.0
   */
  default void leaseGranted(String keyId, Duration lease, boolean renewal) {}

  /**
   * A {@link LocalKeys} cache loaded and validated a key: a first load, a background refresh or a
   * foreground renewal of an expired entry. Called once for each load that succeeded, with the
   * thread and lock rules of {@link #localKeyRefreshFailed}. The failures are not its mirror image:
   * that one tells of refreshes only, as a first load that fails is thrown to its caller; {@link
   * LocalKeys.Stats#loadFailures()} counts every load that failed, first loads included, so loads
   * told here and that count give the failure ratio.
   *
   * @param name the write key name of the cache
   * @param keyId the identifier loaded
   * @param purpose what the entry serves: {@link LocalUse#ENCRYPT} for the write key, or an
   *     identifier asked for with {@link LocalKeys#forAppend(String)}; {@link LocalUse#DECRYPT}
   *     for decryption by identifier ({@link LocalKeys#forDecrypt(String)})
   * @param loadTime how long the load took, its requests and validation included
   * @since 0.10.0
   */
  default void localKeyLoaded(String name, String keyId, LocalUse purpose, Duration loadTime) {}

  /**
   * A {@link LocalKeys} cache's refresh of a cached entry failed: a background refresh, or a
   * foreground renewal of an expired entry, met a KMS or validation failure, or reached its
   * deadline. Called once for each refresh that failed, not for each caller that is then served
   * or refused from the cache, nor for retries the cache makes internally after evicting or
   * replacing an entry. A first load that fails is not reported here: its caller gets the
   * failure. {@code remainingValidity} is how much longer the cache may hand out what it had
   * when the failure was observed (the earliest of its TTL, lease and, for encryption,
   * protection end); zero when it has no usable entry, or the failure was a definite refusal.
   * It is a diagnostic, never an authorization. Called on the thread that ran the refresh,
   * outside the cache's locks, with no call deadline of the cache's; it must not block, and must
   * not use the cache that calls it; an exception it throws is ignored.
   *
   * @param name the write key name of the cache
   * @param keyId the identifier refreshed; null when selecting the write key failed before an
   *     identifier was known
   * @param purpose what the entry served: {@link LocalUse#ENCRYPT} for the write key, or an
   *     exact identifier asked for with {@link LocalKeys#forAppend(String)}; {@link
   *     LocalUse#DECRYPT} for decryption by identifier ({@link LocalKeys#forDecrypt(String)})
   * @param failure what the refresh failed with
   * @param remainingValidity how much longer the entry remains usable, zero or more
   * @since 0.10.0
   */
  default void localKeyRefreshFailed(
      String name,
      String keyId,
      LocalUse purpose,
      KmsException failure,
      Duration remainingValidity) {}

  /**
   * The TLS files of {@link KmsConfig.Builder#reloadOnChange()} changed and were loaded: from the
   * request that noticed the change on, new connections use the new credentials. {@code files} names the watched
   * files, comma-separated. Called on the thread of the request that noticed the change, before
   * that request is sent.
   *
   * @param files the watched files, comma-separated
   */
  default void credentialsReloaded(String files) {}

  /**
   * The TLS files of {@link KmsConfig.Builder#reloadOnChange()} changed but could not be loaded (a
   * file only partly written, a certificate and a key from different renewals, a wrong password):
   * the previous credentials stay in use, and the files are read again at later checks until
   * they load (the 1st, 2nd, 4th, ... up to every 64th check while they do not change) (then {@link #credentialsReloaded} is called). Called once for each state of the
   * files, not for each retry. {@code why} is the message the builder method would have thrown: it
   * names the file and the problem, never key material. Files read while they were still
   * changing that were not whole yet (cut short, empty) are reported by {@link
   * #credentialsStillChanging} instead; whole files that do not load are reported here also then
   * (a key that does not match the certificate, on that forced read), and so is an {@link Error}
   * thrown by a load. A key file and a chain file that do not match, read once they settled after
   * a change, are a renewal written one file at a time until proven otherwise: {@link
   * #credentialsStillChanging} while it lasts, and this at the first read after both two reads
   * and 10 seconds have passed since the first read that found it (at the default one-second
   * interval, about ten reads; at a 30-second interval, the third).
   *
   * @param files the watched files, comma-separated
   * @param why why they could not be loaded, for logs
   */
  default void credentialsReloadFailed(String files, String why) {}

  /**
   * The TLS files of {@link KmsConfig.Builder#reloadOnChange()} changed again before each of
   * several checks in a row (a writer that is not done yet, such as a slow copy written in place)
   * and, read all the same after four checks put off, were not whole yet (a PEM file cut short,
   * an empty file, a PKCS#12 file cut short) or changed while they were read: not a failure. The
   * previous credentials stay in use, and the files are read again once
   * they stop changing (then {@link #credentialsReloaded} or {@link #credentialsReloadFailed} is
   * called) or after as many checks again (and this is called again while they still do not load).
   * {@code changingFor} is the time since a check first saw them changed. Files rewritten whole
   * before every check still load at that read. Also called for a key file and a chain file that
   * do not match after they changed, for two reads in a row and at least 10 seconds (the
   * certificate renewed, the key not yet: {@link #credentialsReloadFailed} says when that
   * persists). Publishing the files
   * atomically avoids this.
   *
   * @param files the watched files, comma-separated
   * @param changingFor how long they have been changing
   */
  default void credentialsStillChanging(String files, Duration changingFor) {}

  /**
   * The client certificate was renewed ({@link Kms#renewClientCertificate()}, or an automatic
   * renewal of {@link CertificateRenewal#automatic}): the new certificate is in the configured
   * files, and new connections of every {@link Kms} of the configuration use it. The server now
   * refuses the old one on new connections. Add the new fingerprint to the server's policy (see <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/production.md#renew-the-client-certificate">Renew
   * the client certificate</a>). Called on the thread that renewed (the caller's, or the SDK's
   * renewal thread), after the files are written.
   *
   * @param previousFingerprint the SHA-256 fingerprint of the certificate replaced, lowercase hex
   * @param fingerprint the SHA-256 fingerprint of the new certificate, lowercase hex
   * @param notAfter when the new certificate expires
   * @since 0.10.0
   */
  default void clientCertificateRenewed(
      String previousFingerprint, String fingerprint, Instant notAfter) {}

  /**
   * A renewal of the client certificate failed: the server refused, could not be reached, or the
   * files could not be read or written. The current certificate stays in use, except when {@code
   * why} says that the server issued the new certificate and this process uses it but could not
   * write it to the files: then call {@link Kms#renewClientCertificate()} again once the cause is
   * fixed, and it writes them ({@link RenewalNotSavedException}, whose message ends with the new
   * certificate). Also called when an automatic renewal cannot read the certificate. An automatic
   * renewal tries again later (a minute, then twice as long each time, up to an hour). A failure
   * after which the client may be locked out is told by {@link #clientCertificateMayBeLockedOut}
   * instead. Called once per attempt that failed, on the thread that tried.
   *
   * @param fingerprint the SHA-256 fingerprint of the certificate it tried to renew, lowercase hex;
   *     null when it could not be read
   * @param why the failure's message, which names files and identifiers, never key material
   * @since 0.10.0
   */
  default void clientCertificateRenewalFailed(String fingerprint, String why) {}

  /**
   * A renewal of the client certificate ended in a state where the client may be locked out of
   * the KMS: a reply was lost and the SDK could not tell whether the server issued the new
   * certificate, or the server issued one the SDK refused. The server may already refuse the
   * certificate in use on new connections. Act now: {@code why} says where the new private key is
   * and how to recover (<a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/production.md#renew-the-client-certificate">Renew
   * the client certificate</a>). Called on the thread that tried.
   *
   * @param fingerprint the SHA-256 fingerprint of the certificate it tried to renew, lowercase hex;
   *     null when it could not be read
   * @param why what happened and how to recover, never key material
   * @since 0.10.0
   */
  default void clientCertificateMayBeLockedOut(String fingerprint, String why) {}

  /**
   * A renewal of the client certificate needs attention, though this report is not its outcome.
   * {@code why} says which of these happened and what to do:
   *
   * <ul>
   *   <li>a pending file written for other identity files was moved aside and the attempt went on;
   *   <li>an automatic renewal's new certificate expires within its window already, perhaps
   *       because the server issued a shorter period than asked (the SDK renews it again after
   *       half its remaining validity);
   *   <li>the server issued a certificate the SDK uses although a check found something the
   *       server judges by its own clock or policy: a notAfter more than a minute from the one
   *       {@link CertificateRenewal#validFor} asked for (both are named), a notBefore after this
   *       machine's time (its clock is likely behind the server's), or a signature that does not
   *       verify with the certificate this client has for its issuer;
   *   <li>a renewal deleted the keys that earlier attempts moved aside for the certificate it
   *       retired, since the server can no longer issue a certificate for them.
   * </ul>
   *
   * <p>The attempt's own outcome is told by {@link #clientCertificateRenewed}, {@link
   * #clientCertificateRenewalFailed} or {@link #clientCertificateMayBeLockedOut}, once. Called on
   * the thread that renewed.
   *
   * @param fingerprint the SHA-256 fingerprint of the certificate concerned, lowercase hex; null
   *     when it could not be read
   * @param why what happened and what to do, never key material
   * @since 0.10.0
   */
  default void clientCertificateRenewalWarning(String fingerprint, String why) {}
}
