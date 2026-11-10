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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link KmsListener#all}: each listener in turn, isolated. It overrides every method of {@link
 * KmsListener} (a test checks), so a method added there is not silently dropped here.
 */
final class KmsListeners implements KmsListener {
  private static final Logger log = LoggerFactory.getLogger(KmsListener.class);

  private final List<KmsListener> listeners;

  /**
   * Calls each of {@code listeners}, flattened ({@link #flatten}): a listener given twice, also
   * inside a {@link KmsListener#all}, is called once per event.
   */
  KmsListeners(List<? extends KmsListener> listeners) {
    for (KmsListener l : listeners) Objects.requireNonNull(l, "listener");
    this.listeners = flatten(listeners);
  }

  /** The listeners called, in order: leaves only, each once by identity. */
  List<KmsListener> listeners() {
    return listeners;
  }

  /**
   * {@code listeners} with each {@link KmsListener#all} replaced by the listeners it calls, at any
   * depth, in calling order: the listeners themselves, each once by identity.
   */
  static List<KmsListener> flatten(List<? extends KmsListener> listeners) {
    List<KmsListener> out = new ArrayList<>();
    flatten(listeners, out);
    return List.copyOf(out);
  }

  private static void flatten(List<? extends KmsListener> listeners, List<KmsListener> out) {
    for (KmsListener l : listeners) {
      if (l instanceof KmsListeners all) flatten(all.listeners, out);
      else if (out.stream().noneMatch(seen -> seen == l)) out.add(l);
    }
  }

  /**
   * Calls {@code event} on each listener. Whatever one throws, an {@link Error} included, is
   * ignored (logged at WARN once per listener class, and at DEBUG with its stack trace) and the
   * next is still called: a listener cannot change the outcome of an operation, nor keep another
   * listener from hearing of it.
   */
  private void each(Consumer<KmsListener> event) {
    for (KmsListener l : listeners) call(l, event);
  }

  static void call(KmsListener listener, Consumer<KmsListener> event) {
    try {
      event.accept(listener);
    } catch (Throwable ignored) {
      // A listener that throws is a defect of the application's: said once per listener class at
      // WARN, so it is noticed, then at DEBUG, so a listener that always throws floods nothing.
      // The WARN line names the throwing line but not the exception's message, which is the
      // application's text and may hold anything; the DEBUG line has the whole stack trace.
      String type = listener.getClass().getName();
      boolean first = warned.size() < MAX_WARNED && warned.add(type);
      if (first && log.isWarnEnabled())
        log.warn(
            "A KmsListener ({}) threw {} at {}; ignored (logged at DEBUG, with its stack trace,"
                + " from now on for this listener class)",
            LogText.safe(type),
            LogText.safe(ignored.getClass().getName()),
            LogText.safe(where(listener, ignored)));
      if (log.isDebugEnabled())
        log.debug(
            "A KmsListener ({}) threw {}; ignored",
            LogText.safe(type),
            LogText.safe(ignored.getClass().getName()),
            ignored);
    }
  }

  /**
   * The line of the listener's that threw: the top frame of {@code listener}'s class (an inner
   * class or lambda of it included), else the top frame outside the JDK, else the top of the stack;
   * "an unknown line" without one. A listener that calls {@code Objects.requireNonNull} is named,
   * not the JDK.
   */
  static String where(KmsListener listener, Throwable thrown) {
    StackTraceElement[] stack = thrown.getStackTrace();
    if (stack.length == 0) return "an unknown line";
    String own = listener.getClass().getName();
    int nested = own.indexOf('$');
    String outer = nested < 0 ? own : own.substring(0, nested);
    for (StackTraceElement frame : stack)
      if (frame.getClassName().equals(outer) || frame.getClassName().startsWith(outer + "$"))
        return frame.toString();
    for (StackTraceElement frame : stack) if (!jdk(frame.getClassName())) return frame.toString();
    return stack[0].toString();
  }

  private static boolean jdk(String className) {
    return className.startsWith("java.")
        || className.startsWith("javax.")
        || className.startsWith("jdk.")
        || className.startsWith("sun.")
        || className.startsWith("com.sun.");
  }

  /** The listener classes whose failure was logged at WARN; at most {@link #MAX_WARNED}. */
  private static final Set<String> warned = ConcurrentHashMap.newKeySet();

  /** How many listener classes are warned of at most: beyond that, DEBUG only. */
  static final int MAX_WARNED = 1024;

  @Override
  public void callStarted(KmsEvent call) {
    each(l -> l.callStarted(call));
  }

  @Override
  public void callFinished(KmsEvent call) {
    each(l -> l.callFinished(call));
  }

  @Override
  public void started(KmsEvent event) {
    each(l -> l.started(event));
  }

  @Override
  public void finished(KmsEvent event) {
    each(l -> l.finished(event));
  }

  @Override
  public void retrying(KmsEvent failed, Duration delay) {
    each(l -> l.retrying(failed, delay));
  }

  @Override
  public void endpointUnavailable(String endpoint, String why) {
    each(l -> l.endpointUnavailable(endpoint, why));
  }

  @Override
  public void endpointAvailable(String endpoint) {
    each(l -> l.endpointAvailable(endpoint));
  }

  @Override
  public void staleHandle(String keyId, List<String> replacements) {
    each(l -> l.staleHandle(keyId, replacements));
  }

  @Override
  public void concurrentReplacement(String keyId, List<String> replacements) {
    each(l -> l.concurrentReplacement(keyId, replacements));
  }

  @Override
  public void currentKeyCheckFailed(String keyId, int failuresInARow, KmsException failure) {
    each(l -> l.currentKeyCheckFailed(keyId, failuresInARow, failure));
  }

  @Override
  public void keyStateChanged(String id, KeyState from, KeyState to) {
    each(l -> l.keyStateChanged(id, from, to));
  }

  @Override
  public void localKeySelected(String name, String previousId, String newId) {
    each(l -> l.localKeySelected(name, previousId, newId));
  }

  @Override
  public void leaseNotGranted(String keyId, Duration bound) {
    each(l -> l.leaseNotGranted(keyId, bound));
  }

  @Override
  public void leaseGranted(String keyId, Duration lease, boolean renewal) {
    each(l -> l.leaseGranted(keyId, lease, renewal));
  }

  @Override
  public void localKeyLoaded(String name, String keyId, LocalUse purpose, Duration loadTime) {
    each(l -> l.localKeyLoaded(name, keyId, purpose, loadTime));
  }

  @Override
  public void localKeyRefreshFailed(
      String name,
      String keyId,
      LocalUse purpose,
      KmsException failure,
      Duration remainingValidity) {
    each(l -> l.localKeyRefreshFailed(name, keyId, purpose, failure, remainingValidity));
  }

  @Override
  public void credentialsReloaded(String files) {
    each(l -> l.credentialsReloaded(files));
  }

  @Override
  public void credentialsReloadFailed(String files, String why) {
    each(l -> l.credentialsReloadFailed(files, why));
  }

  @Override
  public void credentialsStillChanging(String files, Duration changingFor) {
    each(l -> l.credentialsStillChanging(files, changingFor));
  }

  @Override
  public void clientCertificateRenewed(
      String previousFingerprint, String fingerprint, java.time.Instant notAfter) {
    each(l -> l.clientCertificateRenewed(previousFingerprint, fingerprint, notAfter));
  }

  @Override
  public void clientCertificateRenewalFailed(String fingerprint, String why) {
    each(l -> l.clientCertificateRenewalFailed(fingerprint, why));
  }

  @Override
  public void clientCertificateMayBeLockedOut(String fingerprint, String why) {
    each(l -> l.clientCertificateMayBeLockedOut(fingerprint, why));
  }

  @Override
  public void clientCertificateRenewalWarning(String fingerprint, String why) {
    each(l -> l.clientCertificateRenewalWarning(fingerprint, why));
  }
}
