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

import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * The threads the SDK creates: daemons in the SDK's own thread group, a child of the JVM's
 * root group (never the group of whichever caller happened to start one), with no context class
 * loader, so that none holds an application's class loader as its context loader or counts
 * among a caller's threads (on Java 17 to 23 a thread still captures its creator's access
 * control context until it ends). The group is made when a thread is first needed, not when a class is initialized, and
 * one serves the whole SDK. Under a SecurityManager (Java 17 to 23; it cannot be enabled from Java
 * 24), making a child of the root group needs {@code RuntimePermission("modifyThreadGroup")} for
 * the SDK and its callers; where it is refused, the SDK's threads are made in the group the
 * SecurityManager chooses (by default the creating thread's), still daemons without a context class
 * loader where it allows that, and nothing fails. Each thread ends with its owner's {@code close()}
 * (here {@link LocalKeys}'s own refresh worker, which also ends when idle): no SDK thread outlives
 * its use. The pools a class shares (the automatic renewal of client certificates) end each thread
 * once idle for {@link #IDLE_MILLIS}; the renewal's timer, whose one thread waits for its next
 * check, sets a keep-alive as long as the longest wait while an automatic renewal runs, so it
 * does not wake every second, and the short one again when the last one stops.
 */
final class SdkThreads {
  /** How long a shared pool's idle thread lives. */
  static final long IDLE_MILLIS = 1000;

  /** The name of the SDK's thread group. */
  static final String NAME = "keytend-kmip";

  /** The SDK's thread group once found or made; null until then. */
  private static volatile ThreadGroup group;

  private SdkThreads() {}

  /**
   * The SDK's thread group ({@code keytend-kmip}, a child of the root group), one for the whole SDK:
   * the {@code kms}, {@code transport} and {@code server} packages each look for it among the
   * root's subgroups and the first to need it makes it (under the root group's lock, so there is
   * one). Null when a SecurityManager refuses access to the root group.
   */
  static ThreadGroup group() {
    ThreadGroup g = group;
    if (g != null) return g;
    try {
      ThreadGroup root = Thread.currentThread().getThreadGroup();
      while (root.getParent() != null) root = root.getParent();
      synchronized (root) {
        ThreadGroup[] subgroups = new ThreadGroup[root.activeGroupCount() + 16];
        int n = root.enumerate(subgroups, false);
        for (int i = 0; i < n && g == null; i++)
          if (NAME.equals(subgroups[i].getName())) g = subgroups[i];
        if (g == null) g = new ThreadGroup(root, NAME);
      }
      return group = g;
    } catch (SecurityException e) {
      return null;
    }
  }

  /**
   * A daemon thread named {@code name} in the SDK's {@link #group()}, without a context class
   * loader, and without the creating thread's inheritable thread-locals (a caller's logging context
   * is not kept alive by a thread the SDK shares). Under a SecurityManager that refuses the group, the thread is in the group the
   * SecurityManager gives new threads (by default the creating thread's); one that refuses to clear
   * the context class loader leaves the creating thread's, and one that refuses to make it a daemon
   * leaves it a user thread, which still ends when idle or closed. Only a SecurityManager that
   * refuses the thread itself makes this throw (its {@code SecurityException}).
   */
  static Thread daemon(Runnable r, String name) {
    Thread t;
    try {
      t = new Thread(group(), r, name, 0, false);
    } catch (IllegalThreadStateException destroyed) {
      // Someone destroyed the group (JDK 17 and 18 allow it while it has no threads): a new one.
      group = null;
      t = new Thread(group(), r, name, 0, false);
    }
    try {
      t.setDaemon(true);
    } catch (SecurityException e) {
      // A user thread, then: it ends when idle or closed all the same.
    }
    try {
      t.setContextClassLoader(null);
    } catch (SecurityException e) {
      // The creating thread's loader, then.
    }
    return t;
  }

  /**
   * A shared one-thread scheduler whose thread ends when idle for {@link #IDLE_MILLIS}; canceled
   * tasks are removed. While a task waits in it, its thread wakes once each keep-alive time to see
   * whether it may end: a user that waits long sets a longer one while its tasks run ({@link
   * ScheduledThreadPoolExecutor#setKeepAliveTime}).
   */
  static ScheduledThreadPoolExecutor scheduler(String name) {
    ScheduledThreadPoolExecutor s = new ScheduledThreadPoolExecutor(1, r -> daemon(r, name));
    s.setRemoveOnCancelPolicy(true);
    s.setKeepAliveTime(IDLE_MILLIS, TimeUnit.MILLISECONDS);
    s.allowCoreThreadTimeOut(true);
    return s;
  }

  /** A pool of as many threads as tasks, each ending when idle. */
  static ThreadPoolExecutor cached(String name) {
    return new ThreadPoolExecutor(
        0,
        Integer.MAX_VALUE,
        IDLE_MILLIS,
        TimeUnit.MILLISECONDS,
        new SynchronousQueue<>(),
        r -> daemon(r, name));
  }
}
