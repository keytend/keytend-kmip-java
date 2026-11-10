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

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.security.KeyPair;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * {@link KmsListener#leaseGranted} from the TLS followers: one event per object granted, the first
 * grant of each object not a renewal, every later one a renewal; nothing from a server that states
 * no Lease Time.
 */
class LeaseGrantedEventsTest {
  static final Duration HOURLY = Duration.ofHours(1);
  static final CustomAttribute TAG = CustomAttribute.client("lease-granted-events");

  record Granted(String id, Duration lease, boolean renewal) {}

  static final class Recorder implements KmsListener {
    final List<Granted> granted = new CopyOnWriteArrayList<>();

    @Override
    public void leaseGranted(String keyId, Duration lease, boolean renewal) {
      granted.add(new Granted(keyId, lease, renewal));
    }
  }

  final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
  final List<AutoCloseable> closing = new ArrayList<>();

  @AfterEach
  void close() throws Exception {
    for (AutoCloseable c : closing) c.close();
    executor.shutdownNow();
  }

  Kms connect(InMemoryKmipServer server, KmsListener listener) {
    Kms kms =
        Kms.connect(
            server.configure().retryPolicy(RetryPolicy.none()).addListener(listener).build());
    closing.add(0, kms);
    return kms;
  }

  static Set<String> ids(List<Granted> granted, boolean renewal) {
    Set<String> out = new TreeSet<>();
    for (Granted g : granted) if (g.renewal == renewal) out.add(g.id);
    return out;
  }

  @Test
  void anIdentityFollowersGrantsAreFirstThenRenewals() throws Exception {
    InMemoryKmipServer server =
        InMemoryKmipServer.of(KmipVersion.V2_1).leaseTime(Duration.ofHours(1));
    Recorder r = new Recorder();
    Kms kms = connect(server, r);
    Issued ca = TestPki.ca("Lease events CA");
    KeyPair key = TestPki.ec();
    TlsIdentityHandle identity =
        kms.tls()
            .register(key.getPrivate(), TestPki.leaf("lease-events", key, ca).chain(ca))
            .named("lease-events")
            .register();
    Set<String> objects = new TreeSet<>();
    for (KeyHandle c : identity.chain()) objects.add(c.id());
    objects.add(identity.privateKey().id());
    r.granted.clear();

    TlsIdentityFollower follower = kms.tls().follow("lease-events", HOURLY, executor);
    closing.add(0, follower);
    assertEquals(TlsIdentityFollower.Status.CURRENT, follower.status(), follower.state().detail());
    List<Granted> first = List.copyOf(r.granted);
    assertFalse(first.isEmpty());
    assertEquals(objects, ids(first, false), "each object's first grant: " + first);
    for (Granted g : first) assertEquals(Duration.ofHours(1), g.lease());

    r.granted.clear();
    follower.refresh();
    assertEquals(Set.of(), ids(r.granted, false), "no first grant again: " + r.granted);
    assertEquals(objects, ids(r.granted, true), "renewals: " + r.granted);
  }

  @Test
  void aTrustFollowersGrantsAreToldToo() throws Exception {
    InMemoryKmipServer server =
        InMemoryKmipServer.of(KmipVersion.V2_1).leaseTime(Duration.ofMinutes(10));
    Recorder r = new Recorder();
    Kms kms = connect(server, r);
    Issued ca = TestPki.ca("Lease events anchor");
    KeyHandle anchor =
        kms.keys().register(ca.certificate()).usages(KeyUsage.VERIFY).custom(TAG, "ca").register();
    TlsTrustFollower trust =
        kms.tls().trustAnchors(KeyQuery.all().custom(TAG, "ca"), HOURLY, executor);
    closing.add(0, trust);
    assertEquals(List.of(new Granted(anchor.id(), Duration.ofMinutes(10), false)), r.granted);
    r.granted.clear();
    trust.refresh();
    assertEquals(List.of(new Granted(anchor.id(), Duration.ofMinutes(10), true)), r.granted);
  }

  @Test
  void aServerWithoutLeasesGrantsNothing() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    Kms kms = connect(server, r);
    Issued ca = TestPki.ca("No lease CA");
    KeyPair key = TestPki.ec();
    kms.tls()
        .register(key.getPrivate(), TestPki.leaf("no-lease", key, ca).chain(ca))
        .named("no-lease")
        .register();
    TlsIdentityFollower follower = kms.tls().follow("no-lease", HOURLY, executor);
    closing.add(0, follower);
    follower.refresh();
    assertEquals(TlsIdentityFollower.Status.CURRENT, follower.status());
    assertEquals(List.of(), r.granted);
  }
}
