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

package dev.keytend.kmip.testing;

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.KmipClient;
import dev.keytend.kmip.client.KmipException;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.client.Result;
import dev.keytend.kmip.kms.*;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link InMemoryKmipServer#leaseTime} and {@link InMemoryKmipServer#leasesOnlyForActive}: the
 * server states a Lease Time for every object, grants it with Obtain Lease, and (when asked to)
 * refuses the lease of an object that is not Active, as keytend-kmip-server does under
 * --lease-states active.
 */
class InMemoryLeaseTest {
  private static KeyHandle key(Kms kms, KmipVersion version) {
    KeyCreation c =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named("lease-test");
    if (version.compareTo(KmipVersion.V1_4) >= 0) c.extractable(true);
    return c.create();
  }

  private static Result obtain(InMemoryKmipServer server, KmipVersion version, String id)
      throws Exception {
    try (KmipClient client = new KmipClient(server, version.protocolValue())) {
      return client.call(Requests.obtainLease().uniqueIdentifier(id).build());
    } catch (KmipException refused) {
      return refused.result();
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void everyObjectStatesTheLeaseTimeAndObtainLeaseGrantsIt(KmipVersion version) throws Exception {
    try (InMemoryKmipServer server = InMemoryKmipServer.of(version);
        Kms kms = server.connect()) {
      KeyHandle key = key(kms, version);
      assertEquals(Optional.empty(), key.attributes().leaseTime(), "no Lease Time until asked");
      Result before = obtain(server, version, key.id());
      assertEquals(Optional.of(Enums.ResultReason.OPERATION_NOT_SUPPORTED), before.reasonEnum());
      server.leaseTime(Duration.ofMinutes(2));
      assertEquals(Optional.of(Duration.ofMinutes(2)), key.attributes().leaseTime());
      Result granted = obtain(server, version, key.id());
      assertTrue(granted.successful(), granted.toString());
      Ttlv payload = granted.requirePayload();
      assertEquals(key.id(), payload.require(Tag.UNIQUE_IDENTIFIER).textValue());
      assertEquals(120, payload.require(Tag.LEASE_TIME).longValue());
      assertTrue(payload.child(Tag.LAST_CHANGE_DATE).isPresent());
      assertEquals(List.of(), server.violations());
      // The SDK leases before it reads, and the server's grant is what it honors.
      assertEquals(32, key.asSecretKey(Expect.aes(256), LocalUse.DECRYPT).getEncoded().length);
      server.leaseTime(Duration.ZERO);
      assertEquals(
          Optional.of(Duration.ZERO),
          key.attributes().leaseTime(),
          "zero is stated, as keytend-kmip-server does");
      assertEquals(
          0,
          obtain(server, version, key.id()).requirePayload().require(Tag.LEASE_TIME).longValue());
      server.leaseTime(null);
      assertEquals(Optional.empty(), key.attributes().leaseTime());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void onlyActiveObjectsAreLeasedWhenAsked(KmipVersion version) throws Exception {
    try (InMemoryKmipServer server = InMemoryKmipServer.of(version).leaseTime(Duration.ofHours(1));
        Kms kms = server.connect()) {
      KeyHandle key = key(kms, version);
      key.deactivate();
      assertTrue(
          obtain(server, version, key.id()).successful(), "every object is leased by default");
      key.asSecretKey(Expect.aes(256), LocalUse.DECRYPT).destroy();
      server.leasesOnlyForActive(true);
      Result refused = obtain(server, version, key.id());
      assertEquals(Optional.of(Enums.ResultReason.PERMISSION_DENIED), refused.reasonEnum());
      StateConflictException e =
          assertThrows(
              StateConflictException.class,
              () -> key.asSecretKey(Expect.aes(256), LocalUse.DECRYPT));
      assertEquals("obtainLease", e.operation());
      assertEquals(KeyState.DEACTIVATED, e.observedState().orElseThrow());
      assertTrue(
          e.getMessage().contains("Only active objects may receive a lease"), e.getMessage());
      KeyHandle active = key(kms, version);
      assertTrue(obtain(server, version, active.id()).successful());
      server.leasesOnlyForActive(false);
      assertTrue(obtain(server, version, key.id()).successful());
      key.destroy();
      assertEquals(
          Optional.of(Enums.ResultReason.ITEM_NOT_FOUND),
          obtain(server, version, key.id()).reasonEnum());
    }
  }

  @Test
  void attributeListQueryAndFaultsKnowTheLease() throws Exception {
    KmipVersion version = KmipVersion.V2_1;
    try (InMemoryKmipServer server = InMemoryKmipServer.of(version);
        Kms kms = server.connect()) {
      KeyHandle key = key(kms, version);
      try (KmipClient client = new KmipClient(server, version.protocolValue())) {
        Result list = client.call(Requests.getAttributeList().uniqueIdentifier(key.id()).build());
        assertFalse(listsLeaseTime(list), list.toString());
        Result query = client.query(Enums.QueryFunction.QUERY_OPERATIONS);
        assertFalse(
            query.requirePayload().children(Tag.OPERATION).stream()
                .anyMatch(o -> o.intValue() == Operation.OBTAIN_LEASE.code()),
            "not listed while it is not implemented");
        server.leaseTime(Duration.ofSeconds(5));
        list = client.call(Requests.getAttributeList().uniqueIdentifier(key.id()).build());
        assertTrue(listsLeaseTime(list), list.toString());
        query = client.query(Enums.QueryFunction.QUERY_OPERATIONS);
        assertTrue(
            query.requirePayload().children(Tag.OPERATION).stream()
                .anyMatch(o -> o.intValue() == Operation.OBTAIN_LEASE.code()),
            query.toString());
      }
      server.failNext(ServerOperation.OBTAIN_LEASE, Fault.PERMISSION_DENIED);
      PermissionDeniedException denied =
          assertThrows(
              PermissionDeniedException.class,
              () -> key.asSecretKey(Expect.aes(256), LocalUse.ENCRYPT));
      assertEquals("obtainLease", denied.operation());
      key.asSecretKey(Expect.aes(256), LocalUse.ENCRYPT).destroy();
    }
  }

  private static boolean listsLeaseTime(Result list) {
    return list.requirePayload().children(Tag.ATTRIBUTE_REFERENCE).stream()
        .anyMatch(r -> r.type() == Ttlv.Type.ENUMERATION && r.intValue() == Tag.LEASE_TIME.code());
  }

  @Test
  void anObjectsOwnLeaseTimeIsTheOneGranted() throws Exception {
    KmipVersion version = KmipVersion.V2_1;
    try (InMemoryKmipServer server =
            InMemoryKmipServer.of(version).leaseTime(Duration.ofSeconds(60));
        Kms kms = server.connect();
        KmipClient client = new KmipClient(server, version.protocolValue())) {
      KeyHandle key = key(kms, version);
      client.call(
          Requests.addAttribute()
              .uniqueIdentifier(key.id())
              .attribute(
                  dev.keytend.kmip.model.Attributes.attribute(
                      "Lease Time", Ttlv.interval(Tag.LEASE_TIME, 30)))
              .build());
      assertEquals(Optional.of(Duration.ofSeconds(30)), key.attributes().leaseTime());
      assertEquals(
          30,
          obtain(server, version, key.id()).requirePayload().require(Tag.LEASE_TIME).longValue());
    }
  }

  @Test
  void leaseTimesAreWholeSecondsOfAnInterval() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    assertThrows(IllegalArgumentException.class, () -> server.leaseTime(Duration.ofSeconds(-1)));
    assertThrows(IllegalArgumentException.class, () -> server.leaseTime(Duration.ofMillis(1500)));
    assertThrows(
        IllegalArgumentException.class, () -> server.leaseTime(Duration.ofSeconds(0x1_0000_0000L)));
    assertSame(server, server.leaseTime(Duration.ofSeconds(0xffff_ffffL)));
  }
}
