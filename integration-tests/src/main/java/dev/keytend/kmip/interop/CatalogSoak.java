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

package dev.keytend.kmip.interop;

import java.lang.management.ManagementFactory;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Finite soak workload with real rotation, application-cache expiry and resource bounds. */
public final class CatalogSoak {
  private CatalogSoak() {}

  // A cleanup failure is the one thrown; the report has already recorded the run's own failure.
  @SuppressWarnings("Finally")
  public static Map<String, Object> run(CatalogFixture f, Duration duration, Path progress)
      throws Exception {
    if (duration.isNegative() || duration.isZero())
      throw new IllegalArgumentException("Positive duration required");
    f.handshake("client");
    f.provision();
    var suite = new CatalogLiveSuite(f);
    long started = System.nanoTime(),
        until = started + duration.toNanos(),
        calls = 0,
        rotations = 0,
        expirations = 0;
    String rotating = suite.create(256);
    f.client.activate(rotating);
    SecretKey cached = suite.aes(rotating, 256);
    String rotatingHash = Catalog.digest(cached.getEncoded());
    long expires = started + Duration.ofSeconds(30).toNanos(),
        rotate = started + Duration.ofMinutes(1).toNanos(),
        sampleAt = started;
    List<Map<String, Object>> samples = new ArrayList<>();
    Map<String, Object> report = new LinkedHashMap<>(f.provenance());
    report.put("started_at", Instant.now().toString());
    report.put("requested_duration", duration.toString());
    report.put("status", "RUNNING");
    long baselineHeap = -1, baselineFd = -1, baselineThreads = -1;
    try {
      while (System.nanoTime() < until) {
        long now = System.nanoTime();
        CatalogLiveSuite.peer(
            Catalog.digest(suite.aes(f.knownUid, 256).getEncoded()).equals(f.knownSha),
            "Historical soak key changed");
        calls++;
        if (now >= expires) {
          cached = suite.aes(rotating, 256);
          CatalogLiveSuite.peer(
              Catalog.digest(cached.getEncoded()).equals(rotatingHash),
              "Expired cache reloaded different key");
          expires = now + Duration.ofSeconds(30).toNanos();
          expirations++;
        }
        byte[] iv = new byte[12], plain = CatalogLiveSuite.known(47);
        new java.security.SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, cached, new GCMParameterSpec(128, iv));
        byte[] encrypted = cipher.doFinal(plain);
        if (now >= rotate) {
          String next = suite.create(256);
          f.client.activate(next);
          SecretKey replacement = suite.aes(next, 256);
          CatalogLiveSuite.peer(
              !Arrays.equals(replacement.getEncoded(), cached.getEncoded()),
              "Rotation repeated key material");
          cipher.init(Cipher.DECRYPT_MODE, suite.aes(rotating, 256), new GCMParameterSpec(128, iv));
          CatalogLiveSuite.peer(
              Arrays.equals(cipher.doFinal(encrypted), plain),
              "Historical ciphertext failed after rotation");
          suite.retire(rotating);
          rotating = next;
          cached = replacement;
          rotatingHash = Catalog.digest(cached.getEncoded());
          expires = now + Duration.ofSeconds(30).toNanos();
          rotate = now + Duration.ofMinutes(1).toNanos();
          rotations++;
        } else {
          cipher.init(Cipher.DECRYPT_MODE, cached, new GCMParameterSpec(128, iv));
          CatalogLiveSuite.peer(
              Arrays.equals(cipher.doFinal(encrypted), plain), "Soak AES-GCM round trip failed");
        }
        if (now >= sampleAt) {
          // Measure retained heap after collection, rather than an arbitrary allocation peak.
          System.gc();
          long heap = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
          long threads = ManagementFactory.getThreadMXBean().getThreadCount();
          long fd =
              ManagementFactory.getOperatingSystemMXBean()
                      instanceof com.sun.management.UnixOperatingSystemMXBean unix
                  ? unix.getOpenFileDescriptorCount()
                  : -1;
          long elapsed = (System.nanoTime() - started) / 1_000_000_000;
          if (elapsed >= 600 && baselineHeap < 0) {
            baselineHeap = heap;
            baselineFd = fd;
            baselineThreads = threads;
          }
          if (baselineHeap >= 0) {
            Catalog.require(
                heap <= Math.max(baselineHeap * 2, baselineHeap + 64L * 1024 * 1024),
                "Retained soak heap exceeded steady-state allowance");
            Catalog.require(
                threads <= baselineThreads + 16, "Soak thread count grew beyond allowance");
            if (fd >= 0 && baselineFd >= 0)
              Catalog.require(
                  fd <= baselineFd + 32, "Soak file descriptor count grew beyond allowance");
          }
          samples.add(
              Map.of(
                  "elapsed_seconds",
                  elapsed,
                  "retained_heap_bytes",
                  heap,
                  "threads",
                  threads,
                  "open_fds",
                  fd));
          report.put("successful_gets", calls);
          report.put("rotations", rotations);
          report.put("cache_expirations", expirations);
          report.put("resource_samples", samples);
          report.put("elapsed_seconds", elapsed);
          report.put("updated_at", Instant.now().toString());
          report.put(
              "workload",
              "Exact historical Get every second; fresh TLS socket per Get; application key cache"
                  + " expires every 30 seconds; new active key, historical decryption and"
                  + " retired-key cleanup every minute");
          if (progress != null) checkpoint(progress, report);
          sampleAt = now + Duration.ofMinutes(1).toNanos();
        }
        Thread.sleep(1000);
      }
      report.put("status", duration.compareTo(Duration.ofHours(24)) >= 0 ? "PASS" : "SMOKE_ONLY");
      report.put("elapsed_seconds", (System.nanoTime() - started) / 1_000_000_000);
      report.put("successful_gets", calls);
      report.put("rotations", rotations);
      report.put("cache_expirations", expirations);
      report.put("completed_at", Instant.now().toString());
      return report;
    } catch (Exception | AssertionError failure) {
      report.put("status", "FAILED");
      report.put("failure_type", failure.getClass().getSimpleName());
      throw failure;
    } finally {
      try {
        suite.retire(rotating);
      } catch (Exception cleanupFailure) {
        report.put("status", "FAILED");
        report.put("cleanup_failure_type", cleanupFailure.getClass().getSimpleName());
        throw cleanupFailure;
      } finally {
        if (progress != null) checkpoint(progress, report);
      }
    }
  }

  static void checkpoint(Path path, Map<String, Object> report) throws Exception {
    Files.createDirectories(path.toAbsolutePath().getParent());
    Path temporary = path.resolveSibling(path.getFileName() + ".tmp");
    Catalog.write(temporary, report);
    Files.move(
        temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
  }

  /** host port certs server version duration progress-file; short runs never earn a soak pass. */
  public static void main(String[] args) throws Exception {
    if (args.length != 7)
      throw new IllegalArgumentException("host port certs server version duration progress-file");
    String[] version = args[4].split("[.]");
    try (var f =
        new CatalogFixture(
            Path.of(".").toAbsolutePath(),
            args[3],
            args[0],
            Integer.parseInt(args[1]),
            Path.of(args[2]),
            dev.keytend.kmip.model.ProtocolVersion.of(
                Integer.parseInt(version[0]), Integer.parseInt(version[1])),
            System.getProperty("kmip.server.build", "external-unverified"),
            System.getProperty("kmip.server.image", "external-unverified"),
            System.getProperty("kmip.client.commit", "uncommitted"),
            System.getProperty("kmip.server.configurationHash", "external-unverified"))) {
      run(f, Duration.parse(args[5]), Path.of(args[6]));
    }
  }
}
