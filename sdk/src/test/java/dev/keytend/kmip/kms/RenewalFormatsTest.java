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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The files a client certificate renewal leaves on disk stay readable: the pending file, and the
 * files moved aside ({@code .unresolved}, {@code .orphaned}), which may hold the only copy of a
 * key for a year. Each fixture under {@code renewal-formats/<version>/} is what that version wrote
 * ({@link RenewalFormatFixtures}), and this version must still read it, find a file moved aside by
 * its name, and write the same header. The hashes are pinned: a release's fixtures are added,
 * never replaced (docs/compatibility.md, "Stored formats").
 */
class RenewalFormatsTest {
  /** Every fixture of every version, and its SHA-256. */
  static final Map<String, String> PINNED =
      Map.of(
          "0.10.0/" + RenewalFormatFixtures.KEY_ONLY,
          "a1245b1e7dfefd325e044de60de80f60e686bdd61ea89041f337e375ac2edee0",
          "0.10.0/" + RenewalFormatFixtures.ISSUED,
          "c96a83505e471d5ad747713028d893cbee82dc2342fb71e1bd8c10530039065e",
          "0.10.0/" + RenewalFormatFixtures.UNRESOLVED,
          "97cac1b19732bcb8bf3c645f2d77dcbbafb9675730b4c469ec001eeaf40cbe72");

  /** The fixture sets here. */
  static final List<String> WRITTEN = List.of("0.10.0");

  static byte[] fixture(String path) throws IOException {
    try (InputStream in =
        RenewalFormatsTest.class.getResourceAsStream("/renewal-formats/" + path)) {
      assertNotNull(in, "the fixture " + path);
      byte[] b = in.readAllBytes();
      assertEquals(
          PINNED.get(path),
          PersistedFormatsTest.sha256(b),
          "the pinned fixture " + path + ": never regenerate one");
      return b;
    }
  }

  /** {@code fixture} written into {@code dir} under {@code name}. */
  static Path copy(String written, String fixture, Path dir, String name) throws IOException {
    Path p = dir.resolve(name);
    Files.write(p, fixture(written + "/" + fixture));
    return p;
  }

  static RenewalFiles files(Path dir) {
    return new RenewalFiles(
        new TlsFiles.Identity(
            TlsFiles.IdentityKind.PEM,
            null,
            dir.resolve("client.crt"),
            dir.resolve("client.key"),
            null,
            List.of()));
  }

  @Test
  void everyRenewalFileStillReads(@TempDir Path dir) throws Exception {
    for (String written : WRITTEN) {
      Path sub = Files.createDirectory(dir.resolve(written));

      // A pending file holding only the key.
      RenewalFiles.Pending key =
          RenewalFiles.readPending(
              copy(written, RenewalFormatFixtures.KEY_ONLY, sub, "client.key.renewal"), null);
      assertFalse(key.issued());
      assertEquals(RenewalFormatFixtures.REPLACES, key.replaces());
      assertEquals(RenewalFormatFixtures.SERVER_TIME, key.serverTime());
      assertNull(key.certificateId());
      assertTrue(PemIdentity.matches(key.key(), key.publicKey(), null));
      // As the pending file of the identity files beside it.
      assertEquals(key.publicKey(), files(sub).readPending(null).publicKey());

      // One holding the issued chain, its key encrypted.
      RenewalFiles.Pending issued =
          RenewalFiles.readPending(
              copy(written, RenewalFormatFixtures.ISSUED, sub, "issued"),
              RenewalFormatFixtures.PASSWORD.clone());
      assertTrue(issued.issued());
      assertEquals(2, issued.chain().size());
      assertEquals(issued.publicKey(), issued.chain().get(0).getPublicKey());
      issued.chain().get(0).verify(issued.chain().get(1).getPublicKey());
      assertEquals(RenewalFormatFixtures.CERTIFICATE_ID, issued.certificateId());
      assertEquals(RenewalFormatFixtures.REPLACES, issued.replaces());
      assertEquals(RenewalFormatFixtures.SERVER_TIME, issued.serverTime());
      assertTrue(PemIdentity.matches(issued.key(), issued.publicKey(), null));
      Path wrong = sub.resolve("issued");
      assertThrows(
          IllegalArgumentException.class,
          () -> RenewalFiles.readPending(wrong, "wrong".toCharArray()));

      // One moved aside: found by its name beside the identity files, and read.
      Path aside =
          copy(written, RenewalFormatFixtures.UNRESOLVED, sub, RenewalFormatFixtures.UNRESOLVED);
      assertEquals(List.of(aside), files(sub).unresolved());
      assertEquals(RenewalFormatFixtures.REPLACES, RenewalFiles.replaces(aside));
      RenewalFiles.Pending moved = RenewalFiles.readPending(aside, null);
      assertFalse(moved.issued());
      assertTrue(PemIdentity.matches(moved.key(), moved.publicKey(), null));
    }
  }

  /** This version writes the same header lines, in the same order, as each fixture. */
  @Test
  void thisVersionWritesTheSameHeader(@TempDir Path dir) throws Exception {
    RenewalFiles files = files(dir);
    KeyPair key = TestPki.ec();
    files.writePending(
        key.getPrivate(),
        List.of(),
        RenewalFormatFixtures.REPLACES,
        null,
        key.getPublic(),
        null,
        RenewalFormatFixtures.SERVER_TIME);
    List<String> now = header(Files.readAllBytes(files.pendingFile()));
    for (String written : WRITTEN)
      assertEquals(header(fixture(written + "/" + RenewalFormatFixtures.KEY_ONLY)), now, written);
    assertEquals("keytend-kmip client certificate renewal " + RenewalFiles.FORMAT, now.get(0));
  }

  /** Each header line up to its value: the first line whole, the others up to their colon. */
  static List<String> header(byte[] file) {
    String text = new String(file, StandardCharsets.US_ASCII);
    List<String> out = new ArrayList<>();
    for (String line : text.substring(0, text.indexOf("-----BEGIN")).split("\n"))
      out.add(out.isEmpty() ? line : line.substring(0, line.indexOf(':') + 1));
    return out;
  }

  /** Every fixture directory is read, and every fixture in it pinned. */
  @Test
  void everyFixtureIsPinned() throws IOException {
    Path formats = Path.of("src/test/resources/renewal-formats");
    List<String> dirs;
    try (Stream<Path> list = Files.list(formats)) {
      dirs = list.filter(Files::isDirectory).map(d -> d.getFileName().toString()).sorted().toList();
    }
    assertEquals(new TreeSet<>(WRITTEN), new TreeSet<>(dirs));
    for (String v : WRITTEN)
      try (Stream<Path> files = Files.list(formats.resolve(v))) {
        for (Path f : files.toList())
          assertTrue(
              PINNED.containsKey(v + "/" + f.getFileName()),
              "pinned: " + v + "/" + f.getFileName());
      }
  }
}
