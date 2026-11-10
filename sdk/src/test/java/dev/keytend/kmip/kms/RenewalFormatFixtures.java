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

import dev.keytend.kmip.TestX509;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/**
 * The fixtures of {@link RenewalFormatsTest}: the files a client certificate renewal leaves on
 * disk ({@link RenewalFiles}), as a release wrote them. {@link #main} writes them into a
 * directory: a pending file holding only the new key, unencrypted; one holding the issued
 * certificate chain and its identifier, the key encrypted under {@link #PASSWORD}; and one moved
 * aside under its {@code .unresolved} name. {@code RenewalFiles} is package-private: this class
 * reaches it because it is in the same package, as {@link FormatFixtures} does. Never regenerate
 * the fixtures of a released version: they are what that version wrote.
 */
public final class RenewalFormatFixtures {
  /** The password of the encrypted fixture's key. */
  public static final char[] PASSWORD = "renewal-fixture-password".toCharArray();

  /** The fingerprint each fixture names as the certificate it replaces. */
  public static final String REPLACES = "ab".repeat(32);

  /** The server time each fixture records. */
  public static final Instant SERVER_TIME = Instant.parse("2026-11-08T12:00:00Z");

  /** The identifier of the issued fixture's certificate. */
  public static final String CERTIFICATE_ID = "renewal-fixture-certificate";

  /** The file names. */
  public static final String KEY_ONLY = "pending-key.pem",
      ISSUED = "pending-issued-encrypted.pem",
      UNRESOLVED = "client.key.renewal.20261108T120000000Z.unresolved";

  private RenewalFormatFixtures() {}

  /**
   * Writes the fixtures into {@code args[0]}.
   *
   * @param args the directory
   * @throws Exception when a file cannot be written
   */
  public static void main(String[] args) throws Exception {
    Path out = Path.of(args[0]);
    Files.createDirectories(out);
    Path work = Files.createTempDirectory("renewal-fixtures");
    RenewalFiles files =
        new RenewalFiles(
            new TlsFiles.Identity(
                TlsFiles.IdentityKind.PEM,
                null,
                work.resolve("client.crt"),
                work.resolve("client.key"),
                null,
                List.of()));

    KeyPair key = TestPki.ec();
    files.writePending(
        key.getPrivate(), List.of(), REPLACES, null, key.getPublic(), null, SERVER_TIME);
    Files.move(files.pendingFile(), out.resolve(KEY_ONLY));

    KeyPair caKey = TestPki.ec();
    X509Certificate ca =
        TestX509.certificate("Renewal Fixture CA", caKey.getPublic())
            .selfSigned(caKey.getPrivate())
            .ca()
            .build();
    KeyPair issuedKey = TestPki.ec();
    X509Certificate leaf =
        TestX509.certificate("client", issuedKey.getPublic())
            .issuedBy(ca, caKey.getPrivate())
            .build();
    files.writePending(
        issuedKey.getPrivate(),
        List.of(leaf, ca),
        REPLACES,
        CERTIFICATE_ID,
        issuedKey.getPublic(),
        PASSWORD,
        SERVER_TIME);
    Files.move(files.pendingFile(), out.resolve(ISSUED));

    KeyPair aside = TestPki.ec();
    files.writePending(
        aside.getPrivate(), List.of(), REPLACES, null, aside.getPublic(), null, SERVER_TIME);
    Path moved = files.setAside(Instant.parse("2026-11-08T12:00:00Z"));
    Files.move(moved, out.resolve(UNRESOLVED));
    Files.deleteIfExists(work);
  }
}
