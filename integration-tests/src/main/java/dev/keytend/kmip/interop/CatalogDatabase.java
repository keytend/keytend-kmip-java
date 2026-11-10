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

import static dev.keytend.kmip.interop.Catalog.*;
import static dev.keytend.kmip.interop.CatalogLiveSuite.*;
import static dev.keytend.kmip.model.Tag.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.sql.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * Actual H2 encrypted-file consumer fixture. This does not qualify a different database product.
 */
public final class CatalogDatabase {
  static final byte[] ROW = "catalog synthetic database plaintext".getBytes(StandardCharsets.UTF_8);

  static SecretKey fetch(CatalogFixture f, String uid) throws Exception {
    return Keys.aesKey(f.client.get(uid).requirePayload(), uid, 256);
  }

  static Connection connect(Path database, SecretKey key, boolean existing) throws Exception {
    Class.forName("org.h2.Driver");
    byte[] encoded = key.getEncoded();
    char[] hex = new char[encoded.length * 2 + 1];
    char[] digits = "0123456789abcdef".toCharArray();
    for (int i = 0; i < encoded.length; i++) {
      hex[i * 2] = digits[(encoded[i] >>> 4) & 15];
      hex[i * 2 + 1] = digits[encoded[i] & 15];
    }
    hex[hex.length - 1] = ' ';
    Properties p = new Properties();
    p.put("user", "sa");
    p.put("password", hex);
    try {
      return DriverManager.getConnection(
          "jdbc:h2:file:"
              + database.toAbsolutePath()
              + ";CIPHER=AES;DB_CLOSE_ON_EXIT=FALSE"
              + (existing ? ";IFEXISTS=TRUE" : ""),
          p);
    } finally {
      Arrays.fill(encoded, (byte) 0);
      Arrays.fill(hex, '\0');
    }
  }

  static void write(Path db, SecretKey key) throws Exception {
    try (Connection c = connect(db, key, false);
        Statement s = c.createStatement()) {
      s.execute("CREATE TABLE records (id INT PRIMARY KEY, payload VARBINARY)");
      try (PreparedStatement p = c.prepareStatement("INSERT INTO records VALUES (?,?)")) {
        p.setInt(1, 1);
        p.setBytes(2, ROW);
        p.executeUpdate();
      }
    }
    require(
        !new String(Files.readAllBytes(Path.of(db + ".mv.db")), StandardCharsets.ISO_8859_1)
            .contains(new String(ROW, StandardCharsets.UTF_8)),
        "Database file contains plaintext");
  }

  static void read(Path db, SecretKey key) throws Exception {
    try (Connection c = connect(db, key, true);
        Statement s = c.createStatement();
        ResultSet r = s.executeQuery("SELECT payload FROM records WHERE id=1")) {
      require(r.next() && Arrays.equals(r.getBytes(1), ROW), "Persisted database roundtrip failed");
    }
  }

  static void node(CatalogFixture f, Path db, String uid) throws Exception {
    List<String> args =
        List.of(
            Path.of(System.getProperty("java.home"), "bin/java").toString(),
            "-cp",
            System.getProperty("surefire.test.class.path", System.getProperty("java.class.path")),
            CatalogDatabase.class.getName(),
            f.host,
            Integer.toString(f.port),
            f.certs.toString(),
            f.version.toString(),
            db.toString(),
            uid);
    Process child = new ProcessBuilder(args).redirectErrorStream(true).start();
    if (!child.waitFor(15, TimeUnit.SECONDS)) {
      child.destroyForcibly();
      throw new AssertionError("Fresh database node timeout");
    }
    String text = new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    require(
        child.exitValue() == 0 && text.contains("READ_OK"),
        "Fresh database process could not read encrypted data");
  }

  static void execute(String id, CatalogFixture f) throws Exception {
    if (id.equals("ASYM-09"))
      outside(
          "SDK does not ship a JCA remote-signing/JSSE provider; KMIP Sign is not remote TLS"
              + " coverage");
    if (id.equals("ASYM-06")) {
      mismatchedIdentity(f);
      return;
    }
    try {
      Class.forName("org.h2.Driver");
    } catch (ClassNotFoundException e) {
      blocked("H2 consumer fixture requires the integration test classpath");
    }
    f.provision();
    Path dir = Files.createTempDirectory("keytend-catalog-db-");
    Path db = dir.resolve("database");
    String uid = f.knownUid;
    SecretKey key = fetch(f, uid);
    f.evidence.put(
        "database",
        "H2 2.4.240 encrypted-file fixture; KMIP bytes are file-password input to H2's AES128 KDF,"
            + " not raw AES256 file encryption");
    f.evidence.put(
        "key_cache_policy", "No cross-open cache; each fresh process retrieves exact UID");
    try {
      switch (id) {
        case "DB-01", "DB-02" -> {
          write(db, key);
          node(f, db, uid);
        }
        case "DB-03" -> {
          byte[] dek = new byte[32];
          new SecureRandom().nextBytes(dek);
          Cipher wrap = Cipher.getInstance("AESWrap");
          wrap.init(Cipher.WRAP_MODE, key);
          byte[] wrapped = wrap.wrap(new SecretKeySpec(dek, "AES"));
          byte[] iv = new byte[12];
          new SecureRandom().nextBytes(iv);
          Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
          enc.init(
              Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(128, iv));
          byte[] data = enc.doFinal(ROW);
          Arrays.fill(dek, (byte) 0);
          try (Connection c = connect(db, key, false);
              Statement st = c.createStatement()) {
            st.execute(
                "CREATE TABLE envelope (kek_ref VARCHAR, wrapped VARBINARY, iv VARBINARY, cipher"
                    + " VARBINARY)");
            try (PreparedStatement p =
                c.prepareStatement("INSERT INTO envelope VALUES (?,?,?,?)")) {
              p.setString(1, uid);
              p.setBytes(2, wrapped);
              p.setBytes(3, iv);
              p.setBytes(4, data);
              p.executeUpdate();
            }
          }
          // Reopen both database and wrapping context with fresh KMIP key retrieval.
          try (Connection c = connect(db, fetch(f, uid), true);
              Statement st = c.createStatement();
              ResultSet r = st.executeQuery("SELECT * FROM envelope")) {
            require(r.next(), "Envelope missing");
            require(r.getString(1).equals(uid), "KEK reference remapped");
            wrap.init(Cipher.UNWRAP_MODE, fetch(f, r.getString(1)));
            SecretKey recovered = (SecretKey) wrap.unwrap(r.getBytes(2), "AES", Cipher.SECRET_KEY);
            enc.init(Cipher.DECRYPT_MODE, recovered, new GCMParameterSpec(128, r.getBytes(3)));
            require(Arrays.equals(enc.doFinal(r.getBytes(4)), ROW), "Persisted envelope mismatch");
          }
        }
        case "DB-04" -> {
          CatalogLiveSuite suite = new CatalogLiveSuite(f);
          String next = suite.create(256);
          Path second = dir.resolve("rotated");
          write(db, key);
          write(second, fetch(f, next));
          try (Connection c = connect(second, fetch(f, next), true);
              Statement st = c.createStatement()) {
            st.execute("SHUTDOWN COMPACT");
          }
          node(f, db, uid);
          node(f, second, next);
        }
        case "DB-05" -> {
          write(db, key);
          Path zip = dir.resolve("backup.zip");
          try (Connection c = connect(db, key, true);
              Statement st = c.createStatement()) {
            st.execute("BACKUP TO '" + zip.toString().replace("'", "''") + "'");
          }
          Path restored = dir.resolve("fresh-node");
          Files.createDirectories(restored);
          try (ZipInputStream in = new ZipInputStream(Files.newInputStream(zip))) {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
              Path target = restored.resolve(entry.getName()).normalize();
              require(target.startsWith(restored), "Unsafe backup entry");
              Files.createDirectories(target.getParent());
              Files.copy(in, target);
            }
          }
          node(f, restored.resolve("database"), uid);
          f.evidence.put(
              "restore_identity",
              "Fresh process with owner credentials; read-only second-principal grant is a separate"
                  + " AUTH lane");
        }
        case "DB-06", "DB-07" -> {
          if (id.equals("DB-07")) write(db, key);
          int port;
          try (ServerSocket unused = new ServerSocket(0)) {
            port = unused.getLocalPort();
          }
          try (var unavailable =
              new KmipClient(
                  new TlsTransport(
                      "localhost",
                      port,
                      Tls.context(
                          f.certs.resolve("client.p12"),
                          "changeit".toCharArray(),
                          f.certs.resolve("ca.pem")),
                      Duration.ofMillis(200),
                      Duration.ofMillis(200),
                      new dev.keytend.kmip.codec.TtlvCodec()),
                  f.version)) {
            try {
              SecretKey impossible = Keys.aesKey(unavailable.get(uid).requirePayload(), uid, 256);
              connect(dir.resolve("must-not-exist"), impossible, false);
              throw new AssertionError("Unavailable KMS produced a database key");
            } catch (IOException expected) {
            }
          }
          require(
              !Files.exists(dir.resolve("must-not-exist.mv.db")),
              "Missing key created fallback database");
          if (id.equals("DB-07")) read(db, key);
        }
        case "DB-08" -> {
          CatalogLiveSuite suite = new CatalogLiveSuite(f);
          String owned = suite.create(256);
          SecretKey exported = fetch(f, owned);
          write(db, exported);
          f.client.activate(owned);
          f.client.revoke(
              owned, Enums.RevocationReasonCode.CESSATION_OF_OPERATION, "catalog DB policy");
          Result fresh = f.client.execute(Requests.get().uniqueIdentifier(owned).build());
          read(db, exported);
          f.evidence.put("fresh_get_after_revocation_status", fresh.status());
          f.evidence.put(
              "revocation_contract",
              "Exported bytes remain usable; future acquisition follows server policy; no SDK"
                  + " cache");
        }
        case "DB-09" -> {
          write(db, key);
          ExecutorService pool = Executors.newFixedThreadPool(8);
          try {
            List<Future<?>> tasks = new ArrayList<>();
            for (int i = 0; i < 8; i++)
              tasks.add(
                  pool.submit(
                      () -> {
                        try {
                          read(db, fetch(f, uid));
                        } catch (Exception e) {
                          throw new CompletionException(e);
                        }
                      }));
            for (var t : tasks) t.get(15, TimeUnit.SECONDS);
          } finally {
            pool.shutdownNow();
          }
          f.evidence.put(
              "provisioning_contract",
              "Exact pre-provisioned ID; no name-based automatic creation or distributed"
                  + " provisioning feature");
        }
        case "DB-10" -> {
          write(db, key);
          if (f.restart == null) blocked("Persistent KMS recovery hook unavailable");
          f.restart.run();
          node(f, db, uid);
          try (var renewed = f.identity("client-renewed")) {
            Keys.aesKey(renewed.get(uid).requirePayload(), uid, 256);
          }
          f.evidence.put("renewal", "New private key/certificate, same owner CN, fresh transport");
        }
        case "DB-11" -> {
          write(db, key);
          try {
            f.client.get(uid + "-corrupt");
            throw new AssertionError("Corrupt persisted UID resolved");
          } catch (KmipException expected) {
          }
          byte[] wrong = key.getEncoded();
          wrong[0] ^= 1;
          try {
            read(db, new SecretKeySpec(wrong, "AES"));
            throw new AssertionError("Wrong database key was accepted");
          } catch (SQLException expected) {
          }
          Cipher wrap = Cipher.getInstance("AESWrap");
          wrap.init(Cipher.WRAP_MODE, key);
          byte[] blob = wrap.wrap(new SecretKeySpec(known(32), "AES"));
          blob[0] ^= 1;
          wrap.init(Cipher.UNWRAP_MODE, key);
          try {
            wrap.unwrap(blob, "AES", Cipher.SECRET_KEY);
            throw new AssertionError("Corrupt wrapped DEK was accepted");
          } catch (GeneralSecurityException expected) {
          }
        }
        case "DB-12" -> {
          write(db, key);
          CatalogLiveSuite s = new CatalogLiveSuite(f);
          CatalogObjects.rotatingHandshake(s);
          read(db, fetch(f, uid));
          node(f, db, uid);
          f.evidence.put(
              "application_tls_rotation",
              "New listener on same endpoint uses a retrieved replacement identity while an"
                  + " established session retains the original; fresh database process reads"
                  + " historical data");
        }
        default -> throw new AssertionError("No database implementation for " + id);
      }
    } finally {
      try (var walk = Files.walk(dir)) {
        for (Path p : walk.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
      }
    }
  }

  static void mismatchedIdentity(CatalogFixture f) throws Exception {
    KeyStore good = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(f.certs.resolve("chain-server.p12"))) {
      good.load(in, "changeit".toCharArray());
    }
    String alias = good.aliases().nextElement();
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(2048);
    try {
      CatalogObjects.handshake(
          f.certs, g.generateKeyPair().getPrivate(), good.getCertificateChain(alias));
      throw new AssertionError("Mismatched application key/certificate completed TLS");
    } catch (GeneralSecurityException | IOException expected) {
    }
    KeyStore expired = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(f.certs.resolve("expired.p12"))) {
      expired.load(in, "changeit".toCharArray());
    }
    String a = expired.aliases().nextElement();
    try {
      CatalogObjects.handshake(
          f.certs,
          (PrivateKey) expired.getKey(a, "changeit".toCharArray()),
          expired.getCertificateChain(a));
      throw new AssertionError("Expired application identity completed TLS");
    } catch (GeneralSecurityException | IOException expected) {
    }
  }

  /** Fresh process entry point used by cold-start and backup/restore assertions. */
  public static void main(String[] args) throws Exception {
    Path certs = Path.of(args[2]);
    String[] version = args[3].split("\\.");
    try (var client =
        new KmipClient(
            new TlsTransport(
                args[0],
                Integer.parseInt(args[1]),
                Tls.context(
                    certs.resolve("client.p12"),
                    "changeit".toCharArray(),
                    certs.resolve("ca.pem"))),
            ProtocolVersion.of(Integer.parseInt(version[0]), Integer.parseInt(version[1])))) {
      SecretKey key = Keys.aesKey(client.get(args[5]).requirePayload(), args[5], 256);
      read(Path.of(args[4]), key);
      System.out.println("READ_OK");
    }
  }
}
