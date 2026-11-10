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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

/**
 * JKS and PKCS#12 key store files: client identities ({@link
 * KmsConfig.Builder#clientIdentityKeyStore(Path, char[])}) and trust stores ({@link KmsConfig.Builder#trustStore(Path, char[])}). The format is told from the file's
 * first bytes, never from its name, and a file cut short is {@link Pem.Incomplete}, as a PEM file
 * is, so a reload takes it for a writer not done. Messages name the file, never the password.
 */
final class KeyStoreFiles {
  private KeyStoreFiles() {}

  /** The formats read; the JDK's key store type, and what a message calls a file of it. */
  enum Type {
    JKS("JKS", "JKS key store"),
    PKCS12("PKCS12", "PKCS#12 file");
    final String jdk, what;

    Type(String jdk, String what) {
      this.jdk = jdk;
      this.what = what;
    }
  }

  /** What a message calls a trust store file, whose PEM form {@code trustPem} reads. */
  private static final String TRUST_STORE = "trust store";

  private static final int JKS_MAGIC = 0xFEEDFEED, JCEKS_MAGIC = 0xCECECECE;

  /** The length of a JKS file's closing SHA-1 digest. */
  private static final int JKS_DIGEST = 20;

  /**
   * The format of {@code data}, read from {@code file} as {@code what}: {@code expected}, or
   * either when it is null. {@link Pem.Incomplete} when too little is there to tell or the file is
   * cut short; IllegalArgumentException naming the format to use otherwise.
   */
  static Type type(byte[] data, Path file, Type expected, String what) {
    if (data.length < 4)
      throw new Pem.Incomplete(
          file + " is not a whole " + what + " (cut short, or still being written?)");
    int magic =
        ((data[0] & 0xff) << 24)
            | ((data[1] & 0xff) << 16)
            | ((data[2] & 0xff) << 8)
            | (data[3] & 0xff);
    Type found;
    if (magic == JKS_MAGIC) found = Type.JKS;
    else if ((data[0] & 0xff) == 0x30) found = Type.PKCS12;
    else if (magic == JCEKS_MAGIC)
      throw new IllegalArgumentException(
          file
              + " is a JCEKS key store, which is not supported: convert it to PKCS#12 with keytool"
              + " -importkeystore -deststoretype PKCS12");
    else if (pem(data))
      throw new IllegalArgumentException(
          file
              + " is a PEM file, not a "
              + what
              + ": use "
              + (what.equals(TRUST_STORE) ? "trustPem" : "clientIdentityPem"));
    else
      throw new IllegalArgumentException(file + " is neither a JKS key store nor a PKCS#12 file");
    if (expected != null && found != expected)
      throw new IllegalArgumentException(
          file
              + " is a "
              + found.what
              + ", not a "
              + expected.what
              + ": use KmsConfig.sslContextFromKeyStores or clientIdentityKeyStore, which read"
              + " either");
    boolean whole =
        found == Type.JKS
            ? jksEnd(data) >= 0
            // An indefinite length (BER, from some tools) is left to the key store.
            : (data[1] & 0xff) == 0x80 || Pem.derElementEnd(data, 0) >= 0;
    if (!whole)
      throw new Pem.Incomplete(
          file + " is not a whole " + found.what + " (cut short, or still being written?)");
    return found;
  }

  /** Whether {@code data} starts, after whitespace, like a PEM file. */
  private static boolean pem(byte[] data) {
    int i = 0;
    if (data.length >= 3
        && (data[0] & 0xff) == 0xef
        && (data[1] & 0xff) == 0xbb
        && (data[2] & 0xff) == 0xbf) i = 3; // a UTF-8 byte order mark
    while (i < data.length && Character.isWhitespace(data[i])) i++;
    byte[] begin = "-----BEGIN".getBytes(StandardCharsets.US_ASCII);
    return data.length - i >= begin.length
        && Arrays.equals(data, i, i + begin.length, begin, 0, begin.length);
  }

  /**
   * Where the JKS key store in {@code d} ends, after its digest; -1 when the file is cut short
   * before that. A structure this walk does not know (another version, an entry of another kind,
   * a negative length) gives {@code d.length}, and the key store's own reading refuses it.
   */
  static int jksEnd(byte[] d) {
    long n = d.length;
    long[] at = {0};
    // magic, version, count
    if (!skip(at, 4, n)) return -1;
    Long version = readInt(d, at);
    if (version == null) return -1;
    if (version != 1 && version != 2) return d.length;
    Long count = readInt(d, at);
    if (count == null) return -1;
    if (count < 0) return d.length;
    for (long e = 0; e < count; e++) {
      Long tag = readInt(d, at);
      if (tag == null) return -1;
      if (tag != 1 && tag != 2) return d.length;
      if (!utf(d, at, n) || !skip(at, 8, n)) return -1; // alias, date
      if (tag == 1) {
        Long key = readInt(d, at);
        if (key == null) return -1;
        if (key < 0) return d.length;
        if (!skip(at, key, n)) return -1;
        Long chain = readInt(d, at);
        if (chain == null) return -1;
        if (chain < 0) return d.length;
        for (long c = 0; c < chain; c++) {
          int certificate = certificate(d, at, n, version == 2);
          if (certificate <= 0) return certificate < 0 ? -1 : d.length;
        }
      } else {
        int certificate = certificate(d, at, n, version == 2);
        if (certificate <= 0) return certificate < 0 ? -1 : d.length;
      }
    }
    if (!skip(at, JKS_DIGEST, n)) return -1;
    return (int) at[0];
  }

  /** One certificate of a JKS entry: 1 when read, -1 when cut short, 0 when malformed. */
  private static int certificate(byte[] d, long[] at, long n, boolean typed) {
    if (typed && !utf(d, at, n)) return -1;
    Long length = readInt(d, at);
    if (length == null) return -1;
    if (length < 0) return 0;
    return skip(at, length, n) ? 1 : -1;
  }

  /** Skips a modified-UTF-8 string (its two-byte length, then the bytes); false when cut short. */
  private static boolean utf(byte[] d, long[] at, long n) {
    if (at[0] + 2 > n) return false;
    int length = ((d[(int) at[0]] & 0xff) << 8) | (d[(int) at[0] + 1] & 0xff);
    at[0] += 2;
    return skip(at, length, n);
  }

  private static boolean skip(long[] at, long bytes, long n) {
    if (at[0] + bytes > n) return false;
    at[0] += bytes;
    return true;
  }

  /** A big-endian int at the cursor, which moves past it; null when cut short. */
  private static Long readInt(byte[] d, long[] at) {
    if (at[0] + 4 > d.length) return null;
    int i = (int) at[0];
    at[0] += 4;
    return (long)
        (((d[i] & 0xff) << 24)
            | ((d[i + 1] & 0xff) << 16)
            | ((d[i + 2] & 0xff) << 8)
            | (d[i + 3] & 0xff));
  }

  /**
   * The key store in {@code file}, read once by {@code reader} as {@code what}, of {@code expected}
   * format (either when null); the bytes read are wiped. The password is used, not kept.
   */
  static KeyStore read(
      Path file, Type expected, char[] password, TlsFiles.Reader reader, String what) {
    byte[] data = reader.read(file, what);
    try {
      Type type = type(data, file, expected, what);
      KeyStore store;
      try (InputStream in = new ByteArrayInputStream(data)) {
        store = KeyStore.getInstance(type.jdk);
        store.load(in, password);
      } catch (IOException | GeneralSecurityException e) {
        throw new IllegalArgumentException(
            "Cannot read the " + type.what + " " + file + " (corrupt, or wrong password)", e);
      }
      return store;
    } finally {
      Arrays.fill(data, (byte) 0);
    }
  }

  /**
   * The key managers for the one private key in the key store {@code file} ({@code type}), checked
   * to sign for the first certificate of its chain. The key's password must be the store's.
   */
  static KeyManager[] identity(Path file, Type type, char[] password, TlsFiles.Reader reader) {
    return identityKeys(file, type, password, reader).managers();
  }

  /** {@link #identity}, with the leaf certificate the key managers present. */
  static KmsConfig.Keys identityKeys(
      Path file, Type type, char[] password, TlsFiles.Reader reader) {
    KeyStore store = read(file, type, password, reader, type == null ? "key store" : type.what);
    return KmsConfig.identityKeys(store, password, file.toString(), file);
  }

  /**
   * Trust managers for the trusted certificate entries of the JKS or PKCS#12 trust store {@code
   * file}; at least one is needed. Its private key entries, if any, are not trusted.
   */
  static TrustManager[] trust(Path file, char[] password, TlsFiles.Reader reader) {
    KeyStore store = read(file, null, password, reader, TRUST_STORE);
    List<X509Certificate> trusted = new ArrayList<>();
    try {
      for (String alias : Collections.list(store.aliases()))
        if (store.isCertificateEntry(alias)) {
          Certificate c = store.getCertificate(alias);
          if (c instanceof X509Certificate x) trusted.add(x);
        }
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("Cannot read the trust store " + file, e);
    }
    if (trusted.isEmpty())
      throw new IllegalArgumentException(
          file
              + " holds no trusted certificate entry: add the CA certificates with keytool"
              + " -importcert (a PKCS#12 file made by openssl marks none trusted for Java), or use"
              + " trustPem");
    try {
      KeyStore only = KeyStore.getInstance("PKCS12");
      only.load(null, null);
      int i = 0;
      for (X509Certificate c : trusted) only.setCertificateEntry("ca-" + i++, c);
      return KmsConfig.storeTrust(only);
    } catch (IOException | GeneralSecurityException e) {
      throw new IllegalArgumentException("Cannot use the certificates in " + file, e);
    }
  }
}
