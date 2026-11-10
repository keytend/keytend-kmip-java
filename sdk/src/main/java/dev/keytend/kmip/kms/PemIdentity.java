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
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.security.auth.DestroyFailedException;

/**
 * Reads a TLS client identity from PEM files for {@link KmsConfig.Builder#clientIdentityPem} and
 * {@link KmsConfig#sslContextFromPem(Path, Path, Path)}: the certificate chain, the PKCS#8 private
 * key (decrypting it when encrypted) and the check that the key belongs to the first certificate. Failures are {@link IllegalArgumentException}s naming the
 * file; errors about the private key carry no cause (except for reading the file or a missing JDK
 * algorithm), so that no parser or provider message can quote the key.
 */
final class PemIdentity {
  private PemIdentity() {}

  /**
   * A PKCS#12 key store, protected by an empty password, holding the key in {@code privateKey} and
   * the chain in {@code certificateChain} as its one entry, after checking that the key signs for
   * the first certificate. {@code password} decrypts an encrypted key and may be null; {@code
   * reader} reads each file once.
   */
  static KeyStore keyStore(
      Path certificateChain, Path privateKey, char[] password, TlsFiles.Reader reader) {
    List<X509Certificate> chain;
    PrivateKey key;
    boolean combined = combined(certificateChain, privateKey);
    if (combined) {
      // One file holding the key and its chain (HAProxy's form, openssl pkcs12 -nodes), passed as
      // both: read once, so the chain and the key come from the same bytes.
      byte[] text = reader.read(privateKey, "private key file");
      try {
        chain = certificates(text, certificateChain, true, false);
        key = privateKey(text, privateKey, password);
      } finally {
        Arrays.fill(text, (byte) 0);
      }
    } else {
      chain = certificates(certificateChain, reader);
      key = privateKey(privateKey, password, reader);
    }
    PublicKey leaf = chain.get(0).getPublicKey();
    if (!matches(key, leaf, privateKey)) {
      String message =
          "The private key in "
              + privateKey
              + " ("
              + key.getAlgorithm()
              + ") does not match the first certificate in "
              + certificateChain
              + " ("
              + leaf.getAlgorithm()
              + ")";
      // Two files that do not match may be a renewal written one file at a time.
      throw combined ? new IllegalArgumentException(message) : new Mismatch(message);
    }
    try {
      KeyStore store = KeyStore.getInstance("PKCS12");
      store.load(null, null);
      store.setKeyEntry("identity", key, new char[0], chain.toArray(Certificate[]::new));
      return store;
    } catch (IOException | GeneralSecurityException e) {
      throw new IllegalArgumentException(
          "Cannot use the private key in "
              + privateKey
              + " with the certificates in "
              + certificateChain);
    }
  }

  /**
   * A key file and a chain file whose key and first certificate do not match: also what a renewal
   * written one file at a time looks like between its files, so a reload waits before calling it a
   * failure. Callers of the public API see a plain {@link IllegalArgumentException}
   * ({@link Pem#plain}).
   */
  static final class Mismatch extends IllegalArgumentException {
    Mismatch(String message) {
      super(message);
    }
  }

  /**
   * Whether the chain and the key are one file: {@link java.nio.file.Files#isSameFile} (a symbolic
   * or hard link to it too), or, when that cannot be told (a file missing), the same absolute path.
   */
  static boolean combined(Path certificateChain, Path privateKey) {
    try {
      return java.nio.file.Files.isSameFile(certificateChain, privateKey);
    } catch (IOException | RuntimeException unknown) {
      return certificateChain
          .toAbsolutePath()
          .normalize()
          .equals(privateKey.toAbsolutePath().normalize());
    }
  }

  /** The labels of certificate blocks: RFC 7468's, and the two older ones it lists. */
  private static final Set<String> CERTIFICATE_LABELS =
      Set.of("CERTIFICATE", "X509 CERTIFICATE", "X.509 CERTIFICATE");

  /**
   * The certificates in a PEM or DER file, read once by {@code reader}, in file order; at least
   * one. The file is parsed by its structure ({@link Pem}), not left to the JDK: one certificate
   * for each block, each block a whole certificate, nothing but whitespace after the last; a DER
   * file is whole DER certificates back to back. So a file cut short is refused on every JDK.
   */
  static List<X509Certificate> certificates(Path file, TlsFiles.Reader reader) {
    return certificates(reader.read(file, "certificate file"), file, false, false);
  }

  /** {@link #certificates(Path, TlsFiles.Reader)} of a trust file: CA certificates, with advice for one. */
  static List<X509Certificate> trustCertificates(Path file, TlsFiles.Reader reader) {
    return certificates(reader.read(file, "certificate file"), file, false, true);
  }

  /**
   * What to do about a block labeled {@code label} where only certificates belong: the hint for a
   * combined key and chain file after a private key in a chain file, the conversion for a CA bundle
   * in another form.
   */
  private static String advice(String label, boolean trust, Path file) {
    if (label.endsWith("PRIVATE KEY"))
      return trust
          ? " (a trust file holds no private key)"
          : " (pass a file holding the key and its chain as both arguments)";
    if (label.equals("TRUSTED CERTIFICATE"))
      return " (convert it to a plain one: openssl x509 -in "
          + file
          + " -out "
          + (trust ? "ca.pem" : "chain.pem")
          + ")";
    if (label.equals("PKCS7"))
      return " (convert it to CERTIFICATE blocks: openssl pkcs7 -print_certs -in "
          + file
          + " -out "
          + (trust ? "ca.pem" : "chain.pem")
          + ")";
    return "";
  }

  /**
   * The certificates in {@code data}, the contents of {@code file}; with {@code keyFile}, the file
   * is also the private key file, and its private key block is passed over (the key is read from
   * it as a key file); with {@code trust}, it is a trust file (CA certificates), which only
   * changes the advice.
   */
  static List<X509Certificate> certificates(
      byte[] data, Path file, boolean keyFile, boolean trust) {
    List<X509Certificate> out = new ArrayList<>();
    CertificateFactory factory;
    try {
      factory = CertificateFactory.getInstance("X.509");
    } catch (CertificateException e) {
      throw new IllegalStateException("This JDK has no X.509 certificate factory", e);
    }
    // DER: a SEQUENCE with a long-form length (a certificate is longer than 127 bytes), which no
    // text starts with.
    if (data.length > 1 && data[0] == 0x30 && (data[1] & 0xff) > 0x80) {
      for (int at = 0, n = 1; at < data.length; n++) {
        int end = Pem.derElementEnd(data, at);
        if (end < 0 || data[at] != 0x30)
          throw new Pem.Incomplete(
              file + ": DER certificate " + n + " (at byte " + at + ") is cut short or malformed");
        out.add(
            certificate(factory, Arrays.copyOfRange(data, at, end), file, "DER certificate " + n));
        at = end;
      }
      return out;
    }
    List<Pem.Block> blocks = Pem.blocks(data, file);
    if (blocks.isEmpty())
      throw new Pem.Incomplete(file + " holds no certificate (PEM BEGIN CERTIFICATE or DER)");
    int keys = 0;
    for (Pem.Block b : blocks) {
      if (keyFile && b.label().endsWith("PRIVATE KEY")) {
        keys++;
        continue;
      }
      if (!CERTIFICATE_LABELS.contains(b.label()))
        throw new IllegalArgumentException(
            file
                + " holds a BEGIN "
                + b.label()
                + " block at line "
                + b.line()
                + (keyFile
                    ? "; a file that is both the chain and the key holds certificates and one private key"
                    : (trust
                            ? "; a trust file holds only CA certificates, in BEGIN CERTIFICATE blocks"
                            : "; a certificate file holds only BEGIN CERTIFICATE blocks")
                        + advice(b.label(), trust, file)));
      byte[] der = Pem.decode(data, b, file);
      if (Pem.derElementEnd(der, 0) != der.length || der[0] != 0x30)
        throw new IllegalArgumentException(
            file
                + " holds no valid X.509 certificate in the block at line "
                + b.line()
                + " (not one whole DER certificate)");
      out.add(certificate(factory, der, file, "the block at line " + b.line()));
    }
    if (out.isEmpty())
      throw new Pem.Incomplete(
          file + " holds a private key and no certificate (PEM BEGIN CERTIFICATE)");
    // One certificate for each block (the JDK's own parser may drop a block).
    if (out.size() != blocks.size() - keys)
      throw new IllegalArgumentException(
          file
              + " holds "
              + (blocks.size() - keys)
              + " certificate blocks, of which "
              + out.size()
              + " were read");
    return out;
  }

  private static X509Certificate certificate(
      CertificateFactory factory, byte[] der, Path file, String where) {
    try {
      return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
    } catch (CertificateException | ClassCastException e) {
      throw new IllegalArgumentException(
          file
              + " holds no valid X.509 certificate in "
              + where
              + " (PEM BEGIN CERTIFICATE or DER)",
          e);
    }
  }

  private static final String PBES2_OID = "1.2.840.113549.1.5.13";

  /** PKCS#8 private key algorithm identifiers and the JDK key factory for each. */
  private static final Map<String, String> KEY_FACTORIES =
      Map.of(
          "1.2.840.113549.1.1.1", "RSA",
          "1.2.840.113549.1.1.10", "RSASSA-PSS",
          "1.2.840.10045.2.1", "EC",
          "1.3.101.112", "EdDSA",
          "1.3.101.113", "EdDSA");

  /**
   * The PKCS#8 key in the one PEM private key block of {@code file} (read once by {@code
   * reader}), decrypted with {@code password} when encrypted. The file contents, the DER and the decrypted bytes are wiped.
   * Messages name the file and the problem, never the contents.
   */
  private static PrivateKey privateKey(Path file, char[] password, TlsFiles.Reader reader) {
    byte[] text = reader.read(file, "private key file");
    try {
      return privateKey(text, file, password);
    } finally {
      Arrays.fill(text, (byte) 0);
    }
  }

  /** {@link #privateKey(Path, char[], TlsFiles.Reader)} from {@code text}, the file's contents. */
  static PrivateKey privateKey(byte[] text, Path file, char[] password) {
    byte[] der = null;
    try {
      // Parsed by the file's structure as certificate files are (Pem): every block whole, nothing
      // after the last; one private key block, which may come with certificate blocks.
      List<Pem.Block> blocks = Pem.blocks(text, file);
      List<Pem.Block> keys =
          blocks.stream().filter(b -> b.label().endsWith("PRIVATE KEY")).toList();
      if (keys.isEmpty())
        throw new Pem.Incomplete(
            file + " has no PEM private key (BEGIN PRIVATE KEY or BEGIN ENCRYPTED PRIVATE KEY)");
      Pem.Block block = keys.get(0);
      String label = block.label();
      boolean encrypted = label.equals("ENCRYPTED PRIVATE KEY");
      if (!encrypted && !label.equals("PRIVATE KEY"))
        throw new IllegalArgumentException(
            file
                + " holds a BEGIN "
                + label
                + " block, not PKCS#8; convert it with openssl pkcs8 -topk8"
                + " (add -nocrypt to leave it unencrypted)");
      if (keys.size() > 1)
        throw new IllegalArgumentException(
            file + " holds " + keys.size() + " private key blocks; exactly one is needed");
      for (Pem.Block b : blocks)
        if (b != block) {
          if (!CERTIFICATE_LABELS.contains(b.label()))
            throw new IllegalArgumentException(
                file
                    + " holds a BEGIN "
                    + b.label()
                    + " block at line "
                    + b.line()
                    + "; a private key file holds one private key, and may hold certificates");
          byte[] certificate = Pem.decode(text, b, file);
          Arrays.fill(certificate, (byte) 0);
        }
      der = Pem.decode(text, block, file);
      if (encrypted) {
        if (password == null)
          throw new IllegalArgumentException(
              file
                  + " holds an encrypted private key: pass its password with"
                  + " clientIdentityPem(certificateChain, privateKey, keyPassword)");
        byte[] plain = decrypt(der, password, file);
        Arrays.fill(der, (byte) 0);
        der = plain;
      }
      return pkcs8(der, file, encrypted);
    } finally {
      if (der != null) Arrays.fill(der, (byte) 0);
    }
  }

  /** The PrivateKeyInfo inside a DER EncryptedPrivateKeyInfo; the caller wipes the result. */
  private static byte[] decrypt(byte[] der, char[] password, Path file) {
    EncryptedPrivateKeyInfo info;
    try {
      info = new EncryptedPrivateKeyInfo(der);
    } catch (IOException | RuntimeException e) {
      throw new IllegalArgumentException(file + ": the encrypted private key is malformed");
    }
    AlgorithmParameters params = info.getAlgParameters();
    String scheme = info.getAlgName();
    // JDK 17 names PBES2 only by the scheme; its parameters name the full algorithm (for example
    // PBEWithHmacSHA256AndAES_256), which later JDKs return from getAlgName() directly.
    if ((scheme.equals("PBES2") || scheme.equals(PBES2_OID)) && params != null)
      scheme = params.toString();
    SecretKeyFactory factory;
    Cipher cipher;
    try {
      factory = SecretKeyFactory.getInstance(scheme);
      cipher = Cipher.getInstance(scheme);
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new IllegalArgumentException(
          file
              + ": the private key is encrypted with an unsupported scheme ("
              + info.getAlgName()
              + ")");
    }
    // Checked before any key derivation: the count is the file's.
    int iterations;
    try {
      iterations = params.getParameterSpec(PBEParameterSpec.class).getIterationCount();
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new IllegalArgumentException(
          file
              + ": cannot read the iteration count of the private key's encryption ("
              + info.getAlgName()
              + ")");
    }
    if (iterations < 1 || iterations > KmsConfig.Builder.MAX_PBE_ITERATIONS)
      throw new IllegalArgumentException(
          file
              + ": the private key's encryption asks for "
              + iterations
              + " key-derivation iterations; at most "
              + KmsConfig.Builder.MAX_PBE_ITERATIONS
              + " are accepted (re-encrypt it, for example with openssl pkcs8 -topk8 -iter 600000)");
    PBEKeySpec spec = new PBEKeySpec(password);
    SecretKey key = null;
    try {
      key = factory.generateSecret(spec);
      cipher.init(Cipher.DECRYPT_MODE, key, params);
      return cipher.doFinal(info.getEncryptedData());
    } catch (InvalidKeySpecException e) {
      throw new IllegalArgumentException(
          "The password for "
              + file
              + " cannot be used with "
              + scheme
              + " (this JDK accepts printable ASCII passwords only)");
    } catch (BadPaddingException e) {
      throw new IllegalArgumentException(
          "Cannot decrypt the private key in " + file + ": wrong password, or the file is corrupt");
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException(
          "Cannot decrypt the private key in " + file + " (" + scheme + ")");
    } finally {
      spec.clearPassword();
      if (key != null)
        try {
          key.destroy();
        } catch (DestroyFailedException notSupported) {
          // best effort
        }
    }
  }

  private static PrivateKey pkcs8(byte[] der, Path file, boolean decrypted) {
    String oid = privateKeyAlgorithm(der);
    if (oid == null)
      throw new IllegalArgumentException(
          decrypted
              ? "Cannot decrypt the private key in "
                  + file
                  + ": wrong password, or the file is corrupt"
              : file + ": the private key is malformed (not a PKCS#8 PrivateKeyInfo)");
    String algorithm = KEY_FACTORIES.get(oid);
    if (algorithm == null)
      throw new IllegalArgumentException(
          file
              + " holds a private key of an unsupported type (algorithm "
              + oid
              + "); RSA, RSASSA-PSS, EC, Ed25519 and Ed448 are supported");
    try {
      return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalArgumentException(
          file + " holds a " + algorithm + " private key, which this JDK does not support", e);
    } catch (InvalidKeySpecException e) {
      // No cause: a parser message could quote the key's bytes.
      throw new IllegalArgumentException(file + ": the " + algorithm + " private key is malformed");
    }
  }

  /**
   * The algorithm OID of a DER PrivateKeyInfo ({@code SEQUENCE { INTEGER, SEQUENCE { OID, ... },
   * OCTET STRING, ... }} spanning all of {@code der}), or null when it is not one.
   */
  private static String privateKeyAlgorithm(byte[] der) {
    try {
      int[] at = {0};
      if (enter(der, at, 0x30, der.length) != der.length) return null;
      at[0] = enter(der, at, 0x02, der.length);
      int algorithmEnd = enter(der, at, 0x30, der.length);
      int oidEnd = enter(der, at, 0x06, algorithmEnd);
      if (oidEnd == at[0] || (der[oidEnd - 1] & 0x80) != 0) return null;
      StringBuilder oid = new StringBuilder();
      long arc = 0;
      for (int i = at[0]; i < oidEnd; i++) {
        if (arc > (Long.MAX_VALUE >> 7)) return null;
        arc = (arc << 7) | (der[i] & 0x7f);
        if ((der[i] & 0x80) != 0) continue;
        if (oid.length() == 0) {
          long first = Math.min(arc / 40, 2);
          oid.append(first).append('.').append(arc - 40 * first);
        } else oid.append('.').append(arc);
        arc = 0;
      }
      at[0] = algorithmEnd;
      enter(der, at, 0x04, der.length);
      return oid.toString();
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  /** Reads a DER header with {@code tag} at {@code at[0]}, moves past it, returns the value's end. */
  private static int enter(byte[] der, int[] at, int tag, int limit) {
    int i = at[0];
    if (limit - i < 2 || (der[i++] & 0xff) != tag) throw new IllegalArgumentException();
    int length = der[i++] & 0xff;
    if (length > 0x80 && length <= 0x84) {
      int bytes = length - 0x80;
      length = 0;
      for (int n = 0; n < bytes; n++) {
        if (i >= limit || length > (Integer.MAX_VALUE >> 8)) throw new IllegalArgumentException();
        length = (length << 8) | (der[i++] & 0xff);
      }
    } else if (length >= 0x80) throw new IllegalArgumentException();
    if (length > limit - i) throw new IllegalArgumentException();
    at[0] = i;
    return i + length;
  }

  /**
   * Whether {@code key} is the private half of {@code certificateKey}: the key signs a random
   * challenge that the certificate's key must verify. The JDK cannot derive an EC or EdDSA public
   * key from the private key, and comparing an RSA key's modulus and public exponent would not
   * check its private exponent or CRT values, which are what TLS signs with. RSA keys sign with
   * SHA256withRSA, or with RSASSA-PSS when either key is an RSASSA-PSS key, using the parameters a
   * restricted key requires (the private key's, else the certificate key's, else SHA-256 with MGF1
   * and a 32-byte salt).
   *
   * @throws IllegalArgumentException (without a cause) when the key cannot sign, for example an
   *     RSA key whose private values are inconsistent
   */
  static boolean matches(PrivateKey key, PublicKey certificateKey, Path file) {
    String family = family(key.getAlgorithm());
    if (!family.equals(family(certificateKey.getAlgorithm()))) return false;
    String algorithm;
    AlgorithmParameterSpec parameters = null;
    if (family.equals("RSA")) {
      boolean pss =
          key.getAlgorithm().equals("RSASSA-PSS")
              || certificateKey.getAlgorithm().equals("RSASSA-PSS");
      algorithm = pss ? "RSASSA-PSS" : "SHA256withRSA";
      if (pss) parameters = pssParameters(key, certificateKey);
    } else
      algorithm =
          switch (family) {
            case "EC" -> "SHA256withECDSA";
            // Not "DSA" (SHA-1), which the JDK refuses for keys with a 224- or 256-bit q.
            case "DSA" -> "SHA256withDSA";
            default -> family;
          };
    byte[] challenge = new byte[32];
    new SecureRandom().nextBytes(challenge);
    byte[] signature;
    try {
      Signature signer = Signature.getInstance(algorithm);
      signer.initSign(key);
      if (parameters != null) signer.setParameter(parameters);
      signer.update(challenge);
      signature = signer.sign();
    } catch (GeneralSecurityException | RuntimeException e) {
      // No cause: the provider's message is about the key.
      throw new IllegalArgumentException(
          "Cannot sign with the private key in "
              + file
              + " ("
              + key.getAlgorithm()
              + "): it is corrupt or unusable");
    }
    try {
      Signature verifier = Signature.getInstance(algorithm);
      verifier.initVerify(certificateKey);
      if (parameters != null) verifier.setParameter(parameters);
      verifier.update(challenge);
      return verifier.verify(signature);
    } catch (GeneralSecurityException | RuntimeException e) {
      return false; // for example an RSASSA-PSS certificate key restricted to other parameters
    }
  }

  private static AlgorithmParameterSpec pssParameters(PrivateKey key, PublicKey certificateKey) {
    if (key instanceof RSAKey k && k.getParams() instanceof PSSParameterSpec p) return p;
    if (certificateKey instanceof RSAKey k && k.getParams() instanceof PSSParameterSpec p) return p;
    return new PSSParameterSpec(
        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.TRAILER_FIELD_BC);
  }

  private static String family(String keyAlgorithm) {
    return switch (keyAlgorithm) {
      case "RSA", "RSASSA-PSS" -> "RSA";
      case "EdDSA", "Ed25519", "Ed448" -> "EdDSA";
      default -> keyAlgorithm;
    };
  }
}
