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
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.codec.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.Tls;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;

/** Independent JCA/JCE assertions for formats, wrapping, signatures and application TLS. */
final class CatalogObjects {
  record Pair(KeyPair pair, String privateId, String publicId) {}

  static Pair pair(CatalogLiveSuite s, String algorithm, int bits) throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance(algorithm);
    if (algorithm.equals("EC"))
      g.initialize(new ECGenParameterSpec(bits == 256 ? "secp256r1" : "secp384r1"));
    else g.initialize(bits);
    KeyPair p = g.generateKeyPair();
    var a =
        algorithm.equals("EC")
            ? Enums.CryptographicAlgorithm.ECDSA
            : Enums.CryptographicAlgorithm.RSA;
    String priv =
        s.f.client.register(
            ManagedObjects.privateKey(
                ManagedObjects.keyBlock(
                    Enums.KeyFormatType.PKCS_8,
                    bytes(KEY_MATERIAL, p.getPrivate().getEncoded()),
                    a,
                    bits)),
            Attributes.usage(
                Enums.CryptographicUsageMask.SIGN, Enums.CryptographicUsageMask.DECRYPT));
    s.f.owned.add(priv);
    String pub =
        s.f.client.register(
            ManagedObjects.publicKey(
                ManagedObjects.keyBlock(
                    Enums.KeyFormatType.X_509,
                    bytes(KEY_MATERIAL, p.getPublic().getEncoded()),
                    a,
                    bits)),
            Attributes.usage(
                Enums.CryptographicUsageMask.VERIFY, Enums.CryptographicUsageMask.ENCRYPT));
    s.f.owned.add(pub);
    s.f.client.activate(priv);
    s.f.client.activate(pub);
    return new Pair(p, priv, pub);
  }

  static Ttlv material(
      CatalogLiveSuite s, String uid, boolean privateKey, Enums.KeyFormatType format)
      throws Exception {
    return s.call(
            Requests.get().uniqueIdentifier(uid).add(enumeration(KEY_FORMAT_TYPE, format)).build())
        .requirePayload()
        .require(privateKey ? PRIVATE_KEY : PUBLIC_KEY)
        .require(KEY_BLOCK)
        .require(KEY_VALUE)
        .require(KEY_MATERIAL);
  }

  static void rsaFormats(String id, CatalogLiveSuite s) throws Exception {
    Pair p = pair(s, "RSA", 2048);
    if (id.equals("ASYM-01")) {
      PrivateKey key =
          KeyFactory.getInstance("RSA")
              .generatePrivate(
                  new PKCS8EncodedKeySpec(
                      material(s, p.privateId, true, Enums.KeyFormatType.PKCS_8).bytesValue()));
      Signature sig = Signature.getInstance("SHA256withRSA");
      sig.initSign(key);
      sig.update(known(21));
      byte[] signed = sig.sign();
      sig.initVerify(p.pair.getPublic());
      sig.update(known(21));
      peer(sig.verify(signed), "PKCS8 private key changed");
    } else if (id.equals("ASYM-02")) {
      PublicKey key =
          KeyFactory.getInstance("RSA")
              .generatePublic(
                  new X509EncodedKeySpec(
                      material(s, p.publicId, false, Enums.KeyFormatType.X_509).bytesValue()));
      peer(
          Arrays.equals(key.getEncoded(), p.pair.getPublic().getEncoded()),
          "SPKI public key differs");
    } else {
      Result created =
          s.call(
              Requests.createKeyPair()
                  .add(
                      structure(
                          COMMON_TEMPLATE_ATTRIBUTE,
                          Attributes.algorithm(Enums.CryptographicAlgorithm.RSA),
                          Attributes.length(2048),
                          Attributes.usage(
                              Enums.CryptographicUsageMask.SIGN,
                              Enums.CryptographicUsageMask.VERIFY)))
                  .build());
      String priv = created.requirePayload().require(PRIVATE_KEY_UNIQUE_IDENTIFIER).textValue(),
          pub = created.requirePayload().require(PUBLIC_KEY_UNIQUE_IDENTIFIER).textValue();
      s.f.owned.addAll(List.of(priv, pub));
      peer(!priv.equals(pub), "Keypair identifiers collapsed");
    }
  }

  static void rsaCrypto(String id, CatalogLiveSuite s) throws Exception {
    if (!s.f.version.atLeast(ProtocolVersion.V1_4))
      outside("Explicit MGF and PSS salt parameters require KMIP 1.4");
    Pair p = pair(s, "RSA", 2048);
    byte[] data = known(25);
    if (id.equals("CRYPTO-03")) {
      Ttlv[] params = {
        enumeration(PADDING_METHOD, Enums.PaddingMethod.OAEP),
        enumeration(HASHING_ALGORITHM, Enums.HashingAlgorithm.SHA_256),
        enumeration(MASK_GENERATOR, Enums.MaskGenerator.MGF1),
        enumeration(MASK_GENERATOR_HASHING_ALGORITHM, Enums.HashingAlgorithm.SHA_256)
      };
      byte[] ct =
          s.call(
                  Requests.encrypt()
                      .uniqueIdentifier(p.publicId)
                      .cryptographicParameters(params)
                      .data(data)
                      .build())
              .requirePayload()
              .require(DATA)
              .bytesValue();
      Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
      OAEPParameterSpec spec =
          new OAEPParameterSpec(
              "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
      c.init(Cipher.DECRYPT_MODE, p.pair.getPrivate(), spec);
      peer(Arrays.equals(c.doFinal(ct), data), "OAEP hash/MGF mismatch");
      c.init(Cipher.ENCRYPT_MODE, p.pair.getPublic(), spec);
      peer(
          Arrays.equals(
              s.call(
                      Requests.decrypt()
                          .uniqueIdentifier(p.privateId)
                          .cryptographicParameters(params)
                          .data(c.doFinal(data))
                          .build())
                  .requirePayload()
                  .require(DATA)
                  .bytesValue(),
              data),
          "Independent OAEP decrypt mismatch");
    } else
      for (boolean pss : List.of(false, true)) {
        List<Ttlv> params =
            new ArrayList<>(
                List.of(
                    enumeration(CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.RSA),
                    enumeration(
                        PADDING_METHOD,
                        pss ? Enums.PaddingMethod.PSS : Enums.PaddingMethod.PKCS1_V1_5),
                    enumeration(HASHING_ALGORITHM, Enums.HashingAlgorithm.SHA_256),
                    enumeration(
                        DIGITAL_SIGNATURE_ALGORITHM,
                        pss
                            ? Enums.DigitalSignatureAlgorithm.RSASSA_PSS_PKCS_1_V2_1
                            : Enums.DigitalSignatureAlgorithm
                                .SHA_256_WITH_RSA_ENCRYPTION_PKCS_1_V1_5)));
        if (pss)
          params.addAll(
              List.of(
                  integer(SALT_LENGTH, 32),
                  enumeration(MASK_GENERATOR, Enums.MaskGenerator.MGF1),
                  enumeration(MASK_GENERATOR_HASHING_ALGORITHM, Enums.HashingAlgorithm.SHA_256)));
        byte[] signed =
            s.call(
                    Requests.sign()
                        .uniqueIdentifier(p.privateId)
                        .cryptographicParameters(params.toArray(Ttlv[]::new))
                        .data(data)
                        .build())
                .requirePayload()
                .require(SIGNATURE_DATA)
                .bytesValue();
        Signature local = Signature.getInstance(pss ? "RSASSA-PSS" : "SHA256withRSA");
        if (pss)
          local.setParameter(
              new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        local.initVerify(p.pair.getPublic());
        local.update(data);
        peer(local.verify(signed), "RSA signature differs from JCA");
        local.initSign(p.pair.getPrivate());
        local.update(data);
        var verified =
            s.call(
                Requests.signatureVerify()
                    .uniqueIdentifier(p.publicId)
                    .cryptographicParameters(params.toArray(Ttlv[]::new))
                    .data(data)
                    .add(bytes(SIGNATURE_DATA, local.sign()))
                    .build());
        peer(
            verified.requirePayload().require(VALIDITY_INDICATOR).intValue() == 1,
            "Server rejected independent RSA signature");
      }
  }

  static void ec(String id, CatalogLiveSuite s) throws Exception {
    for (int bits : List.of(256, 384)) {
      Pair p = pair(s, "EC", bits);
      PrivateKey priv =
          KeyFactory.getInstance("EC")
              .generatePrivate(
                  new PKCS8EncodedKeySpec(
                      material(s, p.privateId, true, Enums.KeyFormatType.PKCS_8).bytesValue()));
      PublicKey pub =
          KeyFactory.getInstance("EC")
              .generatePublic(
                  new X509EncodedKeySpec(
                      material(s, p.publicId, false, Enums.KeyFormatType.X_509).bytesValue()));
      peer(
          ((java.security.interfaces.ECPublicKey) pub)
                  .getParams()
                  .getCurve()
                  .getField()
                  .getFieldSize()
              == bits,
          "EC curve identity mismatch");
      Signature sig = Signature.getInstance(bits == 256 ? "SHA256withECDSA" : "SHA384withECDSA");
      sig.initSign(priv);
      sig.update(known(17));
      byte[] signed = sig.sign();
      sig.initVerify(pub);
      sig.update(known(17));
      peer(sig.verify(signed), "EC components do not pair");
      if (id.equals("CRYPTO-05")) {
        if (!s.f.version.atLeast(ProtocolVersion.V1_2)) outside("Remote signing requires 1.2");
        byte[] remote =
            s.call(
                    Requests.sign()
                        .uniqueIdentifier(p.privateId)
                        .cryptographicParameters(
                            enumeration(
                                DIGITAL_SIGNATURE_ALGORITHM,
                                bits == 256
                                    ? Enums.DigitalSignatureAlgorithm.ECDSA_WITH_SHA256
                                    : Enums.DigitalSignatureAlgorithm.ECDSA_WITH_SHA384),
                            enumeration(
                                HASHING_ALGORITHM,
                                bits == 256
                                    ? Enums.HashingAlgorithm.SHA_256
                                    : Enums.HashingAlgorithm.SHA_384))
                        .data(known(17))
                        .build())
                .requirePayload()
                .require(SIGNATURE_DATA)
                .bytesValue();
        String encoding =
            verifyRemoteEcdsa(pub, bits == 256 ? "SHA256" : "SHA384", known(17), remote);
        peer(encoding != null, "Remote EC signature invalid");
        s.f.evidence.put("remote_signature_encoding", encoding);
      }
    }
  }

  /**
   * Verifies a server's ECDSA signature over {@code data} with {@code pub} and says which wire
   * encoding it used: {@code "fixed-width r||s (IEEE P1363)"} or {@code "DER"}; null when it does
   * not verify in either (or is malformed). KMIP leaves the encoding to the server. A signature
   * exactly twice the curve's field width is read as r||s first, through the JDK's
   * {@code <hash>withECDSAinP1363Format}; any other length, or a fixed-width one that does not
   * verify as r||s but is a DER SEQUENCE, through the DER {@code <hash>withECDSA}. A signature of
   * another curve's width is not r||s for this key.
   */
  static String verifyRemoteEcdsa(PublicKey pub, String hash, byte[] data, byte[] remote)
      throws GeneralSecurityException {
    int fieldBits =
        ((java.security.interfaces.ECPublicKey) pub)
            .getParams()
            .getCurve()
            .getField()
            .getFieldSize();
    int width = (fieldBits + 7) / 8;
    if (remote.length == 2 * width && verifies(hash + "withECDSAinP1363Format", pub, data, remote))
      return "fixed-width r||s (IEEE P1363)";
    if (remote.length > 0 && remote[0] == 0x30 && verifies(hash + "withECDSA", pub, data, remote))
      return "DER";
    return null;
  }

  private static boolean verifies(String algorithm, PublicKey pub, byte[] data, byte[] signature)
      throws GeneralSecurityException {
    Signature v = Signature.getInstance(algorithm);
    v.initVerify(pub);
    v.update(data);
    try {
      return v.verify(signature);
    } catch (SignatureException malformed) {
      return false;
    }
  }

  static void wrapping(String id, CatalogLiveSuite s) throws Exception {
    // KMIP 1.1 §2.1.6 and §9.1.3.2.32 already define Encoding Option.
    byte[] key = known(32), kek = known(16);
    // The requested wrapping mode must match a Cryptographic Parameters instance stored on the
    // KEK (KMIP 1.4 §2.1.6), so the KEK is registered with NIST Key Wrap parameters.
    String kekId =
        s.register(
            kek,
            Attributes.usage(
                Enums.CryptographicUsageMask.WRAP_KEY, Enums.CryptographicUsageMask.UNWRAP_KEY),
            Attributes.attribute(
                "Cryptographic Parameters",
                structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    enumeration(BLOCK_CIPHER_MODE, Enums.BlockCipherMode.NISTKEY_WRAP))));
    s.f.client.activate(kekId);
    boolean sensitive = id.equals("AUTH-03");
    if (sensitive && !s.f.version.atLeast(ProtocolVersion.V1_4))
      outside("Sensitive attribute requires KMIP 1.4");
    String uid =
        sensitive
            ? s.register(
                key,
                Attributes.booleanAttribute("Sensitive", true),
                Attributes.booleanAttribute("Extractable", true))
            : s.register(key);
    s.f.client.activate(uid);
    if (sensitive) {
      Ttlv attrs =
          s.call(
                  Requests.getAttributes()
                      .uniqueIdentifier(uid)
                      .add(text(ATTRIBUTE_NAME, "Sensitive"), text(ATTRIBUTE_NAME, "Extractable"))
                      .build())
              .requirePayload();
      boolean retained;
      if (s.f.version.legacyAttributes())
        retained =
            attrs.children(ATTRIBUTE).stream()
                .anyMatch(
                    a ->
                        a.require(ATTRIBUTE_NAME).textValue().equals("Sensitive")
                            && a.require(ATTRIBUTE_VALUE).booleanValue());
      else retained = attrs.require(ATTRIBUTES).require(SENSITIVE).booleanValue();
      peer(retained, "Requested sensitive policy was not retained");
      Result raw = s.f.client.execute(Requests.get().uniqueIdentifier(uid).build());
      peer(!raw.successful(), "Sensitive wrapped-only fixture returned plaintext");
      peer(raw.payload().isEmpty(), "Sensitive failure unexpectedly carried an object payload");
    }
    Ttlv encryption =
        structure(
            ENCRYPTION_KEY_INFORMATION,
            text(UNIQUE_IDENTIFIER, kekId),
            structure(
                CRYPTOGRAPHIC_PARAMETERS,
                enumeration(BLOCK_CIPHER_MODE, Enums.BlockCipherMode.NISTKEY_WRAP)));
    Ttlv spec =
        structure(
            KEY_WRAPPING_SPECIFICATION,
            enumeration(WRAPPING_METHOD, Enums.WrappingMethod.ENCRYPT),
            encryption,
            enumeration(ENCODING_OPTION, Enums.EncodingOption.NO_ENCODING));
    Ttlv block =
        s.call(Requests.get().uniqueIdentifier(uid).add(spec).build())
            .requirePayload()
            .require(SYMMETRIC_KEY)
            .require(KEY_BLOCK);
    peer(
        block.require(KEY_VALUE).type() == Ttlv.Type.BYTE_STRING,
        "Wrapped Get returned structured KeyValue; wrapped material requires ByteString");
    byte[] wrapped = block.require(KEY_VALUE).bytesValue();
    Cipher c = Cipher.getInstance("AESWrap");
    c.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, "AES"));
    peer(
        Arrays.equals(c.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded(), key),
        "Independent KW unwrap differs");
    peer(
        block.require(KEY_WRAPPING_DATA).require(WRAPPING_METHOD).intValue() == 1,
        "Wrapping metadata missing");
    if (id.equals("KEY-08")) {
      Ttlv object =
          ManagedObjects.symmetricKey(
              ManagedObjects.keyBlock(
                  Enums.KeyFormatType.RAW,
                  bytes(KEY_VALUE, wrapped),
                  Enums.CryptographicAlgorithm.AES,
                  256,
                  structure(
                      KEY_WRAPPING_DATA,
                      enumeration(WRAPPING_METHOD, Enums.WrappingMethod.ENCRYPT),
                      encryption,
                      enumeration(ENCODING_OPTION, Enums.EncodingOption.NO_ENCODING))));
      String imported =
          s.f.client.register(
              object,
              Attributes.algorithm(Enums.CryptographicAlgorithm.AES),
              Attributes.length(256),
              Attributes.usage(
                  Enums.CryptographicUsageMask.ENCRYPT, Enums.CryptographicUsageMask.DECRYPT));
      s.f.owned.add(imported);
      Ttlv retrieved =
          s.f.client.get(imported).requirePayload().require(SYMMETRIC_KEY).require(KEY_BLOCK);
      byte[] recovered;
      if (retrieved.require(KEY_VALUE).type() == Ttlv.Type.BYTE_STRING) {
        retrieved.require(KEY_WRAPPING_DATA);
        c.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, "AES"));
        recovered =
            c.unwrap(retrieved.require(KEY_VALUE).bytesValue(), "AES", Cipher.SECRET_KEY)
                .getEncoded();
        s.f.evidence.put(
            "wrapped_register_policy",
            "Stored wrapped representation retained and independently unwrapped");
      } else recovered = s.aes(imported, 256).getEncoded();
      peer(Arrays.equals(recovered, key), "Wrapped registration did not recover original material");
    } else if (sensitive) {
      s.f.evidence.put(
          "policy_proof",
          "Sensitive attribute read back; raw Get denied; independent unwrap of permitted wrapped"
              + " Get succeeded");
    }
  }

  /**
   * Registers a certificate with the attributes Certificate Register requires: the
   * subject key's algorithm and length and the certificate length are derived from the
   * certificate, and the usage is {@link #keyUsageMask}. The fixtures include an RSA issuer
   * signing an EC subject; the algorithm is the subject key's, not the issuer's signature
   * algorithm.
   */
  static String registerCertificate(CatalogLiveSuite s, X509Certificate cert) throws Exception {
    UsageMask usage = keyUsageMask(cert);
    CertificateRegistration registration = CertificateRegistration.of(cert, usage);
    if (cert.getPublicKey() instanceof java.security.interfaces.ECPublicKey)
      registration.ecAlgorithm(
          s.f.version.atLeast(Enums.CryptographicAlgorithm.EC.since())
              ? Enums.CryptographicAlgorithm.EC
              : Enums.CryptographicAlgorithm.ECDSA);
    return s.f.client.call(registration.build()).uniqueIdentifier();
  }

  /**
   * The usage mask a certificate is registered with: what its X.509 Key Usage extension grants the
   * subject's public key, mapped as KMIP 1.0 §3.14 and 1.1 to 1.4 §3.19 require (1.4 Table 96):
   * digitalSignature to Verify, keyEncipherment to Wrap Key, dataEncipherment to Encrypt,
   * keyAgreement to Key Agreement, keyCertSign to Certificate Sign and cRLSign to CRL Sign. A 1.x
   * server may refuse a mask that claims a usage the extension does not grant (keytend-kmip-server
   * refuses Verify on a CA that has only keyCertSign and cRLSign). 2.x has no such table, and the
   * same mask is sent there. Without the extension every use is allowed: Verify, and Certificate
   * Sign and CRL Sign for a CA. When the extension grants none of these (contentCommitment alone),
   * Verify. The SDK's {@code KmsKeys.register(X509Certificate)} chooses the same usages.
   */
  static UsageMask keyUsageMask(X509Certificate cert) {
    boolean[] granted = cert.getKeyUsage();
    List<Enums.CryptographicUsageMask> usage = new ArrayList<>();
    if (granted == null) {
      usage.add(Enums.CryptographicUsageMask.VERIFY);
      if (cert.getBasicConstraints() >= 0)
        usage.addAll(
            List.of(
                Enums.CryptographicUsageMask.CERTIFICATE_SIGN,
                Enums.CryptographicUsageMask.CRL_SIGN));
      return UsageMask.of(usage);
    }
    // RFC 5280 bit order; contentCommitment (bit 1) maps to a bit that 2.0 made Reserved.
    Enums.CryptographicUsageMask[] byBit = {
      Enums.CryptographicUsageMask.VERIFY,
      null,
      Enums.CryptographicUsageMask.WRAP_KEY,
      Enums.CryptographicUsageMask.ENCRYPT,
      Enums.CryptographicUsageMask.KEY_AGREEMENT,
      Enums.CryptographicUsageMask.CERTIFICATE_SIGN,
      Enums.CryptographicUsageMask.CRL_SIGN
    };
    for (int bit = 0; bit < byBit.length && bit < granted.length; bit++)
      if (granted[bit] && byBit[bit] != null) usage.add(byBit[bit]);
    if (usage.isEmpty()) usage.add(Enums.CryptographicUsageMask.VERIFY);
    return UsageMask.of(usage);
  }

  static void certificates(String id, CatalogLiveSuite s) throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(s.f.certs.resolve("chain-server.p12"))) {
      ks.load(in, "changeit".toCharArray());
    }
    String alias = ks.aliases().nextElement();
    PrivateKey privateKey = (PrivateKey) ks.getKey(alias, "changeit".toCharArray());
    java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);
    List<String> ids = new ArrayList<>();
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    List<java.security.cert.Certificate> retrieved = new ArrayList<>();
    for (java.security.cert.Certificate cert : chain) {
      String uid = registerCertificate(s, (X509Certificate) cert);
      ids.add(uid);
      s.f.owned.add(uid);
      byte[] der =
          s.f
              .client
              .get(uid)
              .requirePayload()
              .require(CERTIFICATE)
              .require(CERTIFICATE_VALUE)
              .bytesValue();
      X509Certificate decoded =
          (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
      peer(Arrays.equals(decoded.getEncoded(), cert.getEncoded()), "Certificate DER changed");
      decoded.checkValidity();
      retrieved.add(decoded);
    }
    if (id.equals("ASYM-04")) return;
    if (id.equals("ASYM-07")) {
      // The KMIP 3.0 draft replaced the generic Link attribute with one attribute per link type
      // (Parent Link here), which the SDK's 1.x-to-modern conversion does not produce.
      boolean perTypeLinks = !LINK.definedIn(s.f.version);
      for (int i = 0; i + 1 < ids.size(); i++)
        s.call(
            perTypeLinks
                ? Requests.addAttribute()
                    .uniqueIdentifier(ids.get(i))
                    .add(structure(NEW_ATTRIBUTE, reference(PARENT_LINK, ids.get(i + 1))))
                    .build()
                : Requests.addAttribute()
                    .uniqueIdentifier(ids.get(i))
                    .attribute(Attributes.link(Enums.LinkType.PARENT_LINK, ids.get(i + 1)))
                    .build());
      for (String uid : ids)
        s.call(
            Requests.getAttributes()
                .uniqueIdentifier(uid)
                .add(
                    perTypeLinks
                        ? ModernAttributes.reference(PARENT_LINK)
                        : text(ATTRIBUTE_NAME, "Link"))
                .build());
      s.f.evidence.put(
          "traversal",
          "Explicit run-owned IDs; bounded by chain size; SDK has no automatic link traversal");
      return;
    }
    String privateId =
        s.f.client.register(
            ManagedObjects.privateKey(
                ManagedObjects.keyBlock(
                    Enums.KeyFormatType.PKCS_8,
                    bytes(KEY_MATERIAL, privateKey.getEncoded()),
                    Enums.CryptographicAlgorithm.RSA,
                    2048)),
            Attributes.usage(Enums.CryptographicUsageMask.SIGN));
    s.f.owned.add(privateId);
    PrivateKey recovered =
        KeyFactory.getInstance("RSA")
            .generatePrivate(
                new PKCS8EncodedKeySpec(
                    material(s, privateId, true, Enums.KeyFormatType.PKCS_8).bytesValue()));
    handshake(s.f.certs, recovered, retrieved.toArray(java.security.cert.Certificate[]::new));
  }

  static void handshake(Path certs, PrivateKey key, java.security.cert.Certificate[] chain)
      throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(null, null);
    ks.setKeyEntry("application", key, "changeit".toCharArray(), chain);
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(ks, "changeit".toCharArray());
    SSLContext server = SSLContext.getInstance("TLS");
    server.init(kmf.getKeyManagers(), null, null);
    SSLContext client = Tls.context(null, null, certs.resolve("ca.pem"));
    ExecutorService executor = Executors.newSingleThreadExecutor();
    try (SSLServerSocket listener =
        (SSLServerSocket)
            server
                .getServerSocketFactory()
                .createServerSocket(0, 8, InetAddress.getLoopbackAddress())) {
      listener.setSoTimeout(3000);
      Future<?> handshake =
          executor.submit(
              () -> {
                try (SSLSocket socket = (SSLSocket) listener.accept()) {
                  socket.setSoTimeout(3000);
                  socket.startHandshake();
                  socket.getOutputStream().write(42);
                } catch (IOException e) {
                  throw new UncheckedIOException(e);
                }
              });
      try (SSLSocket socket =
          (SSLSocket)
              client.getSocketFactory().createSocket("localhost", listener.getLocalPort())) {
        socket.setSoTimeout(3000);
        var params = socket.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS");
        socket.setSSLParameters(params);
        socket.startHandshake();
        peer(socket.getInputStream().read() == 42, "Application handshake did not complete");
      }
      handshake.get(4, TimeUnit.SECONDS);
    } finally {
      executor.shutdownNow();
    }
  }

  record Identity(SSLContext context, X509Certificate leaf) {}

  static Identity retrievedIdentity(CatalogLiveSuite s, String name) throws Exception {
    KeyStore original = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(s.f.certs.resolve(name + ".p12"))) {
      original.load(in, "changeit".toCharArray());
    }
    String alias = original.aliases().nextElement();
    PrivateKey privateKey = (PrivateKey) original.getKey(alias, "changeit".toCharArray());
    List<java.security.cert.Certificate> chain = new ArrayList<>();
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    for (java.security.cert.Certificate cert : original.getCertificateChain(alias)) {
      String uid = registerCertificate(s, (X509Certificate) cert);
      s.f.owned.add(uid);
      byte[] der =
          s.f
              .client
              .get(uid)
              .requirePayload()
              .require(CERTIFICATE)
              .require(CERTIFICATE_VALUE)
              .bytesValue();
      chain.add(cf.generateCertificate(new ByteArrayInputStream(der)));
    }
    String uid =
        s.f.client.register(
            ManagedObjects.privateKey(
                ManagedObjects.keyBlock(
                    Enums.KeyFormatType.PKCS_8,
                    bytes(KEY_MATERIAL, privateKey.getEncoded()),
                    Enums.CryptographicAlgorithm.RSA,
                    2048)),
            Attributes.usage(Enums.CryptographicUsageMask.SIGN));
    s.f.owned.add(uid);
    PrivateKey recovered =
        KeyFactory.getInstance("RSA")
            .generatePrivate(
                new PKCS8EncodedKeySpec(
                    material(s, uid, true, Enums.KeyFormatType.PKCS_8).bytesValue()));
    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(null, null);
    store.setKeyEntry(
        "app",
        recovered,
        "changeit".toCharArray(),
        chain.toArray(java.security.cert.Certificate[]::new));
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(store, "changeit".toCharArray());
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(kmf.getKeyManagers(), null, null);
    return new Identity(context, (X509Certificate) chain.get(0));
  }

  static SSLServerSocket listener(SSLContext context, int port) throws Exception {
    SSLServerSocket s = (SSLServerSocket) context.getServerSocketFactory().createServerSocket();
    s.setReuseAddress(true);
    s.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
    s.setSoTimeout(3000);
    return s;
  }

  static void rotatingHandshake(CatalogLiveSuite s) throws Exception {
    Identity old = retrievedIdentity(s, "chain-server"),
        replacement = retrievedIdentity(s, "replacement-server");
    SSLContext client = Tls.context(null, null, s.f.certs.resolve("ca.pem"));
    ExecutorService workers = Executors.newFixedThreadPool(2);
    CountDownLatch rotated = new CountDownLatch(1);
    try (SSLServerSocket before = listener(old.context, 0)) {
      int port = before.getLocalPort();
      Future<?> first =
          workers.submit(
              () -> {
                try (SSLSocket socket = (SSLSocket) before.accept()) {
                  socket.setSoTimeout(3000);
                  socket.startHandshake();
                  socket.getOutputStream().write(1);
                  socket.getOutputStream().flush();
                  if (!rotated.await(5, TimeUnit.SECONDS))
                    throw new IOException("Rotation timeout");
                  socket.getOutputStream().write(2);
                } catch (Exception e) {
                  throw new CompletionException(e);
                }
              });
      try (SSLSocket established =
          (SSLSocket) client.getSocketFactory().createSocket("localhost", port)) {
        established.setSoTimeout(3000);
        var parameters = established.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        established.setSSLParameters(parameters);
        established.startHandshake();
        peer(established.getInputStream().read() == 1, "Initial TLS identity failed");
        before.close();
        try (SSLServerSocket after = listener(replacement.context, port)) {
          Future<?> second =
              workers.submit(
                  () -> {
                    try (SSLSocket socket = (SSLSocket) after.accept()) {
                      socket.setSoTimeout(3000);
                      socket.startHandshake();
                      socket.getOutputStream().write(3);
                    } catch (Exception e) {
                      throw new CompletionException(e);
                    }
                  });
          try (SSLSocket fresh =
              (SSLSocket) client.getSocketFactory().createSocket("localhost", port)) {
            fresh.setSoTimeout(3000);
            fresh.setSSLParameters(parameters);
            fresh.startHandshake();
            peer(fresh.getInputStream().read() == 3, "Replacement handshake failed");
            peer(
                Arrays.equals(
                    fresh.getSession().getPeerCertificates()[0].getPublicKey().getEncoded(),
                    replacement.leaf.getPublicKey().getEncoded()),
                "Fresh session used old identity");
          }
          second.get(4, TimeUnit.SECONDS);
        }
        peer(
            Arrays.equals(
                established.getSession().getPeerCertificates()[0].getPublicKey().getEncoded(),
                old.leaf.getPublicKey().getEncoded()),
            "Existing session changed identity");
        rotated.countDown();
        peer(established.getInputStream().read() == 2, "Old TLS session was lost during rotation");
        first.get(4, TimeUnit.SECONDS);
      }
    } finally {
      rotated.countDown();
      workers.shutdownNow();
      workers.awaitTermination(2, TimeUnit.SECONDS);
    }
  }

  static void mac(CatalogLiveSuite s) throws Exception {
    if (!s.f.version.atLeast(ProtocolVersion.V1_2)) outside("MAC requires 1.2");
    byte[] key = known(32), data = known(27);
    String uid =
        s.f.client.register(
            ManagedObjects.rawSymmetricKey(key, Enums.CryptographicAlgorithm.HMAC_SHA256),
            Attributes.usage(
                Enums.CryptographicUsageMask.MAC_GENERATE,
                Enums.CryptographicUsageMask.MAC_VERIFY));
    s.f.owned.add(uid);
    s.f.client.activate(uid);
    Ttlv[] p = {
      enumeration(CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.HMAC_SHA256),
      enumeration(HASHING_ALGORITHM, Enums.HashingAlgorithm.SHA_256)
    };
    byte[] remote =
        s.call(Requests.mac().uniqueIdentifier(uid).cryptographicParameters(p).data(data).build())
            .requirePayload()
            .require(MAC_DATA)
            .bytesValue();
    Mac local = Mac.getInstance("HmacSHA256");
    local.init(new SecretKeySpec(key, "HmacSHA256"));
    peer(Arrays.equals(local.doFinal(data), remote), "MAC differs from JCE");
    for (boolean valid : List.of(true, false)) {
      byte[] value = remote.clone();
      if (!valid) value[0] ^= 1;
      Result r =
          s.call(
              Requests.macVerify()
                  .uniqueIdentifier(uid)
                  .cryptographicParameters(p)
                  .data(data)
                  .add(bytes(MAC_DATA, value))
                  .build());
      peer(
          (r.requirePayload().require(VALIDITY_INDICATOR).intValue() == 1) == valid,
          "MACVerify validity mismatch");
    }
  }

  static void streaming(CatalogLiveSuite s) throws Exception {
    if (!s.f.version.atLeast(ProtocolVersion.V1_3))
      outside("Init/FinalIndicator streaming requires 1.3");
    String uid = s.create(256);
    s.f.client.activate(uid);
    Ttlv[] p = {
      enumeration(BLOCK_CIPHER_MODE, Enums.BlockCipherMode.CBC),
      enumeration(PADDING_METHOD, Enums.PaddingMethod.PKCS5)
    };
    ByteArrayOutputStream all = new ByteArrayOutputStream();
    byte[] correlation = null, iv = known(16);
    for (int i = 0; i < 3; i++) {
      Request.Builder b =
          Requests.encrypt()
              .uniqueIdentifier(uid)
              .cryptographicParameters(p)
              .data(i < 2 ? known(16) : new byte[0])
              .add(bool(INIT_INDICATOR, i == 0), bool(FINAL_INDICATOR, i == 2));
      if (i == 0) b.add(bytes(IV_COUNTER_NONCE, iv));
      else b.add(bytes(CORRELATION_VALUE, correlation));
      Ttlv r = s.call(b.build()).requirePayload();
      r.child(DATA).ifPresent(n -> all.writeBytes(n.bytesValue()));
      if (i < 2) correlation = r.require(CORRELATION_VALUE).bytesValue();
    }
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.DECRYPT_MODE, s.aes(uid, 256), new IvParameterSpec(iv));
    peer(
        Arrays.equals(c.doFinal(all.toByteArray()), concat(known(16), known(16))),
        "Streaming ciphertext mismatch");
  }
}
