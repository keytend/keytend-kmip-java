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

import dev.keytend.kmip.model.Enums;
import java.util.*;

/**
 * What a key may be used for: the flags of the KMIP Cryptographic Usage Mask that applications use.
 * Other bits are kept in {@link KeyAttributes#rawUsageMask()}.
 *
 * @since 0.10.0
 */
public enum KeyUsage {
  /** Signing (KMIP Sign). */
  SIGN(Enums.CryptographicUsageMask.SIGN),
  /** Verifying signatures (KMIP Verify). */
  VERIFY(Enums.CryptographicUsageMask.VERIFY),
  /** Encrypting (KMIP Encrypt). */
  ENCRYPT(Enums.CryptographicUsageMask.ENCRYPT),
  /** Decrypting (KMIP Decrypt). */
  DECRYPT(Enums.CryptographicUsageMask.DECRYPT),
  /** Wrapping other keys (KMIP Wrap Key). */
  WRAP_KEY(Enums.CryptographicUsageMask.WRAP_KEY),
  /** Unwrapping other keys (KMIP Unwrap Key). */
  UNWRAP_KEY(Enums.CryptographicUsageMask.UNWRAP_KEY),
  /** Computing MACs (KMIP MAC Generate). */
  MAC_GENERATE(Enums.CryptographicUsageMask.MAC_GENERATE),
  /** Verifying MACs (KMIP MAC Verify). */
  MAC_VERIFY(Enums.CryptographicUsageMask.MAC_VERIFY),
  /** Deriving keys (KMIP Derive Key). */
  DERIVE_KEY(Enums.CryptographicUsageMask.DERIVE_KEY),
  /** Key agreement (KMIP Key Agreement). */
  KEY_AGREEMENT(Enums.CryptographicUsageMask.KEY_AGREEMENT),
  /** Signing certificates (KMIP Certificate Sign). */
  CERTIFICATE_SIGN(Enums.CryptographicUsageMask.CERTIFICATE_SIGN),
  /** Signing certificate revocation lists (KMIP CRL Sign). */
  CRL_SIGN(Enums.CryptographicUsageMask.CRL_SIGN);

  private final Enums.CryptographicUsageMask flag;

  KeyUsage(Enums.CryptographicUsageMask flag) {
    this.flag = flag;
  }

  /**
   * The KMIP usage flag (protocol layer).
   *
   * @return the KMIP flag
   */
  public Enums.CryptographicUsageMask protocolValue() {
    return flag;
  }

  static int mask(Collection<KeyUsage> usages) {
    int mask = 0;
    for (KeyUsage u : usages) mask |= u.flag.code();
    return mask;
  }

  /**
   * The usages a certificate is registered with when none are given: what its X.509 Key Usage
   * extension grants its public key, mapped as KMIP 1.0 §3.14 and 1.1 to 1.4 §3.19 (1.4 Table 96)
   * map it, which 1.x servers derive and may refuse a mask to exceed (keytend-kmip-server does), taking the
   * public key's side of each row and only usages this enum has, so always a subset of what the
   * table permits: digitalSignature Verify, keyEncipherment Wrap Key, dataEncipherment Encrypt,
   * keyAgreement Key Agreement, keyCertSign Certificate Sign, cRLSign CRL Sign. contentCommitment
   * (Content Commitment, which this enum lacks), encipherOnly and decipherOnly add nothing. Without
   * the extension (every use is allowed): Verify, and for a CA (Basic Constraints with cA true)
   * Certificate Sign and CRL Sign as well. When the extension grants none of these, Verify, which a
   * 1.x server that enforces the mapping refuses: such a certificate (contentCommitment alone, say)
   * cannot be registered there through this API.
   */
  static Set<KeyUsage> of(java.security.cert.X509Certificate certificate) {
    boolean[] granted = certificate.getKeyUsage();
    EnumSet<KeyUsage> out = EnumSet.noneOf(KeyUsage.class);
    if (granted == null) {
      out.add(VERIFY);
      if (certificate.getBasicConstraints() >= 0) out.addAll(List.of(CERTIFICATE_SIGN, CRL_SIGN));
      return out;
    }
    KeyUsage[] byBit = {VERIFY, null, WRAP_KEY, ENCRYPT, KEY_AGREEMENT, CERTIFICATE_SIGN, CRL_SIGN};
    for (int bit = 0; bit < byBit.length && bit < granted.length; bit++)
      if (granted[bit] && byBit[bit] != null) out.add(byBit[bit]);
    if (out.isEmpty()) out.add(VERIFY);
    return out;
  }

  static Set<KeyUsage> of(int mask) {
    EnumSet<KeyUsage> set = EnumSet.noneOf(KeyUsage.class);
    for (KeyUsage u : values()) if ((mask & u.flag.code()) != 0) set.add(u);
    return Collections.unmodifiableSet(set);
  }
}
