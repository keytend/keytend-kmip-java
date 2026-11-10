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

package dev.keytend.kmip.kms.samples;

import dev.keytend.kmip.kms.*;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

/**
 * A4. Remote signing: the private key is created in and never leaves the KMS. Verification on the
 * server returns {@link VerifyResult}; a successful call that returns INVALID is a rejected
 * signature, not an error to ignore. The public key can also be exported to verify locally.
 */
public final class RemoteSignVerify {
  private RemoteSignVerify() {}

  public static KeyPairHandle createSigner(Kms kms, String name, KeyPairSpec spec) {
    return kms.keys()
        .createKeyPair(spec)
        .named(name, name + "-public")
        .privateUsages(KeyUsage.SIGN)
        .publicUsages(KeyUsage.VERIFY)
        .create();
  }

  public static byte[] sign(KeyPairHandle signer, SignatureSpec spec, byte[] message) {
    return signer.privateKey().sign(spec, message);
  }

  /** Accepts only VALID; INVALID and UNKNOWN are both rejections. */
  public static boolean accept(KeyPairHandle signer, SignatureSpec spec, byte[] message, byte[] sig) {
    VerifyResult result = signer.publicKey().verify(spec, message, sig);
    return result == VerifyResult.VALID;
  }

  /** Verifies with the JDK, using the public key fetched from the KMS and the spec's JCA names. */
  public static boolean verifyLocally(
      KeyPairHandle signer, SignatureSpec spec, Expect expect, byte[] message, byte[] sig)
      throws GeneralSecurityException {
    PublicKey key = signer.publicKey().asPublicKey(expect);
    Signature verifier = Signature.getInstance(spec.jcaAlgorithm().orElseThrow());
    if (spec.jcaParameters().isPresent()) verifier.setParameter(spec.jcaParameters().get());
    verifier.initVerify(key);
    verifier.update(message);
    return verifier.verify(sig);
  }
}
