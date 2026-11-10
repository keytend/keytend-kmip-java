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
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * The server issued a renewed client certificate and this process uses it, but the SDK could not
 * write it to the identity files ({@link Kms#renewClientCertificate()}). The server has retired the
 * certificate the files still hold, so until the files are written the new certificate may exist
 * only in this process and in this exception: {@link #pem()} gives it, and the message ends with
 * it. The certificate is public; the new private key is in the pending file the message names.
 *
 * <p>Every {@link Kms} of the configuration, and every configuration of the same files built later
 * in this process, uses the new certificate. Fix the cause (a full disk, say) and call {@link
 * Kms#renewClientCertificate()} again before the process stops: it writes the files. With
 * automatic renewal the SDK tries again after its failure backoff.
 *
 * @since 0.10.0
 */
public final class RenewalNotSavedException extends IOException {
  private static final long serialVersionUID = 1L;

  /** The new certificate chain in PEM, leaf first. */
  private final String pem;

  RenewalNotSavedException(String message, Throwable cause, String pem) {
    super(message, cause);
    this.pem = pem;
  }

  /**
   * The new certificate chain, leaf first, as the SDK would have written it to the chain file.
   *
   * @return the chain in PEM, one {@code CERTIFICATE} block each
   * @since 0.10.0
   */
  public String pem() {
    return pem;
  }

  /**
   * The new certificate chain, leaf first.
   *
   * @return the certificates of {@link #pem()}
   * @since 0.10.0
   */
  public List<X509Certificate> chain() {
    try {
      List<X509Certificate> out = new ArrayList<>();
      for (var c :
          CertificateFactory.getInstance("X.509")
              .generateCertificates(
                  new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII))))
        out.add((X509Certificate) c);
      return List.copyOf(out);
    } catch (CertificateException e) {
      throw new IllegalStateException("The SDK wrote a chain it cannot read", e);
    }
  }

  /** {@code chain} in PEM. */
  static String pem(List<X509Certificate> chain) {
    StringBuilder out = new StringBuilder();
    for (X509Certificate c : chain) {
      try {
        out.append(
            new String(RenewalFiles.pem("CERTIFICATE", c.getEncoded()), StandardCharsets.US_ASCII));
      } catch (CertificateEncodingException e) {
        throw new IllegalStateException("A certificate without an encoding", e);
      }
    }
    return out.toString();
  }
}
