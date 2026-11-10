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

import dev.keytend.kmip.client.KmipClient;
import dev.keytend.kmip.client.RequestOptions;
import java.io.IOException;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;

/**
 * For the live renewal program ({@code dev.keytend.kmip.interop.ClientCertificateRenewal}): the
 * search a renewal runs after a lost reply, through a connection the caller opened. It lives in the
 * SDK's package, on the class path of the integration programs only, because the search is not
 * public API.
 */
public final class RenewalSearchCheck {
  private RenewalSearchCheck() {}

  /** What a search showed. */
  public enum Outcome {
    /** The server holds a certificate for the key. */
    FOUND,
    /** Every candidate was seen, and none is for the key. */
    EXHAUSTED,
    /** The search stopped before it saw every candidate. */
    TRUNCATED
  }

  /**
   * What the search showed, and the identifier of the certificate found.
   *
   * @param outcome what the search showed
   * @param certificateId the certificate found; null unless {@link Outcome#FOUND}
   * @param why the reason a search stopped; null unless {@link Outcome#TRUNCATED}
   */
  public record Result(Outcome outcome, String certificateId, String why) {}

  /**
   * The renewal's search for a certificate the server issued for {@code key}, sent around {@code
   * since} (this machine's clock), through {@code client}: the server's clock read first, then
   * Locate by Initial Date and Get, every page.
   *
   * @param client a client on a connection authenticated with the certificate being renewed
   * @param key the public key of the renewal
   * @param since when the renewal's request was sent
   * @return the outcome
   * @throws IOException when the connection fails
   * @throws dev.keytend.kmip.client.KmipException when the server refuses Locate or Get
   */
  public static Result search(KmipClient client, PublicKey key, Instant since) throws IOException {
    try {
      ClientRenewal.Found f =
          ClientRenewal.search(
              client,
              RequestOptions.DEFAULT,
              key,
              new ClientRenewal.Since(since, null),
              Duration.ofSeconds(30),
              Instant::now);
      return f == null
          ? new Result(Outcome.EXHAUSTED, null, null)
          : new Result(Outcome.FOUND, f.id(), null);
    } catch (ClientRenewal.Truncated t) {
      return new Result(Outcome.TRUNCATED, null, t.getMessage());
    }
  }
}
