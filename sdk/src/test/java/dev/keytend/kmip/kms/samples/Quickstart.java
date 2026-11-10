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
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * The README quickstart: find or create a named key once, then seal and open a record through the
 * key in force. Every line of the README's quickstart block is a line of this class, and {@code
 * SamplesTest} runs {@link #sealAndOpen} on every KMIP version from 1.4.
 */
public final class Quickstart {
  private Quickstart() {}

  /**
   * Connects to two replicas of one KMS with the client identity in {@code client.p12} (its
   * password in the environment variable {@code KMS_CLIENT_PASSWORD}) and the CA certificates in
   * {@code ca.pem}, then seals and opens one record.
   *
   * @param args not used
   */
  public static void main(String[] args) {
    char[] password = System.getenv("KMS_CLIENT_PASSWORD").toCharArray();
    KmsConfig config = KmsConfig.builder()
        .endpoints("kms1.example.com:5696", "kms2.example.com:5696")
        .clientIdentityKeyStore(Path.of("client.p12"), password)
        .trustPem(Path.of("ca.pem"))
        .build();
    byte[] orderJson = "{\"id\":1042,\"total\":\"19.99\"}".getBytes(StandardCharsets.UTF_8);

    try (Kms kms = Kms.connect(config)) {
      byte[] opened = sealAndOpen(kms, orderJson);
      System.out.println(new String(opened, StandardCharsets.UTF_8));
    }
  }

  /**
   * The body of the README's {@code try} block: finds or creates the key {@code "orders-kek"},
   * seals {@code orderJson} bound to its order ID, and opens it again.
   *
   * <p>A key name is not an access-control boundary: on a server where others may create keys,
   * anyone can create one with this name. Where that matters, keep and use the key's handle, use a
   * server that enforces unique names, or select keys by an attribute only you can set.
   *
   * @param kms a connected {@code Kms}
   * @param orderJson the record to protect
   * @return the opened record, equal to {@code orderJson}
   */
  public static byte[] sealAndOpen(Kms kms, byte[] orderJson) {
    kms.keys().createAes(256).named("orders-kek")
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .findOrCreate();
    CurrentKey kek = kms.keys().current("orders-kek");
    byte[] orderId = "order-1042".getBytes(StandardCharsets.UTF_8);
    byte[] sealed = kek.seal(orderJson, orderId);
    byte[] opened = kek.open(sealed, orderId);
    return opened;
  }
}
