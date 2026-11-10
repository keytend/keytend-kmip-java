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

package dev.keytend.kmip.cassandra.tls;

import io.netty.handler.ssl.util.SimpleKeyManagerFactory;
import io.netty.handler.ssl.util.SimpleTrustManagerFactory;
import java.security.KeyStore;
import java.util.Map;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.apache.cassandra.security.AbstractSslContextFactory;

/**
 * TLS for client and internode connections with the node's certificate, private key, trust
 * anchors and allowed peers held in a KMIP server ({@link KmipTlsMaterial}). Configure it as the
 * {@code ssl_context_factory} of {@code client_encryption_options} and {@code
 * server_encryption_options}:
 *
 * <pre>
 * ssl_context_factory:
 *   class_name: dev.keytend.kmip.cassandra.tls.KmipSslContextFactory
 *   parameters:
 *     kmip_endpoints: kms1:5696,kms2:5696
 *     kmip_client_certificate: /etc/cassandra/kms/client.pem
 *     kmip_client_key: /etc/cassandra/kms/client.key
 *     kmip_trust_certificates: /etc/cassandra/kms/ca.pem
 *     kmip_tls_identity: cluster1/node1
 *     kmip_tls_domain: cluster1
 * </pre>
 *
 * The key and trust managers are the SDK's, which present and check the current material at each
 * handshake; a change in the KMS also makes {@link #shouldReload()} true, so Cassandra's hot
 * reloading rebuilds its cached contexts (and logs it) at its next check.
 */
public class KmipSslContextFactory extends AbstractSslContextFactory {
  private final KmipTlsMaterial material;
  private volatile long builtFrom;

  public KmipSslContextFactory(Map<String, Object> parameters) {
    super(parameters);
    material = KmipTlsMaterial.get(parameters);
    builtFrom = material.version();
  }

  public KmipTlsMaterial material() {
    return material;
  }

  @Override
  public void initHotReloading() {
    // the material is followed by KmipTlsMaterial's own refresher
  }

  @Override
  public boolean shouldReload() {
    return material.version() != builtFrom;
  }

  @Override
  protected KeyManagerFactory buildKeyManagerFactory() throws SSLException {
    long version = material.version();
    if (material.certificate().isEmpty())
      throw new SSLException("The KMS has no Active TLS identity for this node: " + material);
    builtFrom = version;
    KeyManager keyManager = material.keyManager();
    return new SimpleKeyManagerFactory() {
      @Override
      protected void engineInit(KeyStore keyStore, char[] password) {}

      @Override
      protected void engineInit(ManagerFactoryParameters parameters) {}

      @Override
      protected KeyManager[] engineGetKeyManagers() {
        return new KeyManager[] {keyManager};
      }
    };
  }

  @Override
  protected KeyManagerFactory buildOutboundKeyManagerFactory() throws SSLException {
    return buildKeyManagerFactory();
  }

  @Override
  protected TrustManagerFactory buildTrustManagerFactory() {
    TrustManager trustManager = material.trustManager();
    return new SimpleTrustManagerFactory() {
      @Override
      protected void engineInit(KeyStore keyStore) {}

      @Override
      protected void engineInit(ManagerFactoryParameters parameters) {}

      @Override
      protected TrustManager[] engineGetTrustManagers() {
        return new TrustManager[] {trustManager};
      }
    };
  }
}
