/*
 * Copyright 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.graserver.configuration;

import de.gematik.idp.data.KeyConfig;
import de.gematik.idp.graserver.exceptions.FdAuthServerException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

@Configuration
@RequiredArgsConstructor
public class SslConfig {

  private final ResourceLoader resourceLoader;
  private final FdAuthServerConfiguration fdAuthServerConfiguration;

  @Bean
  public SSLContext sslContext() {
    return createSSLContext(fdAuthServerConfiguration.getTlsClientPrivKeyConfig(), "00");
  }

  private SSLContext createSSLContext(
      final KeyConfig keyConfiguration, final String keystorePassword) {
    final Resource resource = resourceLoader.getResource(keyConfiguration.getFileName());
    try (final InputStream is = resource.getInputStream()) {
      final KeyStore keyStore = KeyStore.getInstance("PKCS12");
      keyStore.load(is, keystorePassword.toCharArray());

      final KeyManagerFactory kmf =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(keyStore, keystorePassword.toCharArray());

      // SSLContext mit Clientzertifikat erstellen
      final SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(kmf.getKeyManagers(), null, null);
      return sslContext;

    } catch (final NoSuchAlgorithmException
        | KeyManagementException
        | KeyStoreException
        | UnrecoverableKeyException
        | CertificateException
        | IOException e) {
      throw new FdAuthServerException("Could not create SSL context", e);
    }
  }
}
