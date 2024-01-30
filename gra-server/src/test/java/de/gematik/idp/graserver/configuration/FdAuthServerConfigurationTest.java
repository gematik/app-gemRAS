/*
 *  Copyright 2023 gematik GmbH
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

import de.gematik.idp.data.KeyConfig;
import de.gematik.idp.graserver.KeyConfiguration;
import de.gematik.idp.graserver.exceptions.FdAuthServerException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.core.io.ResourceLoader;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class FdAuthServerConfigurationTest {

  @Autowired FdAuthServerConfiguration fdAuthServerConfiguration;
  @Autowired ResourceLoader resourceLoader;

  @Test
  void fullIntTestComponent() {
    assertThat(fdAuthServerConfiguration).isNotNull();
    assertThat(fdAuthServerConfiguration.getServerUrl()).isNotNull();
    assertThat(fdAuthServerConfiguration.getEsSigPrivKeyConfig()).isNotNull();
    assertThat(fdAuthServerConfiguration.getEsSigPubKeyConfig()).isNotNull();
    assertThat(fdAuthServerConfiguration.getEncPrivKeyConfig()).isNotNull();
    assertThat(fdAuthServerConfiguration.getEncPubKeyConfig()).isNotNull();
    assertThat(fdAuthServerConfiguration.getTlsClientPrivKeyConfig()).isNotNull();
    assertThat(fdAuthServerConfiguration.getFedmasterUrl()).isNotNull();
  }

  @Test
  void testBuildComponent() {
    final FdAuthServerConfiguration rasConfig =
        FdAuthServerConfiguration.builder()
            .serverUrl("serverurl")
            .esSigPrivKeyConfig(new KeyConfig("a", "b", "c", false))
            .esSigPubKeyConfig(new KeyConfig("a", "b", "c", false))
            .encPrivKeyConfig(new KeyConfig("d", "e", "f", false))
            .encPubKeyConfig(new KeyConfig("d", "e", "f", false))
            .tlsClientPrivKeyConfig(new KeyConfig("g", "h", "i", false))
            .tokenSigPrivKeyConfig(new KeyConfig("j", "k", "l", false))
            .tokenSigPubKeyConfig(new KeyConfig("j", "k", "l", false))
            .symmetricEncryptionKey("dummyKey")
            .fedmasterUrl("feddi")
            .clientId("dummyClient")
            .build();
    rasConfig.setServerUrl("newUrl");
    assertThat(rasConfig).isNotNull();
    assertThat(rasConfig.getServerUrl()).isEqualTo("newUrl");
    assertThat(rasConfig.getEsSigPrivKeyConfig()).isNotNull();
    assertThat(rasConfig.getEsSigPubKeyConfig()).isNotNull();
    assertThat(rasConfig.getEncPrivKeyConfig()).isNotNull();
    assertThat(rasConfig.getEncPubKeyConfig()).isNotNull();
    assertThat(rasConfig.getTlsClientPrivKeyConfig()).isNotNull();
    assertThat(rasConfig.getTokenSigPrivKeyConfig()).isNotNull();
    assertThat(rasConfig.getTokenSigPubKeyConfig()).isNotNull();
    assertThat(rasConfig.getSymmetricEncryptionKey()).isNotNull();
    assertThat(rasConfig.getFedmasterUrl()).isNotNull();
    assertThat(rasConfig.toString()).hasSizeGreaterThan(0);
    assertThat(rasConfig).isNotEqualTo(fdAuthServerConfiguration);

    assertThat(FdAuthServerConfiguration.builder().toString()).hasSizeGreaterThan(0);
    final FdAuthServerConfiguration rasConfig2 = rasConfig;
    assertThat(rasConfig).isEqualTo(rasConfig2);

    assertThatThrownBy(() -> new KeyConfiguration(resourceLoader, rasConfig).esSigPrivKey())
        .isInstanceOf(FdAuthServerException.class);
  }
}
