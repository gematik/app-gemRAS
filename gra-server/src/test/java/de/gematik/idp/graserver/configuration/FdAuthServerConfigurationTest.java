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
    assertThat(fdAuthServerConfiguration.getSigKeyConfig()).isNotNull();
    assertThat(fdAuthServerConfiguration.getEncKeyConfig()).isNotNull();
    assertThat(fdAuthServerConfiguration.getTlsClientKeyConfig()).isNotNull();
    assertThat(fdAuthServerConfiguration.getFedmasterUrl()).isNotNull();
  }

  @Test
  void testBuildComponent() {
    final FdAuthServerConfiguration rasConfig =
        FdAuthServerConfiguration.builder()
            .serverUrl("serverurl")
            .sigKeyConfig(new KeyConfig("a", "b", "c", false))
            .encKeyConfig(new KeyConfig("d", "e", "f", false))
            .tlsClientKeyConfig(new KeyConfig("g", "h", "i", false))
            .fedmasterUrl("feddi")
            .clientId("dummyClient")
            .build();
    rasConfig.setServerUrl("newUrl");
    assertThat(rasConfig).isNotNull();
    assertThat(rasConfig.getServerUrl()).isEqualTo("newUrl");
    assertThat(rasConfig.getSigKeyConfig()).isNotNull();
    assertThat(rasConfig.getEncKeyConfig()).isNotNull();
    assertThat(rasConfig.toString()).hasSizeGreaterThan(0);
    assertThat(rasConfig).isNotEqualTo(fdAuthServerConfiguration);

    assertThat(FdAuthServerConfiguration.builder().toString()).hasSizeGreaterThan(0);
    final FdAuthServerConfiguration rasConfig2 = rasConfig;
    assertThat(rasConfig).isEqualTo(rasConfig2);

    assertThatThrownBy(() -> new KeyConfiguration(resourceLoader, rasConfig).sigKey())
        .isInstanceOf(FdAuthServerException.class);
  }
}
