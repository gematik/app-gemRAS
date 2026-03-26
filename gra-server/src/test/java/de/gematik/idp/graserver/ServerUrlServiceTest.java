/*
 * Copyright (Change Date see Readme), gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.graserver;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static de.gematik.idp.graserver.common.TestConstants.ENTITY_STATEMENT_FED_MASTER;
import static de.gematik.idp.graserver.common.TestConstants.ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043_JWT;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import com.github.tomakehurst.wiremock.WireMockServer;
import de.gematik.idp.IdpConstants;
import de.gematik.idp.graserver.configuration.FdAuthServerConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;

@Slf4j
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestPropertySource(
    properties = {
      "fd-auth-server.server-url=myFD_AUTH_SERVER_URL",
      "fd-auth-server.fedmaster-url=myFEDMASTER_SERVER_URL"
    })
@DirtiesContext(classMode = ClassMode.BEFORE_EACH_TEST_METHOD)
class ServerUrlServiceTest {

  @Autowired ServerUrlService serverUrlService;
  @Autowired FdAuthServerConfiguration fdAuthServerConfiguration;

  private WireMockServer wireMockServerIdp;
  private final int MOCK_SERVER_PORT_IDP = 8085;

  @BeforeAll
  void setup() {
    wireMockServerIdp = new WireMockServer(MOCK_SERVER_PORT_IDP);
    wireMockServerIdp.start();
  }

  @AfterAll
  void teardown() {
    wireMockServerIdp.stop();
  }

  @Test
  void testDetermineServerUrl() {
    assertThat(serverUrlService.determineServerUrl()).contains("myFD_AUTH_SERVER_URL");
  }

  @Test
  void testFedmasterServerUrl() {
    assertThat(serverUrlService.determineFedmasterUrl()).isEqualTo("myFEDMASTER_SERVER_URL");
  }

  @Test
  void testDetermineFetchEntityStatementEndpoint() {
    wireMockServerIdp.stubFor(
        get(urlEqualTo(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
            .willReturn(
                aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(ENTITY_STATEMENT_FED_MASTER)));
    fdAuthServerConfiguration.setFedmasterUrl("http://localhost:" + MOCK_SERVER_PORT_IDP);
    assertThat(serverUrlService.determineFetchEntityStatementEndpoint())
        .isEqualTo("https://app-ref.federationmaster.de/federation/fetch");
  }

  @Test
  void testDetermineSignedJwksUri() {
    assertThat(
            serverUrlService
                .determineSignedJwksUri(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043_JWT)
                .orElseThrow())
        .isEqualTo("http://localhost:8085/jws.json");
  }
}
