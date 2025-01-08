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

package de.gematik.idp.graserver;

import static de.gematik.idp.graserver.common.TestConstants.ENTITY_STATEMENT_FED_MASTER;
import static de.gematik.idp.graserver.common.TestConstants.ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043_JWT;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.graserver.configuration.FdAuthServerConfiguration;
import org.junit.jupiter.api.Test;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.MediaType;
import org.mockserver.springtest.MockServerTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = ClassMode.BEFORE_EACH_TEST_METHOD)
@MockServerTest("server.url=http://localhost:${mockServerPort}")
class ServerUrlServiceTest {

  @Value("${server.url}")
  private String mockServerUrl;

  @Autowired ServerUrlService serverUrlService;
  @Autowired FdAuthServerConfiguration fdAuthServerConfiguration;
  private MockServerClient mockServerClient;

  @Test
  void testDetermineServerUrl() {
    assertThat(serverUrlService.determineServerUrl()).contains("idpfadi.dev.gematik.solutions");
  }

  @Test
  void testFedmasterServerUrl() {
    assertThat(serverUrlService.determineFedmasterUrl())
        .isEqualTo("https://app-test.federationmaster.de");
  }

  @Test
  void testDetermineFetchEntityStatementEndpoint() {
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STATEMENT_FED_MASTER));
    fdAuthServerConfiguration.setFedmasterUrl(mockServerUrl);
    assertThat(serverUrlService.determineFetchEntityStatementEndpoint())
        .isEqualTo("https://app-ref.federationmaster.de/federation/fetch");
  }

  @Test
    void testDetermineSignedJwksUri() {
      assert(serverUrlService.determineSignedJwksUri(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043_JWT).orElseThrow()).equals("http://localhost:8085/jws.json");
  }
}
