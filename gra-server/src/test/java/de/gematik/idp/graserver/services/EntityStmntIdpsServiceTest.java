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

package de.gematik.idp.graserver.services;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static de.gematik.idp.graserver.common.TestConstants.ENTITY_STATEMENT_FROM_IDP_EXPIRED;
import static de.gematik.idp.graserver.common.TestConstants.ENTITY_STMNT_ABOUT_IDP_EXPIRED;
import static de.gematik.idp.graserver.common.TestConstants.ENTITY_STMNT_ABOUT_IDP_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.graserver.common.TestConstants.ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.graserver.common.TestConstants.SIGNED_JWKS_IDP;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;

import com.github.tomakehurst.wiremock.WireMockServer;
import de.gematik.idp.IdpConstants;
import de.gematik.idp.graserver.ServerUrlService;
import de.gematik.idp.graserver.exceptions.FdAuthServerException;
import de.gematik.idp.token.JsonWebToken;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwk.JsonWebKeySet;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("mock-serverUrlService")
@Slf4j
@SpringBootTest(webEnvironment = WebEnvironment.NONE)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EntityStmntIdpsServiceTest {

  private static final String MOCK_SERVER_URL_IDP = "http://localhost:8085";
  private static final int MOCK_SERVER_PORT_IDP = 8085;
  private static final JsonWebToken ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043_JWT =
      new JsonWebToken(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043);
  private static final JsonWebToken ENTITY_STATEMENT_IDP_EXPIRED_JWT =
      new JsonWebToken(ENTITY_STATEMENT_FROM_IDP_EXPIRED);
  private static final JsonWebToken ENTITY_STATEMENT_ABOUT_IDP_EXPIRED_JWT =
      new JsonWebToken(ENTITY_STMNT_ABOUT_IDP_EXPIRED);

  @Autowired EntityStmntIdpsService entityStmntIdpsService;
  @Autowired ServerUrlService serverUrlService;
  private WireMockServer wireMockServerIdp;

  @BeforeAll
  void setupMock() {
    wireMockServerIdp = new WireMockServer(MOCK_SERVER_PORT_IDP);
    wireMockServerIdp.start();
  }

  @BeforeEach
  void setup() {
    wireMockServerIdp.resetAll();
    entityStmntIdpsService.clearEntityStatements();
  }

  @AfterAll
  void tearDown() {
    wireMockServerIdp.stop();
  }

  @Test
  void getEntityStatementIdp() {
    Mockito.doReturn(MOCK_SERVER_URL_IDP + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    wireMockServerIdp.stubFor(
        get(urlPathEqualTo(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
            .willReturn(
                aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043)));
    wireMockServerIdp.stubFor(
        get(urlPathEqualTo("/federation/fetch"))
            .willReturn(
                aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(ENTITY_STMNT_ABOUT_IDP_EXPIRES_IN_YEAR_2043)));
    final JsonWebToken entStmntIdp =
        entityStmntIdpsService.getEntityStatementIdp(MOCK_SERVER_URL_IDP);
    assertThat(entStmntIdp).isNotNull();
  }

  @Test
  void testUpdateStatementIdpIfExpiredAndNewIsAvailable() {
    // bring in an expired entity statement
    entityStmntIdpsService.putEntityStatementIdp(
        MOCK_SERVER_URL_IDP, ENTITY_STATEMENT_IDP_EXPIRED_JWT);

    // server has to fetch the entity statement because it is expired
    Mockito.doReturn(MOCK_SERVER_URL_IDP + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    wireMockServerIdp.stubFor(
        get(urlPathEqualTo(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
            .willReturn(
                aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043)));

    wireMockServerIdp.stubFor(
        get(urlPathEqualTo("/federation/fetch"))
            .willReturn(
                aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(ENTITY_STMNT_ABOUT_IDP_EXPIRES_IN_YEAR_2043)));

    assertThat(entityStmntIdpsService.getEntityStatementIdp(MOCK_SERVER_URL_IDP).getRawString())
        .isEqualTo(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043);
  }

  @Test
  void testUpdateStatementAboutIdpIfExpiredAndNewIsAvailable() {
    // insert an expired entity statement
    entityStmntIdpsService.putEntityStatementAboutIdp(
        MOCK_SERVER_URL_IDP, ENTITY_STATEMENT_ABOUT_IDP_EXPIRED_JWT);

    Mockito.doReturn(MOCK_SERVER_URL_IDP + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    wireMockServerIdp.stubFor(
        get(urlPathEqualTo(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
            .willReturn(
                aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043)));

    wireMockServerIdp.stubFor(
        get(urlPathEqualTo("/federation/fetch"))
            .willReturn(
                aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(ENTITY_STMNT_ABOUT_IDP_EXPIRES_IN_YEAR_2043)));
    // server has to fetch the entity statement because it is expired

    assertThat(entityStmntIdpsService.getEntityStatementIdp(MOCK_SERVER_URL_IDP).getRawString())
        .isEqualTo(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043);
  }

  @Test
  void fetchEntityStatementIdp_answerNot200() {
    assertThatThrownBy(() -> entityStmntIdpsService.getEntityStatementIdp(MOCK_SERVER_URL_IDP))
        .isInstanceOf(FdAuthServerException.class)
        .hasMessageContaining("No entity statement from IDP");
  }

  @Test
  void fetchEntityStatementAboutIdp_answerNot200() {
    Mockito.doReturn(MOCK_SERVER_URL_IDP + "/42").when(serverUrlService).determineFedmasterUrl();
    Mockito.doReturn(MOCK_SERVER_URL_IDP + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    wireMockServerIdp.stubFor(
        get(urlPathEqualTo("/federation/fetch"))
            .willReturn(aResponse().withStatus(HttpStatus.INTERNAL_SERVER_ERROR.value())));

    assertThatThrownBy(() -> entityStmntIdpsService.getEntityStatementAboutIdp(MOCK_SERVER_URL_IDP))
        .isInstanceOf(FdAuthServerException.class)
        .hasMessageContaining("No entity statement for IDP");
  }

  @Test
  void getAuthorizationEndpoint() {
    final String expectedAuthorizationEndpoint = "http://localhost:8085/auth";

    Mockito.doReturn(MOCK_SERVER_URL_IDP + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();

    wireMockServerIdp.stubFor(
        get(urlPathEqualTo(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
            .willReturn(
                aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043)));
    wireMockServerIdp.stubFor(
        get(urlPathEqualTo("/federation/fetch"))
            .willReturn(
                aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(ENTITY_STMNT_ABOUT_IDP_EXPIRES_IN_YEAR_2043)));
    assertThat(
            entityStmntIdpsService.getAuthorizationEndpoint(
                entityStmntIdpsService.getEntityStatementIdp(MOCK_SERVER_URL_IDP)))
        .isEqualTo(expectedAuthorizationEndpoint);
  }

  @Test
  void getTokenEndpoint() {
    final String expectedTokenEndpoint = "http://localhost:8085/token";
    assertThat(entityStmntIdpsService.getTokenEndpoint(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043_JWT))
        .isEqualTo(expectedTokenEndpoint);
  }

  @Test
  void testGetSignedJwksIdp() {

    Mockito.doReturn(MOCK_SERVER_URL_IDP + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();

    Mockito.doReturn(Optional.of(MOCK_SERVER_URL_IDP + "/jws.json"))
        .when(serverUrlService)
        .determineSignedJwksUri(any());
    wireMockServerIdp.stubFor(
        get(urlPathEqualTo(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
            .willReturn(
                aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043)));
    wireMockServerIdp.stubFor(
        get(urlPathEqualTo("/federation/fetch"))
            .willReturn(
                aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(ENTITY_STMNT_ABOUT_IDP_EXPIRES_IN_YEAR_2043)));
    wireMockServerIdp.stubFor(
        get(urlPathEqualTo("/jws.json"))
            .willReturn(
                aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(SIGNED_JWKS_IDP)));
    final JsonWebKeySet jwks = entityStmntIdpsService.getSignedJwksIdp(MOCK_SERVER_URL_IDP);
    assertThat(jwks).isNotNull();
    assertThat(jwks.findJsonWebKey("puk_fed_idp_token", "EC", "sig", "ES256")).isNotNull();
    assertThat(jwks.findJsonWebKey("puk_idp_sig", "EC", "sig", "ES256")).isNotNull();
  }
}
