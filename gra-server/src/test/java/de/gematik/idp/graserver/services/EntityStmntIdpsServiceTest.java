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

package de.gematik.idp.graserver.services;

import static de.gematik.idp.graserver.common.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.graserver.ServerUrlService;
import de.gematik.idp.graserver.configuration.FdAuthServerConfiguration;
import de.gematik.idp.graserver.exceptions.FdAuthServerException;
import de.gematik.idp.token.JsonWebToken;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwk.JsonWebKeySet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;
import org.mockserver.client.MockServerClient;
import org.mockserver.model.MediaType;
import org.mockserver.springtest.MockServerTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

@ActiveProfiles("mock-serverUrlService")
@Slf4j
@MockServerTest("server.url=http://localhost:${mockServerPort}")
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EntityStmntIdpsServiceTest {

  @Value("${server.url}")
  private String mockServerUrl;

  private MockServerClient mockServerClient;
  @Autowired EntityStmntIdpsService entityStmntIdpsService;
  @Autowired FdAuthServerConfiguration fdAuthServerConfiguration;
  @Autowired ServerUrlService serverUrlService;

  private static final JsonWebToken ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043_JWT =
      new JsonWebToken(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043);
  private static final JsonWebToken ENTITY_STATEMENT_IDP_EXPIRED_JWT =
      new JsonWebToken(ENTITY_STATEMENT_FROM_IDP_EXPIRED);

  private static final JsonWebToken ENTITY_STATEMENT_ABOUT_IDP_EXPIRED_JWT =
      new JsonWebToken(ENTITY_STMNT_ABOUT_IDP_EXPIRED);

  @BeforeEach
  void setup() {
    entityStmntIdpsService.clearEntityStatements();
  }

  @Test
  void getEntityStatementIdp() {
    Mockito.doReturn(mockServerUrl + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043));
    mockServerClient
        .when(request().withMethod("GET").withPath("/federation/fetch"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_EXPIRES_IN_YEAR_2043));
    fdAuthServerConfiguration.setFedmasterUrl(mockServerUrl);
    final JsonWebToken entStmntIdp = entityStmntIdpsService.getEntityStatementIdp(mockServerUrl);
    assertThat(entStmntIdp).isNotNull();
  }

  @Test
  void testUpdateStatementIdpIfExpiredAndNewIsAvailable() {
    // bring in an expired entity statement
    entityStmntIdpsService.putEntityStatementIdp(mockServerUrl, ENTITY_STATEMENT_IDP_EXPIRED_JWT);

    // server has to fetch the entity statement because it is expired
    Mockito.doReturn(mockServerUrl + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043));
    mockServerClient
        .when(request().withMethod("GET").withPath("/federation/fetch"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_EXPIRES_IN_YEAR_2043));
    fdAuthServerConfiguration.setFedmasterUrl(mockServerUrl);

    assertThat(entityStmntIdpsService.getEntityStatementIdp(mockServerUrl).getRawString())
        .isEqualTo(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043);
  }

  @Test
  void testUpdateStatementAboutIdpIfExpiredAndNewIsAvailable() {
    // bring in an expired entity statement
    entityStmntIdpsService.putEntityStatementAboutIdp(
        mockServerUrl, ENTITY_STATEMENT_ABOUT_IDP_EXPIRED_JWT);

    Mockito.doReturn(mockServerUrl + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043));
    // server has to fetch the entity statement because it is expired
    mockServerClient
        .when(request().withMethod("GET").withPath("/federation/fetch"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_EXPIRES_IN_YEAR_2043));
    fdAuthServerConfiguration.setFedmasterUrl(mockServerUrl);

    assertThat(entityStmntIdpsService.getEntityStatementIdp(mockServerUrl).getRawString())
        .isEqualTo(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043);
  }

  @Test
  void fetchEntityStatementIdp_answerNot200() {
    assertThatThrownBy(() -> entityStmntIdpsService.getEntityStatementIdp(mockServerUrl))
        .isInstanceOf(FdAuthServerException.class)
        .hasMessageContaining("No entity statement from IDP");
  }

  @Test
  void fetchEntityStatementAboutIdp_answerNot200() {
    Mockito.doReturn(mockServerUrl + "/42").when(serverUrlService).determineFedmasterUrl();
    Mockito.doReturn(mockServerUrl + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();
    mockServerClient
        .when(request().withMethod("GET").withPath("/federation/fetch"))
        .respond(response().withStatusCode(500));

    assertThatThrownBy(() -> entityStmntIdpsService.getEntityStatementAboutIdp(mockServerUrl))
        .isInstanceOf(FdAuthServerException.class)
        .hasMessageContaining("No entity statement for IDP");
  }

  @Test
  void getAuthorizationEndpoint() {
    final String expectedAuthorizationEndpoint = "http://localhost:8085/auth";

    Mockito.doReturn(mockServerUrl + "/federation/fetch")
        .when(serverUrlService)
        .determineFetchEntityStatementEndpoint();

    mockServerClient
        .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043));
    mockServerClient
        .when(request().withMethod("GET").withPath("/federation/fetch"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(ENTITY_STMNT_ABOUT_IDP_EXPIRES_IN_YEAR_2043));
    assertThat(
            entityStmntIdpsService.getAuthorizationEndpoint(
                entityStmntIdpsService.getEntityStatementIdp(mockServerUrl)))
        .isEqualTo(expectedAuthorizationEndpoint);
  }

  @Test
  void getTokenEndpoint() {
    final String expectedTokenEndpoint = "http://localhost:8085/token";
    assertThat(entityStmntIdpsService.getTokenEndpoint(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043_JWT))
        .isEqualTo(expectedTokenEndpoint);
  }

  @Test
    void testGetSignedJwksIdp(){

      Mockito.doReturn(mockServerUrl + "/federation/fetch")
              .when(serverUrlService)
              .determineFetchEntityStatementEndpoint();

      Mockito.doReturn(Optional.of(mockServerUrl + "/jws.json"))
              .when(serverUrlService)
              .determineSignedJwksUri(any());
      mockServerClient
              .when(request().withMethod("GET").withPath(IdpConstants.ENTITY_STATEMENT_ENDPOINT))
              .respond(
                      response()
                              .withStatusCode(200)
                              .withContentType(MediaType.APPLICATION_JSON)
                              .withBody(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043));
      mockServerClient
              .when(request().withMethod("GET").withPath("/federation/fetch"))
              .respond(
                      response()
                              .withStatusCode(200)
                              .withContentType(MediaType.APPLICATION_JSON)
                              .withBody(ENTITY_STMNT_ABOUT_IDP_EXPIRES_IN_YEAR_2043));
      mockServerClient
              .when(request().withMethod("GET").withPath("/jws.json"))
              .respond(
                      response()
                              .withStatusCode(200)
                              .withContentType(MediaType.APPLICATION_JSON)
                              .withBody(SIGNED_JWKS_IDP));
      final JsonWebKeySet jwks = entityStmntIdpsService.getSignedJwksIdp(mockServerUrl);
      assertThat(jwks).isNotNull();
      assertThat(jwks.findJsonWebKey("puk_fed_idp_token","EC", "sig", "ES256")).isNotNull();
      assertThat(jwks.findJsonWebKey("puk_idp_sig","EC", "sig", "ES256")).isNotNull();

  }
}
