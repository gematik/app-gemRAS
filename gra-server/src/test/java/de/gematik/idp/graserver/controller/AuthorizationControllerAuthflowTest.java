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

package de.gematik.idp.graserver.controller;

import static de.gematik.idp.IdpConstants.FED_AUTH_ENDPOINT;
import static de.gematik.idp.IdpConstants.TOKEN_ENDPOINT;
import static de.gematik.idp.field.ClientUtilities.generateCodeChallenge;
import static de.gematik.idp.graserver.common.TestConstants.ENTITY_STMNT_ABOUT_IDP_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.graserver.common.TestConstants.ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043;
import static de.gematik.idp.graserver.common.TestConstants.FEDIDP_PAR_AUTH_ENDPOINT;
import static de.gematik.idp.graserver.common.TestConstants.ID_TOKEN_DECRYPTED_EXPIRES_IN_YEAR_2045;
import static de.gematik.idp.graserver.common.TestConstants.ID_TOKEN_ENCRYPTED_EXPIRES_IN_YEAR_2045;
import static de.gematik.idp.graserver.common.TestConstants.SIGNED_JWKS_IDP;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doReturn;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import de.gematik.idp.data.ParResponse;
import de.gematik.idp.data.TokenResponse;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.graserver.data.AccessTokenResponse;
import de.gematik.idp.graserver.data.AuthCodeResponse;
import de.gematik.idp.graserver.services.EntityStmntIdpsService;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.TokenClaimExtraction;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import kong.unirest.core.Empty;
import kong.unirest.core.GetRequest;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestInstance;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.jose4j.jwk.JsonWebKeySet;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import tools.jackson.databind.json.JsonMapper;

@Slf4j
@ActiveProfiles("mock-EntityStmntIdpsService")
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthorizationControllerAuthflowTest {

  @Autowired EntityStmntIdpsService entityStmntIdpsService;
  private static final int MOCK_SERVER_PORT_IDP = 8085;

  @LocalServerPort private int localServerPort;

  private String testHostUrl;
  private UnirestInstance unirestInstance;
  private JsonMapper objectMapper;
  private WireMockServer wireMockServerIdp;

  private String sekIdpParEndpoint;

  @SneakyThrows
  @BeforeAll
  void setup() {
    wireMockServerIdp = new WireMockServer(MOCK_SERVER_PORT_IDP);
    wireMockServerIdp.start();
    mockEntityStmntIdpsService();
    testHostUrl = "http://localhost:" + localServerPort;
    unirestInstance = Unirest.spawnInstance();
    unirestInstance.config().reset();
    unirestInstance.config().followRedirects(false);
    objectMapper = JsonMapper.builder().findAndAddModules().build();
    unirestInstance
        .config()
        .setObjectMapper(
            new kong.unirest.core.ObjectMapper() {
              @Override
              public <T> T readValue(final String value, final Class<T> valueType) {
                try {
                  return objectMapper.readValue(value, valueType);
                } catch (final Exception e) {
                  throw new RuntimeException(e);
                }
              }

              @Override
              public String writeValue(final Object value) {
                try {
                  return objectMapper.writeValueAsString(value);
                } catch (final Exception e) {
                  throw new RuntimeException(e);
                }
              }
            });
    sekIdpParEndpoint =
        entityStmntIdpsService.getPushedAuthorizationEndpoint(
            new JsonWebToken(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043));
    final Integer sekIdpParEndpointPort = new URI(sekIdpParEndpoint).toURL().getPort();
    log.info("sekIdpParEndpointPort: {}", sekIdpParEndpointPort);
  }

  @BeforeEach
  void resetWireMock() {
    wireMockServerIdp.resetAll();
  }

  @AfterAll
  void teardown() {
    wireMockServerIdp.stop();
  }

  @Test
  void authorizationResponse_notBadRequest() {
    final HttpResponse<Empty> respMsg4 =
        unirestInstance
            .get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("client_id", "eRezeptApp")
            .queryString("state", "state")
            .queryString("redirect_uri", "https://idpfadi.dev.gematik.solutions/auth")
            .queryString("code_challenge", "4711")
            .queryString("code_challenge_method", "S256")
            .queryString("response_type", "code")
            .queryString("scope", "e-rezept")
            .queryString("idp_iss", "IDP_SEKTORAL")
            .asEmpty();
    assertThat(respMsg4.getStatus()).isNotEqualTo(HttpStatus.BAD_REQUEST.value());
  }

  @Test
  void authorizationResponse_withNonce_OK() {
    final String grasState = sendAuthorizationRequestMsg1_getMsgNr4("42_AND_08-15", "4715");
    Assertions.assertThat(grasState).isNotEmpty();
  }

  @Test
  void authorizationResponse_noNonce_OK() {
    final String grasState = sendAuthorizationRequestMsg1_getMsgNr4(null, "4716");
    // nonce is optional
    Assertions.assertThat(grasState).isNotEmpty();
  }

  @Test
  void authorizationRequest_missingParams() {
    final HttpResponse<String> respMsg4 =
        unirestInstance
            .get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("client_id", "eRezeptApp")
            .queryString("state", "state")
            .queryString("redirect_uri", "https://idpfadi.dev.gematik.solutions/auth")
            .queryString("code_challenge", "4712")
            .queryString("response_type", "code")
            .queryString("scope", "e-rezept")
            .queryString("idp_iss", "TODO")
            .asString();
    assertThat(respMsg4.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
    assertThat(respMsg4.getBody()).contains("Required request parameter 'code_challenge_method'");
  }

  @Test
  void authorizationRequest_invalidParam_code_challenge_method() {
    final HttpResponse<String> respMsg4 =
        unirestInstance
            .get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("client_id", "eRezeptApp")
            .queryString("state", "state")
            .queryString("redirect_uri", "https://idpfadi.dev.gematik.solutions/auth")
            .queryString("code_challenge", "4713")
            .queryString("code_challenge_method", "S257")
            .queryString("response_type", "code")
            .queryString("scope", "e-rezept")
            .queryString("idp_iss", "TODO")
            .asString();
    assertThat(respMsg4.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
    assertThat(respMsg4.getBody()).contains("S256");
  }

  /** Msg Nr 9 */
  @Test
  void authorizationCode_invalidParamState() {
    final HttpResponse<String> respMsg12 =
        unirestInstance
            .post(testHostUrl + FED_AUTH_ENDPOINT)
            .header(
                org.springframework.http.HttpHeaders.CONTENT_TYPE,
                MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .field("state", "unknownState")
            .field("code", "todoCode")
            .asString();
    assertThat(respMsg12.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
    assertThat(respMsg12.getBody()).contains("Content of parameter state is unknown");
  }

  /*
   * create session in gra-server
   * tx Msg Nr 1
   * mock Msg Nr 3
   * rx Msg Nr 4
   * use session
   * tx Msg Nr 9
   * mock Msg Nr 11
   * rx Msg Nr 12
   * tx Msg Nr 13
   * rx Msg Nr 14
   */
  @Test
  void msgNr1_to_msgNr14() {
    final String nullNonce = null;
    final String codeVerifier = "P62rd1KSUnScGIEs1WrpYj3g_poTqmx8mM4msxehNdk";
    final String codeChallenge = generateCodeChallenge(codeVerifier);
    // create session in gra-server
    final String grasState = sendAuthorizationRequestMsg1_getMsgNr4(nullNonce, codeChallenge);

    // send msgNr9 to Auth server, Auth server will send msgNr10, mock msgNr11
    mockMsg11();
    final HttpResponse<AuthCodeResponse> respMsg12 =
        unirestInstance
            .post(testHostUrl + FED_AUTH_ENDPOINT)
            .header(
                org.springframework.http.HttpHeaders.CONTENT_TYPE,
                MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .field("state", grasState)
            .field("code", "anyAUTHORIZATION_CODE_IDP")
            .asObject(AuthCodeResponse.class);

    assertThat(respMsg12.getStatus()).isEqualTo(HttpStatus.OK.value());
    final AuthCodeResponse authCodeResponse = respMsg12.getBody();

    final HttpResponse<AccessTokenResponse> respMsg14 =
        unirestInstance
            .post(testHostUrl + TOKEN_ENDPOINT)
            .header(
                org.springframework.http.HttpHeaders.CONTENT_TYPE,
                MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .field("grant_type", "authorization_code")
            .field("code", authCodeResponse.getCode())
            .field("code_verifier", codeVerifier)
            .field("client_id", "eRezeptApp")
            .field("redirect_uri", "https://idpfadi.dev.gematik.solutions/auth")
            .asObject(AccessTokenResponse.class);

    assertThat(respMsg14.getStatus()).isEqualTo(HttpStatus.OK.value());
    final JsonWebToken accessToken = new JsonWebToken(respMsg14.getBody().getAccessToken());
    assertThat(accessToken.getBodyClaim(ClaimName.TELEMATIK_ID)).isPresent();
    assertThat(accessToken.getBodyClaim(ClaimName.TELEMATIK_ID)).contains("X110411675");
  }

  String sendAuthorizationRequestMsg1_getMsgNr4(
      final String optionalNonce, final String codeChallenge) {
    mockMsg3();

    final kong.unirest.core.HttpRequest<GetRequest> requestMsg1 =
        unirestInstance
            .get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("client_id", "eRezeptApp")
            .queryString("state", "clientState42")
            .queryString("redirect_uri", "https://idpfadi.dev.gematik.solutions/auth")
            .queryString("code_challenge", codeChallenge)
            .queryString("code_challenge_method", "S256")
            .queryString("response_type", "code")
            .queryString("scope", "e-rezept")
            .queryString("idp_iss", "http://localhost:8085");
    if (optionalNonce != null) {
      requestMsg1.queryString("nonce", optionalNonce);
    }
    // send
    final HttpResponse<String> respMsg4 = requestMsg1.asString();

    final List<LoggedRequest> recordedRequestsAtParEndpoint =
        wireMockServerIdp.findAll(
            WireMock.postRequestedFor(WireMock.urlEqualTo(FEDIDP_PAR_AUTH_ENDPOINT)));
    assertThat(recordedRequestsAtParEndpoint.getFirst().getBodyAsString())
        .contains("redirect_uri=https%3A%2F%2Fidpfadi.dev.gematik.solutions%2Fauth");
    assertThat(respMsg4.getStatus()).isEqualTo(HttpStatus.FOUND.value());
    // extract state from request
    return getParameterFromHttpRequest(recordedRequestsAtParEndpoint.getFirst(), "state");
  }

  @Test
  void test_mockEntityStatement() {
    final String mockedEntStmntIdp =
        entityStmntIdpsService.getEntityStatementIdp("dummyIssuer").getRawString();
    assertThat(mockedEntStmntIdp).isEqualTo(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043);

    final String mockedentStmntAboutIdp =
        entityStmntIdpsService.getEntityStatementAboutIdp("dummySub").getRawString();
    assertThat(mockedentStmntAboutIdp).isEqualTo(ENTITY_STMNT_ABOUT_IDP_EXPIRES_IN_YEAR_2043);
  }

  @Test
  void test_msg1To4() {
    mockMsg3();

    final HttpResponse<String> msg4 =
        unirestInstance
            .get(testHostUrl + FED_AUTH_ENDPOINT)
            .queryString("client_id", "eRezeptApp")
            .queryString("state", "clientState42")
            .queryString("redirect_uri", "https://idpfadi.dev.gematik.solutions/auth")
            .queryString("code_challenge", "4717")
            .queryString("code_challenge_method", "S256")
            .queryString("response_type", "code")
            .queryString("scope", "e-rezept")
            .queryString("idp_iss", "http://localhost:8085")
            .asString();

    assertThat(msg4.getStatus()).isEqualTo(HttpStatus.FOUND.value());
  }

  @Test
  void test_mockMsg3() {
    mockMsg3();
    final HttpResponse<String> mockReturn = unirestInstance.post(sekIdpParEndpoint).asString();
    assertThat(mockReturn.getStatus()).isEqualTo(HttpStatus.OK.value());
  }

  @Test
  void test_getIssFromToken() {
    assertThat(
            TokenClaimExtraction.extractClaimsFromJwtBody(ID_TOKEN_DECRYPTED_EXPIRES_IN_YEAR_2045))
        .containsEntry("iss", "https://gsi.dev.gematik.solutions");
  }

  @SneakyThrows
  private void mockEntityStmntIdpsService() {
    doReturn(new JsonWebToken(ENTITY_STMNT_IDP_EXPIRES_IN_YEAR_2043))
        .when(entityStmntIdpsService)
        .getEntityStatementIdp(any());
    doReturn(new JsonWebToken(ENTITY_STMNT_ABOUT_IDP_EXPIRES_IN_YEAR_2043))
        .when(entityStmntIdpsService)
        .getEntityStatementAboutIdp(any());
    doReturn(new JsonWebKeySet(new JsonWebToken(SIGNED_JWKS_IDP).getPayloadDecoded()))
        .when(entityStmntIdpsService)
        .getSignedJwksIdp(any());
    doCallRealMethod() // "http://localhost:8085/PAR_Auth")
        .when(entityStmntIdpsService)
        .getPushedAuthorizationEndpoint(any());
    doCallRealMethod() // "http://localhost:8085/auth")
        .when(entityStmntIdpsService)
        .getAuthorizationEndpoint(any());
    doCallRealMethod() // "http://localhost:8085/token")
        .when(entityStmntIdpsService)
        .getTokenEndpoint(any());
  }

  @SneakyThrows
  private void mockMsg3() {
    wireMockServerIdp.stubFor(
        WireMock.post(WireMock.urlEqualTo(FEDIDP_PAR_AUTH_ENDPOINT))
            .willReturn(
                WireMock.aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        objectMapper.writeValueAsString(
                            ParResponse.builder()
                                .requestUri("urn:https://gsi.dev.gematik.solutions:a04ed2844e0ea4a")
                                .expiresIn(10)
                                .build()))));
  }

  @SneakyThrows
  private void mockMsg11() {
    wireMockServerIdp.stubFor(
        WireMock.post(WireMock.urlEqualTo("/token"))
            .willReturn(
                WireMock.aResponse()
                    .withStatus(HttpStatus.OK.value())
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        objectMapper.writeValueAsString(
                            TokenResponse.builder()
                                .idToken(ID_TOKEN_ENCRYPTED_EXPIRES_IN_YEAR_2045)
                                .accessToken("TODO ACCESS_TOKEN")
                                .tokenType("Bearer")
                                .expiresIn(300)
                                .build()))));
  }

  private String getParameterFromHttpRequest(
      final LoggedRequest loggedRequest, final String parameter) {
    final String requestBody = loggedRequest.getBodyAsString();
    final String[] params = requestBody.split("&");
    return Arrays.stream(params)
        .filter(p -> p.split("=")[0].equals(parameter))
        .findFirst()
        .orElseThrow()
        .split("=")[1];
  }
}
