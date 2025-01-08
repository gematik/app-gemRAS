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

package de.gematik.idp.graserver.controller;

import static de.gematik.idp.IdpConstants.ENTITY_STATEMENT_ENDPOINT;
import static de.gematik.idp.IdpConstants.ENTITY_STATEMENT_TYP;
import static de.gematik.idp.IdpConstants.FED_AUTH_ENDPOINT;
import static de.gematik.idp.IdpConstants.IDP_LIST_ENDPOINT;
import static de.gematik.idp.field.ClientUtilities.generateCodeChallenge;
import static de.gematik.idp.field.ClientUtilities.generateCodeVerifier;
import static de.gematik.idp.graserver.Constants.ENTITY_STATEMENT_EXPIRED_ENDPOINT;
import static de.gematik.idp.graserver.Constants.ENTITY_STATEMENT_INVALID_SIG_ENDPOINT;
import static de.gematik.idp.graserver.Constants.FD_AUTH_SERVER_NONCE_LENGTH;
import static de.gematik.idp.graserver.Constants.FD_AUTH_SERVER_STATE_LENGTH;
import static de.gematik.idp.graserver.Constants.FED_SIGNED_JWKS_ENDPOINT;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.data.ParResponse;
import de.gematik.idp.data.TokenResponse;
import de.gematik.idp.graserver.ServerUrlService;
import de.gematik.idp.graserver.configuration.FdAuthServerConfiguration;
import de.gematik.idp.graserver.data.AuthSession;
import de.gematik.idp.graserver.data.AuthorizationCodeBuilder;
import de.gematik.idp.graserver.exceptions.FdAuthServerException;
import de.gematik.idp.graserver.services.ClientAssertionBuilder;
import de.gematik.idp.graserver.services.EntityListService;
import de.gematik.idp.graserver.services.EntityStatementBuilder;
import de.gematik.idp.graserver.services.EntityStmntIdpsService;
import de.gematik.idp.graserver.services.JwksBuilder;
import de.gematik.idp.graserver.services.LocationBuilder;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.TokenClaimExtraction;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import kong.unirest.core.Unirest;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwk.JsonWebKeySet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Validated
@RequiredArgsConstructor
@Slf4j
public class AuthorizationController {

  @Autowired FederationPrivKey encPrivKey;
  @Autowired FederationPrivKey tlsClientPrivKey;

  private static final int NONCE_LENGTH_MAX = 512;

  private static final int MAX_AUTH_SESSION_AMOUNT = 10000;

  private final ServerUrlService serverUrlService;
  private final EntityStmntIdpsService entityStmntIdpsService;
  private final EntityListService entityListService;
  private final ClientAssertionBuilder clientAssertionBuilder;
  private final IdpJwtProcessor jwtProcessorEsSigPrivKey;
  private final ObjectMapper objectMapper;
  private final EntityStatementBuilder entityStatementBuilder;
  private final JwksBuilder jwksBuilder;
  private final AuthorizationCodeBuilder authorizationCodeBuilder;

  private final FdAuthServerConfiguration fdAuthServerConfiguration;

  private final Map<String, AuthSession> authSessions =
      Collections.synchronizedMap(
          new LinkedHashMap<>() {

            @Override
            protected boolean removeEldestEntry(final Entry<String, AuthSession> eldest) {
              return size() > MAX_AUTH_SESSION_AMOUNT;
            }
          });

  private static void setNoCacheHeader(final HttpServletResponse response) {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Pragma", "no-cache");
  }

  /*
   * Request  (in) == message nr.2a (from Idp-Sektoral)
   * Response(out) == message nr.2b
   */
  @GetMapping(
      value = ENTITY_STATEMENT_ENDPOINT,
      produces = "application/entity-statement+jwt;charset=UTF-8")
  public String getEntityStatement() {
    return JwtHelper.signJson(
        jwtProcessorEsSigPrivKey,
        objectMapper,
        entityStatementBuilder.buildEntityStatement(
            serverUrlService.determineServerUrl(), fdAuthServerConfiguration.getFedmasterUrl()),
        ENTITY_STATEMENT_TYP);
  }

  /*
   * Request  (in) == message nr.0a (from Client Frontend)
   * Response(out) == message nr.0b
   */
  @GetMapping(value = IDP_LIST_ENDPOINT, produces = "application/jwt;charset=UTF-8")
  public String getEntityListing() {
    return entityListService.getEntityList();
  }

  @GetMapping(value = FED_SIGNED_JWKS_ENDPOINT, produces = "application/jwk-set+json;charset=UTF-8")
  public String getSignedJwks() {
    return JwtHelper.signJson(
        jwtProcessorEsSigPrivKey,
        objectMapper,
        jwksBuilder.build(serverUrlService.determineServerUrl()),
        "jwk-set+json");
  }

  /**
   * @return an expired entity statement for testing wether an idp has implemented a correct
   *     validation. this ist not part of a PoC/RefImpl but can be used in IOP-tests
   */
  @GetMapping(
      value = ENTITY_STATEMENT_EXPIRED_ENDPOINT,
      produces = "application/entity-statement+jwt;charset=UTF-8")
  public String getExpiredEntityStatement() {
    return JwtHelper.signJson(
        jwtProcessorEsSigPrivKey,
        objectMapper,
        entityStatementBuilder.buildExpiredEntityStatement(
            serverUrlService.determineServerUrl(), fdAuthServerConfiguration.getFedmasterUrl()),
        ENTITY_STATEMENT_TYP);
  }

  /**
   * @return an entity statement with an invalid signature for testing wether an idp has implemented
   *     a correct validation. this ist not part of a PoC/RefImpl but can be used in IOP-tests
   */
  @GetMapping(
      value = ENTITY_STATEMENT_INVALID_SIG_ENDPOINT,
      produces = "application/entity-statement+jwt;charset=UTF-8")
  public String getInvalidSigEntityStatement() {
    final String jwsString =
        JwtHelper.signJson(
            jwtProcessorEsSigPrivKey,
            objectMapper,
            entityStatementBuilder.buildEntityStatement(
                serverUrlService.determineServerUrl(), fdAuthServerConfiguration.getFedmasterUrl()),
            ENTITY_STATEMENT_TYP);
    return JwtHelper.invalidateJsonSignature(jwsString);
  }

  /************************************    App2App     *********************************/

  /* Federation App2App flow
   * Request(in)  == message nr.1
   *                 messages nr.1a ... nr.2b
   * Response(out)== message nr.4
   * Parameter "params" is used to filter by HTTP parameters and let spring decide which (multiple mappings of same endpoint) mapping matches.
   */
  @GetMapping(value = FED_AUTH_ENDPOINT, params = "redirect_uri")
  public void getRequestUri(
      @RequestParam(name = "client_id") @NotEmpty final String frontendClientId,
      @RequestParam(name = "state") @NotEmpty final String frontendState,
      @RequestParam(name = "redirect_uri") @NotEmpty final String frontendRedirectUri,
      @RequestParam(name = "code_challenge") @NotEmpty final String frontendCodeChallenge,
      @RequestParam(name = "code_challenge_method") @NotEmpty @Pattern(regexp = "S256")
          final String frontendCodeChallengeMethod,
      @RequestParam(name = "response_type") @NotEmpty @Pattern(regexp = "code")
          final String responseType,
      @RequestParam(name = "nonce", required = false)
          @Pattern(regexp = "^[_\\-a-zA-Z0-9]{1," + NONCE_LENGTH_MAX + "}$", message = "2007")
          final String frontendNonce,
      @RequestParam(name = "scope") @NotEmpty final String scope,
      @RequestParam(name = "idp_iss") @NotEmpty final String idpIss,
      final HttpServletResponse respMsgNr4) {
    log.debug("RX message nr.1, frontendClientId: {}, idpIss: {}", frontendClientId, idpIss);

    final String fdAuthServerUrl = serverUrlService.determineServerUrl();
    final String fdAuthServerState = Nonce.getNonceAsHex(FD_AUTH_SERVER_STATE_LENGTH);
    final String fdAuthServerNonce = Nonce.getNonceAsHex(FD_AUTH_SERVER_NONCE_LENGTH);
    final String fdAuthServerCodeVerifier = generateCodeVerifier(); // top secret
    final String fdAuthServerCodeChallenge = generateCodeChallenge(fdAuthServerCodeVerifier);

    authSessions.put(
        fdAuthServerState,
        AuthSession.builder()
            .frontendClientId(frontendClientId)
            .frontendCodeChallenge(frontendCodeChallenge)
            .frontendCodeChallengeMethod(frontendCodeChallengeMethod)
            .frontendResponseType(responseType)
            .frontendScope(scope)
            .frontendState(frontendState)
            .frontendRedirectUri(frontendRedirectUri)
            .fdAuthServerCodeVerifier(fdAuthServerCodeVerifier)
            .frontendNonce(frontendNonce)
            .idpIss(idpIss)
            .build());
    log.debug(
        "New FdAuthServer Auth Session stored. Idp-Sektoral(idpIss): {}, amount of sessions now:"
            + " {}",
        idpIss,
        authSessions.size());

    final JsonWebToken entityStmntIdp = entityStmntIdpsService.getEntityStatementIdp(idpIss);

    final String sekIdpAuthEndpoint = getSekIdpAuthEndpointFromEntityStmnt(entityStmntIdp);
    final String sekIdpParEndpoint = getSekIdpParEndpointFromEntityStmnt(entityStmntIdp);
    log.debug("TX PAR to sekIdpParEndpoint: " + sekIdpParEndpoint);
    /*
     * Request(out) == message nr.2 (PAR)
     * Response(in) == message nr.3
     */
    final ParResponse respMsgNr3Body =
        sendPar(
            sekIdpParEndpoint,
            fdAuthServerUrl,
            fdAuthServerState,
            fdAuthServerCodeChallenge,
            fdAuthServerNonce);

    log.debug("RX message nr.3 at: {}", fdAuthServerUrl);
    /* ParResponse example: {"request_uri":"urn:http://127.0.0.1:8084:4434f963244b9f0f","expires_in":90} */
    final String requestUri =
        Objects.requireNonNull(respMsgNr3Body.getRequestUri(), "request_uri not found");

    respMsgNr4.setStatus(HttpStatus.FOUND.value());
    // message nr.4
    setNoCacheHeader(respMsgNr4);

    final String tokenLocation =
        LocationBuilder.createLocationForAuthorizationRequest(
            sekIdpAuthEndpoint, fdAuthServerUrl, requestUri);
    log.debug("tokenLocation: {}", tokenLocation);
    respMsgNr4.setHeader(HttpHeaders.LOCATION, tokenLocation);
  }

  private ParResponse sendPar(
      final String sekIdpParEndpoint,
      final String fdAuthServerUrl,
      final String fdAuthServerState,
      final String fdAuthServerCodeChallenge,
      final String fdAuthServerNonce) {
    try {
      return objectMapper.readValue(
          Unirest.post(sekIdpParEndpoint)
              .field("client_id", fdAuthServerUrl)
              .field("state", fdAuthServerState)
              .field("redirect_uri", fdAuthServerUrl + FED_AUTH_ENDPOINT)
              .field("code_challenge", fdAuthServerCodeChallenge)
              .field("code_challenge_method", "S256")
              .field("response_type", "code")
              .field("nonce", fdAuthServerNonce)
              .field("scope", "urn:telematik:display_name urn:telematik:versicherter openid")
              .field("acr_values", "gematik-ehealth-loa-high")
              .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
              .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
              .asString()
              .getBody(),
          ParResponse.class);
    } catch (final JsonProcessingException e) {
      throw new FdAuthServerException(
          "Error while parsing PAR response from " + sekIdpParEndpoint, e);
    }
  }

  /* Federation App2App flow
   * Request(in)  == message nr.9
   *                Request(out) messages nr.10
   *                Response(in) messages nr.11
   * Response(out)== message nr.12
   * Parameter "params" is used to filter by HTTP parameters and let spring decide which (multiple mappings of same endpoint) mapping matches.
   */
  @SneakyThrows
  @PostMapping(
      value = FED_AUTH_ENDPOINT,
      params = "code",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  public void postAuthorizationCode(
      @RequestParam(name = "code") @NotEmpty final String authorizationCodeFedIdp,
      @RequestParam(name = "state") @NotEmpty final String fdAuthServerState,
      final HttpServletResponse respMsgNr12) {

    final String thisServerUrl = serverUrlService.determineServerUrl();
    log.debug(
        "App2App-Flow: RX message nr 9 (Authorization Code) at {}\n code: {} state: {}",
        thisServerUrl,
        authorizationCodeFedIdp,
        fdAuthServerState);
    final AuthSession session =
        Optional.ofNullable(authSessions.get(fdAuthServerState))
            .orElseThrow(
                () ->
                    new FdAuthServerException(
                        "Content of parameter state is unknown.", HttpStatus.BAD_REQUEST));
    final String sekIdpTokenEndpoint =
        getSekIdpTokenEndpointFromEntityStmnt(
            entityStmntIdpsService.getEntityStatementIdp(session.getIdpIss()));

    log.debug("App2App-Flow: TX message nr 10 to {}", sekIdpTokenEndpoint);
    /*
     * Request(out) message nr.10
     * Response(in) message nr.11
     */
    final TokenResponse respMsgNr11Body =
        objectMapper.readValue(
            Unirest.post(sekIdpTokenEndpoint)
                .field("grant_type", "authorization_code")
                .field("code", authorizationCodeFedIdp)
                .field("code_verifier", session.getFdAuthServerCodeVerifier())
                .field("client_id", thisServerUrl)
                .field("redirect_uri", thisServerUrl + FED_AUTH_ENDPOINT)
                .field(
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .field(
                    "client_assertion", createClientAssertion(thisServerUrl, sekIdpTokenEndpoint))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .asString()
                .getBody(),
            TokenResponse.class);

    log.debug(
        "App2App-Flow: RX message nr 11 (ID_TOKEN + ACCESS_TOKEN), body: \n{}", respMsgNr11Body);
    final JsonWebToken idTokenEncrypted = new JsonWebToken(respMsgNr11Body.getIdToken());
    final IdpJwe idpJwe = new IdpJwe(idTokenEncrypted.getRawString());
    final JsonWebToken idTokenDecrypted =
        idpJwe.decryptJwt(encPrivKey.getIdentity().getPrivateKey());

    verifyIdToken(idTokenDecrypted);

    final IdpJwe authorizationCodeJwe =
        authorizationCodeBuilder.buildAuthorizationcodeFromSektoralIdToken(
            idTokenDecrypted, ZonedDateTime.now(), session);
    // return MsgNr12, Authorization code  (for Token-Endpoint)
    setNoCacheHeader(respMsgNr12);
    respMsgNr12.setStatus(HttpStatus.FOUND.value());
    final String tokenLocation =
        LocationBuilder.createLocationForAuthorizationCode(
            session.getFrontendRedirectUri(),
            authorizationCodeJwe.getRawString(),
            session.getFrontendState());

    respMsgNr12.setHeader(HttpHeaders.LOCATION, tokenLocation);
  }

  private void verifyIdToken(final JsonWebToken idToken) {
    final String tokenSigKeyId = (String) idToken.getHeaderClaims().get("kid");
    final String iss =
        (String) TokenClaimExtraction.extractClaimsFromJwtBody(idToken.getRawString()).get("iss");
    final JsonWebKeySet jwks = entityStmntIdpsService.getSignedJwksIdp(iss);
    idToken.verify(TokenClaimExtraction.getECPublicKey(jwks, tokenSigKeyId));
  }

  private String createClientAssertion(final String serverUrl, final String sekIdpAuthEndpoint) {
    return JwtHelper.signJson(
        jwtProcessorEsSigPrivKey,
        objectMapper,
        clientAssertionBuilder.buildClientAssertion(serverUrl, sekIdpAuthEndpoint),
        "JWT");
  }

  private String getSekIdpAuthEndpointFromEntityStmnt(final JsonWebToken entityStmnt) {
    return entityStmntIdpsService.getAuthorizationEndpoint(entityStmnt);
  }

  private String getSekIdpParEndpointFromEntityStmnt(final JsonWebToken entityStmnt) {
    return entityStmntIdpsService.getPushedAuthorizationEndpoint(entityStmnt);
  }

  private String getSekIdpTokenEndpointFromEntityStmnt(final JsonWebToken entityStmnt) {
    return entityStmntIdpsService.getTokenEndpoint(entityStmnt);
  }
}
