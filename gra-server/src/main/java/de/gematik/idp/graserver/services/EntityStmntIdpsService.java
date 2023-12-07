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

import de.gematik.idp.IdpConstants;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.graserver.ServerUrlService;
import de.gematik.idp.graserver.exceptions.FdAuthServerException;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.TokenClaimExtraction;
import java.security.PublicKey;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jose4j.jwk.JsonWebKeySet;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EntityStmntIdpsService {

  private final ResourceReader resourceReader;
  private final ServerUrlService serverUrlService;

  /** Entity statements of Idp-Sektorals. Delivered by respective Idp-Sektoral. */
  private static final Map<String, JsonWebToken> ENTITY_STATEMENTS_IDP = new HashMap<>();

  /** Entity statements about all Idp-Sektorals. Delivered by Fedmaster. */
  private static final Map<String, JsonWebToken> ENTITY_STATEMENTS_FEDMASTER_ABOUT_IDP =
      new HashMap<>();

  public void clearEntityStatements() {
    ENTITY_STATEMENTS_IDP.clear();
    ENTITY_STATEMENTS_FEDMASTER_ABOUT_IDP.clear();
  }

  void putEntityStatementIdp(final String issuer, final JsonWebToken entityStatement) {
    ENTITY_STATEMENTS_IDP.put(issuer, entityStatement);
  }

  void putEntityStatementAboutIdp(final String issuer, final JsonWebToken entityStatement) {
    ENTITY_STATEMENTS_FEDMASTER_ABOUT_IDP.put(issuer, entityStatement);
  }

  public JsonWebToken getEntityStatementIdp(final String issuer) {
    log.info("Entitystatement for IDP [{}] requested.", issuer);
    updateStatementIdpIfExpiredAndNewIsAvailable(issuer);
    return ENTITY_STATEMENTS_IDP.get(issuer);
  }

  public String getAuthorizationEndpoint(final JsonWebToken entityStmnt) {
    final Map<String, Object> bodyClaims = entityStmnt.getBodyClaims();
    final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
    final Map<String, Object> openidProvider = getInnerClaimMap(metadata, "openid_provider");
    return Objects.requireNonNull(
        (String) openidProvider.get("authorization_endpoint"),
        "missing claim: authorization_endpoint");
  }

  public String getPushedAuthorizationEndpoint(final JsonWebToken entityStmnt) {
    final Map<String, Object> bodyClaims = entityStmnt.getBodyClaims();
    final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
    final Map<String, Object> openidProvider = getInnerClaimMap(metadata, "openid_provider");
    return Objects.requireNonNull(
        (String) openidProvider.get("pushed_authorization_request_endpoint"),
        "missing claim: pushed_authorization_request_endpoint");
  }

  public String getTokenEndpoint(final JsonWebToken entityStmnt) {
    final Map<String, Object> bodyClaims = entityStmnt.getBodyClaims();
    final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
    final Map<String, Object> openidProvider = getInnerClaimMap(metadata, "openid_provider");
    return Objects.requireNonNull(
        (String) openidProvider.get("token_endpoint"), "missing claim: token_endpoint");
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> getInnerClaimMap(
      final Map<String, Object> claimMap, final String key) {
    return Objects.requireNonNull((Map<String, Object>) claimMap.get(key), "missing claim: " + key);
  }

  private void updateStatementIdpIfExpiredAndNewIsAvailable(final String issuer) {
    if (ENTITY_STATEMENTS_IDP.containsKey(issuer)) {
      if (stmntIsEpired(ENTITY_STATEMENTS_IDP.get(issuer))) {
        fetchEntityStatementIdp(issuer);
      }
      return;
    }
    fetchEntityStatementIdp(issuer);
  }

  private boolean stmntIsEpired(final JsonWebToken entityStmnt) {
    final Map<String, Object> bodyClaims = entityStmnt.getBodyClaims();
    final Long exp = (Long) bodyClaims.get("exp");
    return isExpired(exp);
  }

  private boolean isExpired(final Long exp) {
    final ZonedDateTime currentUtcTime = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime expiredUtcTime =
        ZonedDateTime.ofInstant(Instant.ofEpochSecond(exp), ZoneOffset.UTC);
    return currentUtcTime.isAfter(expiredUtcTime);
  }

  private void fetchEntityStatementIdp(final String issuer) {
    log.debug("Fetch EntityStatement from: {}", issuer);
    final HttpResponse<String> resp =
        Unirest.get(issuer + IdpConstants.ENTITY_STATEMENT_ENDPOINT).asString();
    if (resp.getStatus() == HttpStatus.OK.value()) {
      final JsonWebToken entityStmnt = new JsonWebToken(resp.getBody());
      verifyEntityStmntIdp(entityStmnt);
      ENTITY_STATEMENTS_IDP.put(issuer, entityStmnt);
    } else {
      log.info(resp.getBody());
      throw new FdAuthServerException(
          "No entity statement from IDP ["
              + issuer
              + "] available. Reason: "
              + resp.getBody()
              + HttpStatus.valueOf(resp.getStatus()),
          HttpStatus.BAD_REQUEST);
    }
  }

  private void verifyEntityStmntIdp(final JsonWebToken entityStmnt) {
    final String iss =
        (String)
            TokenClaimExtraction.extractClaimsFromJwtBody(entityStmnt.getRawString()).get("iss");
    final String keyIdSigEntStmnt = (String) entityStmnt.getHeaderClaims().get("kid");
    final JsonWebToken esAboutRp = getEntityStatementAboutIdp(iss);
    final JsonWebKeySet jwks = TokenClaimExtraction.extractJwksFromBody(esAboutRp.getRawString());
    entityStmnt.verify(TokenClaimExtraction.getECPublicKey(jwks, keyIdSigEntStmnt));
  }

  public JsonWebToken getEntityStatementAboutIdp(final String sub) {
    updateStatementAboutIdpIfExpiredAndNewIsAvailable(sub);
    return ENTITY_STATEMENTS_FEDMASTER_ABOUT_IDP.get(sub);
  }

  private void updateStatementAboutIdpIfExpiredAndNewIsAvailable(final String sub) {
    if (ENTITY_STATEMENTS_FEDMASTER_ABOUT_IDP.containsKey(sub)) {
      if (stmntIsEpired(ENTITY_STATEMENTS_FEDMASTER_ABOUT_IDP.get(sub))) {
        fetchEntityStatementAboutIdp(sub);
      }
      return;
    }
    fetchEntityStatementAboutIdp(sub);
  }

  private void fetchEntityStatementAboutIdp(final String sub) {
    final String entityIdentifierFedmaster = serverUrlService.determineFedmasterUrl();
    log.info("FedmasterUrl: " + entityIdentifierFedmaster);
    final HttpResponse<String> resp =
        Unirest.get(serverUrlService.determineFetchEntityStatementEndpoint())
            .queryString("iss", entityIdentifierFedmaster)
            .queryString("sub", sub)
            .asString();
    if (resp.getStatus() == HttpStatus.OK.value()) {
      final JsonWebToken entityStatementAboutIdp = new JsonWebToken(resp.getBody());
      entityStatementAboutIdp.verify(getFedmasterSigKey());
      ENTITY_STATEMENTS_FEDMASTER_ABOUT_IDP.put(sub, entityStatementAboutIdp);
    } else {
      log.info(resp.getBody());
      throw new FdAuthServerException(
          "No entity statement for IDP ["
              + sub
              + "] at Fedmaster iss: "
              + entityIdentifierFedmaster
              + " available. Reason: "
              + resp.getBody()
              + HttpStatus.valueOf(resp.getStatus()),
          HttpStatus.BAD_REQUEST);
    }
  }

  // TODO: read from file with public key only
  private PublicKey getFedmasterSigKey() {
    return CryptoLoader.getCertificateFromPem(
            resourceReader.getFileFromResourceAsBytes("cert/fedmaster-sig-TU.pem"))
        .getPublicKey();
  }
}
