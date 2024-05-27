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

import static de.gematik.idp.graserver.Constants.FED_SIGNED_JWKS_ENDPOINT;

import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.graserver.data.EntityStatement;
import de.gematik.idp.graserver.data.FederationEntity;
import de.gematik.idp.graserver.data.Metadata;
import de.gematik.idp.graserver.data.OpenidRelyingParty;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

@RequiredArgsConstructor
@Slf4j
public class EntityStatementBuilder {

  private static final int ENTITY_STATEMENT_TTL_DAYS = 1;
  private static final int ENTITY_STATEMENT_EXPIRED_DAYS_IN_PAST = 2;
  @Autowired FederationPubKey esSigPubKey;

  public EntityStatement buildEntityStatement(final String serverUrl, final String fedmasterUrl) {
    log.debug("build EntityStatement, serverUrl: " + serverUrl);
    final ZonedDateTime currentTime = ZonedDateTime.now();
    return buildEntityStatement(
        serverUrl, fedmasterUrl, currentTime.plusDays(ENTITY_STATEMENT_TTL_DAYS).toEpochSecond());
  }

  public EntityStatement buildEntityStatement(
      final String serverUrl, final String fedmasterUrl, final long expSeconds) {
    final ZonedDateTime currentTime = ZonedDateTime.now();
    return EntityStatement.builder()
        .exp(expSeconds)
        .iat(currentTime.toEpochSecond())
        .iss(serverUrl)
        .sub(serverUrl)
        .jwks(JwtHelper.getJwks(esSigPubKey))
        .authorityHints(new String[] {fedmasterUrl})
        .metadata(getMetadata(serverUrl))
        .build();
  }

  public EntityStatement buildExpiredEntityStatement(
      final String serverUrl, final String fedmasterUrl) {
    log.debug("build EntityStatement, serverUrl: " + serverUrl);
    final ZonedDateTime currentTime = ZonedDateTime.now();
    return EntityStatement.builder()
        .exp(
            currentTime
                .minusDays(ENTITY_STATEMENT_EXPIRED_DAYS_IN_PAST)
                .plusDays(ENTITY_STATEMENT_TTL_DAYS)
                .toEpochSecond())
        .iat(currentTime.minusDays(ENTITY_STATEMENT_EXPIRED_DAYS_IN_PAST).toEpochSecond())
        .iss(serverUrl)
        .sub(serverUrl)
        .jwks(JwtHelper.getJwks(esSigPubKey))
        .authorityHints(new String[] {fedmasterUrl})
        .metadata(getMetadata(serverUrl))
        .build();
  }

  private Metadata getMetadata(final String serverUrl) {
    final OpenidRelyingParty openidRelyingParty =
        OpenidRelyingParty.builder()
            .signedJwksUri(serverUrl + FED_SIGNED_JWKS_ENDPOINT)
            .organizationName("Fachdienst007 des FedIdp POCs")
            .clientName("Fachdienst007")
            .logoUri(serverUrl + "/noLogoYet")
            .redirectUris(
                new String[] {
                  "http://127.0.0.1:8084/auth",
                  "https://Fachdienst007.de/client",
                  "https://redirect.testsuite.gsi",
                  "https://idpfadi.dev.gematik.solutions/auth"
                })
            .responseTypes(new String[] {"code"})
            .clientRegistrationTypes(new String[] {"automatic"})
            .grantTypes(new String[] {"authorization_code"})
            .requirePushedAuthorizationRequests(true)
            .tokenEndpointAuthMethod("self_signed_tls_client_auth")
            .defaultAcrValues(new String[] {"gematik-ehealth-loa-high"})
            .idTokenSignedResponseAlg("ES256")
            .idTokenEncryptedResponseAlg("ECDH-ES")
            .idTokenEncryptedResponseEnc("A256GCM")
            .scope("urn:telematik:display_name urn:telematik:versicherter openid")
            .build();
    final FederationEntity federationEntity =
        FederationEntity.builder()
            .name("Fachdienst007")
            .contacts(new String[] {"Support@Fachdienst007.de"})
            .homepageUri("https://Fachdienst007.de")
            .build();
    return Metadata.builder()
        .openidRelyingParty(openidRelyingParty)
        .federationEntity(federationEntity)
        .build();
  }
}
