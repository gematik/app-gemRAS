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

import static de.gematik.idp.graserver.Constants.ENTITY_STATEMENT_EXPIRED_ENDPOINT;
import static de.gematik.idp.graserver.Constants.ENTITY_STATEMENT_INVALID_SIG_ENDPOINT;
import static de.gematik.idp.graserver.Constants.FED_SIGNED_JWKS_ENDPOINT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.exceptions.IdpJwtSignatureInvalidException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.JsonWebToken;
import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kong.unirest.HttpResponse;
import kong.unirest.HttpStatus;
import kong.unirest.Unirest;
import org.apache.commons.io.FileUtils;
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthorizationControllerEntityStatementTest {

  static final List<String> OPENID_RELYING_PARTY_CLAIMS =
      List.of(
          "signed_jwks_uri",
          "organization_name",
          "client_name",
          "logo_uri",
          "redirect_uris",
          "response_types",
          "client_registration_types",
          "grant_types",
          "require_pushed_authorization_requests",
          "token_endpoint_auth_method",
          "default_acr_values",
          "id_token_signed_response_alg",
          "id_token_encrypted_response_alg",
          "id_token_encrypted_response_enc",
          "scope");

  private static final String SERVER_CERT_FILE = "src/test/resources/fachdienst-sig.pem";

  @LocalServerPort private int localServerPort;
  private String testHostUrl;
  private HttpResponse<String> responseGood;
  private JsonWebToken jwtInResponseGood;
  private Map<String, Object> bodyClaims;
  private X509Certificate serverCertificate;

  @BeforeAll
  void setup() throws IOException {
    testHostUrl = "http://localhost:" + localServerPort;
    responseGood = retrieveEntityStatement();
    assertThat(responseGood.getStatus()).isEqualTo(HttpStatus.OK);
    jwtInResponseGood = new JsonWebToken(responseGood.getBody());
    bodyClaims = jwtInResponseGood.extractBodyClaims();
    this.serverCertificate =
        CryptoLoader.getCertificateFromPem(
            FileUtils.readFileToByteArray(new File(SERVER_CERT_FILE)));
  }

  @Test
  void entityStatementResponse_ContentTypeEntityStatement() {
    assertThat(responseGood.getHeaders().get(HttpHeaders.CONTENT_TYPE).get(0))
        .isEqualTo("application/entity-statement+jwt;charset=UTF-8");
  }

  @Test
  void entityStatementResponse_JoseHeader() {
    assertThat(jwtInResponseGood.extractHeaderClaims()).containsOnlyKeys("typ", "alg", "kid");
  }

  @Test
  void entityStatement_BodyClaimsComplete() {
    assertThat(bodyClaims)
        .containsOnlyKeys("iss", "sub", "iat", "exp", "jwks", "authority_hints", "metadata");
  }

  @Test
  void entityStatement_ContainsJwks() {
    assertThat(bodyClaims.get("jwks")).isNotNull();
  }

  @Test
  void entityStatement_MetadataClaims() {
    final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
    assertThat(metadata).containsOnlyKeys("openid_relying_party", "federation_entity");
  }

  @SuppressWarnings("unchecked")
  @Test
  void entityStatement_OpenidRelyingPartyClaimsComplete() {
    final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
    final Map<String, Object> openidRelyingParty =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_relying_party"),
            "missing claim: openid_relying_party");

    assertThat(openidRelyingParty).containsOnlyKeys(OPENID_RELYING_PARTY_CLAIMS);
  }

  @SuppressWarnings("unchecked")
  @Test
  void entityStatement_openidRelyingPartyClaimsContentCorrect() {

    final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
    final Map<String, Object> openidRelyingParty =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("openid_relying_party"),
            "missing claim: openid_relying_party");

    assertThat(openidRelyingParty)
        .containsEntry("signed_jwks_uri", "https://idpfadi.dev.gematik.solutions" + "/jws.json");
    assertThat(openidRelyingParty.get("organization_name")).asString().isNotEmpty();
    assertThat(openidRelyingParty.get("client_name")).asString().isNotEmpty();
    assertThat(openidRelyingParty.get("logo_uri")).asString().isNotEmpty();
    assertThat((List<String>) openidRelyingParty.get("redirect_uris")).hasSizeGreaterThan(0);
    assertThat((List<String>) openidRelyingParty.get("response_types"))
        .containsExactlyInAnyOrder("code");
    assertThat((List<String>) openidRelyingParty.get("client_registration_types"))
        .containsExactlyInAnyOrder("automatic");
    assertThat((List<String>) openidRelyingParty.get("grant_types"))
        .containsExactlyInAnyOrder("authorization_code");
    assertThat((List<String>) openidRelyingParty.get("default_acr_values"))
        .containsExactlyInAnyOrder("gematik-ehealth-loa-high");
    assertThat((Boolean) openidRelyingParty.get("require_pushed_authorization_requests")).isTrue();
    assertThat(openidRelyingParty)
        .containsEntry("token_endpoint_auth_method", "self_signed_tls_client_auth")
        .containsEntry("id_token_signed_response_alg", "ES256")
        .containsEntry("id_token_encrypted_response_alg", "ECDH-ES")
        .containsEntry("id_token_encrypted_response_enc", "A256GCM")
        .containsEntry("scope", "urn:telematik:display_name urn:telematik:versicherter openid");
  }

  @SuppressWarnings("unchecked")
  @Test
  void entityStatement_FederationEntityClaimsContentCorrect() {
    final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
    final Map<String, Object> federationEntity =
        Objects.requireNonNull(
            (Map<String, Object>) metadata.get("federation_entity"),
            "missing claim: federation_entity");

    assertThat(federationEntity)
        .containsEntry("name", "Fachdienst007")
        .containsEntry("homepage_uri", "https://Fachdienst007.de");
    assertThat((List<String>) federationEntity.get("contacts"))
        .containsExactlyInAnyOrder("Support@Fachdienst007.de");
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> getInnerClaimMap(
      final Map<String, Object> claimMap, final String key) {
    return Objects.requireNonNull((Map<String, Object>) claimMap.get(key), "missing claim: " + key);
  }

  private HttpResponse<String> retrieveEntityStatement() {
    return Unirest.get(testHostUrl + IdpConstants.ENTITY_STATEMENT_ENDPOINT).asString();
  }

  @Test
  void getSignedJwks() {
    final HttpResponse<String> response =
        Unirest.get(testHostUrl + FED_SIGNED_JWKS_ENDPOINT).asString();

    assertThat(response.getHeaders().get("Content-Type"))
        .containsExactly("application/jwk-set+json;charset=UTF-8");
    @SuppressWarnings("unchecked")
    final List<Map<String, Object>> keyList =
        (List<Map<String, Object>>)
            new JsonWebToken(response.getBody()).getBodyClaims().get("keys");

    assertThat(keyList).hasSize(2);
  }

  @Test
  void headerClaimsOfSignedJwks() {
    final HttpResponse<String> response =
        Unirest.get(testHostUrl + FED_SIGNED_JWKS_ENDPOINT).asString();
    final Map<String, Object> headerClaims = new JsonWebToken(response.getBody()).getHeaderClaims();

    assertThat(headerClaims).containsEntry("alg", "ES256");
    assertThat(headerClaims).containsEntry("typ", "jwk-set+json");
    assertThat(headerClaims).containsEntry("kid", "puk_fd_sig");
  }

  @Test
  void checkKeyIdsInSignedJwks() {
    final HttpResponse<String> response =
        Unirest.get(testHostUrl + FED_SIGNED_JWKS_ENDPOINT).asString();

    @SuppressWarnings("unchecked")
    final List<Map<String, Object>> keyList =
        (List<Map<String, Object>>)
            new JsonWebToken(response.getBody()).getBodyClaims().get("keys");

    assertThat(keyList.stream().anyMatch(key -> key.get("kid").equals("puk_tls_sig"))).isTrue();
    assertThat(keyList.stream().anyMatch(key -> key.get("kid").equals("puk_fd_enc"))).isTrue();
  }

  @Test
  void checkX5cInSignedJwks() {
    final HttpResponse<String> response =
        Unirest.get(testHostUrl + FED_SIGNED_JWKS_ENDPOINT).asString();

    @SuppressWarnings("unchecked")
    final List<Map<String, Object>> keyList =
        (List<Map<String, Object>>)
            new JsonWebToken(response.getBody()).getBodyClaims().get("keys");

    // fdEncKey must exist and must not contain x5c
    final Map<String, Object> fdEncKey =
        keyList.stream().filter(key -> key.get("kid").equals("puk_fd_enc")).findAny().orElseThrow();
    assertThat(fdEncKey.get("x5c")).isNull();

    // tlsSigKey must exist and must contain x5c
    final Map<String, Object> tlsSigKey =
        keyList.stream()
            .filter(key -> key.get("kid").equals("puk_tls_sig"))
            .findAny()
            .orElseThrow();
    assertThat(tlsSigKey.get("x5c")).isNotNull();
  }

  @Test
  void checkExpiredEntityStatementIsExpired() {
    final HttpResponse<String> httpResponse =
        Unirest.get(testHostUrl + ENTITY_STATEMENT_EXPIRED_ENDPOINT).asString();
    final JsonWebToken expiredEntityStatement = new JsonWebToken(httpResponse.getBody());
    assertThat((Long) expiredEntityStatement.getBodyClaim(ClaimName.EXPIRES_AT).orElseThrow())
        .isLessThan(ZonedDateTime.now().toEpochSecond());
  }

  @Test
  void checkEntityStatementHasValidSignature() {
    final HttpResponse<String> httpResponse =
        Unirest.get(testHostUrl + IdpConstants.ENTITY_STATEMENT_ENDPOINT).asString();
    final JsonWebToken entityStatement = new JsonWebToken(httpResponse.getBody());
    entityStatement.verify(serverCertificate.getPublicKey());
  }

  @Test
  void checkInvalidSignatureEntityStatementHasInvalidSignature() {
    final HttpResponse<String> httpResponse =
        Unirest.get(testHostUrl + ENTITY_STATEMENT_INVALID_SIG_ENDPOINT).asString();
    final JsonWebToken entityStatementWithInvalidSignature =
        new JsonWebToken(httpResponse.getBody());
    final PublicKey publicKey = serverCertificate.getPublicKey();
    assertThatThrownBy(() -> entityStatementWithInvalidSignature.verify(publicKey))
        .isInstanceOf(IdpJwtSignatureInvalidException.class);
  }
}
