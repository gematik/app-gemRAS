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

package de.gematik.idp.graserver.data;

import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTH_TIME;
import static de.gematik.idp.field.ClaimName.CLIENT_ID;
import static de.gematik.idp.field.ClaimName.CODE_CHALLENGE;
import static de.gematik.idp.field.ClaimName.CODE_CHALLENGE_METHOD;
import static de.gematik.idp.field.ClaimName.DISPLAY_NAME;
import static de.gematik.idp.field.ClaimName.EXPIRES_AT;
import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.ID_NUMBER;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.ISSUER;
import static de.gematik.idp.field.ClaimName.JWT_ID;
import static de.gematik.idp.field.ClaimName.ORGANIZATION_NAME;
import static de.gematik.idp.field.ClaimName.PROFESSION_OID;
import static de.gematik.idp.field.ClaimName.REDIRECT_URI;
import static de.gematik.idp.field.ClaimName.RESPONSE_TYPE;
import static de.gematik.idp.field.ClaimName.SCOPE;
import static de.gematik.idp.field.ClaimName.SERVER_NONCE;
import static de.gematik.idp.field.ClaimName.STATE;
import static de.gematik.idp.field.ClaimName.TOKEN_TYPE;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.security.Key;
import java.time.ZonedDateTime;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthorizationCodeBuilderTest {

  @Autowired AuthorizationCodeBuilder authorizationCodeBuilder;
  @Autowired Key symmetricEncryptionKey;
  @Autowired FederationPrivKey esSigPrivKey;
  @Autowired FederationPubKey tokenSigPubKey;

  // ID_TOKEN, expiration not in scope
  static final String SEKTORALER_ID_TOKEN =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InB1a19mZWRfaWRwX3Rva2VuIn0.eyJzdWIiOiJYMTEwNDExNjc1LWh0dHA6Ly9sb2NhbGhvc3Q6ODA4NSIsInVybjp0ZWxlbWF0aWs6Y2xhaW1zOmlkIjoiWDExMDQxMTY3NSIsInVybjp0ZWxlbWF0aWs6Y2xhaW1zOm9yZ2FuaXphdGlvbiI6IjEwOTUwMDk2OSIsImFtciI6InVybjp0ZWxlbWF0aWs6YXV0aDplSUQiLCJpc3MiOiJodHRwczovL2dzaS5kZXYuZ2VtYXRpay5zb2x1dGlvbnMiLCJ1cm46dGVsZW1hdGlrOmNsYWltczpkaXNwbGF5X25hbWUiOiJEYXJpdXMgTWljaGFlbCBCcmlhbiBVYmJvIEdyYWYgdm9uIELDtmRlZmVsZCIsIm5vbmNlIjoiNDIiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODUiLCJhY3IiOiJnZW1hdGlrLWVoZWFsdGgtbG9hLWhpZ2giLCJ1cm46dGVsZW1hdGlrOmNsYWltczpwcm9mZXNzaW9uIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJleHAiOjE2OTAxODc4NTgsImlhdCI6MTY5MDE4NzU1OH0.1MLlGiBynPAptNl8AaAYbpJfH1dvLzeoGmEULG4MuEtVZYFoJRj_KHQOfIrWTmOrvE6rrkzM6HjPaVkUDKuKzg";

  @Test
  void buildAuthorizationcodeFromSektoralIdTokenTest() {
    final AuthSession authSession =
        AuthSession.builder()
            .frontendClientId("frontendClientId")
            .frontendCodeChallenge("frontendCodeChallenge")
            .frontendCodeChallengeMethod("frontendCodeChallengeMethod")
            .frontendState("frontendState")
            .frontendRedirectUri("frontendRedirectUri")
            .fdAuthServerCodeVerifier("fdAuthServerCodeVerifier")
            .idpIss("idpIss")
            .frontendScope("openid e-rezept")
            .build();
    final IdpJwe encryptedAuthCode =
        authorizationCodeBuilder.buildAuthorizationcodeFromSektoralIdToken(
            new JsonWebToken(SEKTORALER_ID_TOKEN), ZonedDateTime.now(), authSession);
    final JsonWebToken decryptedAuthCode =
        encryptedAuthCode.decryptNestedJwt(symmetricEncryptionKey);
    decryptedAuthCode.verify(tokenSigPubKey.getPublicKey().orElseThrow());
  }

  @Test
  void checkClaimsForAuthorizationcodeFromSektoralIdTokenTest() {
    final AuthSession authSession =
        AuthSession.builder()
            .frontendClientId("frontendClientId")
            .frontendCodeChallenge("frontendCodeChallenge")
            .frontendCodeChallengeMethod("frontendCodeChallengeMethod")
            .frontendState("frontendState")
            .frontendRedirectUri("frontendRedirectUri")
            .fdAuthServerCodeVerifier("fdAuthServerCodeVerifier")
            .idpIss("idpIss")
            .frontendScope("openid e-rezept")
            .build();
    final IdpJwe encryptedAuthCode =
        authorizationCodeBuilder.buildAuthorizationcodeFromSektoralIdToken(
            new JsonWebToken(SEKTORALER_ID_TOKEN), ZonedDateTime.now(), authSession);
    final JsonWebToken decryptedAuthCode =
        encryptedAuthCode.decryptNestedJwt(symmetricEncryptionKey);

    assertThat(decryptedAuthCode.getBodyClaims())
        .containsOnlyKeys(
            DISPLAY_NAME.getJoseName(),
            ID_NUMBER.getJoseName(),
            PROFESSION_OID.getJoseName(),
            ORGANIZATION_NAME.getJoseName(),
            EXPIRES_AT.getJoseName(),
            CODE_CHALLENGE.getJoseName(),
            CODE_CHALLENGE_METHOD.getJoseName(),
            CLIENT_ID.getJoseName(),
            REDIRECT_URI.getJoseName(),
            SCOPE.getJoseName(),
            ISSUED_AT.getJoseName(),
            STATE.getJoseName(),
            RESPONSE_TYPE.getJoseName(),
            TOKEN_TYPE.getJoseName(),
            AUTH_TIME.getJoseName(),
            SERVER_NONCE.getJoseName(),
            ISSUER.getJoseName(),
            JWT_ID.getJoseName(),
            AUTHENTICATION_METHODS_REFERENCE.getJoseName(),
            GIVEN_NAME.getJoseName(),
            FAMILY_NAME.getJoseName());
    assertThat(decryptedAuthCode.getBodyClaim(GIVEN_NAME)).contains("");
    assertThat(decryptedAuthCode.getBodyClaim(FAMILY_NAME)).contains("");
  }
}
