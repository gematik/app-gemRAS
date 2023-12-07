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

import static de.gematik.idp.IdpConstants.AMR_FAST_TRACK;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTH_TIME;
import static de.gematik.idp.field.ClaimName.CLIENT_ID;
import static de.gematik.idp.field.ClaimName.CODE_CHALLENGE;
import static de.gematik.idp.field.ClaimName.CODE_CHALLENGE_METHOD;
import static de.gematik.idp.field.ClaimName.DISPLAY_NAME;
import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.ID_NUMBER;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.ISSUER;
import static de.gematik.idp.field.ClaimName.JWT_ID;
import static de.gematik.idp.field.ClaimName.NONCE;
import static de.gematik.idp.field.ClaimName.ORGANIZATION_NAME;
import static de.gematik.idp.field.ClaimName.PROFESSION_OID;
import static de.gematik.idp.field.ClaimName.REDIRECT_URI;
import static de.gematik.idp.field.ClaimName.RESPONSE_TYPE;
import static de.gematik.idp.field.ClaimName.SCOPE;
import static de.gematik.idp.field.ClaimName.SERVER_NONCE;
import static de.gematik.idp.field.ClaimName.STATE;
import static de.gematik.idp.field.ClaimName.TELEMATIK_DISPLAY_NAME;
import static de.gematik.idp.field.ClaimName.TELEMATIK_ID;
import static de.gematik.idp.field.ClaimName.TELEMATIK_ORGANIZATION;
import static de.gematik.idp.field.ClaimName.TELEMATIK_PROFESSION;
import static de.gematik.idp.field.ClaimName.TOKEN_TYPE;
import static de.gematik.idp.field.ClaimName.TYPE;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.security.Key;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class AuthorizationCodeBuilder {

  private final IdpJwtProcessor jwtProcessorTokenKey;
  private final Key encryptionKey;
  private final String issuerUrl;

  public IdpJwe buildAuthorizationcodeFromSektoralIdToken(
      final JsonWebToken idTokenPlain,
      final ZonedDateTime issueingTime,
      final AuthSession authSession) {

    final Map<String, Object> claimsMap = new HashMap<>();

    claimsMap.put(
        DISPLAY_NAME.getJoseName(), extractClaimFromIdToken(idTokenPlain, TELEMATIK_DISPLAY_NAME));

    claimsMap.put(ID_NUMBER.getJoseName(), extractClaimFromIdToken(idTokenPlain, TELEMATIK_ID));
    claimsMap.put(
        PROFESSION_OID.getJoseName(), extractClaimFromIdToken(idTokenPlain, TELEMATIK_PROFESSION));
    claimsMap.put(
        ORGANIZATION_NAME.getJoseName(),
        extractClaimFromIdToken(idTokenPlain, TELEMATIK_ORGANIZATION));

    addFamNameAndGivenNameForScopeERezept(claimsMap);

    claimsMap.put(CODE_CHALLENGE.getJoseName(), authSession.getFrontendCodeChallenge());
    claimsMap.put(
        CODE_CHALLENGE_METHOD.getJoseName(), authSession.getFrontendCodeChallengeMethod());
    if (authSession.getFrontendNonce() != null) {
      claimsMap.put(NONCE.getJoseName(), authSession.getFrontendNonce());
    }
    claimsMap.put(CLIENT_ID.getJoseName(), authSession.getFrontendClientId());
    claimsMap.put(REDIRECT_URI.getJoseName(), authSession.getFrontendRedirectUri());
    claimsMap.put(SCOPE.getJoseName(), authSession.getFrontendScope());
    claimsMap.put(ISSUED_AT.getJoseName(), issueingTime.toEpochSecond());
    claimsMap.put(STATE.getJoseName(), authSession.getFrontendState());
    claimsMap.put(RESPONSE_TYPE.getJoseName(), authSession.getFrontendResponseType());
    claimsMap.put(TOKEN_TYPE.getJoseName(), "code");
    claimsMap.put(AUTH_TIME.getJoseName(), ZonedDateTime.now().toEpochSecond());
    claimsMap.put(SERVER_NONCE.getJoseName(), Nonce.getNonceAsBase64UrlEncodedString(24));
    claimsMap.put(ISSUER.getJoseName(), issuerUrl);
    claimsMap.put(JWT_ID.getJoseName(), Nonce.getNonceAsHex(IdpConstants.JTI_LENGTH));
    claimsMap.put(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), List.of(AMR_FAST_TRACK));

    final Map<String, Object> headerMap = new HashMap<>();
    headerMap.put(TYPE.getJoseName(), "JWT");

    return jwtProcessorTokenKey
        .buildJwt(
            new JwtBuilder()
                .addAllHeaderClaims(headerMap)
                .addAllBodyClaims(claimsMap)
                .expiresAt(ZonedDateTime.now().plusHours(1)))
        .encryptAsNjwt(encryptionKey);
  }

  /*
   *A_22271-01 states that for the erezept auth server these claims are to be included with an empty
   * string as the value
   */
  private static void addFamNameAndGivenNameForScopeERezept(Map<String, Object> claimsMap) {
    claimsMap.put(GIVEN_NAME.getJoseName(), "");
    claimsMap.put(FAMILY_NAME.getJoseName(), "");
  }

  private Object extractClaimFromIdToken(final JsonWebToken idToken, final ClaimName claimName) {
    return idToken
        .getBodyClaim(claimName)
        .orElseThrow(
            () ->
                new IdpJoseException(
                    "Unexpected structure in ID-Token, claim " + claimName + " not found."));
  }
}
