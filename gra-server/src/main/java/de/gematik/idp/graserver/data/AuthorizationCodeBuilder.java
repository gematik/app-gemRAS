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

package de.gematik.idp.graserver.data;

import static de.gematik.idp.field.ClaimName.AUTHENTICATION_CLASS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTH_TIME;
import static de.gematik.idp.field.ClaimName.CLIENT_ID;
import static de.gematik.idp.field.ClaimName.CODE_CHALLENGE;
import static de.gematik.idp.field.ClaimName.CODE_CHALLENGE_METHOD;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.ISSUER;
import static de.gematik.idp.field.ClaimName.JWT_ID;
import static de.gematik.idp.field.ClaimName.NONCE;
import static de.gematik.idp.field.ClaimName.REDIRECT_URI;
import static de.gematik.idp.field.ClaimName.RESPONSE_TYPE;
import static de.gematik.idp.field.ClaimName.SCOPE;
import static de.gematik.idp.field.ClaimName.SERVER_NONCE;
import static de.gematik.idp.field.ClaimName.STATE;
import static de.gematik.idp.field.ClaimName.TOKEN_TYPE;
import static de.gematik.idp.field.ClaimName.TYPE;
import static de.gematik.idp.graserver.Constants.ESSENTIAL_CLAIMS;
import static de.gematik.idp.graserver.Constants.OPTIONAL_CLAIMS;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.graserver.exceptions.FdAuthServerException;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.security.Key;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;

@AllArgsConstructor
public class AuthorizationCodeBuilder {

  private final IdpJwtProcessor jwtProcessorTokenSigPrivKey;
  private final Key encryptionKey;
  private final String issuerUrl;

  public IdpJwe buildAuthorizationcodeFromSektoralIdToken(
      final JsonWebToken idTokenPlain,
      final ZonedDateTime issueingTime,
      final AuthSession authSession) {

    final Map<String, Object> claimsMap = new HashMap<>();
    addOptionalClaimsFromSektoralIdTokenToAuthCode(idTokenPlain, claimsMap);
    addEssentialClaimsFromSektoralIdTokenToAuthCode(idTokenPlain, claimsMap);

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
    claimsMap.put(
        AUTHENTICATION_METHODS_REFERENCE.getJoseName(),
        ((List<?>) idTokenPlain.getBodyClaim(AUTHENTICATION_METHODS_REFERENCE).orElseThrow())
            .getFirst());
    claimsMap.put(
        AUTHENTICATION_CLASS_REFERENCE.getJoseName(),
        idTokenPlain.getBodyClaim(AUTHENTICATION_CLASS_REFERENCE).orElseThrow());

    final Map<String, Object> headerMap = new HashMap<>();
    headerMap.put(TYPE.getJoseName(), "JWT");

    return jwtProcessorTokenSigPrivKey
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

  private static void addOptionalClaimsFromSektoralIdTokenToAuthCode(
      final JsonWebToken idToken, final Map<String, Object> claimsMap) {
    OPTIONAL_CLAIMS.stream()
        .filter(claim -> idToken.getBodyClaim(claim).isPresent())
        .forEach(claim -> claimsMap.put(claim.getJoseName(), idToken.getBodyClaim(claim).get()));
  }

  private static void addEssentialClaimsFromSektoralIdTokenToAuthCode(
      final JsonWebToken idToken, final Map<String, Object> claimsMap) {
    ESSENTIAL_CLAIMS.forEach(
        claim ->
            claimsMap.put(
                claim.getJoseName(),
                idToken
                    .getBodyClaim(claim)
                    .orElseThrow(
                        () ->
                            new FdAuthServerException(
                                "essential claim " + claim.getJoseName() + " not found.",
                                HttpStatus.BAD_REQUEST))));
  }
}
