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

package de.gematik.idp.graserver.token;

import static de.gematik.idp.field.ClaimName.TYPE;
import static de.gematik.idp.graserver.Constants.ESSENTIAL_CLAIMS;
import static de.gematik.idp.graserver.Constants.OPTIONAL_CLAIMS;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.token.JsonWebToken;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class AccessTokenBuilder {

  private final IdpJwtProcessor jwtProc;
  private final Map<String, Object> authCodeBodyClaims;

  public JsonWebToken buildAccessToken() {
    final Map<String, Object> headerClaims = new HashMap<>();
    headerClaims.put(TYPE.getJoseName(), "JWT");
    final Map<String, Object> bodyClaims = new HashMap<>();
    addOptionalClaimsFromAuthCodeToAccessToken(authCodeBodyClaims, bodyClaims);
    addEssentialClaimsFromAuthCodeToAccessToken(authCodeBodyClaims, bodyClaims);
    return jwtProc.buildJwt(
        new JwtBuilder().addAllHeaderClaims(headerClaims).addAllBodyClaims(bodyClaims));
  }

  private static void addOptionalClaimsFromAuthCodeToAccessToken(
      final Map<String, Object> authCodeBodyClaims, final Map<String, Object> bodyClaims) {
    OPTIONAL_CLAIMS.stream()
        .filter(claim -> authCodeBodyClaims.containsKey(claim.getJoseName()))
        .forEach(
            claim ->
                bodyClaims.put(claim.getJoseName(), authCodeBodyClaims.get(claim.getJoseName())));
  }

  private static void addEssentialClaimsFromAuthCodeToAccessToken(
      final Map<String, Object> authCodeBodyClaims, final Map<String, Object> bodyClaims) {
    ESSENTIAL_CLAIMS.forEach(
        claim -> bodyClaims.put(claim.getJoseName(), authCodeBodyClaims.get(claim.getJoseName())));
  }
}
