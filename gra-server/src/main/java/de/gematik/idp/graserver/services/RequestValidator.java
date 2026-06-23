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

package de.gematik.idp.graserver.services;

import static de.gematik.idp.field.ClientUtilities.generateCodeChallenge;

import de.gematik.idp.graserver.data.AuthSession;
import de.gematik.idp.graserver.exceptions.FdAuthServerException;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpStatus;

public class RequestValidator {

  public static AuthSession validateStateAndGetSession(
      final String fdAuthServerState, final Map<String, AuthSession> authSession) {
    return Optional.ofNullable(authSession.get(fdAuthServerState))
        .orElseThrow(
            () ->
                new FdAuthServerException(
                    "Content of parameter state is unknown", HttpStatus.BAD_REQUEST));
  }

  public static void verifyRedirectUri(
      final String redirectUri, final Object redirectUriFromAuthCode) {
    if (!redirectUri.equals(redirectUriFromAuthCode)) {
      throw new FdAuthServerException(
          "Redirect_uri does not match redirect_uri from authorization code",
          HttpStatus.BAD_REQUEST);
    }
  }

  public static void verifyCodeVerifier(final String codeVerifier, final Object codeChallenge) {
    if (!generateCodeChallenge(codeVerifier).equals(codeChallenge)) {
      throw new FdAuthServerException("CodeVerifier is invalid", HttpStatus.BAD_REQUEST);
    }
  }
}
