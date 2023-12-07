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

import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.graserver.data.ClientAssertion;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class ClientAssertionBuilder {

  private static final int JTI_MAX_LENGTH = 32;
  private static final int JWT_TTL_SECS = 90;

  public ClientAssertion buildClientAssertion(
      final String serverUrl, final String sekIdpAuthEndpoint) {
    final ZonedDateTime currentTime = ZonedDateTime.now();
    return ClientAssertion.builder()
        .iss(serverUrl)
        .sub(serverUrl)
        .aud(sekIdpAuthEndpoint)
        .jti(Nonce.getNonceAsHex(JTI_MAX_LENGTH))
        .exp(currentTime.plusSeconds(JWT_TTL_SECS).toEpochSecond())
        .iat(currentTime.toEpochSecond())
        .build();
  }
}
