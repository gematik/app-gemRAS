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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AuthSessionTest {

  @Test
  void getSession() {
    final AuthSession fas =
        AuthSession.builder()
            .frontendClientId("frontendClientId")
            .frontendCodeChallenge("frontendCodeChallenge")
            .frontendCodeChallengeMethod("frontendCodeChallengeMethod")
            .frontendState("frontendState")
            .frontendRedirectUri("frontendRedirectUri")
            .fdAuthServerCodeVerifier("fdAuthServerCodeVerifier")
            .idpIss("idpIss")
            .build();

    assertThat(fas.getFrontendClientId()).isNotEmpty();
    assertThat(fas.getFrontendCodeChallenge()).isNotEmpty();
    assertThat(fas.getFrontendCodeChallengeMethod()).isNotEmpty();
    assertThat(fas.getFrontendState()).isNotEmpty();
    assertThat(fas.getFrontendRedirectUri()).isNotEmpty();
    assertThat(fas.getFdAuthServerCodeVerifier()).isNotEmpty();
    assertThat(fas.getIdpIss()).isNotEmpty();

    fas.setFdAuthServerAuthorizationCode("fdAuthServerAuthorizationCode");
  }
}
