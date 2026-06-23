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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import de.gematik.idp.graserver.data.AuthSession;
import de.gematik.idp.graserver.exceptions.FdAuthServerException;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RequestValidatorTest {
  @Test
  void testValidateStateAndGetSession_validState() {
    final AuthSession authSession = mock(AuthSession.class);
    final Map<String, AuthSession> sessions = new HashMap<>();
    sessions.put("state123", authSession);
    final Object result = RequestValidator.validateStateAndGetSession("state123", sessions);
    assertThat(result).isEqualTo(authSession);
  }

  @Test
  void testValidateStateAndGetSession_invalidState() {
    final Map<String, AuthSession> sessions = new HashMap<>();
    assertThatThrownBy(() -> RequestValidator.validateStateAndGetSession("unknownState", sessions))
        .isInstanceOf(FdAuthServerException.class);
  }

  @Test
  void testVerifyRedirectUri_invalidUri() {
    assertThatThrownBy(
            () ->
                RequestValidator.verifyRedirectUri(
                    "https://valid.example.com/cb", "https://other.example.com/cb"))
        .isInstanceOf(FdAuthServerException.class);
  }

  @Test
  void testVerifyCodeVerifier_invalidCodeVerifier() {
    assertThatThrownBy(
            () -> RequestValidator.verifyCodeVerifier("invalidVerifier", "expectedChallenge"))
        .isInstanceOf(FdAuthServerException.class);
  }
}
