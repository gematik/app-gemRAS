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

package de.gematik.idp.graserver;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.graserver.data.AuthorizationCodeBuilder;
import de.gematik.idp.graserver.services.ClientAssertionBuilder;
import de.gematik.idp.graserver.services.EntityStatementBuilder;
import de.gematik.idp.graserver.services.JwksBuilder;
import java.security.Key;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class FlowBeanCreation {

  private final IdpJwtProcessor jwtProcessorTokenSigPrivKey;
  private final Key symmetricEncryptionKey;
  private final ServerUrlService serverUrlService;

  @Bean
  public AuthorizationCodeBuilder authorizationCodeBuilder() {
    return new AuthorizationCodeBuilder(
        jwtProcessorTokenSigPrivKey, symmetricEncryptionKey, serverUrlService.determineServerUrl());
  }

  @Bean
  public EntityStatementBuilder entityStatementBuilder() {
    return new EntityStatementBuilder();
  }

  @Bean
  public ClientAssertionBuilder clientAssertionBuilder() {
    return new ClientAssertionBuilder();
  }

  @Bean
  public JwksBuilder jwksBuilder() {
    return new JwksBuilder();
  }
}
