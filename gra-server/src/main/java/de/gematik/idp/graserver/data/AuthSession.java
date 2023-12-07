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

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

/**
 * Federation Authorization session fdAuthServerState is key to session, wird in Nachricht 7 des
 * App2App flows vom Idp-Sektoral an das Frontend versendet und kommt vom Frontend als Param von
 * Nachricht 9 hierher zurück
 */
@Getter
@Builder
public class AuthSession {

  // outer session related artifacts taken from app request
  private final String frontendClientId;
  // is part of message 12 of App2App flow
  private final String frontendState;
  private final String frontendRedirectUri;
  private final String frontendCodeChallenge;
  private final String frontendCodeChallengeMethod;
  private final String frontendResponseType;
  private final String frontendScope;
  // Fd-Auth-Server, inner session related artifacts
  private final String fdAuthServerCodeVerifier;
  private final String frontendNonce;
  private final String idpIss;
  @Setter private String fdAuthServerAuthorizationCode;
}
