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

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class Constants {

  public static final String FED_SIGNED_JWKS_ENDPOINT = "/jws.json";
  public static final String FD_API_ENDPOINT = "/api";

  public static final String ENTITY_STATEMENT_EXPIRED_ENDPOINT = "/expired_entity_statement";
  public static final String ENTITY_STATEMENT_INVALID_SIG_ENDPOINT =
      "/invalid_sig_entity_statement";
  public static final int FD_AUTH_SERVER_STATE_LENGTH = 32;
  public static final int FD_AUTH_SERVER_NONCE_LENGTH = 32;
}
