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

package de.gematik.idp.graserver.configuration;

import de.gematik.idp.data.KeyConfig;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("fd-auth-server")
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FdAuthServerConfiguration {

  private String serverUrl;
  private KeyConfig esSigPrivKeyConfig;
  private KeyConfig esSigPubKeyConfig;
  private KeyConfig tokenSigPrivKeyConfig;
  private KeyConfig tokenSigPubKeyConfig;
  private KeyConfig encPrivKeyConfig;
  private KeyConfig encPubKeyConfig;
  private KeyConfig tlsClientPrivKeyConfig;
  private KeyConfig tlsClientPrivKeyRotationConfig;
  private String symmetricEncryptionKey;
  private String fedmasterUrl;
  private String fedmasterSigPubKeyFilePath;
  private String clientId;
  private String loglevel;
}
