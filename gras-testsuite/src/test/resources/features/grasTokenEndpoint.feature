#
# Copyright (Change Date see Readme), gematik GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
#

@TokenEndpoint
Feature: Test Token Endpoint

  Background: Initialisiere Testkontext
    Then TGR HttpClient followRedirects Konfiguration deaktiviert

  @TCID:GRAS_TOKEN_ENDPOINT_001
  @Approval
  Scenario: Gras Token Endpoint - Gutfall - Validiere Token Response

  ```
  Wir holen uns einen sektoralen AuthCode vom GSI und senden ihn in einem Token Request an den GRAS.

  Die HTTP Response muss:

  - den Code 200 enthalten
  - den ACCESS_TOKEN des GRAS enthalten

    Given TGR clear recorded messages
    When TGR send GET request to "http://graserver/auth" with:
      | client_id  | state       | redirect_uri                               | code_challenge        | code_challenge_method | response_type | nonce                | scope     | idp_iss                           |
      | gPatClient | yyystateyyy | https://idpfadi.dev.gematik.solutions/auth | ${gras.codeChallenge} | S256                  | code          | vy7rM801AQw1or22GhrZ | gpatscope | https://gsi.dev.gematik.solutions |
    And TGR find first request to path ".*"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$.header.Location.request_uri.value')}"
    And TGR set local variable "gsiAuthEndpoint" to "!{rbel:currentResponseAsString('$.header.Location.basicPath')}"
    And TGR clear recorded messages
    When TGR sende eine GET Anfrage an "${gsiAuthEndpoint}" mit folgenden Daten:
      | request_uri   | user_id    | selected_claims         |
      | ${requestUri} | X110411675 | urn:telematik:claims:id |
    And TGR find first request to path ".*"
    And TGR set local variable "gsiAuthCode" to "!{rbel:currentResponseAsString('$.header.Location.code.value')}"
    And TGR set local variable "fachdienstState" to "!{rbel:currentResponseAsString('$.header.Location.state.value')}"
    And TGR clear recorded messages
    When TGR sende eine POST Anfrage an "http://graserver/auth" mit folgenden Daten:
      | code           | state              |
      | ${gsiAuthCode} | ${fachdienstState} |
    And TGR find first request to path ".*"
    And TGR set local variable "grasAuthCode" to "!{rbel:currentResponseAsString('$.body.code.content')}"
    And TGR clear recorded messages
    When TGR sende eine POST Anfrage an "http://graserver/token" mit folgenden Daten:
      | code            | code_verifier        | grant_type         | redirect_uri                               | client_id  |
      | ${grasAuthCode} | ${gras.codeVerifier} | authorization_code | https://idpfadi.dev.gematik.solutions/auth | gPatClient |
    And TGR find first request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "200"
    Then TGR current response at "$.body" matches as JSON:
            """
          {
            access_token:                       '.*'
          }
        """