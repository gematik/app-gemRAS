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

@AuthorizationEndpoint
Feature: Test Auth Endpoint

  Background: Initialisiere Testkontext
    Then TGR HttpClient followRedirects Konfiguration deaktiviert

  @TCID:GRAS_AUTH_ENDPOINT_001
  @Approval
  Scenario: Gras Auth Endpoint - Gutfall - Validiere Authorization Response

  ```
  Wir senden einen Authorization Request an den GRAS.

  Die HTTP Response muss:

  - den Code 302 enthalten
  - request_uri in der Location enthalten

    Given TGR clear recorded messages
    When TGR send GET request to "http://graserver/auth" with:
      | client_id  | state       | redirect_uri                               | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | idp_iss                           |
      | gPatClient | yyystateyyy | https://idpfadi.dev.gematik.solutions/auth | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gpatscope | https://gsi.dev.gematik.solutions |
    And TGR find first request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "302"
    And TGR current response with attribute "$.header.Location" matches ".*request_uri=.*"


  @TCID:GRAS_AUTH_ENDPOINT_002
  @Approval
  @OpenBug
  Scenario Outline: Gras Auth Endpoint - Negativfall - invalid Parameter im Authorization Request

  ```
  Wir senden einen Authorization Request mit ungültigen Parametern an den GRAS. Die resultierende Response muss eine Fehlermeldung sein


    Given TGR clear recorded messages
    When TGR send GET request to "http://graserver/auth" with:
      | client_id  | state       | redirect_uri                               | code_challenge                              | code_challenge_method    | response_type | nonce                | scope     | idp_iss   |
      | gPatClient | yyystateyyy | https://idpfadi.dev.gematik.solutions/auth | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | <code_challenge_message> | code          | vy7rM801AQw1or22GhrZ | gpatscope | <idp_iss> |
    And TGR find first request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "302"
    And TGR current response with attribute "$.header.Location" matches ".*request_uri=.*"

    Examples:
      | idp_iss                                  | code_challenge_message |
      | https://invalididp.dev.gematik.solutions | S256                   |
      | https://gsi.dev.gematik.solutions        | A356                   |


  @TCID:GRAS_AUTH_ENDPOINT_003
  @Approval
  Scenario: Gras Auth Endpoint - Gutfall - Validiere Authcode Response

  ```
  Wir senden einen Authorization Request an den GRAS. Die resultierende request_uri reichen wir beim GSI ein. Dann senden wir den AuthorizationCode Request an den GRAS

  Die HTTP Response muss:

  - den Code 302 enthalten
  - den authCode des GSI enthalten

    Given TGR clear recorded messages
    When TGR send GET request to "http://graserver/auth" with:
      | client_id  | state       | redirect_uri                               | code_challenge                              | code_challenge_method | response_type | nonce                | scope     | idp_iss                           |
      | gPatClient | yyystateyyy | https://idpfadi.dev.gematik.solutions/auth | 9tI-0CQIkUYaGQOVR1emznlDFjlX0kVY1yd3oiMtGUI | S256                  | code          | vy7rM801AQw1or22GhrZ | gpatscope | https://gsi.dev.gematik.solutions |
    And TGR find first request to path ".*"
    And TGR set local variable "requestUri" to "!{rbel:currentResponseAsString('$.header.Location.request_uri.value')}"
    And TGR set local variable "gsiAuthEndpoint" to "!{rbel:currentResponseAsString('$.header.Location.basicPath')}"
    And TGR clear recorded messages
    When TGR sende eine GET Anfrage an "${gsiAuthEndpoint}" mit folgenden Daten:
      | request_uri   | user_id    | selected_claims         |
      | ${requestUri} | X110411675 | urn:telematik:claims:id |
    And TGR find first request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "302"
    And TGR current response with attribute "$.header.Location.code.value" matches ".*"
    And TGR set local variable "gsiAuthCode" to "!{rbel:currentResponseAsString('$.header.Location.code.value')}"
    And TGR set local variable "fachdienstState" to "!{rbel:currentResponseAsString('$.header.Location.state.value')}"
    And TGR clear recorded messages
    When TGR sende eine POST Anfrage an "http://graserver/auth" mit folgenden Daten:
      | code           | state              |
      | ${gsiAuthCode} | ${fachdienstState} |
    And TGR find first request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "200"
    And TGR current response with attribute "$.body.code.content" matches "ey.*"
    And TGR current response with attribute "$.body.state" matches "yyystateyyy"
