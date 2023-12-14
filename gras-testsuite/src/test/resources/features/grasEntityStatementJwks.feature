#
# Copyright 2023 gematik GmbH
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

@EntityStatementJwks
Feature: Test optional JWKS in Entity Statement of a Relying Party (not applicable for GRAS)

  @TCID:RP_ES_JWKS_001
  @Approval
  Scenario: RP EntityStatementJwks - Gutfall - Validiere Enc Key
  ```
  Wir rufen das Entity Statement einer Relying Party der Föderation ab

  Das Entity Statement muss einen JWKS und dieser muss einen ENC-Key enthalten:

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${tiger.fachdienstEntityStatementEndpoint}"
    And TGR find request to path ".*"
    Then TGR current response at "$.body.body.metadata.openid_relying_party.jwks.keys.[?(@.use.content == 'enc')]" matches as JSON:
      """
        {
          use:                           'enc',
          kid:                           '.*',
          kty:                           'EC',
          crv:                           'P-256',
          x:                             "${json-unit.ignore}",
          y:                             "${json-unit.ignore}",
          alg:                           ".*"
        }
      """


  @TCID:RP_SIGNED_JWKS_005
  @Approval
  Scenario: RP SignedJwks - Gutfall - Validiere TLS Key
  ```
  Wir rufen das Entity Statement einer Relying Party der Föderation ab

  Das Entity Statement muss einen JWKS und dieser muss einen Sig-Key mit x5c-Element enthalten:

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${tiger.fachdienstEntityStatementEndpoint}"
    And TGR find request to path ".*"
    Then TGR current response at "$.body.body.metadata.openid_relying_party.jwks.keys.[?((@.use.content == 'sig') && ( @.x5c.0.content =~ '.*'))]" matches as JSON:
      """
        {
          use:                           'sig',
          kid:                           '.*',
          kty:                           'EC',
          crv:                           'P-256',
          x:                             "${json-unit.ignore}",
          y:                             "${json-unit.ignore}",
          alg:                           "ES256",
          x5c:                           "${json-unit.ignore}"
        }
      """