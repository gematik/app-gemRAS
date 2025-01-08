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

@SignedJwks
Feature: Test optional signed JWKS of a Relying Party (i.e. GRAS)

  Background: Initialisiere Testkontext durch Abfrage des Entity Statements
    When TGR sende eine leere GET Anfrage an "${tiger.fachdienstEntityStatementEndpoint}"
    And TGR find request to path "/${tiger.fachdienstEntityStatementPath}"
    Then TGR set local variable "signed_jwks_uri" to "!{rbel:currentResponseAsString('$..signed_jwks_uri')}"


  @TCID:RP_SIGNED_JWKS_001
  @Approval
  Scenario: RP SignedJwks - Gutfall - Validiere Response
  ```
  Wir rufen das signed jwks einer Relying Party der Föderation ab

  Die HTTP Response muss:

  - den Code 200
  - den Media Type "application/jwk-set" enthalten

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${signed_jwks_uri}"
    And TGR find request to path ".*"
    Then TGR current response with attribute "$.responseCode" matches "200"
    And TGR current response with attribute "$.header.Content-Type" matches "application/jwk-set.*"


  @TCID:RP_SIGNED_JWKS_002
  @Approval
  Scenario: RP SignedJwks - Gutfall - Validiere Response Header Claims
  ```
  Wir rufen das signed jwks einer Relying Party der Föderation ab

  Der Response Body muss ein JWS mit den folgenden Header Claims sein

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${signed_jwks_uri}"
    And TGR find request to path ".*"
    Then TGR current response at "$.body.header" matches as JSON:
            """
          {
          alg:        'ES256',
          kid:        '.*',
          typ:        'jwk-set+json'
          }
        """


  @TCID:RP_SIGNED_JWKS_003
  @Approval
  Scenario: RP SignedJwks - Gutfall - Validiere Response Body Claims
  ```
  Wir rufen das signed jwks einer Relying Party der Föderation ab

  Der Response Body muss ein JWS mit den korrekten Body Claims sein:

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${signed_jwks_uri}"
    And TGR find request to path ".*"
    Then TGR current response at "$.body.body" matches as JSON:
    """
      {
        iss:                           '.*',
        iat:                           "${json-unit.ignore}",
        keys:                          "${json-unit.ignore}"
      }
    """


  @TCID:RP_SIGNED_JWKS_004
  @Approval
  Scenario: RP SignedJwks - Gutfall - Validiere Enc Key
  ```
  Wir rufen das signed jwks einer Relying Party der Föderation ab

  Der JWKS muss einen ENC-Key enthalten:

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${signed_jwks_uri}"
    And TGR find request to path ".*"
    Then TGR current response at "$.body.body.keys.[?(@.use.content == 'enc')]" matches as JSON:
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
  Wir rufen das signed jwks einer Relying Party der Föderation ab

  Der JWKS muss einen SIG-Key mit dem TLS-Clientzertifikat im x5c-Element enthalten:

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${signed_jwks_uri}"
    And TGR find request to path ".*"
    Then TGR current response at "$.body.body.keys.[?((@.use.content == 'sig') && ( @.x5c.0.content =~ '.*') && ( @.kid.content == "puk_tls_sig"))]" matches as JSON:
      """
        {
          use:                           'sig',
          kid:                           'puk_tls_sig',
          kty:                           'EC',
          crv:                           'P-256',
          x:                             "${json-unit.ignore}",
          y:                             "${json-unit.ignore}",
          alg:                           "ES256",
          x5c:                           "${json-unit.ignore}"
        }
      """
    And TGR current response at "$.body.body.keys.[?((@.use.content == 'sig') && ( @.x5c.0.content =~ '.*') && ( @.kid.content == "puk_tls_sig_rotation"))]" matches as JSON:
      """
          {
            use:                           'sig',
            kid:                           'puk_tls_sig_rotation',
            kty:                           'EC',
            crv:                           'P-256',
            x:                             "${json-unit.ignore}",
            y:                             "${json-unit.ignore}",
            alg:                           "ES256",
            x5c:                           "${json-unit.ignore}"
          }
        """