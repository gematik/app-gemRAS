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

@EntityStatement
Feature: Test Entity Statement of a Relying Party (i.e. GRAS)

  Background:
    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${tiger.fachdienstEntityStatementEndpoint}"

  @TCID:RP_ENTITY_STATEMENT_001
  @Approval
  Scenario: RP EntityStatement - Gutfall - Validiere Response

  ```
  Wir rufen das Entity Statement einer Relying Party der Föderation ab
  Die HTTP Response muss:
  - den Code 200
  - einen JWS enthalten

    When TGR find request to path "/${tiger.fachdienstEntityStatementPath}"
    Then TGR current response with attribute "$.responseCode" matches "200"
    And TGR current response with attribute "$.header.Content-Type" matches "application/entity-statement\+jwt.*"


  @TCID:RP_ENTITY_STATEMENT_002
  @Approval
  Scenario: RP EntityStatement - Gutfall - Validiere Response Header Claims

  ```
  Wir rufen das Entity Statement einer Relying Party der Föderation ab

  Der Response Body muss ein JWS mit den folgenden Header Claims sein:


    When TGR find request to path "/${tiger.fachdienstEntityStatementPath}"
    Then TGR current response at "$.body.header" matches as JSON:
            """
          {
          alg:        'ES256',
          kid:        '.*',
          typ:        'entity-statement+jwt'
          }
        """

  @TCID:RP_ENTITY_STATEMENT_003
  @Approval
  Scenario: RP EntityStatement - Gutfall - Validiere Response Body Claims

  ```
  Wir rufen das Entity Statement einer Relying Party der Föderation ab

  Der Response Body muss ein JWS mit den folgenden Body Claims sein:

    When TGR find request to path "/${tiger.fachdienstEntityStatementPath}"
    Then TGR current response at "$.body.body" matches as JSON:
            """
          {
            iss:                           'http.*',
            sub:                           'http.*',
            iat:                           "${json-unit.ignore}",
            exp:                           "${json-unit.ignore}",
            jwks:                          "${json-unit.ignore}",
            authority_hints:               "${json-unit.ignore}",
            metadata:                      "${json-unit.ignore}",
          }
        """
    And current response with attributes iat and exp to be of type Long and iat < exp
    And TGR current response with attribute "$.body.body.authority_hints.0" matches ".*.federationmaster.de"


  @TCID:RP_ENTITY_STATEMENT_004
  @Approval
  Scenario: RP EntityStatement - Gutfall - Validiere Metadata Body Claim

  ```
  Wir rufen das Entity Statement einer Relying Party der Föderation ab

  Der Response Body muss ein JWS sein. Dieser muss einen korrekt aufgebauten Body Claim metadata enthalten

    When TGR find request to path "/${tiger.fachdienstEntityStatementPath}"
    Then TGR current response at "$.body.body.metadata" matches as JSON:
    """
          {
            openid_relying_party:                      "${json-unit.ignore}",
            federation_entity:                         "${json-unit.ignore}"
          }
    """
    And TGR current response at "$.body.body.metadata.openid_relying_party" matches as JSON:
    """
          {
            ____signed_jwks_uri:                          'http.*',
            ____organization_name:                        '.*',
            client_name:                                  '.*',
            ____logo_uri:                                 'http.*',
            redirect_uris:                                "${json-unit.ignore}",
            response_types:                               ["code"],
            client_registration_types:                    ["automatic"],
            grant_types:                                  ["authorization_code"],
            require_pushed_authorization_requests:        true,
            token_endpoint_auth_method:                   "self_signed_tls_client_auth",
            default_acr_values:                           "${json-unit.ignore}",
            id_token_signed_response_alg:                 "ES256",
            id_token_encrypted_response_alg:              "ECDH-ES",
            id_token_encrypted_response_enc:              "A256GCM",
            scope:                                        '.*'
          }
    """
    And TGR current response with attribute "$.body.body.metadata.openid_relying_party.redirect_uris.0" matches ".*"
    And TGR current response at "$.body.body.metadata.federation_entity" matches as JSON:
    """
          {
            ____name:                 '.*',
            contacts:             "${json-unit.ignore}",
            ____homepage_uri:     'http.*'
          }
    """
    And TGR current response with attribute "$.body.body.metadata.federation_entity.contacts.0" matches ".*"


  @TCID:RP_ENTITY_STATEMENT_005
  @Approval
  Scenario: RP EntityStatement - Gutfall - Validiere JWKS in Body Claims

  ```
  Wir rufen das Entity Statement einer Relying Party der Föderation ab

  Der Response Body muss ein JWS mit einem JWKS Claim sein.
  Das JWKS muss mindestens einen strukturell korrekten JWK mit use = sig und x5c-Element enthalten.

    When TGR find request to path "/${tiger.fachdienstEntityStatementPath}"
    And TGR set local variable "entityStatementSigKeyKid" to "!{rbel:currentResponseAsString('$.body.header.kid')}"
    Then TGR current response at "$.body.body.jwks.keys.[?(@.kid.content =='${entityStatementSigKeyKid}')]" matches as JSON:
        """
          {
            use:                           'sig',
            kid:                           '.*',
            kty:                           'EC',
            crv:                           'P-256',
            x:                             "${json-unit.ignore}",
            y:                             "${json-unit.ignore}",
            alg:                           "ES256"
          }
        """


  @TCID:RP_ENTITY_STATEMENT_006
  @Approval
  Scenario: RP EntityStatement - Gutfall - Validiere Signatur

  ```
  Wir rufen das Entity Statement einer Relying Party der Föderation ab

  Die Signatur muss valide sein:

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${tiger.fachdienstEntityStatementEndpoint}"
    And TGR find request to path "/${tiger.fachdienstEntityStatementPath}"
    And TGR current response with attribute "$.body.signature.isValid" matches "true"


  @TCID:RP_ENTITY_STATEMENT_007
  @Approval
  Scenario: RP EntityStatement - Gutfall - Validiere Scope Claim

  ```
  Wir rufen das Entity Statement einer Relying Party der Föderation ab.
  Der Scope muss mindestens die Claims openid und urn:telematik:versicherter (für das Schreiben in der ePA) enthalten


    When TGR find request to path "/${tiger.fachdienstEntityStatementPath}"
    And TGR current response with attribute "$.body.body.metadata.openid_relying_party.scope" matches ".*openid.*"
    And TGR current response with attribute "$.body.body.metadata.openid_relying_party.scope" matches ".*urn:telematik:versicherter.*"