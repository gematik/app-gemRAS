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
Feature: Test Entity Statement of Gematik Authorization Server (GRAS)

  @TCID:GRAS_ENTITY_STATEMENT_001
  @Approval
  Scenario: GRAS Check Entity Statement

  ```
  Wir rufen das Entity Statement des GRAS ab
  Die HTTP Response muss:
  - den Code 200
  - einen JWS enthalten

    Given TGR clear recorded messages
    When TGR sende eine leere GET Anfrage an "${gras.fachdienstEntityStatementEndpoint}"

    And TGR find request to path ".*/.well-known/openid-federation"
    Then TGR current response with attribute "$.responseCode" matches "200"
    And TGR current response with attribute "$.header.Content-Type" matches "application/entity-statement\+jwt.*"

