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

package de.gematik.idp.graserver.services;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.idp.token.JsonWebToken;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EntityListServiceTest {

  @Autowired EntityListService entityListService;

  /**
   * @formatter:off "idp_entity": [ { "name": "IDP_SEKTORAL", "iss": "http://127.0.0.1:8082",
   *     "logo_uri": "todo-logo", "user_type_supported": "IP" } ]
   * @formatter:on
   */
  @Test
  void getEntityList() {
    assertThat(entityListService.getEntityList()).isNotEmpty();
  }

  @Test
  void issTest() {
    final Map<String, Object> bodyClaims =
        new JsonWebToken(entityListService.getEntityList()).extractBodyClaims();
    final String iss = (String) bodyClaims.get("iss");
    assertThat(iss).containsPattern("http");
  }
}
