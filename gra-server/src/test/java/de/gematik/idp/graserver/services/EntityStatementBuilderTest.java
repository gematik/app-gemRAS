/*
 * Copyright (Change Date see Readme), gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.graserver.services;

import static de.gematik.idp.IdpConstants.ENTITY_STATEMENT_TYP;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.graserver.configuration.FdAuthServerConfiguration;
import java.time.ZonedDateTime;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import tools.jackson.databind.json.JsonMapper;

@Slf4j
@SpringBootTest(webEnvironment = WebEnvironment.NONE)
class EntityStatementBuilderTest {

  @Autowired private IdpJwtProcessor jwtProcessorEsSigPrivKey;
  @Autowired private EntityStatementBuilder entityStatementBuilder;
  @Autowired private FdAuthServerConfiguration fdAuthServerConfiguration;

  @Test
  void generateEntityStatementValid20Years() {
    final int entityStatementTtlYears = 20;
    final long nowPlus20Years =
        ZonedDateTime.now().plusYears(entityStatementTtlYears).toEpochSecond();
    final String es =
        jwtProcessorEsSigPrivKey
            .buildJws(
                JsonMapper.builder()
                    .build()
                    .writeValueAsString(
                        entityStatementBuilder.buildEntityStatement(
                            "http://localhost:8084",
                            fdAuthServerConfiguration.getFedmasterUrl(),
                            nowPlus20Years)),
                Map.ofEntries(Map.entry("typ", ENTITY_STATEMENT_TYP)),
                false)
            .getRawString();

    assertThat(es).isNotEmpty();
    log.info("Entity statement (valid {} years):\n{}", entityStatementTtlYears, es);
  }
}
