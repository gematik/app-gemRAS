/*
 *  Copyright 2024 gematik GmbH
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

package de.gematik.idp.graserver.test.steps;

import de.gematik.rbellogger.data.RbelElement;
import de.gematik.rbellogger.data.facet.RbelValueFacet;
import de.gematik.test.tiger.lib.TigerDirector;
import groovy.util.logging.Slf4j;
import io.cucumber.java.en.And;
import java.util.Deque;

@Slf4j
public class StepsGlue {

  @And("current response with attributes iat and exp to be of type Long and iat < exp")
  public void checkIatBeforeExp() throws Exception {
    final Long iat = readClaimAsLongOrThrow("iat");
    final Long exp = readClaimAsLongOrThrow("exp");
    if (iat > exp) {
      throw new Exception("iat has to be < exp");
    }
  }

  private Long readClaimAsLongOrThrow(final String claimName) throws Exception {
    final Deque<RbelElement> rbelMessages =
        TigerDirector.getTigerTestEnvMgr().getLocalTigerProxyOrFail().getRbelMessages();
    rbelMessages.getLast();
    final Object claim =
        rbelMessages
            .getLast()
            .findElement("$.body.body." + claimName)
            .orElseThrow()
            .getFacet(RbelValueFacet.class)
            .get()
            .getValue();
    if (!(claim instanceof Long)) {
      throw new Exception(
          "Attribute "
              + claimName
              + " has to be of type Long, but is of type "
              + claim.getClass().getSimpleName());
    }
    return (Long) claim;
  }
}
