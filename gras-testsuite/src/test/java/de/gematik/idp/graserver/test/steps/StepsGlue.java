/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.idp.graserver.test.steps;

import com.fasterxml.jackson.databind.node.ArrayNode;
import de.gematik.rbellogger.data.RbelElement;
import de.gematik.rbellogger.data.core.RbelValueFacet;
import de.gematik.rbellogger.facets.jackson.RbelJsonFacet;
import de.gematik.test.tiger.lib.rbel.RbelMessageRetriever;
import groovy.util.logging.Slf4j;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Then;
import java.util.List;

@Slf4j
public class StepsGlue {

  private final RbelMessageRetriever rbelMessageRetriever = RbelMessageRetriever.getInstance();

  @And("current response with attributes iat and exp to be of type Long and iat < exp")
  public void checkIatBeforeExp() throws Exception {
    final Long iat = readClaimAsLongOrThrow("iat");
    final Long exp = readClaimAsLongOrThrow("exp");
    if (iat > exp) {
      throw new Exception("iat has to be < exp");
    }
  }

  @Then("current response with optional attribute contacts is either not present or a JSON Array")
  public void readContactsInCurrentResponse() throws Exception {
    final String rbelPath = "$.body.body.metadata.federation_entity.contacts";
    try {
      final List<RbelElement> rbelElements =
          rbelMessageRetriever.findElementsInCurrentResponse(rbelPath);
      final Object contactsArray =
          rbelElements
              .getFirst()
              .getFacet(RbelJsonFacet.class)
              .orElseThrow(() -> new Exception("contacts is not an array"))
              .getJsonElement();
      if (!(contactsArray instanceof ArrayNode)) {
        throw new Exception("contacts is not an array");
      } else if (((ArrayNode) contactsArray).isEmpty()) {
        throw new Exception(
            "contacts is empty, but should either not be present or have at least one entry");
      }
    } catch (final AssertionError e) {
      if (!e.getMessage()
          .contains(
              "Unable to find element in response for rbel path '" + rbelPath + "' in message")) {
        throw e;
      }
    }
  }

  private Long readClaimAsLongOrThrow(final String claimName) {
    return (Long)
        rbelMessageRetriever
            .findElementsInCurrentResponse("$.body.body." + claimName)
            .getFirst()
            .getFacet(RbelValueFacet.class)
            .orElseThrow()
            .getValue();
  }
}
