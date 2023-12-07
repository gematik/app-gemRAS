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

import static de.gematik.idp.IdpConstants.IDP_LIST_ENDPOINT;

import de.gematik.idp.graserver.configuration.FdAuthServerConfiguration;
import de.gematik.idp.token.JsonWebToken;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Optional;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EntityListService {

  private static final String OLD_DEFAULT_ENTITY_LIST_AS_JWS =
      "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InB1a19mZWRfc2lnIn0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjY0MDc3IiwiaWF0IjoxNjY1MTM3MjY0LCJleHAiOjE2NjUxMzcyNjUsImlkcF9lbnRpdHkiOlt7Im9yZ2FuaXphdGlvbl9uYW1lIjoiSURQX1NFS1RPUkFMIiwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgyIiwibG9nb191cmkiOiJ0b2RvLWxvZ28iLCJ1c2VyX3R5cGVfc3VwcG9ydGVkIjoiSVAifV19.da166z60dpM4C6plZu-cha38jivMGLjJhF8Gb1fe8uUwNcx-yjZh_dexqe_NoszT6LJVpGSdhuRe60ow5RJCOw";
  private final FdAuthServerConfiguration fdAuthServerConfiguration;
  private String entityListAsJws = OLD_DEFAULT_ENTITY_LIST_AS_JWS;

  public String getEntityList() {
    updateEntityListIfExpiredAndNewIsAvailable();
    return entityListAsJws;
  }

  private void updateEntityListIfExpiredAndNewIsAvailable() {
    final Map<String, Object> bodyClaims = new JsonWebToken(entityListAsJws).getBodyClaims();
    final Long exp = (Long) bodyClaims.get("exp");
    if (isExpired(exp)) {
      final Optional<String> s = fetchEntityList();
      s.ifPresent(
          value -> {
            entityListAsJws = value;
            log.debug("EntityList updated to: " + entityListAsJws);
          });
    }
  }

  private boolean isExpired(final Long exp) {
    final ZonedDateTime currentUtcTime = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime expiredUtcTime =
        ZonedDateTime.ofInstant(Instant.ofEpochSecond(exp), ZoneOffset.UTC);
    return currentUtcTime.isAfter(expiredUtcTime);
  }

  private Optional<String> fetchEntityList() {
    final String fedmasterEntityListUrl =
        fdAuthServerConfiguration.getFedmasterUrl() + IDP_LIST_ENDPOINT;
    try {
      final HttpResponse<String> response = Unirest.get(fedmasterEntityListUrl).asString();
      if (response.isSuccess()) {
        return Optional.of(new JsonWebToken(response.getBody()).getRawString());
      }
    } catch (final UnirestException e) {
      log.error("Creation of JsonWebToken from fetched entity list failed.");
    }
    return Optional.empty();
  }
}
