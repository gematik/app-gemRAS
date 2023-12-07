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

import de.gematik.idp.graserver.exceptions.FdAuthServerException;
import java.net.URISyntaxException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.utils.URIBuilder;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class LocationBuilder {

  public static String createLocationForAuthorizationRequest(
      @NonNull final String redirectUri,
      @NonNull final String clientId,
      @NonNull final String requestUri) {

    try {
      final URIBuilder uriBuilder = new URIBuilder(redirectUri);
      uriBuilder.addParameter("client_id", clientId).addParameter("request_uri", requestUri);
      return uriBuilder.build().toString();
    } catch (final URISyntaxException e) {
      throw new FdAuthServerException(e);
    }
  }

  public static String createLocationForAuthorizationCode(
      final String redirectUri, final String code, final String state) {
    try {
      final URIBuilder redirectUriBuilder = new URIBuilder(redirectUri);
      redirectUriBuilder.addParameter("code", code).addParameter("state", state);
      return redirectUriBuilder.build().toString();
    } catch (final URISyntaxException e) {
      throw new FdAuthServerException(e);
    }
  }
}
