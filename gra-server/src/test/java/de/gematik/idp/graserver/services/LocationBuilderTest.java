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
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

import de.gematik.idp.graserver.exceptions.FdAuthServerException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LocationBuilderTest {

  @Test
  void createLocationForAuthorizationRequest() {
    assertThat(
            LocationBuilder.createLocationForAuthorizationRequest(
                "myRedirect", "myClient", "myReqUri"))
        .isNotEmpty();
  }

  @Test
  void createLocationForAuthorizationRequest_Exception() {
    assertThatThrownBy(
            () ->
                LocationBuilder.createLocationForAuthorizationRequest(
                    "myInvalidRedirect_\\", "myClient", "myReqUri"))
        .isInstanceOf(FdAuthServerException.class);
  }

  @Test
  void createLocationForAuthorizationCode() {
    assertThat(
            LocationBuilder.createLocationForAuthorizationCode("myRedirect", "myCode", "myState"))
        .isNotEmpty();
  }

  @Test
  void createLocationForAuthorizationCode_Exception() {
    assertThatThrownBy(
            () ->
                LocationBuilder.createLocationForAuthorizationCode(
                    "myInvalidRedirect_\\", "myCode", "myState"))
        .isInstanceOf(FdAuthServerException.class);
  }
}
