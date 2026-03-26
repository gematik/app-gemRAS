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

package de.gematik.idp.graserver.validation;

import de.gematik.idp.graserver.configuration.FdAuthServerConfiguration;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class RedirectUriValidator implements ConstraintValidator<ValidateRedirectUri, String> {

  final FdAuthServerConfiguration fdAuthServerConfiguration;

  @Override
  public boolean isValid(final String redirectUri, final ConstraintValidatorContext cxt) {
    if (redirectUri == null) {
      cxt.disableDefaultConstraintViolation();
      cxt.buildConstraintViolationWithTemplate("redirectUri is missing").addConstraintViolation();
      return false;
    }
    if (!fdAuthServerConfiguration.getRedirectUris().contains(redirectUri)) {
      cxt.disableDefaultConstraintViolation();
      cxt.buildConstraintViolationWithTemplate("unregistered redirect_uri")
          .addConstraintViolation();
      return false;
    }
    return true;
  }
}
