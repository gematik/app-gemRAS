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

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.gematik.idp.graserver.configuration.FdAuthServerConfiguration;
import de.gematik.idp.graserver.data.RedirectUri;
import jakarta.validation.ConstraintValidatorContext;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ValidateRedirectUriTest {

  @Mock FdAuthServerConfiguration fdAuthServerConfiguration;
  RedirectUriValidator redirectUriValidator;
  ConstraintValidatorContext context;
  ConstraintValidatorContext.ConstraintViolationBuilder builder;

  @BeforeEach
  void setUp() {
    redirectUriValidator = new RedirectUriValidator(fdAuthServerConfiguration);
    context = mock(ConstraintValidatorContext.class);
    builder = mock(ConstraintValidatorContext.ConstraintViolationBuilder.class);
  }

  @Test
  void testValidateRedirectUri_validUri() {
    when(fdAuthServerConfiguration.getRedirectUris())
        .thenReturn(List.of("https://idpfadi.dev.gematik.solutions/auth"));
    assertThat(redirectUriValidator.isValid("https://idpfadi.dev.gematik.solutions/auth", context))
        .isTrue();
  }

  @Test
  void testValidateRedirectUri_invalidUri() {
    when(fdAuthServerConfiguration.getRedirectUris())
        .thenReturn(List.of("https://idpfadi.dev.gematik.solutions/auth"));
    when(context.buildConstraintViolationWithTemplate(anyString())).thenReturn(builder);
    when(builder.addConstraintViolation()).thenReturn(context);
    assertThat(redirectUriValidator.isValid("invalidRedirectUri", context)).isFalse();
  }

  @Test
  void testValidateRedirectUri_nullUri() {
    final RedirectUri emptyRedirectUri = new RedirectUri(null);
    when(context.buildConstraintViolationWithTemplate(anyString())).thenReturn(builder);
    when(builder.addConstraintViolation()).thenReturn(context);
    assertThat(redirectUriValidator.isValid(emptyRedirectUri.toString(), context)).isFalse();
  }
}
