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

package de.gematik.idp.graserver.exceptions.handler;

import de.gematik.idp.graserver.data.GrasErrorResponse;
import de.gematik.idp.graserver.exceptions.FdAuthServerException;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.ValidationException;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
@RequiredArgsConstructor
@Slf4j
public class FdAuthServerExceptionHandler {

  @ExceptionHandler(FdAuthServerException.class)
  public ResponseEntity<GrasErrorResponse> handleGrasException(final FdAuthServerException exc) {
    final GrasErrorResponse body = getBody(exc);
    return new ResponseEntity<>(body, getHeader(), exc.getStatusCode());
  }

  @ExceptionHandler({
    ConstraintViolationException.class,
    ValidationException.class,
    MethodArgumentNotValidException.class
  })
  public ResponseEntity<GrasErrorResponse> handleValidationException(final Exception exc) {
    return handleGrasException(
        (FdAuthServerException)
            ExceptionUtils.getThrowableList(exc).stream()
                .filter(FdAuthServerException.class::isInstance)
                .findAny()
                .orElseGet(
                    () ->
                        new FdAuthServerException(exc.getMessage(), exc, HttpStatus.BAD_REQUEST)));
  }

  @ExceptionHandler(RuntimeException.class)
  public ResponseEntity<GrasErrorResponse> handleRuntimeException(final Exception exc) {
    log.info(
        "RuntimeException, send GrasErrorResponse with exception message: {}", exc.getMessage());
    return handleGrasException(
        new FdAuthServerException(
            "RuntimeException: " + exc.getMessage(), exc, HttpStatus.INTERNAL_SERVER_ERROR));
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  public ResponseEntity<GrasErrorResponse> handleMissingServletRequestParameter(
      final MissingServletRequestParameterException ex) {
    return handleGrasException(
        new FdAuthServerException(ex.getMessage(), ex, HttpStatus.BAD_REQUEST));
  }

  private HttpHeaders getHeader() {
    final HttpHeaders responseHeaders = new HttpHeaders();
    responseHeaders.add(HttpHeaders.CONTENT_TYPE, "application/json; charset=utf-8");
    responseHeaders.remove(HttpHeaders.CACHE_CONTROL);
    responseHeaders.remove(HttpHeaders.PRAGMA);
    return responseHeaders;
  }

  private GrasErrorResponse getBody(final FdAuthServerException exception) {
    return GrasErrorResponse.builder()
        .timestamp(ZonedDateTime.now().toEpochSecond())
        .errorMessage(exception.getReason())
        .build();
  }
}
