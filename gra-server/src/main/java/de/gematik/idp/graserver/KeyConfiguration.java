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

package de.gematik.idp.graserver;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.KeyUtility;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.data.KeyConfig;
import de.gematik.idp.data.KeyConfigurationBase;
import de.gematik.idp.file.ResourceReader;
import de.gematik.idp.graserver.configuration.FdAuthServerConfiguration;
import de.gematik.idp.graserver.exceptions.FdAuthServerException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.StreamUtils;

@Configuration
@RequiredArgsConstructor
public class KeyConfiguration implements KeyConfigurationBase {

  private final ResourceLoader resourceLoader;

  private final FdAuthServerConfiguration fdAuthServerConfiguration;

  @Bean
  public FederationPrivKey esSigPrivKey() {
    return getFederationPrivKey(fdAuthServerConfiguration.getEsSigPrivKeyConfig());
  }

  @Bean
  public FederationPubKey esSigPubKey() {
    return getFederationPubkey(fdAuthServerConfiguration.getEsSigPubKeyConfig());
  }

  @Bean
  public FederationPrivKey tokenSigPrivKey() {
    return getFederationPrivKey(fdAuthServerConfiguration.getTokenSigPrivKeyConfig());
  }

  @Bean
  public FederationPubKey tokenSigPubKey() {
    return getFederationPubkey(fdAuthServerConfiguration.getTokenSigPubKeyConfig());
  }

  @Bean
  public FederationPrivKey tlsClientPrivKey() {
    return getFederationPrivKeyFromP12(fdAuthServerConfiguration.getTlsClientPrivKeyConfig());
  }

  @Bean
  public FederationPubKey tlsClientPubKey() {
    return getFederationPubKeyFromP12(fdAuthServerConfiguration.getTlsClientPrivKeyConfig());
  }

  @Bean
  public FederationPubKey tlsClientPubKeyRotation() {
    return getFederationPubKeyFromP12(
        fdAuthServerConfiguration.getTlsClientPrivKeyRotationConfig());
  }

  @Bean
  public FederationPrivKey encPrivKey() {
    return getFederationPrivKey(fdAuthServerConfiguration.getEncPrivKeyConfig());
  }

  @Bean
  public FederationPubKey encPubKey() {
    return getFederationPubkey(fdAuthServerConfiguration.getEncPubKeyConfig());
  }

  @Bean
  public IdpJwtProcessor jwtProcessorEsSigPrivKey() {
    return new IdpJwtProcessor(
        esSigPrivKey().getIdentity().getPrivateKey(), esSigPrivKey().getKeyId());
  }

  @Bean
  public IdpJwtProcessor jwtProcessorTokenSigPrivKey() {
    return new IdpJwtProcessor(
        tokenSigPrivKey().getIdentity().getPrivateKey(), tokenSigPrivKey().getKeyId());
  }

  @Bean
  public Key symmetricEncryptionKey() {
    return new SecretKeySpec(
        DigestUtils.sha256(fdAuthServerConfiguration.getSymmetricEncryptionKey()), "AES");
  }

  @Bean
  public PublicKey fedmasterSigKey() throws IOException {
    return KeyUtility.readX509PublicKey(
        ResourceReader.getFileFromResourceAsTmpFile(
            fdAuthServerConfiguration.getFedmasterSigPubKeyFilePath()));
  }

  private FederationPrivKey getFederationPrivKey(final KeyConfig keyConfiguration) {
    try {
      final PrivateKey privateKey =
          KeyUtility.readX509PrivateKeyPlain(
              ResourceReader.getFileFromResourceAsTmpFile(keyConfiguration.getFileName()));
      final PkiIdentity pkiIdentity = new PkiIdentity();
      pkiIdentity.setPrivateKey(privateKey);
      final FederationPrivKey federationPrivKey = new FederationPrivKey(pkiIdentity);
      federationPrivKey.setKeyId(keyConfiguration.getKeyId());
      federationPrivKey.setUse(Optional.of(keyConfiguration.getUse()));
      federationPrivKey.setAddX5c(Optional.of(keyConfiguration.isX5cInJwks()));
      return federationPrivKey;
    } catch (final IOException | NullPointerException e) {
      throw new FdAuthServerException(
          "Error while loading GRA-Server Key from resource '"
              + keyConfiguration.getFileName()
              + "'",
          e);
    }
  }

  private FederationPrivKey getFederationPrivKeyFromP12(final KeyConfig keyConfiguration) {
    final Resource resource = resourceLoader.getResource(keyConfiguration.getFileName());
    try (final InputStream inputStream = resource.getInputStream()) {
      final PkiIdentity pkiIdentity =
          CryptoLoader.getIdentityFromP12(StreamUtils.copyToByteArray(inputStream), "00");
      return getFederationPrivKey(keyConfiguration, pkiIdentity);
    } catch (final IOException | NullPointerException e) {
      throw new FdAuthServerException(
          "Error while loading GRA-Server Key from resource '"
              + keyConfiguration.getFileName()
              + "'",
          e);
    }
  }

  private FederationPubKey getFederationPubKeyFromP12(final KeyConfig keyConfiguration) {
    final Resource resource = resourceLoader.getResource(keyConfiguration.getFileName());
    try (final InputStream inputStream = resource.getInputStream()) {
      final PkiIdentity pkiIdentity =
          CryptoLoader.getIdentityFromP12(StreamUtils.copyToByteArray(inputStream), "00");
      final FederationPubKey federationPubKey = new FederationPubKey();
      federationPubKey.setKeyId(keyConfiguration.getKeyId());
      federationPubKey.setUse(Optional.of(keyConfiguration.getUse()));
      if (keyConfiguration.isX5cInJwks()) {
        federationPubKey.setCertificate(Optional.of(pkiIdentity.getCertificate()));
      }
      return federationPubKey;
    } catch (final IOException | NullPointerException e) {
      throw new FdAuthServerException(
          "Error while loading GRA-Server Key from resource '"
              + keyConfiguration.getFileName()
              + "'",
          e);
    }
  }

  private FederationPubKey getFederationPubkey(final KeyConfig keyConfiguration) {
    try {
      final PublicKey publicKey =
          KeyUtility.readX509PublicKey(
              ResourceReader.getFileFromResourceAsTmpFile(keyConfiguration.getFileName()));
      final FederationPubKey federationPubKey = new FederationPubKey();
      federationPubKey.setPublicKey(Optional.ofNullable(publicKey));
      federationPubKey.setKeyId(keyConfiguration.getKeyId());
      federationPubKey.setUse(Optional.of(keyConfiguration.getUse()));
      return federationPubKey;
    } catch (final IOException e) {
      throw new FdAuthServerException(
          "Error while loading GRA-Server Key from resource '"
              + keyConfiguration.getFileName()
              + "'",
          e);
    }
  }
}
