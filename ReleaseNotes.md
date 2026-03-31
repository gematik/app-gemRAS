# Release 5.2.1

- fix unit tests
- update dependencies

# Release 5.2.0

- migrate to spring boot 4.0.x
- migrate to jackson 3.x
- implement token endpoint MVP
- update dependencies

# Release 5.1.1

- refactor setting/printing log level - see [gras logging](README.md#gra-server-logging)
- add claim for ti features supported
- add feature test for new claim in entity statement
- update dependencies

# Release 5.0.1

- Java 21
- switch to docker base image eclipse-temurin:21-jre
- update dependencies
- set values for acr/amr in auth code to values from id token
- add another tls cert in signed_jwks for key rotation
- change ttl of entity statement to 2 hours
- read sig key from signed_jwks

# Release 4.1.2

- update dependencies
- improve logging (line numbers)
- remove parent pom from testsuite to avoid dependency conflicts
- add local redirect_uri to entity statement
- refactor keys
- implements https://github.com/gematik/app-gemRAS/issues/6

# Release 4.0.1

- switch to docker base image eclipse-temurin:17-jre
- rename docker images
- update dependencies

# Release 4.0.0

- refactor key handling, use PrivateKey instead of p12 container when certificate is not required

# Release 3.0.2

- add unit test
- add tests in testsuite

# Release 3.0.0

- source code for server behind https://idpfadi.dev.gematik.solutions (except certificates and keys)
- basic testsuite for authorization server (one simple testcase, further development in progress)
