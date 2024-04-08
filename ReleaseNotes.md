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
