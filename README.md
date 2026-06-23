<img align="right" width="250" height="47" src="https://raw.githubusercontent.com/gematik/gematik.github.io/master/Gematik_Logo_Flag_With_Background.png"/> <br/> 

# Gematik Reference Authorization Server

![GitHub Latest Release)](https://img.shields.io/github/v/release/gematik/app-gemRAS?label=release&logo=github) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## About The Project

Project **gras-global**

* **gra-server:** "Gematik Reference Authorization Server"
  is (together with the idp-server) a reference implementation of a eRezept Authorization Server
  <br>
* **gras-testsuite:** Testsuite for a Relying Party (i.e. the gra-server)

## Getting Started

### Release Notes

See [ReleaseNotes.md](./ReleaseNotes.md) for all information regarding the (newest) releases.

### build project and run unit tests

To quickly check your build environment do in project root:

`mvn clean package`
<br> or skip unit tests: <br>
`mvn clean package -Dskip.unittests`

Assume the entity statement to be tested is under
*https://api.mydiga.de:8443/oidc/.well-known/openid-federation*

### To run the tests against the gra-server (as one module of this project)do:

```bash
export TIGER_TESTENV_CFGFILE=tiger-local.yaml
mvn verify -Dskip.unittests=true -Dcucumber.filter.tags="@EntityStatement and not @TCID:RP_ENTITY_STATEMENT_003"
```

In case of success, you should see something like this:

```
[INFO]   - Full Report: file:///Users/.../app-gemRas/gras-testsuite/target/site/serenity/index.html
[INFO] GENERATING SINGLE PAGE HTML REPORT FROM /Users/.../app-gemRas/gras-testsuite/target/site/serenity
[INFO] OUTPUT WILL BE GENERATED IN /Users/.../app-gemRas/gras-testsuite/target/site/serenity
[INFO] FOUND 9 TEST OUTCOMES
[INFO]   - Single Page HTML Summary: file:///Users/.../app-gemRas/gras-testsuite/target/site/serenity/serenity-summary.html
[INFO]   - JSON Summary: file:///Users/.../app-gemRas/gras-testsuite/target/site/serenity/serenity-summary.json
[INFO]
[INFO] --- failsafe:3.5.5:verify (default) @ gras-testsuite ---
[INFO] ------------------------------------------------------------------------
[INFO] Reactor Summary for gras-global 5.2.1:
[INFO]
[INFO] gras-global ........................................ SUCCESS [  0.737 s]
[INFO] gra-server ......................................... SUCCESS [  0.934 s]
[INFO] Code Coverage Reports .............................. SUCCESS [  0.239 s]
[INFO] gras-testsuite ..................................... SUCCESS [ 30.536 s]
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
```

The file .../gras-testsuite/target/site/serenity/index.html contains a detailed report of the test
results.

### To run the tests against your own server just do the following things:

* edit the tiger-external.yaml and replace "localhost:443" in line 17 with the host and the port of
  your server (i.e.*api.mydiga.de:8443*)
* Alternatively, you can simply start the gra-server (part of this project) to check test
  environment.
* edit the tiger-external.yaml and replace ".well-known/openid-federation" in line 20 with the path
  of your entity statement (i.e.*oidc/.well-known/openid-federation*)
* open a shell and enter

The keys
`gra-server/src/main/resources/keys/ref-privkey.pem`
`gra-server/src/main/resources/keys/ref-privkey-rotation.pem`
are added for unit tests only and can be published.

```bash
export TIGER_TESTENV_CFGFILE=tiger-external.yaml
mvn clean verify -Dskip.unittests=true -Dcucumber.filter.tags="@EntityStatement or @SignedJwks"
#or   
mvn clean verify -Dskip.unittests=true -Dcucumber.filter.tags="@EntityStatement or @EntityStatementJwks"
```

The difference between the two maven calls is: The first expects your server to use the optional "
signed_jwks_uri" and the latter does not.

### gra-server logging

Logs are written via log4j2 to console.

Export `LOG_LEVEL_GEMATIK=<YOUR LOG LEVEL>` to set the log level.
Export REQUEST_LOGGING_ENABLED=true to enable request logging.
See also [GRAS application.yml](gra-server/src/main/resources/application.yml) for configuration.

## License

Copyright 2023-2026 gematik GmbH

Apache License, Version 2.0

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under
the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the
   license conditions for use. These are regularly typical conditions in connection with open source
   or free software. Programs described/provided/linked here are free software, unless otherwise
   stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal in the Software
   without restriction, including without limitation the rights to use, copy, modify, merge,
   publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to
   whom the Software is furnished to do so, subject to the following conditions:
    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all
       copies or substantial portions of the Software.
    2. The software is provided "as is" without warranty of any kind, either express or implied,
       including, but not limited to, the warranties of fitness for a particular purpose,
       merchantability, and/or non-infringement. The authors or copyright holders shall not be
       liable in any manner whatsoever for any damages or other claims arising from, out of or in
       connection with the software or the use or other dealings with the software, whether in an
       action of contract, tort, or otherwise.
    3. The software is the result of research and development activities, therefore not necessarily
       quality assured and without the character of a liable product. For this reason, gematik does
       not provide any support or other user assistance (unless otherwise stated in individual cases
       and without justification of a legal obligation). Furthermore, there is no claim to further
       development and adaptation of the results to a more current state of the art.
3. Gematik may remove published results temporarily or permanently from the place of publication at
   any time without prior notice or justification.
4. Please note: Parts of this code may have been generated using AI-supported technology. Please
   take this into account, especially when troubleshooting, for security analyses and possible
   adjustments.

## Contact

We take open source license compliance very seriously. We are always striving to achieve compliance
at all times and to improve our processes.
This software is currently being tested to ensure its technical quality and legal compliance. Your
feedback is highly valued.
If you find any issues or have any suggestions or comments, or if you see any other ways in which we
can improve, please open an issue or pull request.
