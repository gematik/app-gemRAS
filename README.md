## Overview

Project **gras-global**

* **gra-server:** "Gematik Reference Authorization Server"
  is (together with the idp-server) a reference implementation of a eRezept Authorization Server
  <br>
* **gras-testsuite:** Testsuite for a Relying Party (i.e. the gra-server)

### build project and run unit tests

To quickly check your build environment do in project root:

`mvn clean package`
<br> or skip unit tests: <br>
`mvn clean package -Dskip.unittests`


Assume the entity statement to be tested is under
*https://api.mydiga.de:8443/oidc/.well-known/openid-federation*

### To run the tests against your own server just do the following things:

* edit the tiger-external.yaml and replace "localhost:443" in line 17 with the host and the port of
  your server (i.e.*api.mydiga.de:8443*) 
* Alternatively, you can simply start the gra-server (part of this project) to check test environment.
* edit the tiger-external.yaml and replace ".well-known/openid-federation" in line 20 with the path
  of your entity statement (i.e.*oidc/.well-known/openid-federation*)
* open a shell and enter

```bash
export TIGER_TESTENV_CFGFILE=tiger-external.yaml
mvn clean verify -Dskip.unittests=true -Dcucumber.filter.tags="@EntityStatement or @SignedJwks"
#or   
mvn clean verify -Dskip.unittests=true -Dcucumber.filter.tags="@EntityStatement or @EntityStatementJwks"
```

The difference between the two maven calls is: The first expects your server to use the optional "
signed_jwks_uri" and the latter does not. 
