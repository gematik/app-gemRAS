#!/bin/bash
mvn clean install -ntp -Dskip.unittests -Dskip.inttests &&
mvn test -ntp &&
mvn verify -ntp -Dskip.unittests -Dcucumber.filter.tags="@Approval and not @OpenBug and not @WiP and not @EntityStatementJwks"
