FROM eclipse-temurin:21-jre

ARG COMMIT_HASH
ARG VERSION

LABEL de.gematik.vendor="gematik GmbH" \
      maintainer="software-development@gematik.de" \
      de.gematik.app="Gematik Reference Authorization Server" \
      de.gematik.git-repo-name="...gras.git" \
      de.gematik.commit-sha=$COMMIT_HASH \
      de.gematik.version=$VERSION
      
# The STOPSIGNAL instruction sets the system call signal that will be sent to the container to exit
# SIGTERM = 15 - https://de.wikipedia.org/wiki/Signal_(Unix)
STOPSIGNAL SIGTERM

HEALTHCHECK CMD curl --fail http://localhost:8180/actuator/health | grep UP || exit 1

# Default USERID and GROUPID
ARG USERID=11000
ARG GROUPID=11000

# create user and group for non-root execution
RUN addgroup --system --gid $GROUPID appgroup \
 && adduser --system --uid $USERID --ingroup appgroup appuser

COPY --chown=$USERID:$GROUPID gra-server*.jar /app/gra-server.jar
WORKDIR /app

# Run as User (not root)
USER $USERID:$GROUPID

CMD ["java", "-jar", "/app/gra-server.jar"]
