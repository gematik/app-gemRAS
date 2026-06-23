FROM gematik1/osadl-alpine-openjdk21-jre:1.0.12@sha256:c555a8bc3f15bbd957c99486ac8100539ac6021089612401aa646b12f7f6698f

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

HEALTHCHECK --interval=15s \
            --timeout=10s \
            --start-period=30s \
            --retries=3 \
  CMD ["/usr/bin/wget", "--quiet", "--tries=1", "--spider", \
       "http://localhost:8180/actuator/health"]

# Default USERID and GROUPID
ARG USERID=11000
ARG GROUPID=11000

# Run as User (not root)
USER $USERID:$GROUPID

COPY --chown=$USERID:$GROUPID gra-server*.jar /app/gra-server.jar
WORKDIR /app

# Run as User (not root)
USER $USERID:$GROUPID

CMD ["java", "-jar", "/app/gra-server.jar"]
