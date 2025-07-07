# docker/Dockerfile  ───────────────────────────────────────────
FROM quay.io/keycloak/keycloak:26.3.0

USER root

# fix the path relative to build context
COPY docker/kc.conf /opt/keycloak/conf/kc.conf

# fix the path relative to build context (target is at project root level)
COPY target/*kc-provider.jar /opt/keycloak/providers/

USER 1000

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
# prod mode (HTTPS, DB, etc.)
CMD ["start-dev"]
