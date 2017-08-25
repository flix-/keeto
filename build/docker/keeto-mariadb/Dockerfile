FROM mariadb:latest

ARG NAME
ARG VERSION

# metadata
LABEL org.label-schema.schema-version="1.0" \
    org.label-schema.name=${NAME} \
    org.label-schema.version=${VERSION} \
    org.label-schema.vendor="Sebastian Roland <seroland86@gmail.com>" \
    org.label-schema.url="https://keeto.io"

ENV MYSQL_ROOT_PASSWORD="test123"
ENV MYSQL_DATABASE="keeto-audit"

COPY sql/keeto-audit-ddl.sql /docker-entrypoint-initdb.d/

