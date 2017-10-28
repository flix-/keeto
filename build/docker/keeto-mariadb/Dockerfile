FROM mariadb:latest

# set timezone
RUN ln -sf /usr/share/zoneinfo/Europe/Berlin /etc/localtime

ENV MYSQL_ROOT_PASSWORD="test123"
ENV MYSQL_DATABASE="keeto-audit"

COPY sql/keeto-audit-ddl.sql /docker-entrypoint-initdb.d/

