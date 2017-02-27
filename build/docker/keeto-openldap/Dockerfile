FROM centos:7

ARG NAME
ARG VERSION

# metadata
LABEL org.label-schema.schema-version="1.0" \
    org.label-schema.name=${NAME} \
    org.label-schema.version=${VERSION} \
    org.label-schema.vendor="Sebastian Roland <seroland86@gmail.com>" \
    org.label-schema.url="https://keeto.io"

# install packages
RUN yum -y update && yum -y install openldap-clients openldap-servers \
    && yum clean all

# setup openldap
RUN rm -rf /etc/openldap/slapd.d/* && mkdir -p /var/lib/openldap/dc\=keeto\,dc\=io
COPY DB_CONFIG /var/lib/openldap/dc\=keeto\,dc\=io/
COPY schema/keeto.ldif /etc/openldap/schema/
COPY ldif /etc/openldap/ldif
WORKDIR /etc/openldap/ldif
RUN slapadd -l 00-slapd.ldif -F /etc/openldap/slapd.d/ -n0 -v && rm -f 00-slapd.ldif \
    && for file in *.ldif; do slapadd -l $file -F /etc/openldap/slapd.d/ -n1 -v; done

EXPOSE 389/tcp

ENTRYPOINT /usr/sbin/slapd -4 && tail -f /dev/null

