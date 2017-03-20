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
RUN yum -y update && yum -y install \
    openldap-clients \
    openldap-servers \
    openssl-perl \
    && yum clean all

# setup openldap
WORKDIR /etc/openldap/
COPY config/cert_store/ cert_store/
COPY config/slapd.ldif .
COPY schema/keeto.ldif schema/
COPY ldif/ ldif/
COPY config/key_store/ key_store/
COPY config/DB_CONFIG /var/lib/openldap/dc\=keeto\,dc\=io/
RUN rm -rf slapd.d/* \
    && c_rehash cert_store/ \
    && slapadd -l slapd.ldif -F slapd.d/ -n0 -v \
    && for file in ldif/*.ldif; do slapadd -l $file -F slapd.d/ -n1 -v; done

EXPOSE 389/tcp

ENTRYPOINT /usr/sbin/slapd -4 -h "ldap:///" && tail -f /dev/null

