FROM centos:latest

# install packages
RUN yum -y update && yum -y install \
    openldap-clients \
    openldap-servers \
    && yum clean all

# set timezone
RUN ln -sf /usr/share/zoneinfo/Europe/Berlin /etc/localtime

# setup openldap
WORKDIR /etc/openldap/
COPY config/cert_store/ cert_store/
COPY config/key_store/ key_store/
RUN chmod 600 key_store/10-ee-server-1-key.pem
COPY ldif/ ldif/
COPY config/DB_CONFIG /var/lib/openldap/dc\=keeto\,dc\=io/
COPY schema/keeto-openldap-schema.ldif schema/
COPY config/slapd.ldif .
RUN rm -rf slapd.d/* \
    && slapadd -l slapd.ldif -F slapd.d/ -n0 -v \
    && for file in ldif/*.ldif; do slapadd -l $file -F slapd.d/ -n1 -v; done

EXPOSE 389/tcp 636/tcp

ENTRYPOINT /usr/sbin/slapd -4 -h "ldap:/// ldaps:///" && tail -f /dev/null

