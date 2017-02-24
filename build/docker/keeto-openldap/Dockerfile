FROM centos:7

# install packages
RUN yum -y update && yum -y install openldap-servers openldap-clients

# setup openldap
RUN rm -rf /etc/openldap/slapd.d/*
RUN mkdir -p /var/lib/openldap/dc\=keeto\,dc\=io
ADD DB_CONFIG /var/lib/openldap/dc\=keeto\,dc\=io
ADD schema/keeto.ldif /etc/openldap/schema
ADD ldif/*.ldif /etc/openldap/
RUN slapadd -l /etc/openldap/slapd.ldif -F /etc/openldap/slapd.d/ -n0
RUN slapadd -l /etc/openldap/keeto-add-skeleton.ldif \
    && slapadd -l /etc/openldap/keeto-add-ssh-server.ldif \
    && slapadd -l /etc/openldap/keeto-add-people.ldif \
    && slapadd -l /etc/openldap/keeto-add-technical-accounts.ldif \
    && slapadd -l /etc/openldap/keeto-add-people-groups.ldif \
    && slapadd -l /etc/openldap/keeto-add-technical-account-groups.ldif \
    && slapadd -l /etc/openldap/keeto-add-direct-access-profiles.ldif \
    && slapadd -l /etc/openldap/keeto-add-access-on-behalf-profiles.ldif \
    && slapadd -l /etc/openldap/keeto-add-keystore-options.ldif

EXPOSE 389/tcp

CMD /usr/sbin/slapd -4 && tail -f /dev/null

