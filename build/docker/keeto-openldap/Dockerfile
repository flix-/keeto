FROM centos:7

# install packages
RUN yum -y update && yum -y install openldap-clients openldap-servers \
    && yum clean all

# setup openldap
RUN rm -rf /etc/openldap/slapd.d/* && mkdir -p /var/lib/openldap/dc\=keeto\,dc\=io
COPY DB_CONFIG /var/lib/openldap/dc\=keeto\,dc\=io/
COPY schema/keeto.ldif /etc/openldap/schema/
COPY ldif /etc/openldap/
RUN slapadd -l /etc/openldap/slapd.ldif -F /etc/openldap/slapd.d/ -n0 -v \
    && slapadd -l /etc/openldap/keeto-add-skeleton.ldif -F /etc/openldap/slapd.d/ -n1 -v \
    && slapadd -l /etc/openldap/keeto-add-people.ldif -F /etc/openldap/slapd.d/ -n1 -v \
    && slapadd -l /etc/openldap/keeto-add-technical-accounts.ldif -F /etc/openldap/slapd.d/ -n1 -v \
    && slapadd -l /etc/openldap/keeto-add-groups-people.ldif -F /etc/openldap/slapd.d/ -n1 -v \
    && slapadd -l /etc/openldap/keeto-add-groups-technical-accounts.ldif -F /etc/openldap/slapd.d/ -n1 -v \
    && slapadd -l /etc/openldap/keeto-add-keystore-options.ldif -F /etc/openldap/slapd.d/ -n1 -v \
    && slapadd -l /etc/openldap/keeto-add-direct-access-profiles-project-keeto-dev.ldif -F /etc/openldap/slapd.d/ -n1 -v \
    && slapadd -l /etc/openldap/keeto-add-access-on-behalf-profiles-project-keeto-dev.ldif -F /etc/openldap/slapd.d/ -n1 -v \
    && slapadd -l /etc/openldap/keeto-add-ssh-servers.ldif -F /etc/openldap/slapd.d/ -n1 -v

EXPOSE 389/tcp

ENTRYPOINT /usr/sbin/slapd -4 && tail -f /dev/null

