FROM centos:latest

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
    epel-release \
    wget

WORKDIR /etc/yum.repos.d/
RUN wget https://copr.fedorainfracloud.org/coprs/czanik/syslog-ng311/repo/epel-7/czanik-syslog-ng311-epel-7.repo

RUN yum -y install \
    syslog-ng \
    syslog-ng-java \
    && yum clean all

# set timezone
RUN ln -sf /usr/share/zoneinfo/Europe/Berlin /etc/localtime

# setup syslog-ng
WORKDIR /etc/syslog-ng/
COPY config/syslog-ng.conf .
COPY config/keeto-audit.xml patterndb.d/
COPY destinations/ destinations/

RUN mkdir -p /usr/share/java/
COPY lib/mariadb-java-client-2.1.2.jar /usr/share/java/
ENV LD_LIBRARY_PATH="/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.144-0.b01.el7_4.x86_64/jre/lib/amd64/server:$LD_LIBRARY_PATH"

COPY config/entry_point.sh /
RUN chmod 755 /entry_point.sh

EXPOSE 601/tcp

#ENTRYPOINT ["/usr/sbin/syslog-ng", "--no-caps", "-F"]
#ENTRYPOINT ["/usr/sbin/syslog-ng", "--no-caps", "-Fd"]
ENTRYPOINT ["/entry_point.sh"]

