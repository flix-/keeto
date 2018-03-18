FROM centos:latest

ARG SYSLOG_NG_REPO_URL

# install packages
RUN yum -y update && yum -y install \
    epel-release \
    wget

WORKDIR /etc/yum.repos.d/
RUN wget ${SYSLOG_NG_REPO_URL}

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
COPY lib/mariadb-java-client-latest.jar /usr/share/java/
ENV LD_LIBRARY_PATH="/usr/lib/jvm/jre/lib/amd64/server:$LD_LIBRARY_PATH"

COPY config/entry_point.sh /
RUN chmod 755 /entry_point.sh

EXPOSE 601/tcp

#ENTRYPOINT ["/usr/sbin/syslog-ng", "--no-caps", "-F"]
#ENTRYPOINT ["/usr/sbin/syslog-ng", "--no-caps", "-Fd"]
ENTRYPOINT ["/entry_point.sh"]

