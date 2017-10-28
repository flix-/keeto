FROM centos:latest

# install packages
RUN yum -y update && yum -y install \
    epel-release \
    patch \
    file \
    which \
    flex \
    bison \
    gcc \
    make \
    wget \
    java-1.8.0-openjdk-devel \
    glib2-devel \
    openssl-devel \
    json-c-devel \
    && yum clean all

# set timezone
RUN ln -sf /usr/share/zoneinfo/Europe/Berlin /etc/localtime

# compile syslog-ng
COPY patches/java-logmsg-proxy.patch /tmp/
WORKDIR /usr/local/src/
RUN wget https://github.com/balabit/syslog-ng/releases/download/syslog-ng-3.12.1/syslog-ng-3.12.1.tar.gz \
    && tar xvfz syslog-ng-*.tar.gz \
    && cd /usr/local/src/syslog-ng-*/ \
    && patch -p1 < /tmp/java-logmsg-proxy.patch \
    && ./configure --prefix=/usr --libexecdir=/usr/lib --sbindir=/sbin \
        --localstatedir=/var/lib/syslog-ng --datadir=/usr/share \
        --sysconfdir=/etc/syslog-ng --enable-shared --disable-static \
        --enable-dynamic-linking --enable-java \
    && make \
    && make install \
    && ldconfig

# setup syslog-ng
WORKDIR /etc/syslog-ng/
COPY config/syslog-ng.conf .
COPY config/keeto-audit.xml patterndb.d/
COPY destinations/ destinations/

RUN mkdir -p /usr/share/java/
COPY lib/mariadb-java-client-2.1.2.jar /usr/share/java/
ENV LD_LIBRARY_PATH="/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.151-1.b12.el7_4.x86_64/jre/lib/amd64/server:$LD_LIBRARY_PATH"

COPY config/entry_point.sh /
RUN chmod 755 /entry_point.sh

EXPOSE 601/tcp

#ENTRYPOINT ["/usr/sbin/syslog-ng", "--no-caps", "-F"]
#ENTRYPOINT ["/usr/sbin/syslog-ng", "--no-caps", "-Fd"]
ENTRYPOINT ["/entry_point.sh"]

