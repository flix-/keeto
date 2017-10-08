FROM centos:latest

ARG NAME
ARG VERSION
ARG KEETO_RPM_URL
ARG OPENSSH_SRC_URL
ARG SYSLOG_NG_REPO_URL

# metadata
LABEL org.label-schema.schema-version="1.0" \
    org.label-schema.name=${NAME} \
    org.label-schema.version=${VERSION} \
    org.label-schema.vendor="Sebastian Roland <seroland86@gmail.com>" \
    org.label-schema.url="https://keeto.io"

# install packages
RUN yum -y update && yum -y install \
    epel-release \
    gcc \
    make \
    openssl-devel \
    pam-devel \
    wget \
    zlib-devel

WORKDIR /etc/yum.repos.d/
RUN wget ${SYSLOG_NG_REPO_URL}

RUN yum -y install \
    syslog-ng \
    && yum clean all

# set timezone
RUN ln -sf /usr/share/zoneinfo/Europe/Berlin /etc/localtime

# setup syslog-ng
WORKDIR /etc/syslog-ng/
COPY config/syslog-ng.conf .
COPY config/keeto-audit.xml patterndb.d/

# setup local users
RUN useradd -M sshd \
    && useradd -m birgit \
    && useradd -m wolfgang \
    && useradd -m keeto \
    && useradd -m opendj \
    && useradd -m slapd

# setup openssh / keeto
WORKDIR /tmp/
RUN wget ${KEETO_RPM_URL} \
    && yum -y install --setopt=tsflags='' $(echo ${KEETO_RPM_URL##*/}) \
    && yum clean all

# remove openssh-server config file (openssh-server has been installed as dependency)
RUN rm -f /etc/ssh/sshd_config

# compile latest openssh
RUN wget ${OPENSSH_SRC_URL} \
    && tar xvfz openssh-*.tar.gz \
    && cd openssh-* \
    && ./configure --prefix=/usr --sysconfdir=/etc/ssh --with-pam \
    && make \
    && make install \
    && mkdir -p /run/sshd/

# copy keeto config
WORKDIR /etc/ssh/
COPY config/cert_store/ cert_store/
COPY config/sshd /etc/pam.d/
COPY config/keeto.conf .
RUN chmod 600 keeto.conf
COPY config/sshd_config .

# setup entry point
COPY config/entry_point.sh /
RUN chmod 755 /entry_point.sh

EXPOSE 22/tcp

ENTRYPOINT ["/entry_point.sh"]

