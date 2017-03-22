FROM centos:7

ARG NAME
ARG VERSION
ARG KEETO_RPM_URL

# metadata
LABEL org.label-schema.schema-version="1.0" \
    org.label-schema.name=${NAME} \
    org.label-schema.version=${VERSION} \
    org.label-schema.vendor="Sebastian Roland <seroland86@gmail.com>" \
    org.label-schema.url="https://keeto.io"

# install packages
RUN yum -y update && yum -y install \
    epel-release

RUN yum -y install \
    wget \
    pam \
    openssl-libs \
    openssl-perl \
    openldap \
    libconfuse \
    openssh-server \
    && yum clean all

# setup local users
RUN useradd -m birgit \
    && useradd -m wolfgang \
    && useradd -m keeto \
    && useradd -m opendj \
    && useradd -m slapd

# setup openssh / keeto
WORKDIR /tmp/
RUN wget ${KEETO_RPM_URL} && rpm -i $(echo ${KEETO_RPM_URL##*/})
WORKDIR /etc/ssh/
COPY config/cert_store/ cert_store/
COPY config/keeto.conf .
COPY config/sshd_config .
COPY config/sshd /etc/pam.d/
RUN mkdir -p /run/sshd/ && ssh-keygen -A

EXPOSE 22/tcp

ENTRYPOINT ["/usr/sbin/sshd", "-D"]

