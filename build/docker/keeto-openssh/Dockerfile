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
RUN yum -y update && yum -y install epel-release
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
RUN useradd -m oliver \
    && useradd -m sebastian \
    && useradd -m bjoern \
    && useradd -m db2admin \
    && useradd -m postgres

# setup openssh / keeto
WORKDIR /tmp
RUN wget ${KEETO_RPM_URL} && rpm -i $(echo ${KEETO_RPM_URL##*/})
COPY configs/keeto.conf /etc/ssh/
RUN chmod 600 /etc/ssh/keeto.conf
COPY configs/sshd_config /etc/ssh/
COPY configs/sshd /etc/pam.d/
COPY cert_store /etc/ssh/cert_store/
# in older versions of c_rehash only .pem files are considered. create symlinks as a workaround.
RUN ln -s /etc/ssh/cert_store/root.crl /etc/ssh/cert_store/root.crl.pem \
    && ln -s /etc/ssh/cert_store/int-user.crl /etc/ssh/cert_store/int-user.crl.pem \
    && c_rehash /etc/ssh/cert_store/
RUN mkdir -p /run/sshd && ssh-keygen -A

EXPOSE 22/tcp

ENTRYPOINT ["/usr/sbin/sshd", "-D"]

