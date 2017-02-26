#!/bin/bash

IMAGE_NAME="seroland86/keeto-openldap"
IMAGE_VERSION="0.2.0-beta"
CONTAINER_NAME="keeto-openldap"
HOSTNAME=$CONTAINER_NAME
NETWORK_NAME="keeto-net"
CONTAINER_LDAP_PORT=389
HOST_LDAP_PORT=1389

docker run -d -h ${HOSTNAME} --name ${CONTAINER_NAME} --network ${NETWORK_NAME} -p 127.0.0.1:${HOST_LDAP_PORT}:${CONTAINER_LDAP_PORT} --rm -v /dev/log:/dev/log ${IMAGE_NAME}:${IMAGE_VERSION}

