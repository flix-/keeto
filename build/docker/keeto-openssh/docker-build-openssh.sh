#!/bin/bash

NAME="seroland86/keeto-openssh"
VERSION="0.2.0-beta"
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
KEETO_RPM_LINK="https://keeto.io/static/downloads/keeto-0.2.0-beta/keeto-0.2.0-0.2.beta.el7.centos.x86_64.rpm"
KEETO_RPM_NAME="$(echo ${KEETO_RPM_LINK} | awk -F '/' '{print $7}')"

docker build --build-arg NAME=${NAME} \
    --build-arg VERSION=${VERSION} \
    --build-arg BUILD_DATE=${BUILD_DATE} \
    --build-arg KEETO_RPM_LINK=${KEETO_RPM_LINK} \
    --build-arg KEETO_RPM_NAME=${KEETO_RPM_NAME} \
    -t ${NAME}:${VERSION} .

