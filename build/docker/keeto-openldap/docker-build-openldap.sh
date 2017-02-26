#!/bin/bash

NAME="seroland86/keeto-openldap"
VERSION="0.2.0-beta"
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

docker build --build-arg NAME=${NAME} \
    --build-arg VERSION=${VERSION} \
    --build-arg BUILD_DATE=${BUILD_DATE} \
    -t ${NAME}:${VERSION} .

