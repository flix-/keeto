#!/bin/bash

IMAGE_NAME="seroland86/keeto-openldap"
IMAGE_VERSION="0.1.0"

docker build -t ${IMAGE_NAME}:${IMAGE_VERSION} .

