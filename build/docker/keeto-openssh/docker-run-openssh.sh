#!/bin/bash

IMAGE_NAME="seroland86/keeto-openssh"
IMAGE_VERSION="0.1.0"
CONTAINER_NAME="keeto-openssh"
HOSTNAME=$CONTAINER_NAME
NETWORK_NAME="keeto-net"
CONTAINER_SSH_PORT=22
HOST_SSH_PORT=1022

docker run -d -h ${HOSTNAME} --name ${CONTAINER_NAME} --network ${NETWORK_NAME} -p 127.0.0.1:${HOST_SSH_PORT}:${CONTAINER_SSH_PORT} --rm -v /dev/log:/dev/log ${IMAGE_NAME}:${IMAGE_VERSION}

