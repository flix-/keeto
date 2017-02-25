#!/bin/bash

NETWORK_NAME="keeto-net"
SUBNET="192.168.86.0/29"

docker network create --subnet ${SUBNET} ${NETWORK_NAME}
./keeto-openldap/docker-run-openldap.sh
./keeto-openssh/docker-run-openssh.sh

