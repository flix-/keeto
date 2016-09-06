#!/bin/bash

CAT='/usr/bin/cat'
MV='/usr/bin/mv'
RM='/usr/bin/rm'
SED='/usr/bin/sed'
OPENSSL='/usr/bin/openssl'
SSHKEYGEN='/usr/bin/ssh-keygen'
TMPDIR='openssh-keys-temp'
DSTDIR='openssh-keys'
ONELINER='ssh-rsa.txt'

AMOUNT=49
KEYSIZES=(1024 2048 4096)

mkdir ${TMPDIR}
rm -rf ${DSTDIR}
mkdir ${DSTDIR}

for keysize in "${KEYSIZES[@]}"
do
    for i in $(seq -w 0 $AMOUNT)
    do
        FILENAME="ssh-${keysize}-${i}"
        ${SSHKEYGEN} -b ${keysize} -C "" -P "" -f ${TMPDIR}/${FILENAME}
        echo -n "${FILENAME}.pem:" >> ${ONELINER}
        ${OPENSSL} rsa -in ${TMPDIR}/${FILENAME} -pubout \
            -out ${TMPDIR}/${FILENAME}.pem
        ${CAT} ${TMPDIR}/${FILENAME}.pub | ${SED} 's/ *$//' >> ${ONELINER}
    done
done


${MV} ${TMPDIR}/*.pem ${DSTDIR}
${MV} ${ONELINER} ${DSTDIR}
${RM} -rf ${TMPDIR}

