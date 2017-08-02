#!/bin/bash

CAT='/usr/bin/cat'
MV='/usr/bin/mv'
RM='/usr/bin/rm'
AWK='/usr/bin/awk'
GREP='/usr/bin/grep'
OPENSSL='/usr/bin/openssl'
SSHKEYGEN='/usr/bin/ssh-keygen'
TMPDIR='openssh-fingerprints-temp'
DSTDIR='openssh-fingerprints'
DIGEST='md5'
ONELINER="ssh-rsa-${DIGEST}.txt"

AMOUNT=50
KEYSIZES=(1024 2048 4096)

mkdir ${TMPDIR}
rm -rf ${DSTDIR}
mkdir ${DSTDIR}

for keysize in "${KEYSIZES[@]}"
do
    for i in $(seq -w $AMOUNT)
    do
        FILENAME="ssh-${keysize}-${DIGEST}-${i}"
        ${SSHKEYGEN} -b ${keysize} -C "" -P "" -f ${TMPDIR}/${FILENAME}
        echo -n "${FILENAME}.pem:" >> ${ONELINER}
        HASH=$(${SSHKEYGEN} -E ${DIGEST} -lf ${TMPDIR}/${FILENAME} | \
            ${AWK} -F" " '{print $2}' | ${GREP} -ioP "${DIGEST}:\K.*")
        echo "${HASH}" >> ${ONELINER}
        ${OPENSSL} rsa -in ${TMPDIR}/${FILENAME} -pubout \
            -out ${TMPDIR}/${FILENAME}.pem
    done
done


${MV} ${TMPDIR}/*.pem ${DSTDIR}
${MV} ${ONELINER} ${DSTDIR}
${RM} -rf ${TMPDIR}

