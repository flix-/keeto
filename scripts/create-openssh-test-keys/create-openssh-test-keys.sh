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
AMOUNT=1

mkdir ${TMPDIR}
rm -rf ${DSTDIR}
mkdir ${DSTDIR}
for i in $(seq 0 $AMOUNT)
do
	FILENAME="ssh-${i}"
	${SSHKEYGEN} -C "" -P "" -f ${TMPDIR}/${FILENAME}
	echo -n "ssh-${i}.pem:" >> ${ONELINER}
	${OPENSSL} rsa -in ${TMPDIR}/${FILENAME} -pubout \
        -out ${TMPDIR}/${FILENAME}.pem
	${CAT} ${TMPDIR}/${FILENAME}.pub | ${SED} 's/ *$//' >> ${ONELINER}
done

${MV} ${TMPDIR}/*.pem ${DSTDIR}
${MV} ${ONELINER} ${DSTDIR}
${RM} -rf ${TMPDIR}

