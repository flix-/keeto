#!/bin/bash

########################################
#
# create multi-level ca and end user
# certificates...
#
# never use this script to create a
# serious ca. its for testing purposes
# only.
#
# author: sebastian roland
# date: 21.03.2017
#
########################################

### BEGIN CONFIG ###

# path to root directory of testing env
ROOT='/home/sebastian/documents/programming/ca'
# path to openssl
OPENSSL='/usr/bin/openssl'
# prefix for subject dn
SUBJECT_PREFIX='/DC=io/DC=keeto'

# validity in days for root ca
ROOT_CA_VALIDITY=36500

# server fqdn
SERVER_FQDN='keeto-openldap'

### END CONFIG ###

# make var accessible for openssl config
PATHLEN=0
export ROOT PATHLEN

### BEGIN FUNCTIONS ###

usage()
{
    echo "${0} init <path_to_openssl_config>"
    echo "${0} create_ee <server|email|user> <openssl>"

    exit -1
}

env_already_created()
{
    if [ -f "${ROOT}/tmp/.init-complete" ]
    then
        # return true
        return 0
    else
        # return false
        return 1
    fi
}

get_next_free_index()
{
    cert_type=${1}
    index=1

    for cert in $(ls -1 ${ROOT}/ca | grep -E 10-ee-${cert_type}-[[:digit:]]+-)
    do
        present_index=$(echo $cert | cut -d '-' -f 4)
        if [ ${present_index} -ge ${index} ]
        then
            index=$(expr ${present_index} + 1)
        fi
    done

    echo ${index}
}

# all functions used for creating a specific keystore get the cert_type
# as argument. possible values are <server|email|user>. as a convention
# filename should be "10-ee_${cert_type}_${index}_*"

create_keystore_openssl()
{
    cert_type=${1}

    # determine next available number for cert type
    index=$(get_next_free_index ${cert_type})

    # create csr
    if [ ${cert_type} = "server" ]
    then
        subject="${SUBJECT_PREFIX}/CN=${SERVER_FQDN}"
    else
        subject="${SUBJECT_PREFIX}/CN=10-ee-${cert_type}-${index}"
    fi

    ${OPENSSL} req -new -keyout ${ROOT}/ca/10-ee-${cert_type}-${index}-key.pem \
        -out ${ROOT}/ca/csr/10-ee-${cert_type}-${index}-cert.csr \
        -subj ${subject} -config ${openssl_conf} &> /dev/null
    # sign request
    ${OPENSSL} ca -name ca_int_${cert_type} \
        -in ${ROOT}/ca/csr/10-ee-${cert_type}-${index}-cert.csr \
        -out ${ROOT}/ca/10-ee-${cert_type}-${index}-cert.pem -notext \
        -config ${openssl_conf} &> /dev/null << EOF
y
y
EOF
}

create_keystore_mq()
{
    cert_type=${1}

    # determine next available number for cert type
    index=$(get_next_free_index ${cert_type})

    echo "mq keystores are currently not supported!"
}

create_keystore_java()
{
    cert_type=${1}

    # determine next available number for cert type
    index=$(get_next_free_index ${cert_type})

    echo "java keystores are currently not supported!"
}

create_keystore_windows()
{
    cert_type=${1}

    # determine next available number for cert type
    index=$(get_next_free_index ${cert_type})

    echo "windows keystores are currently not supported!"
}

create_keystore_pkcs12()
{
    cert_type=${1}

    # determine next available number for cert type
    index=$(get_next_free_index ${cert_type})

    echo "pkcs12 keystores are currently not supported!"
}

create_keystore_sap()
{
    cert_type=${1}

    # determine next available number for cert type
    index=$(get_next_free_index ${cert_type})

    echo "sap keystores are currently not supported!"
}

### END FUNCTIONS ###

### MAIN ###
arg_count=${#}
arg1=${1}
openssl_conf="${ROOT}/etc/openssl-test-env.conf"

if [ ! -x ${OPENSSL} ]
then
    echo "ERROR: '${OPENSSL}' either not existent or executable"
    exit -2
fi

case "${arg1}" in
    init)
            if [ ${arg_count} -ne 2 ]
            then
                usage
            fi

            arg_openssl_conf=${2}

            # do some checks
            if [ ! -r "${arg_openssl_conf}" ]
            then
                echo "ERROR: cannot read openssl config ('${arg_openssl_conf}')"
                exit -2
            fi

            if env_already_created
            then
                read -n 1 -p "testing environment has already been setup. \
create new? [y/n]: " overwrite_root
                echo ""
                case "${overwrite_root}" in
                    [yY])
                            ;;
                    *)
                            exit -3
                            ;;
                esac
            fi

            # create directory structure and files

            # check permissions
            root_parent=$(dirname ${ROOT})
            if [ ! -w ${root_parent} ]
            then
                echo "ERROR: '${root_parent}' is not writeable"
                exit -4
            fi

            rm -rf ${ROOT}
            echo "creating directory structure and files"
            mkdir -p ${ROOT}/ca/csr ${ROOT}/ca/res ${ROOT}/ca/crl ${ROOT}/etc \
                ${ROOT}/tmp
            touch ${ROOT}/ca/res/ca-database
            echo "01" > ${ROOT}/ca/res/ca-serial
            echo "01" > ${ROOT}/ca/res/crl-number

            # copy openssl config
            echo "copying openssl config"
            cp ${arg_openssl_conf} ${openssl_conf}

            # create root ca
            echo "creating root ca"
            PATHLEN=1
            ${OPENSSL} req -new -x509 -days ${ROOT_CA_VALIDITY} \
                -keyout ${ROOT}/ca/00-ca-root-key.pem \
                -out ${ROOT}/ca/00-ca-root-cert.pem \
                -extensions extensions_ca_root \
                -subj "${SUBJECT_PREFIX}/CN=00-ca-root" \
                -config ${openssl_conf} &> /dev/null

            # create intermediate ca's
            echo "creating intermediate ca's"
            # create csr's
            ${OPENSSL} req -new -keyout ${ROOT}/ca/01-ca-int-server-key.pem \
                -out ${ROOT}/ca/csr/01-ca-int-server-cert.csr \
                -subj "${SUBJECT_PREFIX}/CN=01-ca-int-server" \
                -config ${openssl_conf} &> /dev/null
            ${OPENSSL} req -new -keyout ${ROOT}/ca/01-ca-int-email-key.pem \
                -out ${ROOT}/ca/csr/01-ca-int-email-cert.csr \
                -subj "${SUBJECT_PREFIX}/CN=01-ca-int-email" \
                -config ${openssl_conf} &> /dev/null
            ${OPENSSL} req -new -keyout ${ROOT}/ca/01-ca-int-user-key.pem \
                -out ${ROOT}/ca/csr/01-ca-int-user-cert.csr \
                -subj "${SUBJECT_PREFIX}/CN=01-ca-int-user" \
                -config ${openssl_conf} &> /dev/null
            # sign requests
            PATHLEN=0
            ${OPENSSL} ca -name ca_root \
                -in ${ROOT}/ca/csr/01-ca-int-server-cert.csr \
                -out ${ROOT}/ca/01-ca-int-server-cert.pem -notext \
                -config ${openssl_conf} &> /dev/null << EOF
y
y
EOF
            ${OPENSSL} ca -name ca_root \
                -in ${ROOT}/ca/csr/01-ca-int-email-cert.csr \
                -out ${ROOT}/ca/01-ca-int-email-cert.pem -notext \
                -config ${openssl_conf} &> /dev/null << EOF
y
y
EOF
            ${OPENSSL} ca -name ca_root \
                -in ${ROOT}/ca/csr/01-ca-int-user-cert.csr \
                -out ${ROOT}/ca/01-ca-int-user-cert.pem -notext \
                -config ${openssl_conf} &> /dev/null << EOF
y
y
EOF

            # initialization complete
            touch ${ROOT}/tmp/.init-complete

            ;;

    create_ee)
            if [ ${arg_count} -ne 3 ]
            then
                usage
            fi

            if ! env_already_created
            then
                echo "ERROR: cannot find testing environment. please create \
first with ${0} init"
                exit -5
            fi

            cert_type=${2}
            case "${cert_type}" in
                server)
                        ;;
                email)
                        ;;
                user)
                        ;;
                *)
                        echo "ERROR: '${cert_type}' is not a valid cert type"
                        exit -6
                        ;;
            esac

            keystore=${3}
            case "${keystore}" in
                openssl)
                        create_keystore_openssl ${cert_type}
                        ;;
                mq)
                        create_keystore_mq ${cert_type}
                        ;;
                java)
                        create_keystore_java ${cert_type}
                        ;;
                windows)
                        create_keystore_windows ${cert_type}
                        ;;
                pkcs12)
                        create_keystore_pkcs12 ${cert_type}
                        ;;
                sap)
                        create_keystore_sap ${cert_type}
                        ;;
                *)
                        echo "ERROR: '${keystore}' is not a valid keystore"
                        exit -7
                        ;;
            esac
            ;;

    *)
            usage
            ;;
esac
#EOF

