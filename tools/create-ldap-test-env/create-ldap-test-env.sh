#!/bin/bash

# config
LDAP_HOST="localhost"
LDAP_PORT=1389
LDAP_BIND_DN="cn=directory-manager,dc=keeto,dc=io"
LDAP_BIND_PWD="test123"

NUM_ACCESS_PROFILES=500
NUM_NE_PROFILES=50
DIRECT_ACCESS_PROFILE_PREFIX="direct-access-profile"
AOB_PROFILE_PREFIX="access-on-behalf-profile"

# env
CONFIG_DIR="config"
LDIF_DIR="ldif"
SCHEMA_DIR="schema"

# dn's
NOT_EXISTENT="cn=not-existent,dc=keeto,dc=io"
SSH_SERVER="cn=keeto-test-server,ou=servers,ou=ssh,dc=keeto,dc=io"

NUM_DIRECT_ACCESS_PROFILES=$(expr ${NUM_ACCESS_PROFILES} / 2)
NUM_AOB_PROFILES1=$(expr ${NUM_DIRECT_ACCESS_PROFILES} / 2)
NUM_AOB_PROFILES2=$(expr ${NUM_ACCESS_PROFILES} - \
    ${NUM_DIRECT_ACCESS_PROFILES} - ${NUM_AOB_PROFILES1})

create_direct_access_profiles()
{
    for i in $(seq ${NUM_DIRECT_ACCESS_PROFILES})
    do
        ldapadd -H "ldap://${LDAP_HOST}:${LDAP_PORT}" -D ${LDAP_BIND_DN} -w ${LDAP_BIND_PWD} <<EOF
dn: cn=${DIRECT_ACCESS_PROFILE_PREFIX}-${i},ou=access-profiles,ou=ssh,dc=keeto,dc=io
objectClass: top
objectClass: keetoAccessProfile
objectClass: keetoDirectAccessProfile
keetoEnabled: TRUE
keetoKeyProvider: ${NOT_EXISTENT}
keetoKeyProviderGroup: ${NOT_EXISTENT}
keetoKeyProviderGroup: cn=unix-administrators,ou=people,ou=groups,dc=keeto,dc=io
keetoKeystoreOptions: cn=admin-lan-only,ou=keystore-options,ou=ssh,dc=keeto,dc=io
description: direct access profile for unix administration
EOF
    done
}

create_access_on_behalf_profiles()
{
    for i in $(seq ${NUM_AOB_PROFILES1})
    do
        ldapadd -H "ldap://${LDAP_HOST}:${LDAP_PORT}" -D ${LDAP_BIND_DN} -w ${LDAP_BIND_PWD} <<EOF
dn: cn=${AOB_PROFILE_PREFIX}1-${i},ou=access-profiles,ou=ssh,dc=keeto,dc=io
objectClass: top
objectClass: keetoAccessProfile
objectClass: keetoAccessOnBehalfProfile
keetoEnabled: TRUE
keetoKeyProvider: ${NOT_EXISTENT}
keetoKeyProviderGroup: ${NOT_EXISTENT}
keetoKeyProviderGroup: cn=ldap-administrators,ou=people,ou=groups,dc=keeto,dc=io
keetoTargetKeystore: ${NOT_EXISTENT}
keetoTargetKeystoreGroup: ${NOT_EXISTENT}
keetoTargetKeystoreGroup: cn=ldap-accounts,ou=technical-accounts,ou=groups,dc=keeto,dc=io
description: access on behalf profile for ldap administration
EOF
    done

    for i in $(seq ${NUM_AOB_PROFILES2})
    do
        ldapadd -H "ldap://${LDAP_HOST}:${LDAP_PORT}" -D ${LDAP_BIND_DN} -w ${LDAP_BIND_PWD} <<EOF
dn: cn=${AOB_PROFILE_PREFIX}2-${i},ou=access-profiles,ou=ssh,dc=keeto,dc=io
objectClass: top
objectClass: keetoAccessProfile
objectClass: keetoAccessOnBehalfProfile
keetoEnabled: TRUE
keetoKeyProvider: ${NOT_EXISTENT}
keetoKeyProviderGroup: ${NOT_EXISTENT}
keetoKeyProviderGroup: cn=keeto-engineers,ou=people,ou=groups,dc=keeto,dc=io
keetoTargetKeystore: ${NOT_EXISTENT}
keetoTargetKeystoreGroup: ${NOT_EXISTENT}
keetoTargetKeystore: uid=keeto,ou=technical-accounts,dc=keeto,dc=io
description: access on behalf profile for keeto engineering
EOF
    done
}

add_access_profiles()
{
    # add direct access profiles
    for i in $(seq ${NUM_DIRECT_ACCESS_PROFILES})
    do
        ldapmodify -H "ldap://${LDAP_HOST}:${LDAP_PORT}" -D ${LDAP_BIND_DN} -w ${LDAP_BIND_PWD} <<EOF
dn: ${SSH_SERVER}
changetype: modify
add: keetoAccessProfile
keetoAccessProfile: cn=${DIRECT_ACCESS_PROFILE_PREFIX}-${i},ou=access-profiles,ou=ssh,dc=keeto,dc=io
EOF
    done

    # add non existing profiles
    for i in $(seq ${NUM_NE_PROFILES})
    do
        ldapmodify -H "ldap://${LDAP_HOST}:${LDAP_PORT}" -D ${LDAP_BIND_DN} -w ${LDAP_BIND_PWD} <<EOF
dn: ${SSH_SERVER}
changetype: modify
add: keetoAccessProfile
keetoAccessProfile: cn=not-existent-${i},dc=keeto,dc=io
EOF
    done

    # add access on behalf profiles1
    for i in $(seq ${NUM_AOB_PROFILES1})
    do
        ldapmodify -H "ldap://${LDAP_HOST}:${LDAP_PORT}" -D ${LDAP_BIND_DN} -w ${LDAP_BIND_PWD} <<EOF
dn: ${SSH_SERVER}
changetype: modify
add: keetoAccessProfile
keetoAccessProfile: cn=${AOB_PROFILE_PREFIX}1-${i},ou=access-profiles,ou=ssh,dc=keeto,dc=io
EOF
    done

    # add access on behalf profiles2
    for i in $(seq ${NUM_AOB_PROFILES2})
    do
        ldapmodify -H "ldap://${LDAP_HOST}:${LDAP_PORT}" -D ${LDAP_BIND_DN} -w ${LDAP_BIND_PWD} <<EOF
dn: ${SSH_SERVER}
changetype: modify
add: keetoAccessProfile
keetoAccessProfile: cn=${AOB_PROFILE_PREFIX}2-${i},ou=access-profiles,ou=ssh,dc=keeto,dc=io
EOF
    done
}

# create initial tree
killall slapd
rm -rf /var/lib/openldap/dc\=keeto\,dc\=io/*
rm -rf /var/lib/openldap/openldap-data/
rm -rf /etc/openldap/slapd.d/*
cp /etc/openldap/DB_CONFIG.example /var/lib/openldap/dc\=keeto\,dc\=io/DB_CONFIG
schema2ldif ${SCHEMA_DIR}/keeto.schema > /etc/openldap/schema/keeto.ldif
slapadd -l ${CONFIG_DIR}/slapd.ldif -F /etc/openldap/slapd.d/ -n0
/usr/bin/slapd -4 -h "ldap://${LDAP_HOST}:${LDAP_PORT}/"

# add ldif
for file in ${LDIF_DIR}/*.ldif
do
    ldapadd -H "ldap://${LDAP_HOST}:${LDAP_PORT}" -D ${LDAP_BIND_DN} -w ${LDAP_BIND_PWD} -f ${file}
done

# add entries
create_direct_access_profiles
create_access_on_behalf_profiles
add_access_profiles

