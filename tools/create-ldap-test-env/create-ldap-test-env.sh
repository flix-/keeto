#!/bin/bash

# config
LDAP_HOST="localhost"
LDAP_PORT=1389
LDAP_BIND_DN="cn=directory-manager,dc=keeto,dc=io"
LDAP_BIND_PWD="test123"

NUM_DIRECT_ACCESS_PROFILES=100
NUM_AOB_PROFILES=100
NUM_NE_PROFILES=20
DIRECT_ACCESS_PROFILE_PREFIX="direct-access-profile"
AOB_PROFILE_PREFIX="access-on-behalf-profile"

# env
LDIF_DIR="ldif"

# dn's
NOT_EXISTENT="cn=not-existent,dc=keeto,dc=io"
PEOPLE_NO_UID="cn=no-uid,ou=people,dc=keeto,dc=io"
PEOPLE_NO_CERTS="cn=no-certificates,ou=people,dc=keeto,dc=io"
PEOPLE_VALID="cn=valid,ou=people,dc=keeto,dc=io"
ACCOUNT_VALID="uid=db2admin,ou=technical-accounts,dc=keeto,dc=io"
GROUP_PEOPLE_INVALID="cn=invalid,ou=people,ou=groups,dc=keeto,dc=io"
GROUP_PEOPLE_VALID="cn=valid,ou=people,ou=groups,dc=keeto,dc=io"
GROUP_ACCOUNT_INVALID="cn=invalid,ou=technical-accounts,ou=groups,dc=keeto,dc=io"
GROUP_ACCOUNT_VALID="cn=valid,ou=technical-accounts,ou=groups,dc=keeto,dc=io"
KEYSTORE_OPTIONS_VALID="cn=valid,ou=keystore-options,ou=ssh,dc=keeto,dc=io"
SSH_SERVER="cn=keeto-test-server,ou=servers,ou=ssh,dc=keeto,dc=io"

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
keetoKeyProvider: ${PEOPLE_NO_UID}
keetoKeyProvider: ${PEOPLE_NO_CERTS}
keetoKeyProvider: ${PEOPLE_VALID}
keetoKeyProvider: ${NOT_EXISTENT}
keetoKeyProviderGroup: ${GROUP_PEOPLE_INVALID}
keetoKeyProviderGroup: ${GROUP_PEOPLE_VALID}
keetoKeyProviderGroup: ${NOT_EXISTENT}
keetoKeystoreOptions: ${KEYSTORE_OPTIONS_VALID}
EOF
    done
}

create_access_on_behalf_profiles()
{
    for i in $(seq ${NUM_DIRECT_ACCESS_PROFILES})
    do
        ldapadd -H "ldap://${LDAP_HOST}:${LDAP_PORT}" -D ${LDAP_BIND_DN} -w ${LDAP_BIND_PWD} <<EOF
dn: cn=${AOB_PROFILE_PREFIX}-${i},ou=access-profiles,ou=ssh,dc=keeto,dc=io
objectClass: top
objectClass: keetoAccessProfile
objectClass: keetoAccessOnBehalfProfile
keetoEnabled: TRUE
keetoKeyProvider: ${NOT_EXISTENT}
keetoKeyProvider: ${PEOPLE_NO_UID}
keetoKeyProvider: ${PEOPLE_NO_CERTS}
keetoKeyProvider: ${PEOPLE_VALID}
keetoKeyProviderGroup: ${NOT_EXISTENT}
keetoKeyProviderGroup: ${GROUP_PEOPLE_INVALID}
keetoKeyProviderGroup: ${GROUP_PEOPLE_VALID}
keetoTargetKeystore: ${NOT_EXISTENT}
keetoTargetKeystore: ${ACCOUNT_VALID}
keetoTargetKeystoreGroup: ${GROUP_ACCOUNT_INVALID}
keetoTargetKeystoreGroup: ${NOT_EXISTENT}
keetoTargetKeystoreGroup: ${GROUP_ACCOUNT_VALID}
keetoKeystoreOptions: ${KEYSTORE_OPTIONS_VALID}
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

    # add access on behalf profiles
    for i in $(seq ${NUM_AOB_PROFILES})
    do
        ldapmodify -H "ldap://${LDAP_HOST}:${LDAP_PORT}" -D ${LDAP_BIND_DN} -w ${LDAP_BIND_PWD} <<EOF
dn: ${SSH_SERVER}
changetype: modify
add: keetoAccessProfile
keetoAccessProfile: cn=${AOB_PROFILE_PREFIX}-${i},ou=access-profiles,ou=ssh,dc=keeto,dc=io
EOF
    done
}

# create initial tree
killall slapd
rm -rf /var/lib/openldap/dc\=keeto\,dc\=io/*                                     
rm -rf /var/lib/openldap/openldap-data/                                          
rm -rf /etc/openldap/slapd.d/*                                                   
cp /etc/openldap/DB_CONFIG.example /var/lib/openldap/dc\=keeto\,dc\=io/DB_CONFIG 
schema2ldif ${LDIF_DIR}/keeto.schema > /etc/openldap/schema/keeto.ldif
slapadd -l ${LDIF_DIR}/00-slapd.ldif -F /etc/openldap/slapd.d/ -n0                
/usr/bin/slapd -4 -h "ldap://${LDAP_HOST}:${LDAP_PORT}/"

# add ldif
for file in ${LDIF_DIR}/*keeto*.ldif
do
    ldapadd -H "ldap://${LDAP_HOST}:${LDAP_PORT}" -D ${LDAP_BIND_DN} -w ${LDAP_BIND_PWD} -f ${file}
done

# add entries
create_direct_access_profiles
create_access_on_behalf_profiles
add_access_profiles

