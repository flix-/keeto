/*
 * Copyright (C) 2014-2016 Sebastian Roland <seroland86@gmail.com>
 *
 * This file is part of Keeto.
 *
 * Keeto is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Keeto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Keeto.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "pox509-ldap.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <confuse.h>
#include <lber.h>
#include <ldap.h>
#include <openssl/x509.h>

#include "pox509-error.h"
#include "pox509-log.h"
#include "pox509-util.h"

#define LDAP_SEARCH_FILTER_BUFFER_SIZE 1024

static void
free_attr_values_as_string(char **values)
{
    if (values == NULL) {
        return;
    }
    for (int i = 0; values[i] != NULL; i++) {
        free(values[i]);
    }
    free(values);
}

static void
free_attr_values_as_binary(struct berval **values)
{
    if (values == NULL) {
        return;
    }
    ldap_value_free_len(values);
}

static int
get_attr_values_as_string(LDAP *ldap_handle, LDAPMessage *entry, char *attr,
    char ***ret)
{
    if (ldap_handle == NULL || entry == NULL || attr == NULL || ret == NULL) {
        fatal("ldap_handle, entry, attr or ret == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    /* get attribute values */
    entry = ldap_first_entry(ldap_handle, entry);
    if (entry == NULL) {
        log_error("failed to parse ldap search result set");
        return POX509_LDAP_ERR;
    }

    /* retrieve attribute value(s) */
    struct berval **values = ldap_get_values_len(ldap_handle, entry, attr);
    if (values == NULL) {
        return POX509_LDAP_NO_SUCH_ATTR;
    }

    /* count values so we know how wide our buffer has to be */
    int count = ldap_count_values_len(values);
    if (count == 0) {
        log_error("ldap search result set empty for attribute '%s'", attr);
        res = POX509_LDAP_ERR;
        goto cleanup_a;
    }

    char **values_string = malloc(sizeof(char *) * (count + 1));
    if (values_string == NULL) {
        log_error("failed to allocate memory for attribute value buffer");
        res = POX509_NO_MEMORY;
        goto cleanup_a;
    }

    for (int i = 0; values[i] != NULL; i++) {
        char *value = values[i]->bv_val;
        ber_len_t len = values[i]->bv_len;
        values_string[i] = strndup(value, len);
        if (values_string[i] == NULL) {
            log_error("failed to duplicate attribute value string");
            res = POX509_NO_MEMORY;
            goto cleanup_b;
        }
    }
    values_string[count] = NULL;

    *ret = values_string;
    values_string = NULL;
    res = POX509_OK;

cleanup_b:
    if (values_string != NULL) {
        free_attr_values_as_string(values_string);
    }
cleanup_a:
    ldap_value_free_len(values);
    return res;
}

static int
get_attr_values_as_binary(LDAP *ldap_handle, LDAPMessage *entry, char *attr,
    struct berval ***ret)
{
    if (ldap_handle == NULL || entry == NULL || attr == NULL || ret == NULL) {
        fatal("ldap_handle, entry, attr or ret == NULL");
    }

    /* get attribute values */
    entry = ldap_first_entry(ldap_handle, entry);
    if (entry == NULL) {
        log_error("failed to parse ldap search result set");
        return POX509_LDAP_ERR;
    }
    *ret = ldap_get_values_len(ldap_handle, entry, attr);
    if (*ret == NULL) {
        return POX509_LDAP_NO_SUCH_ATTR;
    }
    return POX509_OK;
}

static int
get_access_profile_type(LDAP *ldap_handle, LDAPMessage *access_profile_entry,
    enum pox509_access_profile_type *ret)
{
    if (ldap_handle == NULL || access_profile_entry == NULL || ret == NULL) {
        fatal("ldap_handle, access_profile_entry or ret == NULL");
    }

    /* determine access profile type from objectClass attribute */
    char **objectclasses = NULL;
    int rc = get_attr_values_as_string(ldap_handle, access_profile_entry,
        "objectClass", &objectclasses);
    switch (rc) {
    case POX509_OK:
        break;
    case POX509_NO_MEMORY:
        return rc;
    default:
        log_error("failed to obtain access profile type: attribute '%s' (%s)",
            "objectClass", pox509_strerror(rc));
        return POX509_LDAP_SCHEMA_ERR;
    }

    int res = POX509_UNKNOWN_ACCESS_PROFILE_TYPE;
    /* search for access profile type */
    for (int i = 0; objectclasses[i] != NULL; i++) {
        char *objectclass = objectclasses[i];
        if (strcmp(objectclass, POX509_DAP_OBJCLASS) == 0) {
            *ret = DIRECT_ACCESS_PROFILE;
            res = POX509_OK;
            break;
        } else if (strcmp(objectclass, POX509_AOBP_OBJCLASS) == 0) {
            *ret = ACCESS_ON_BEHALF_PROFILE;
            res = POX509_OK;
            break;
        }
    }
    free_attr_values_as_string(objectclasses);
    return res;
}

static int
get_group_member_entry(LDAP *ldap_handle, struct pox509_info *info,
    char *group_dn, char *group_member_attr, LDAPMessage **ret)
{
    if (ldap_handle == NULL || info == NULL || group_dn == NULL ||
        group_member_attr == NULL || ret == NULL) {

        fatal("ldap_handle, info, group_dn, group_member_attr or ret == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    char *attr[] = { group_member_attr, NULL };
    /* query ldap for group members */
    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);
    LDAPMessage *group_member_entry = NULL;
    int rc = ldap_search_ext_s(ldap_handle, group_dn, LDAP_SCOPE_BASE, NULL,
        attr, 0, NULL, NULL, &search_timeout, 1, &group_member_entry);
    if (rc != LDAP_SUCCESS) {
        log_error("failed to search ldap: base '%s' (%s)", group_dn,
            ldap_err2string(rc));
        res = POX509_LDAP_NO_SUCH_ENTRY;
        goto cleanup;
    }
    *ret = group_member_entry;
    group_member_entry = NULL;
    res = POX509_OK;

cleanup:
    if (group_member_entry != NULL) {
        ldap_msgfree(group_member_entry);
    }
    return res;
}

static int
check_access_profile_relevance_aobp(LDAP *ldap_handle, struct pox509_info *info,
    LDAPMessage *access_profile_entry, bool *ret)
{
    if (ldap_handle == NULL || info == NULL || access_profile_entry == NULL ||
        ret == NULL) {
        fatal("ldap_handle, info, access_profile_entry or ret == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    /* get target keystore group dn */
    char **target_keystore_group_dn = NULL;
    int rc = get_attr_values_as_string(ldap_handle, access_profile_entry,
        POX509_AOBP_TARGET_KEYSTORE_ATTR, &target_keystore_group_dn);
    switch (rc) {
    case POX509_OK:
        break;
    case POX509_NO_MEMORY:
        return rc;
    default:
        log_error("failed to obtain target keystore group dn: attribute '%s' (%s)",
            POX509_AOBP_TARGET_KEYSTORE_ATTR, pox509_strerror(rc));
        return POX509_LDAP_SCHEMA_ERR;
    }
    log_info("processing target keystore group '%s'",
        target_keystore_group_dn[0]);

    /* get group member entry */
    char *target_keystore_group_member_attr = cfg_getstr(info->cfg,
        "ldap_target_keystore_group_member_attr");
    LDAPMessage *group_member_entry = NULL;
    rc = get_group_member_entry(ldap_handle, info, target_keystore_group_dn[0],
        target_keystore_group_member_attr, &group_member_entry);
    if (rc != POX509_OK) {
        log_error("failed to obtain target keystore group member entry (%s)",
            pox509_strerror(rc));
        res = POX509_LDAP_NO_SUCH_ENTRY;
        goto cleanup_a;
    }
    /* get target keystore dns */
    char **target_keystore_dns = NULL;
    rc = get_attr_values_as_string(ldap_handle, group_member_entry,
        target_keystore_group_member_attr, &target_keystore_dns);
    switch (rc) {
    case POX509_OK:
        break;
    case POX509_NO_MEMORY:
        res = rc;
        goto cleanup_b;
    default:
        log_error("failed to obtain target keystore dns: attribute '%s' (%s)",
            target_keystore_group_member_attr, pox509_strerror(rc));
        res = POX509_LDAP_SCHEMA_ERR;
        goto cleanup_b;
    }

    /* check target keystores */
    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);
    char *target_keystore_uid_attr = cfg_getstr(info->cfg,
        "ldap_target_keystore_uid_attr");
    char *attrs[] = { target_keystore_uid_attr, NULL };
    bool relevant = false;
    for (int i = 0; target_keystore_dns[i] != NULL && !relevant; i++) {
        char *target_keystore_dn = target_keystore_dns[i];
        log_info("checking target keystore '%s'", target_keystore_dn);

        LDAPMessage *target_keystore_entry = NULL;
        rc = ldap_search_ext_s(ldap_handle, target_keystore_dn, LDAP_SCOPE_BASE,
            NULL, attrs, 0, NULL, NULL, &search_timeout, 1,
            &target_keystore_entry);
        if (rc != LDAP_SUCCESS) {
            log_error("failed to search ldap: base '%s' (%s)", target_keystore_dn,
                ldap_err2string(rc));
            log_info("skipped target keystore");
            goto cleanup_inner;
        }
        /* get uid of target keystore */
        char **target_keystore_uid = NULL;
        rc = get_attr_values_as_string(ldap_handle, target_keystore_entry,
            target_keystore_uid_attr, &target_keystore_uid);
        switch (rc) {
        case POX509_OK:
            break;
        case POX509_NO_MEMORY:
            res = rc;
            ldap_msgfree(target_keystore_entry);
            goto cleanup_c;
        default:
            log_error("failed to obtain target keystore uid: attribute '%s' (%s)",
                target_keystore_uid_attr, pox509_strerror(rc));
            log_info("skipped target keystore");
            goto cleanup_inner;
        }
        /* check uid */
        if (strcmp(info->uid, target_keystore_uid[0]) == 0) {
            relevant = true;
        }
        free_attr_values_as_string(target_keystore_uid);
cleanup_inner:
        ldap_msgfree(target_keystore_entry);
    }
    *ret = relevant;
    res = POX509_OK;

cleanup_c:
    free_attr_values_as_string(target_keystore_dns);
cleanup_b:
    ldap_msgfree(group_member_entry);
cleanup_a:
    free_attr_values_as_string(target_keystore_group_dn);
    return res;
}

static int
check_access_profile_enabled(LDAP *ldap_handle,
    LDAPMessage *access_profile_entry, bool *ret)
{
    if (ldap_handle == NULL || access_profile_entry == NULL || ret == NULL) {
        fatal("ldap_handle, access_profile_entry or ret == NULL");
    }

    /*
     * determine state of access profile from POX509_AP_ENABLED
     * attribute.
     */
    char **access_profile_state = NULL;
    int rc = get_attr_values_as_string(ldap_handle, access_profile_entry,
        POX509_AP_ENABLED, &access_profile_state);
    switch (rc) {
    case POX509_OK:
        break;
    case POX509_NO_MEMORY:
        return rc;
    default:
        log_error("failed to obtain access profile state: attribute '%s' (%s)",
            POX509_AP_ENABLED, pox509_strerror(rc));
        return POX509_LDAP_SCHEMA_ERR;
    }
    *ret = strcmp(access_profile_state[0], LDAP_BOOL_TRUE) == 0 ? true : false;
    free_attr_values_as_string(access_profile_state);
    return POX509_OK;
}

static int
check_access_profile_relevance_generic(LDAP *ldap_handle,
    LDAPMessage *access_profile_entry, bool *ret)
{
    if (ldap_handle == NULL || access_profile_entry == NULL || ret == NULL) {
        fatal("ldap_handle, access_profile_entry or ret == NULL");
    }

    /* check if acccess profile entry is enabled */
    bool profile_enabled = false;
    int rc = check_access_profile_enabled(ldap_handle, access_profile_entry,
        &profile_enabled);
    switch (rc) {
    case POX509_OK:
        break;
    case POX509_NO_MEMORY:
        return rc;
    default:
        log_error("failed to check if profile is enabled (%s)",
            pox509_strerror(rc));
        return rc;
    }
    if (!profile_enabled) {
        log_info("access profile disabled");
        *ret = false;
        return POX509_OK;
    }
    /* do further checks here in the future */
    *ret = true;
    return POX509_OK;
}

static int
add_keystore_options(LDAP *ldap_handle, LDAPMessage *keystore_options_entry,
    struct pox509_access_profile *access_profile)
{
    if (ldap_handle == NULL || keystore_options_entry == NULL ||
        access_profile == NULL) {

        fatal("ldap_handle, keystore_options_entry or access_profile == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    struct pox509_keystore_options *keystore_options = new_keystore_options();
    if (keystore_options == NULL) {
        log_error("failed to allocate memory for keystore options");
        return POX509_NO_MEMORY;
    }
    keystore_options->dn = ldap_get_dn(ldap_handle, keystore_options_entry);
    if (keystore_options->dn == NULL) {
        log_error("failed to obtain dn from keystore options entry");
        res = POX509_LDAP_ERR;
        goto cleanup_a;
    }
    int rc = get_rdn_from_dn(keystore_options->dn, &keystore_options->uid);
    if (rc != POX509_OK) {
        log_error("failed to obtain rdn from dn '%s' (%s)", keystore_options->dn,
            pox509_strerror(rc));
        res = rc;
        goto cleanup_a;
    }

    /* get attribute values (optional) */
    char **keystore_options_command = NULL;
    rc = get_attr_values_as_string(ldap_handle, keystore_options_entry,
        POX509_KEYSTORE_OPTIONS_CMD_ATTR, &keystore_options_command);
    switch (rc) {
    case POX509_OK:
        keystore_options->command_option = strdup(keystore_options_command[0]);
        if (keystore_options->command_option == NULL) {
            log_error("failed to duplicate keystore option 'command'");
            res = POX509_NO_MEMORY;
            goto cleanup_b;
        }
        log_info("added keystore option 'command'");
        break;
    case POX509_NO_MEMORY:
        res = rc;
        goto cleanup_a;
    case POX509_LDAP_NO_SUCH_ATTR:
        log_info("skipped keystore option 'command' (%s)",
            POX509_KEYSTORE_OPTIONS_CMD_ATTR);
        break;
    default:
        log_error("failed to obtain keystore option 'command': attribute '%s' (%s)",
            POX509_KEYSTORE_OPTIONS_CMD_ATTR, pox509_strerror(rc));
        res = rc;
        goto cleanup_a;
    }

    char **keystore_options_from = NULL;
    rc = get_attr_values_as_string(ldap_handle, keystore_options_entry,
        POX509_KEYSTORE_OPTIONS_FROM_ATTR, &keystore_options_from);
    switch (rc) {
    case POX509_OK:
        keystore_options->from_option = strdup(keystore_options_from[0]);
        if (keystore_options->from_option == NULL) {
            log_error("failed to duplicate keystore option 'from'");
            res = POX509_NO_MEMORY;
            goto cleanup_c;
        }
        log_info("added keystore option 'from'");
        break;
    case POX509_NO_MEMORY:
        res = rc;
        goto cleanup_b;
    case POX509_LDAP_NO_SUCH_ATTR:
        log_info("skipped keystore option 'from' (%s)",
            POX509_KEYSTORE_OPTIONS_FROM_ATTR);
        break;
    default:
        log_error("failed to obtain keystore option 'from': attribute '%s' (%s)",
            POX509_KEYSTORE_OPTIONS_FROM_ATTR, pox509_strerror(rc));
        res = rc;
        goto cleanup_b;
    }

    /* only add keystore options if at least one options has been set */
    if (keystore_options->from_option == NULL &&
        keystore_options->command_option == NULL) {

        res = POX509_NO_KEYSTORE_OPTION;
        goto cleanup_c;
    }
    access_profile->keystore_options = keystore_options;
    keystore_options = NULL;
    res = POX509_OK;

cleanup_c:
    free_attr_values_as_string(keystore_options_from);
cleanup_b:
    free_attr_values_as_string(keystore_options_command);
cleanup_a:
    if (keystore_options != NULL) {
        free_keystore_options(keystore_options);
    }
    return res;
}

static int
add_key(struct berval *cert, struct pox509_keys *keys)
{
    if (cert == NULL || keys == NULL) {
        fatal("cert or keys == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    struct pox509_key *key = new_key();
    if (key == NULL) {
        log_error("failed to allocate memory for key");
        return POX509_NO_MEMORY;
    }

    char *x509 = cert->bv_val;
    ber_len_t x509_len = cert->bv_len;
    key->x509 = d2i_X509(NULL, (const unsigned char **) &x509, x509_len);
    if (key->x509 == NULL) {
        log_error("failed to decode certificate");
        res = POX509_X509_ERR;
        goto cleanup;
    }
    TAILQ_INSERT_TAIL(keys, key, next);
    key = NULL;
    res = POX509_OK;

cleanup:
    if (key != NULL) {
        free_key(key);
    }
    return res;
}

static int
add_keys(LDAP *ldap_handle, struct pox509_info *info,
    LDAPMessage *key_provider_entry, struct pox509_key_provider *key_provider)
{
    if (ldap_handle == NULL || info == NULL || key_provider_entry == NULL ||
        key_provider == NULL) {

        fatal("ldap_handle, info, key_provider_entry or key_provider == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    /* get certificates */
    char *key_provider_cert_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_cert_attr");
    struct berval **key_provider_certs = NULL;
    int rc = get_attr_values_as_binary(ldap_handle, key_provider_entry,
        key_provider_cert_attr, &key_provider_certs);
    if (rc != POX509_OK) {
        log_error("failed to obtain key provider certificate: attribute '%s' (%s)",
            key_provider_cert_attr, pox509_strerror(rc));
        return POX509_LDAP_SCHEMA_ERR;
    }

    struct pox509_keys *keys = new_keys();
    if (keys == NULL) {
        log_error("failed to allocate memory for keys");
        res = POX509_NO_MEMORY;
        goto cleanup_a;
    }

    for (int i = 0; key_provider_certs[i] != NULL; i++) {
        rc = add_key(key_provider_certs[i], keys);
        switch (rc) {
        case POX509_OK:
            log_info("added key");
            break;
        case POX509_NO_MEMORY:
            res = rc;
            goto cleanup_b;
        default:
            log_info("skipped key (%s)", pox509_strerror(rc));
        }
    }
    /* check if not empty */
    if (TAILQ_EMPTY(keys)) {
        res = POX509_NO_CERT;
        goto cleanup_b;
    }
    key_provider->keys = keys;
    keys = NULL;
    res = POX509_OK;

cleanup_b:
    if (keys != NULL) {
        free_keys(keys);
    }
cleanup_a:
    free_attr_values_as_binary(key_provider_certs);
    return res;
}

static int
add_key_provider(LDAP *ldap_handle, struct pox509_info *info,
    struct pox509_access_profile *access_profile,
    LDAPMessage *key_provider_entry, struct pox509_key_providers *key_providers)
{
    if (ldap_handle == NULL || info == NULL || access_profile == NULL ||
        key_provider_entry == NULL || key_providers == NULL) {

        fatal("ldap_handle, info, access_profile, key_provider_entry or "
            "key_providers == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    /* get key provider uid */
    char *key_provider_uid_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_uid_attr");
    char **key_provider_uid = NULL;
    int rc = get_attr_values_as_string(ldap_handle, key_provider_entry,
        key_provider_uid_attr, &key_provider_uid);
    switch (rc) {
    case POX509_OK:
        break;
    case POX509_NO_MEMORY:
        return rc;
    default:
        log_error("failed to obtain key provider uid: attribute '%s' (%s)",
            key_provider_uid_attr, pox509_strerror(rc));
        return POX509_LDAP_SCHEMA_ERR;
    }
    /*
     * for direct access profiles a key provider is only relevant if
     * the uid of the key provider matches the uid of the user
     * currently logging in.
     */
    if (access_profile->type == DIRECT_ACCESS_PROFILE) {
        bool authorized = strcmp(key_provider_uid[0], info->uid) == 0 ?
            true : false;
        if (!authorized) {
            res = POX509_NOT_RELEVANT;
            goto cleanup_a;
        }
    }
    /* create and populate key provider */
    struct pox509_key_provider *key_provider = new_key_provider();
    if (key_provider == NULL) {
        log_error("failed to allocate memory for key provider");
        res = POX509_NO_MEMORY;
        goto cleanup_a;
    }
    key_provider->dn = ldap_get_dn(ldap_handle, key_provider_entry);
    if (key_provider->dn == NULL) {
        log_error("failed to obtain dn from key provider entry");
        res = POX509_LDAP_ERR;
        goto cleanup_b;
    }
    key_provider->uid = strdup(key_provider_uid[0]);
    if (key_provider->uid == NULL) {
        log_error("failed to duplicate key provider uid");
        res = POX509_NO_MEMORY;
        goto cleanup_b;
    }

    /* add keys */
    rc = add_keys(ldap_handle, info, key_provider_entry, key_provider);
    if (rc != POX509_OK) {
        res = rc;
        goto cleanup_b;
    }

    TAILQ_INSERT_TAIL(key_providers, key_provider, next);
    key_provider = NULL;
    res = POX509_OK;

cleanup_b:
    if (key_provider != NULL) {
        free_key_provider(key_provider);
    };
cleanup_a:
    free_attr_values_as_string(key_provider_uid);
    return res;
}

static int
add_key_providers(LDAP *ldap_handle, struct pox509_info *info,
    LDAPMessage *group_member_entry,
    struct pox509_access_profile *access_profile)
{
    if (ldap_handle == NULL || info == NULL || group_member_entry == NULL ||
        access_profile == NULL) {

        fatal("ldap_handle, info, group_member_entry or access_profile == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    /* get key provider dns */
    char *key_provider_group_member_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_group_member_attr");
    char **key_provider_dns = NULL;
    int rc = get_attr_values_as_string(ldap_handle, group_member_entry,
        key_provider_group_member_attr, &key_provider_dns);
    switch (rc) {
    case POX509_OK:
        break;
    case POX509_NO_MEMORY:
        return rc;
    default:
        log_error("failed to obtain key provider dns: attribute '%s' (%s)",
            key_provider_group_member_attr, pox509_strerror(rc));
        return POX509_LDAP_SCHEMA_ERR;
    }

    struct pox509_key_providers *key_providers = new_key_providers();
    if (key_providers == NULL) {
        log_error("failed to allocate memory for key providers");
        res = POX509_NO_MEMORY;
        goto cleanup_a;
    }

    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);
    char *key_provider_uid_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_uid_attr");
    char *key_provider_cert_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_cert_attr");
    char *attrs[] = { key_provider_uid_attr, key_provider_cert_attr, NULL };
    /* add key providers */
    for (int i = 0; key_provider_dns[i] != NULL; i++) {
        char *key_provider_dn = key_provider_dns[i];
        log_info("processing key provider '%s'", key_provider_dn);

        LDAPMessage *key_provider_entry = NULL;
        rc = ldap_search_ext_s(ldap_handle, key_provider_dn, LDAP_SCOPE_BASE,
            NULL, attrs, 0, NULL, NULL, &search_timeout, 1, &key_provider_entry);
        if (rc != LDAP_SUCCESS) {
            log_error("failed to search ldap: base '%s' (%s)", key_provider_dn,
                ldap_err2string(rc));
            log_info("skipped key provider");
            goto cleanup_inner;
        }
        rc = add_key_provider(ldap_handle, info, access_profile,
            key_provider_entry, key_providers);
        switch (rc) {
        case POX509_OK:
            log_info("added key provider");
            break;
        case POX509_NO_MEMORY:
            res = rc;
            ldap_msgfree(key_provider_entry);
            goto cleanup_b;
        default:
            log_info("skipped key provider (%s)", pox509_strerror(rc));
            goto cleanup_inner;
        }
cleanup_inner:
        ldap_msgfree(key_provider_entry);
    }
    /* check if not empty */
    if (TAILQ_EMPTY(key_providers)) {
        res = POX509_NO_KEY_PROVIDER;
        goto cleanup_b;
    }
    access_profile->key_providers = key_providers;
    key_providers = NULL;
    res = POX509_OK;

cleanup_b:
    if (key_providers != NULL) {
        free_key_providers(key_providers);
    }
cleanup_a:
    free_attr_values_as_string(key_provider_dns);
    return res;
}

static int
process_access_profile(LDAP *ldap_handle, struct pox509_info *info,
    LDAPMessage *access_profile_entry,
    struct pox509_access_profile *access_profile)
{
    if (ldap_handle == NULL || info == NULL || access_profile_entry == NULL ||
        access_profile == NULL) {

        fatal("ldap_handle, info, access_profile_entry or access_profile == "
            "NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    /* add key providers */
    char **key_provider_group_dn = NULL;
    int rc = get_attr_values_as_string(ldap_handle, access_profile_entry,
        POX509_AP_KEY_PROVIDER_ATTR, &key_provider_group_dn);
    switch (rc) {
    case POX509_OK:
        break;
    case POX509_NO_MEMORY:
        return rc;
    default:
        log_error("failed to obtain key provider group dn: attribute '%s' (%s)",
            POX509_AP_KEY_PROVIDER_ATTR, pox509_strerror(rc));
        return POX509_LDAP_SCHEMA_ERR;
    }
    log_info("processing key provider group '%s'", key_provider_group_dn[0]);

    char *key_provider_group_member_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_group_member_attr");
    LDAPMessage *group_member_entry = NULL;
    rc = get_group_member_entry(ldap_handle, info, key_provider_group_dn[0],
        key_provider_group_member_attr, &group_member_entry);
    if (rc != POX509_OK) {
        log_error("failed to obtain key provider group member entry (%s)",
            pox509_strerror(rc));
        res = POX509_LDAP_NO_SUCH_ENTRY;
        goto cleanup_a;
    }
    rc = add_key_providers(ldap_handle, info, group_member_entry, access_profile);
    if (rc != POX509_OK) {
        res = rc;
        goto cleanup_b;
    }

    /* add keystore options (optional) */
    char **keystore_options_dn = NULL;
    rc = get_attr_values_as_string(ldap_handle, access_profile_entry,
        POX509_AP_KEYSTORE_OPTIONS_ATTR, &keystore_options_dn);
    switch (rc) {
    case POX509_OK:
        log_info("processing keystore options '%s'", keystore_options_dn[0]);
        struct timeval search_timeout = get_ldap_search_timeout(info->cfg);
        char *attrs[] = {
            POX509_KEYSTORE_OPTIONS_FROM_ATTR,
            POX509_KEYSTORE_OPTIONS_CMD_ATTR,
            NULL
        };
        LDAPMessage *keystore_options_entry = NULL;
        rc = ldap_search_ext_s(ldap_handle, keystore_options_dn[0],
            LDAP_SCOPE_BASE, NULL, attrs, 0, NULL, NULL, &search_timeout, 1,
            &keystore_options_entry);
        if (rc != LDAP_SUCCESS) {
            log_error("failed to search ldap: base '%s' (%s)",
                keystore_options_dn[0], ldap_err2string(rc));
            res = POX509_LDAP_NO_SUCH_ENTRY;
            ldap_msgfree(keystore_options_entry);
            goto cleanup_c;
        }
        rc = add_keystore_options(ldap_handle, keystore_options_entry,
            access_profile);
        switch (rc) {
        case POX509_OK:
            log_info("added keystore options");
            break;
        case POX509_NO_MEMORY:
            res = rc;
            ldap_msgfree(keystore_options_entry);
            goto cleanup_c;
        case POX509_NO_KEYSTORE_OPTION:
            log_info("keystore options entry has no option set - remove "
                "keystore options from access profile?!");
            break;
        default:
            log_error("failed to add keystore options (%s)", pox509_strerror(rc));
            res = rc;
            ldap_msgfree(keystore_options_entry);
            goto cleanup_c;
        }
        ldap_msgfree(keystore_options_entry);
        break;
    case POX509_NO_MEMORY:
        res = rc;
        goto cleanup_b;
    case POX509_LDAP_NO_SUCH_ATTR:
        log_info("skipped keystore options (%s)", pox509_strerror(rc));
        res = POX509_OK;
        goto cleanup_b;
    default:
        log_error("failed to obtain keystore options dn: attribute '%s' (%s)",
            POX509_AP_KEYSTORE_OPTIONS_ATTR, pox509_strerror(rc));
        res = rc;
        goto cleanup_b;
    }
    res = POX509_OK;

cleanup_c:
    free_attr_values_as_string(keystore_options_dn);
cleanup_b:
    ldap_msgfree(group_member_entry);
cleanup_a:
    free_attr_values_as_string(key_provider_group_dn);
    return res;
}

static int
add_access_profile(LDAP *ldap_handle, struct pox509_info *info, 
    LDAPMessage *access_profile_entry,
    struct pox509_access_profiles *access_profiles)
{
    if (ldap_handle == NULL || info == NULL || access_profile_entry == NULL ||
        access_profiles == NULL) {

        fatal("ldap_handle, info, access_profile_dn or access_profiles == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    /* check if acccess profile is relevant */
    bool access_profile_relevant = false;
    int rc = check_access_profile_relevance_generic(ldap_handle,
        access_profile_entry, &access_profile_relevant);
    switch (rc) {
    case POX509_OK:
        break;
    case POX509_NO_MEMORY:
        return rc;
    default:
        log_error("failed to check access profile relevance (%s)",
            pox509_strerror(rc));
        return rc;
    }
    if (!access_profile_relevant) {
        return POX509_NOT_RELEVANT;
    }

    /* get access profile type */
    enum pox509_access_profile_type access_profile_type;
    rc = get_access_profile_type(ldap_handle, access_profile_entry,
        &access_profile_type);
    switch (rc) {
    case POX509_OK:
        break;
    case POX509_NO_MEMORY:
        return rc;
    default:
        log_error("failed to determine access profile type (%s)",
            pox509_strerror(rc));
        return rc;
    }
    /*
     * an access on behalf profile is only relevant if there is a
     * target keystore with a uid matching the uid of the user
     * currently logging in.
     */
    if (access_profile_type == ACCESS_ON_BEHALF_PROFILE) {
        bool aobp_relevant = false;
        rc = check_access_profile_relevance_aobp(ldap_handle, info,
            access_profile_entry, &aobp_relevant);
        switch (rc) {
        case POX509_OK:
            break;
        case POX509_NO_MEMORY:
            return rc;
        default:
            log_error("failed to check access on behalf profile relevance (%s)",
                pox509_strerror(rc));
            return rc;
        }
        if (!aobp_relevant) {
            return POX509_NOT_RELEVANT;
        }
    }

    /* create and populate access profile */
    struct pox509_access_profile *access_profile = new_access_profile();
    if (access_profile == NULL) {
        log_error("failed to allocate memory for access profile");
        return POX509_NO_MEMORY;
    }
    access_profile->type = access_profile_type;
    access_profile->dn = ldap_get_dn(ldap_handle, access_profile_entry);
    if (access_profile->dn == NULL) {
        log_error("failed to obtain dn from access profile entry");
        res = POX509_LDAP_ERR;
        goto cleanup;
    }
    rc = get_rdn_from_dn(access_profile->dn, &access_profile->uid);
    if (rc != POX509_OK) {
        log_error("failed to obtain rdn from dn '%s' (%s)", access_profile->dn,
            pox509_strerror(rc));
        res = POX509_LDAP_ERR;
        goto cleanup;
    }

    /* process access profile */
    rc = process_access_profile(ldap_handle, info, access_profile_entry,
        access_profile);
    if (rc != POX509_OK) {
        res = rc;
        goto cleanup;
    }
    TAILQ_INSERT_TAIL(access_profiles, access_profile, next);
    access_profile = NULL;
    res = POX509_OK;

cleanup:
    if (access_profile != NULL) {
        free_access_profile(access_profile);
    }
    return res;
}

static int
add_access_profiles(LDAP *ldap_handle, LDAPMessage *ssh_server_entry,
    struct pox509_info *info)
{
    if (ldap_handle == NULL || ssh_server_entry == NULL || info == NULL) {
        fatal("ldap_handle, ssh_server_entry or info == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    /* get access profile dns */
    char **access_profile_dns = NULL;
    int rc = get_attr_values_as_string(ldap_handle, ssh_server_entry,
        POX509_SSH_SERVER_AP_ATTR, &access_profile_dns);
    switch (rc) {
    case POX509_OK:
        break;
    case POX509_NO_MEMORY:
        return rc;
    default:
        log_error("failed to obtain access profile dns: attribute '%s' (%s)",
            POX509_SSH_SERVER_AP_ATTR, pox509_strerror(rc));
        return POX509_LDAP_SCHEMA_ERR;
    }

    struct pox509_access_profiles *access_profiles = new_access_profiles();
    if (access_profiles == NULL) {
        log_error("failed to allocate memory for access profiles");
        res = POX509_NO_MEMORY;
        goto cleanup_a;
    }

    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);
    /* add access profiles */
    for (int i = 0; access_profile_dns[i] != NULL; i++) {
        char *access_profile_dn = access_profile_dns[i];
        log_info("processing access profile '%s'", access_profile_dn);

        LDAPMessage *access_profile_entry = NULL;
        rc = ldap_search_ext_s(ldap_handle, access_profile_dn, LDAP_SCOPE_BASE,
            NULL, NULL, 0, NULL, NULL, &search_timeout, 1, &access_profile_entry);
        if (rc != LDAP_SUCCESS) {
            log_error("failed to search ldap: base '%s' (%s)", access_profile_dn,
                ldap_err2string(rc));
            log_info("skipped access profile");
            goto cleanup_inner;
        }
        rc = add_access_profile(ldap_handle, info, access_profile_entry,
            access_profiles);
        switch (rc) {
        case POX509_OK:
            log_info("added access profile");
            break;
        case POX509_NO_MEMORY:
            res = rc;
            ldap_msgfree(access_profile_entry);
            goto cleanup_b;
        default:
            log_info("skipped access profile (%s)", pox509_strerror(rc));
            goto cleanup_inner;
        }
cleanup_inner:
        ldap_msgfree(access_profile_entry);
    }

    /* check if not empty */
    if (TAILQ_EMPTY(access_profiles)) {
        res = POX509_NO_ACCESS_PROFILE;
        goto cleanup_b;
    }
    info->access_profiles = access_profiles;
    access_profiles = NULL;
    res = POX509_OK;

cleanup_b:
    if (access_profiles != NULL) {
        free_access_profiles(access_profiles);
    }
cleanup_a:
    free_attr_values_as_string(access_profile_dns);
    return res;
}

static int
add_ssh_server_entry(LDAP *ldap_handle, struct pox509_info *info,
    LDAPMessage **ret)
{
    if (ldap_handle == NULL || info == NULL || ret == NULL) {
        fatal("ldap_handle, info or ret == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    char *ssh_server_base_dn = cfg_getstr(info->cfg, "ldap_ssh_server_base_dn");
    int ssh_server_search_scope =
        cfg_getint(info->cfg, "ldap_ssh_server_search_scope");
    /* construct search filter */
    char filter[LDAP_SEARCH_FILTER_BUFFER_SIZE];
    char *ssh_server_uid = cfg_getstr(info->cfg, "ssh_server_uid");
    int rc = create_ldap_search_filter(POX509_SSH_SERVER_UID_ATTR, ssh_server_uid,
        filter, sizeof filter);
    if (rc != POX509_OK) {
        log_error("failed to create ldap search filter (%s)", pox509_strerror(rc));
        return POX509_SYSTEM_ERR;
    }
    char *attrs[] = { POX509_SSH_SERVER_AP_ATTR, NULL };
    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);

    /* query ldap for ssh server entry */
    LDAPMessage *ssh_server_entry = NULL;
    rc = ldap_search_ext_s(ldap_handle, ssh_server_base_dn,
        ssh_server_search_scope, filter, attrs, 0, NULL, NULL, &search_timeout,
        1, &ssh_server_entry);
    if (rc != LDAP_SUCCESS) {
        log_error("failed to search ldap: base '%s' (%s)", ssh_server_base_dn,
            ldap_err2string(rc));
        res = POX509_LDAP_NO_SUCH_ENTRY;
        goto cleanup_a;
    }

    /* check if ssh server entry has been found */
    rc = ldap_count_entries(ldap_handle, ssh_server_entry);
    switch (rc) {
    case 0:
        log_error("ssh server entry not existent");
        res = POX509_LDAP_NO_SUCH_ENTRY;
        goto cleanup_a;
    case 1:
        break;
    default:
        log_error("failed to parse ldap search result count");
        res = POX509_LDAP_ERR;
        goto cleanup_a;
    }

    /* get ssh server */
    struct pox509_ssh_server *ssh_server = new_ssh_server();
    if (ssh_server == NULL) {
        log_error("failed to allocate memory for ssh server");
        res = POX509_NO_MEMORY;
        goto cleanup_a;
    }

    ssh_server->dn = ldap_get_dn(ldap_handle, ssh_server_entry);
    if (ssh_server->dn == NULL) {
        log_error("failed to obtain dn from ssh server entry");
        res = POX509_LDAP_ERR;
        goto cleanup_b;
    }
    ssh_server->uid = strdup(cfg_getstr(info->cfg, "ssh_server_uid"));
    if (ssh_server->uid == NULL) {
        log_error("failed to duplicate ssh server uid");
        res = POX509_NO_MEMORY;
        goto cleanup_b;
    }

    *ret = ssh_server_entry;
    ssh_server_entry = NULL;
    info->ssh_server = ssh_server;
    ssh_server = NULL;
    res = POX509_OK;

cleanup_b:
    if (ssh_server != NULL) {
        free_ssh_server(ssh_server);
    }
cleanup_a:
    if (ssh_server_entry != NULL) {
        ldap_msgfree(ssh_server_entry);
    }
    return res;
}

static int
init_starttls(LDAP *ldap_handle)
{
    if (ldap_handle == NULL) {
        fatal("ldap_handle == NULL");
    }

    /* establishes connection to ldap */
    int rc = ldap_start_tls_s(ldap_handle, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
        char *msg = NULL;
        rc = ldap_get_option(ldap_handle, LDAP_OPT_DIAGNOSTIC_MESSAGE, &msg);
        if (rc == LDAP_OPT_SUCCESS) {
            log_error("failed to initialize starttls (%s)", msg);
            ldap_memfree(msg);
            return POX509_LDAP_CONNECTION_ERR;
        }
        log_error("failed to initialize starttls");
        return POX509_LDAP_CONNECTION_ERR;
    }
    return POX509_OK;
}

static int
connect_to_ldap(LDAP *ldap_handle, struct pox509_info *info)
{
    if (ldap_handle == NULL || info == NULL) {
        fatal("ldap_handle or info == NULL");
    }

    int rc;
    bool ldap_starttls = cfg_getint(info->cfg, "ldap_starttls");
    if (ldap_starttls) {
        rc = init_starttls(ldap_handle);
        if (rc != POX509_OK) {
            return rc;
        }
    }

    char *ldap_bind_dn = cfg_getstr(info->cfg, "ldap_bind_dn");
    char *ldap_bind_pwd = cfg_getstr(info->cfg, "ldap_bind_pwd");
    size_t ldap_bind_pwd_length = strlen(ldap_bind_pwd);
    struct berval cred = {
        .bv_len = ldap_bind_pwd_length,
        .bv_val = ldap_bind_pwd
    };
    rc = ldap_sasl_bind_s(ldap_handle, ldap_bind_dn, LDAP_SASL_SIMPLE, &cred,
            NULL, NULL, NULL);
    memset(ldap_bind_pwd, 0, ldap_bind_pwd_length);
    if (rc != LDAP_SUCCESS) {
        log_error("failed to bind to ldap (%s)", ldap_err2string(rc));
        return POX509_LDAP_CONNECTION_ERR;
    }
    return POX509_OK;
}

static int
set_ldap_options(LDAP *ldap_handle, struct pox509_info *info)
{
    if (ldap_handle == NULL || info == NULL) {
        fatal("ldap_handle or info == NULL");
    }

    /* set protocol version */
    int ldap_version = LDAP_VERSION3;
    int rc = ldap_set_option(ldap_handle, LDAP_OPT_PROTOCOL_VERSION,
            &ldap_version);
    if (rc != LDAP_OPT_SUCCESS) {
        log_error("failed to set ldap option: key 'LDAP_OPT_PROTOCOL_VERSION', "
                "value '%d'", ldap_version);
        return POX509_LDAP_ERR;
    }

    /* force validation of certificates when using ldaps */
    int req_cert = LDAP_OPT_X_TLS_HARD;
    rc = ldap_set_option(ldap_handle, LDAP_OPT_X_TLS_REQUIRE_CERT, &req_cert);
    if (rc != LDAP_OPT_SUCCESS) {
        log_error("failed to set ldap option: key 'LDAP_OPT_X_TLS_REQUIRE_CERT', "
                "value '%d'", req_cert);
        return POX509_LDAP_ERR;
    }

    /* set path to trusted ca's */
    char *cert_store_dir = cfg_getstr(info->cfg, "cert_store_dir");
    rc = ldap_set_option(ldap_handle, LDAP_OPT_X_TLS_CACERTDIR, cert_store_dir);
    if (rc != LDAP_OPT_SUCCESS) {
        log_error("failed to set ldap option: key 'LDAP_OPT_X_TLS_CACERTDIR', "
                "value '%s'", cert_store_dir);
        return POX509_LDAP_ERR;
    }

    /*
     * new context has to be set in order to apply options set above
     * regarding tls.
     */
    int new_ctx = POX509_UNDEF;
    rc = ldap_set_option(ldap_handle, LDAP_OPT_X_TLS_NEWCTX, &new_ctx);
    if (rc != LDAP_OPT_SUCCESS) {
        log_error("failed to set ldap option: key 'LDAP_OPT_X_TLS_NEWCTX', "
                "value '%d'", new_ctx);
        return POX509_LDAP_ERR;
    }
    return POX509_OK;
}

static int
init_ldap_handle(struct pox509_info *info, LDAP **ret)
{
    if (info == NULL || ret == NULL) {
        fatal("info or ret == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    LDAP *ldap_handle = NULL;
    char *ldap_uri = cfg_getstr(info->cfg, "ldap_uri");
    int rc = ldap_initialize(&ldap_handle, ldap_uri);
    if (rc != LDAP_SUCCESS) {
        log_error("failed to initialize ldap handle (%s)", ldap_err2string(rc));
        return POX509_LDAP_ERR;
    }
    rc = set_ldap_options(ldap_handle, info);
    if (rc != POX509_OK) {
        log_error("failed to set ldap options (%s)", pox509_strerror(rc));
        res = POX509_LDAP_ERR;
        goto cleanup;
    }
    *ret = ldap_handle;
    ldap_handle = NULL;
    res = POX509_OK;

cleanup:
    if (ldap_handle != NULL) {
        rc = ldap_unbind_ext_s(ldap_handle, NULL, NULL);
        if (rc != LDAP_SUCCESS) {
            log_debug("ldap_unbind_ext_s(): '%s'", ldap_err2string(rc));
        }
    }
    return res;
}

int
get_access_profiles_from_ldap(struct pox509_info *info)
{
    if (info == NULL) {
        fatal("info == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    /* init ldap handle */
    LDAP *ldap_handle = NULL;
    int rc = init_ldap_handle(info, &ldap_handle);
    if (rc != POX509_OK) {
        return rc;
    }

    /* connect to ldap server */
    rc = connect_to_ldap(ldap_handle, info);
    if (rc != POX509_OK) {
        res = rc;
        goto cleanup_a;
    }
    log_info("connection to ldap established");
    info->ldap_online = 1;

    /* add ssh server entry */
    LDAPMessage *ssh_server_entry = NULL;
    rc = add_ssh_server_entry(ldap_handle, info, &ssh_server_entry);
    switch (rc) {
    case POX509_OK:
        break;
    case POX509_NO_MEMORY:
        res = rc;
        goto cleanup_a;
    default:
        log_error("failed to add ssh server (%s)", pox509_strerror(rc));
        res = POX509_NO_SSH_SERVER;
        goto cleanup_a;
    }
    log_info("added ssh server '%s' (%s)", info->ssh_server->uid,
        info->ssh_server->dn);

    /* add access profiles */
    rc = add_access_profiles(ldap_handle, ssh_server_entry, info);
    if (rc != POX509_OK) {
        res = rc;
        goto cleanup_b;
    }
    res = POX509_OK;

cleanup_b:
    ldap_msgfree(ssh_server_entry);
cleanup_a:
    rc = ldap_unbind_ext_s(ldap_handle, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
        log_debug("ldap_unbind_ext_s(): '%s'", ldap_err2string(rc));
    }
    return res;
}

