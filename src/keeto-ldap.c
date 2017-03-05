/*
 * Copyright (C) 2014-2017 Sebastian Roland <seroland86@gmail.com>
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

#include "keeto-ldap.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <confuse.h>
#include <lber.h>
#include <ldap.h>
#include <openssl/x509.h>

#include "keeto-error.h"
#include "keeto-log.h"
#include "keeto-util.h"

#define LDAP_SEARCH_FILTER_BUFFER_SIZE 2048

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

    int res = KEETO_UNKNOWN_ERR;
    /* get attribute values */
    entry = ldap_first_entry(ldap_handle, entry);
    if (entry == NULL) {
        log_error("failed to parse ldap search result set");
        return KEETO_LDAP_ERR;
    }

    /* retrieve attribute value(s) */
    struct berval **values = ldap_get_values_len(ldap_handle, entry, attr);
    if (values == NULL) {
        return KEETO_LDAP_NO_SUCH_ATTR;
    }

    /* count values so we know how wide our buffer has to be */
    int count = ldap_count_values_len(values);
    if (count == 0) {
        log_error("ldap search result set empty for attribute '%s'", attr);
        res = KEETO_LDAP_ERR;
        goto cleanup_a;
    }

    char **values_string = malloc(sizeof(char *) * (count + 1));
    if (values_string == NULL) {
        log_error("failed to allocate memory for attribute value buffer");
        res = KEETO_NO_MEMORY;
        goto cleanup_a;
    }

    for (int i = 0; values[i] != NULL; i++) {
        char *value = values[i]->bv_val;
        ber_len_t len = values[i]->bv_len;
        values_string[i] = strndup(value, len);
        if (values_string[i] == NULL) {
            log_error("failed to duplicate attribute value string");
            res = KEETO_NO_MEMORY;
            goto cleanup_b;
        }
    }
    values_string[count] = NULL;

    *ret = values_string;
    values_string = NULL;
    res = KEETO_OK;

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
        return KEETO_LDAP_ERR;
    }
    *ret = ldap_get_values_len(ldap_handle, entry, attr);
    if (*ret == NULL) {
        return KEETO_LDAP_NO_SUCH_ATTR;
    }
    return KEETO_OK;
}

static int
get_group_member_entry(LDAP *ldap_handle, struct keeto_info *info,
    char *group_dn, char *group_member_attr, LDAPMessage **ret)
{
    if (ldap_handle == NULL || info == NULL || group_dn == NULL ||
        group_member_attr == NULL || ret == NULL) {
        fatal("ldap_handle, info, group_dn, group_member_attr or ret == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;
    char *attr[] = { group_member_attr, NULL };
    /* query ldap for group members */
    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);
    LDAPMessage *group_member_entry = NULL;
    int rc = ldap_search_ext_s(ldap_handle, group_dn, LDAP_SCOPE_BASE, NULL,
        attr, 0, NULL, NULL, &search_timeout, 1, &group_member_entry);
    if (rc != LDAP_SUCCESS) {
        log_error("failed to search ldap: base '%s' (%s)", group_dn,
            ldap_err2string(rc));
        res = KEETO_LDAP_NO_SUCH_ENTRY;
        goto cleanup;
    }
    *ret = group_member_entry;
    group_member_entry = NULL;
    res = KEETO_OK;

cleanup:
    if (group_member_entry != NULL) {
        ldap_msgfree(group_member_entry);
    }
    return res;
}

static int
check_target_keystores(LDAP *ldap_handle, struct keeto_info *info,
    LDAPMessage *target_keystore_group_entry, char *target_keystore_member_attr,
    bool *ret)
{
    if (ldap_handle == NULL || info == NULL ||
        target_keystore_group_entry == NULL ||
        target_keystore_member_attr == NULL || ret == NULL) {
        fatal("ldap_handle, info, target_keystore_group_entry, "
            "target_keystore_member_attr or ret == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;
    bool relevant = false;

    /* check target keystores */
    char **target_keystore_dns = NULL;
    int rc = get_attr_values_as_string(ldap_handle, target_keystore_group_entry,
        target_keystore_member_attr, &target_keystore_dns);
    switch (rc) {
    case KEETO_OK:
        break;
    case KEETO_NO_MEMORY:
        return rc;
    case KEETO_LDAP_NO_SUCH_ATTR:
        log_info("no target keystores specified");
        return rc;
    default:
        log_error("failed to obtain target keystore dns: attribute '%s' (%s)",
            target_keystore_member_attr, keeto_strerror(rc));
        return rc;
    }

    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);
    char *target_keystore_uid_attr = cfg_getstr(info->cfg,
        "ldap_target_keystore_uid_attr");
    char *attrs[] = { target_keystore_uid_attr, NULL };

    for (int i = 0; target_keystore_dns[i] != NULL && !relevant; i++) {
        char *target_keystore_dn = target_keystore_dns[i];
        log_info("checking target keystore '%s'", target_keystore_dn);

        LDAPMessage *target_keystore_entry = NULL;
        rc = ldap_search_ext_s(ldap_handle, target_keystore_dn, LDAP_SCOPE_BASE,
            NULL, attrs, 0, NULL, NULL, &search_timeout, 1,
            &target_keystore_entry);
        if (rc != LDAP_SUCCESS) {
            log_error("failed to search ldap: base '%s' (%s) - skipping",
                target_keystore_dn, ldap_err2string(rc));
            goto cleanup_inner;
        }

        /* get uids of target keystore */
        char **target_keystore_uids = NULL;
        rc = get_attr_values_as_string(ldap_handle, target_keystore_entry,
            target_keystore_uid_attr, &target_keystore_uids);
        switch (rc) {
        case KEETO_OK:
            break;
        case KEETO_NO_MEMORY:
            res = rc;
            ldap_msgfree(target_keystore_entry);
            goto cleanup;
        case KEETO_LDAP_NO_SUCH_ATTR:
            log_error("target keystore has no uids - skipping");
            goto cleanup_inner;
        default:
            log_error("failed to obtain target keystore uids: attribute '%s' "
                "(%s) - skipping", target_keystore_uid_attr, keeto_strerror(rc));
            goto cleanup_inner;
        }

        /* check uids */
        for (int j = 0; target_keystore_uids[j] != NULL; j++) {
            if (strcmp(target_keystore_uids[j], info->uid) == 0) {
                relevant = true;
                break;
            }
        }
        free_attr_values_as_string(target_keystore_uids);
    cleanup_inner:
        ldap_msgfree(target_keystore_entry);
    }

    *ret = relevant;
    res = KEETO_OK;

cleanup:
    free_attr_values_as_string(target_keystore_dns);
    return res;
}

static int
check_access_profile_relevance_aobp(LDAP *ldap_handle, struct keeto_info *info,
    LDAPMessage *access_profile_entry, bool *ret)
{
    if (ldap_handle == NULL || info == NULL || access_profile_entry == NULL ||
        ret == NULL) {
        fatal("ldap_handle, info, access_profile_entry or ret == NULL");
    }

    bool relevant = false;
    log_info("checking target keystores");

    /* check direct target keystores */
    log_info("checking direct target keystores");
    int rc = check_target_keystores(ldap_handle, info, access_profile_entry,
        KEETO_AOBP_TARGET_KEYSTORE_ATTR, &relevant);
    switch (rc) {
    case KEETO_OK:
    case KEETO_LDAP_NO_SUCH_ATTR:
        break;
    case KEETO_NO_MEMORY:
        return rc;
    default:
        log_error("failed to check direct target keystores (%s)",
            keeto_strerror(rc));
        break;
    }
    if (relevant) {
        *ret = true;
        return KEETO_OK;
    }

    /* check target keystore groups */
    log_info("checking target keystore groups");
    char **target_keystore_group_dns = NULL;
    rc = get_attr_values_as_string(ldap_handle, access_profile_entry,
        KEETO_AOBP_TARGET_KEYSTORE_GROUP_ATTR, &target_keystore_group_dns);
    switch (rc) {
    case KEETO_OK:
        ;
        char *target_keystore_group_member_attr = cfg_getstr(info->cfg,
        "ldap_target_keystore_group_member_attr");

        for (int i = 0; target_keystore_group_dns[i] != NULL && !relevant; i++) {
            char *target_keystore_group_dn = target_keystore_group_dns[i];
            log_info("checking target keystore group '%s'",
                target_keystore_group_dn);

            LDAPMessage *group_member_entry = NULL;
            rc = get_group_member_entry(ldap_handle, info,
                target_keystore_group_dn, target_keystore_group_member_attr,
                &group_member_entry);
            if (rc != KEETO_OK) {
                log_info("skipped target keystore group");
                continue;
            }

            rc = check_target_keystores(ldap_handle, info, group_member_entry,
                target_keystore_group_member_attr, &relevant);
            switch (rc) {
            case KEETO_OK:
            case KEETO_LDAP_NO_SUCH_ATTR:
                break;
            case KEETO_NO_MEMORY:
                ldap_msgfree(group_member_entry);
                free_attr_values_as_string(target_keystore_group_dns);
                return rc;
            default:
                log_error("failed to check target keystores (%s)",
                    keeto_strerror(rc));
                goto cleanup_inner;
            }
        cleanup_inner:
            ldap_msgfree(group_member_entry);
        }
        free_attr_values_as_string(target_keystore_group_dns);
        break;
    case KEETO_NO_MEMORY:
        return rc;
    case KEETO_LDAP_NO_SUCH_ATTR:
        log_info("no target keystore groups specified");
        break;
    default:
        log_error("failed to check target keystore groups (%s)",
            keeto_strerror(rc));
        break;
    }
    if (relevant) {
        *ret = true;
        return KEETO_OK;
    }

    *ret = false;
    return KEETO_OK;
}

static int
check_access_profile_enabled(LDAP *ldap_handle,
    LDAPMessage *access_profile_entry, bool *ret)
{
    if (ldap_handle == NULL || access_profile_entry == NULL || ret == NULL) {
        fatal("ldap_handle, access_profile_entry or ret == NULL");
    }

    /*
     * determine state of access profile from KEETO_AP_ENABLED_ATTR
     * attribute.
     */
    char **access_profile_state = NULL;
    int rc = get_attr_values_as_string(ldap_handle, access_profile_entry,
        KEETO_AP_ENABLED_ATTR, &access_profile_state);
    switch (rc) {
    case KEETO_OK:
        break;
    case KEETO_NO_MEMORY:
        return rc;
    default:
        log_error("failed to obtain access profile state: attribute '%s' (%s)",
            KEETO_AP_ENABLED_ATTR, keeto_strerror(rc));
        return KEETO_LDAP_SCHEMA_ERR;
    }
    *ret = strcmp(access_profile_state[0], LDAP_BOOL_TRUE) == 0 ? true : false;
    free_attr_values_as_string(access_profile_state);
    return KEETO_OK;
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
    case KEETO_OK:
        break;
    case KEETO_NO_MEMORY:
        return rc;
    default:
        log_error("failed to check if profile is enabled (%s)",
            keeto_strerror(rc));
        return rc;
    }
    if (!profile_enabled) {
        log_info("access profile disabled");
        *ret = false;
        return KEETO_OK;
    }
    /* do further checks here in the future */
    *ret = true;
    return KEETO_OK;
}

static int
check_access_profile_relevance(LDAP *ldap_handle, struct keeto_info *info,
    struct keeto_access_profile *access_profile,
    LDAPMessage *access_profile_entry, bool *ret)
{
    if (ldap_handle == NULL || info == NULL || access_profile == NULL ||
        access_profile_entry == NULL || ret == NULL) {
        fatal("ldap_handle, info, access_profile, access_profile_entry or ret "
            "== NULL");
    }

    bool relevant = false;
    int rc = check_access_profile_relevance_generic(ldap_handle,
        access_profile_entry, &relevant);
    switch (rc) {
    case KEETO_OK:
        break;
    case KEETO_NO_MEMORY:
        return rc;
    default:
        log_error("failed to check generic access profile relevance (%s)",
            keeto_strerror(rc));
        return rc;
    }
    if (!relevant) {
        *ret = false;
        return KEETO_OK;
    }

    /*
     * an access on behalf profile is only relevant if there is a
     * target keystore with a uid matching the uid of the user
     * currently logging in.
     */
    if (access_profile->type == ACCESS_ON_BEHALF_PROFILE) {
        bool relevant = false;
        rc = check_access_profile_relevance_aobp(ldap_handle, info,
            access_profile_entry, &relevant);
        switch (rc) {
        case KEETO_OK:
            break;
        case KEETO_NO_MEMORY:
            return rc;
        default:
            log_error("failed to check access on behalf profile relevance (%s)",
                keeto_strerror(rc));
            return rc;
        }
        if (!relevant) {
            *ret = false;
            return KEETO_OK;
        }
    }
    *ret = true;
    return KEETO_OK;
}

static int
add_access_profile_type(LDAP *ldap_handle, LDAPMessage *access_profile_entry,
    struct keeto_access_profile *access_profile)
{
    if (ldap_handle == NULL || access_profile_entry == NULL ||
        access_profile == NULL) {
        fatal("ldap_handle, access_profile_entry or access_profile == NULL");
    }

    /* determine access profile type from objectClass attribute */
    char **objectclasses = NULL;
    int rc = get_attr_values_as_string(ldap_handle, access_profile_entry,
        "objectClass", &objectclasses);
    switch (rc) {
    case KEETO_OK:
        break;
    case KEETO_NO_MEMORY:
        return rc;
    default:
        log_error("failed to obtain access profile type: attribute '%s' (%s)",
            "objectClass", keeto_strerror(rc));
        return KEETO_LDAP_SCHEMA_ERR;
    }

    int res = KEETO_UNKNOWN_ACCESS_PROFILE_TYPE;
    /* search for access profile type */
    for (int i = 0; objectclasses[i] != NULL; i++) {
        char *objectclass = objectclasses[i];
        if (strcmp(objectclass, KEETO_DAP_OBJCLASS) == 0) {
            access_profile->type = DIRECT_ACCESS_PROFILE;
            res = KEETO_OK;
            break;
        } else if (strcmp(objectclass, KEETO_AOBP_OBJCLASS) == 0) {
            access_profile->type = ACCESS_ON_BEHALF_PROFILE;
            res = KEETO_OK;
            break;
        }
    }
    free_attr_values_as_string(objectclasses);
    return res;
}

static int
add_keystore_options(LDAP *ldap_handle, LDAPMessage *keystore_options_entry,
    struct keeto_access_profile *access_profile)
{
    if (ldap_handle == NULL || keystore_options_entry == NULL ||
        access_profile == NULL) {
        fatal("ldap_handle, keystore_options_entry or access_profile == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;
    /* create and populate keeto keystore options struct */
    struct keeto_keystore_options *keystore_options = new_keystore_options();
    if (keystore_options == NULL) {
        log_error("failed to allocate memory for keystore options");
        return KEETO_NO_MEMORY;
    }
    keystore_options->dn = ldap_get_dn(ldap_handle, keystore_options_entry);
    if (keystore_options->dn == NULL) {
        log_error("failed to obtain dn from keystore options entry");
        res = KEETO_LDAP_ERR;
        goto cleanup_a;
    }
    int rc = get_rdn_from_dn(keystore_options->dn, &keystore_options->uid);
    if (rc != KEETO_OK) {
        log_error("failed to obtain rdn from dn '%s' (%s)", keystore_options->dn,
            keeto_strerror(rc));
        res = rc;
        goto cleanup_a;
    }

    /* get attribute values */
    char **keystore_options_command = NULL;
    rc = get_attr_values_as_string(ldap_handle, keystore_options_entry,
        KEETO_KEYSTORE_OPTIONS_CMD_ATTR, &keystore_options_command);
    switch (rc) {
    case KEETO_OK:
        keystore_options->command_option = strdup(keystore_options_command[0]);
        if (keystore_options->command_option == NULL) {
            log_error("failed to duplicate keystore option 'command'");
            res = KEETO_NO_MEMORY;
            goto cleanup_b;
        }
        log_info("added keystore option 'command'");
        break;
    case KEETO_NO_MEMORY:
        res = rc;
        goto cleanup_a;
    case KEETO_LDAP_NO_SUCH_ATTR:
        log_info("skipped keystore option 'command' (%s)",
            KEETO_KEYSTORE_OPTIONS_CMD_ATTR);
        break;
    default:
        log_error("failed to obtain keystore option 'command': attribute '%s' (%s)",
            KEETO_KEYSTORE_OPTIONS_CMD_ATTR, keeto_strerror(rc));
        res = rc;
        goto cleanup_a;
    }

    char **keystore_options_from = NULL;
    rc = get_attr_values_as_string(ldap_handle, keystore_options_entry,
        KEETO_KEYSTORE_OPTIONS_FROM_ATTR, &keystore_options_from);
    switch (rc) {
    case KEETO_OK:
        keystore_options->from_option = strdup(keystore_options_from[0]);
        if (keystore_options->from_option == NULL) {
            log_error("failed to duplicate keystore option 'from'");
            res = KEETO_NO_MEMORY;
            goto cleanup_c;
        }
        log_info("added keystore option 'from'");
        break;
    case KEETO_NO_MEMORY:
        res = rc;
        goto cleanup_b;
    case KEETO_LDAP_NO_SUCH_ATTR:
        log_info("skipped keystore option 'from' (%s)",
            KEETO_KEYSTORE_OPTIONS_FROM_ATTR);
        break;
    default:
        log_error("failed to obtain keystore option 'from': attribute '%s' (%s)",
            KEETO_KEYSTORE_OPTIONS_FROM_ATTR, keeto_strerror(rc));
        res = rc;
        goto cleanup_b;
    }

    /* only add keystore options if at least one options has been set */
    if (keystore_options->from_option == NULL &&
        keystore_options->command_option == NULL) {

        res = KEETO_NO_KEYSTORE_OPTION;
        goto cleanup_c;
    }
    access_profile->keystore_options = keystore_options;
    keystore_options = NULL;
    res = KEETO_OK;

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
add_key(struct berval *cert, struct keeto_keys *keys)
{
    if (cert == NULL || keys == NULL) {
        fatal("cert or keys == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;
    /* create and populate keeto key struct */
    struct keeto_key *key = new_key();
    if (key == NULL) {
        log_error("failed to allocate memory for key");
        return KEETO_NO_MEMORY;
    }

    char *x509 = cert->bv_val;
    ber_len_t x509_len = cert->bv_len;
    key->x509 = d2i_X509(NULL, (const unsigned char **) &x509, x509_len);
    if (key->x509 == NULL) {
        log_error("failed to decode certificate");
        res = KEETO_X509_ERR;
        goto cleanup;
    }
    TAILQ_INSERT_TAIL(keys, key, next);
    key = NULL;
    res = KEETO_OK;

cleanup:
    if (key != NULL) {
        free_key(key);
    }
    return res;
}

static int
add_keys(LDAP *ldap_handle, struct keeto_info *info,
    LDAPMessage *key_provider_entry, struct keeto_key_provider *key_provider)
{
    if (ldap_handle == NULL || info == NULL || key_provider_entry == NULL ||
        key_provider == NULL) {
        fatal("ldap_handle, info, key_provider_entry or key_provider == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;
    log_info("processing keys");
    /* get certificates */
    char *key_provider_cert_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_cert_attr");
    struct berval **key_provider_certs = NULL;
    int rc = get_attr_values_as_binary(ldap_handle, key_provider_entry,
        key_provider_cert_attr, &key_provider_certs);
    if (rc != KEETO_OK) {
        log_error("failed to obtain key provider certificate: attribute '%s' (%s)",
            key_provider_cert_attr, keeto_strerror(rc));
        return KEETO_LDAP_SCHEMA_ERR;
    }

    /* create and populate keeto keys struct */
    struct keeto_keys *keys = new_keys();
    if (keys == NULL) {
        log_error("failed to allocate memory for keys");
        res = KEETO_NO_MEMORY;
        goto cleanup_a;
    }

    for (int i = 0; key_provider_certs[i] != NULL; i++) {
        rc = add_key(key_provider_certs[i], keys);
        switch (rc) {
        case KEETO_OK:
            log_info("added key");
            break;
        case KEETO_NO_MEMORY:
            res = rc;
            goto cleanup_b;
        default:
            log_info("skipped key (%s)", keeto_strerror(rc));
        }
    }
    /* check if not empty */
    if (TAILQ_EMPTY(keys)) {
        res = KEETO_NO_CERT;
        goto cleanup_b;
    }
    key_provider->keys = keys;
    keys = NULL;
    res = KEETO_OK;

cleanup_b:
    if (keys != NULL) {
        free_keys(keys);
    }
cleanup_a:
    free_attr_values_as_binary(key_provider_certs);
    return res;
}

static int
add_key_provider(LDAP *ldap_handle, struct keeto_info *info,
    struct keeto_access_profile *access_profile,
    LDAPMessage *key_provider_entry, struct keeto_key_providers *key_providers)
{
    if (ldap_handle == NULL || info == NULL || access_profile == NULL ||
        key_provider_entry == NULL || key_providers == NULL) {
        fatal("ldap_handle, info, access_profile, key_provider_entry or "
            "key_providers == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;
    /* get key provider uids */
    char *key_provider_uid_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_uid_attr");
    char **key_provider_uids = NULL;
    int rc = get_attr_values_as_string(ldap_handle, key_provider_entry,
        key_provider_uid_attr, &key_provider_uids);
    switch (rc) {
    case KEETO_OK:
        break;
    case KEETO_NO_MEMORY:
        return rc;
    default:
        log_error("failed to obtain key provider uids: attribute '%s' (%s)",
            key_provider_uid_attr, keeto_strerror(rc));
        return KEETO_LDAP_SCHEMA_ERR;
    }
    /*
     * for direct access profiles a key provider is only relevant if
     * the uid of the key provider matches the uid of the user
     * currently logging in.
     */
    if (access_profile->type == DIRECT_ACCESS_PROFILE) {
        bool relevant = false;
        for (int i = 0; key_provider_uids[i] != NULL; i++) {
            if (strcmp(key_provider_uids[i], info->uid) == 0) {
                relevant = true;
                break;
            }
        }
        if (!relevant) {
            res = KEETO_NOT_RELEVANT;
            goto cleanup_a;
        }
    }
    /* create and populate keeto key provider struct */
    struct keeto_key_provider *key_provider = new_key_provider();
    if (key_provider == NULL) {
        log_error("failed to allocate memory for key provider");
        res = KEETO_NO_MEMORY;
        goto cleanup_a;
    }
    key_provider->dn = ldap_get_dn(ldap_handle, key_provider_entry);
    if (key_provider->dn == NULL) {
        log_error("failed to obtain dn from key provider entry");
        res = KEETO_LDAP_ERR;
        goto cleanup_b;
    }
    key_provider->uid = strdup(key_provider_uids[0]);
    if (key_provider->uid == NULL) {
        log_error("failed to duplicate key provider uid");
        res = KEETO_NO_MEMORY;
        goto cleanup_b;
    }

    /* add keys */
    rc = add_keys(ldap_handle, info, key_provider_entry, key_provider);
    if (rc != KEETO_OK) {
        res = rc;
        goto cleanup_b;
    }

    TAILQ_INSERT_TAIL(key_providers, key_provider, next);
    key_provider = NULL;
    res = KEETO_OK;

cleanup_b:
    if (key_provider != NULL) {
        free_key_provider(key_provider);
    };
cleanup_a:
    free_attr_values_as_string(key_provider_uids);
    return res;
}

static int
add_key_provider_groups(LDAP *ldap_handle, struct keeto_info *info,
    struct keeto_access_profile *access_profile,
    LDAPMessage *access_profile_entry, struct keeto_key_providers *key_providers)
{
    if (ldap_handle == NULL || info == NULL || access_profile == NULL ||
        access_profile_entry == NULL || key_providers == NULL) {
        fatal("ldap_handle, info, access_profile, access_profile_entry or "
            "key_providers == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;
    log_info("processing key provider groups");

    /* add key provider groups */
    char **key_provider_group_dns = NULL;
    int rc = get_attr_values_as_string(ldap_handle, access_profile_entry,
        KEETO_AP_KEY_PROVIDER_GROUP_ATTR, &key_provider_group_dns);
    switch (rc) {
    case KEETO_OK:
        break;
    case KEETO_NO_MEMORY:
        return rc;
    case KEETO_LDAP_NO_SUCH_ATTR:
        log_info("no key provider groups specified");
        return rc;
    default:
        log_error("failed to obtain key provider group dns: attribute '%s' (%s)",
            KEETO_AP_KEY_PROVIDER_GROUP_ATTR, keeto_strerror(rc));
        return rc;
    }

    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);
    char *key_provider_uid_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_uid_attr");
    char *key_provider_cert_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_cert_attr");
    char *attrs[] = { key_provider_uid_attr, key_provider_cert_attr, NULL };
    char *key_provider_group_member_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_group_member_attr");

    for (int i = 0; key_provider_group_dns[i] != NULL; i++) {
        char *key_provider_group_dn = key_provider_group_dns[i];
        log_info("processing key provider group '%s'", key_provider_group_dn);

        LDAPMessage *group_member_entry = NULL;
        rc = get_group_member_entry(ldap_handle, info, key_provider_group_dn,
            key_provider_group_member_attr, &group_member_entry);
        if (rc != KEETO_OK) {
            log_info("skipped key provider group");
            continue;
        }

        /* get key provider dns */
        char **key_provider_dns = NULL;
        rc = get_attr_values_as_string(ldap_handle, group_member_entry,
            key_provider_group_member_attr, &key_provider_dns);
        switch (rc) {
        case KEETO_OK:
            break;
        case KEETO_NO_MEMORY:
            res = rc;
            ldap_msgfree(group_member_entry);
            goto cleanup;
        case KEETO_LDAP_NO_SUCH_ENTRY:
            log_info("no members in group specified");
            goto cleanup_inner_a;
        default:
            log_error("failed to obtain key provider dns: attribute '%s' (%s)",
                key_provider_group_member_attr, keeto_strerror(rc));
            goto cleanup_inner_a;
        }

        for (int j = 0; key_provider_dns[j] != NULL; j++) {
            char *key_provider_dn = key_provider_dns[j];
            log_info("processing key provider '%s'", key_provider_dn);

            LDAPMessage *key_provider_entry = NULL;
            rc = ldap_search_ext_s(ldap_handle, key_provider_dn, LDAP_SCOPE_BASE,
                NULL, attrs, 0, NULL, NULL, &search_timeout, 1,
                &key_provider_entry);
            if (rc != LDAP_SUCCESS) {
                log_error("failed to search ldap: base '%s' (%s) - skipping",
                key_provider_dn, ldap_err2string(rc));
                goto cleanup_inner_b;
            }

            rc = add_key_provider(ldap_handle, info, access_profile,
                key_provider_entry, key_providers);
            switch (rc) {
            case KEETO_OK:
                log_info("added key provider");
                break;
            case KEETO_NO_MEMORY:
                res = rc;
                ldap_msgfree(key_provider_entry);
                free_attr_values_as_string(key_provider_dns);
                ldap_msgfree(group_member_entry);
                goto cleanup;
            default:
                log_info("skipped key provider (%s)", keeto_strerror(rc));
                goto cleanup_inner_b;
            }
        cleanup_inner_b:
            ldap_msgfree(key_provider_entry);
        }

        free_attr_values_as_string(key_provider_dns);
    cleanup_inner_a:
        ldap_msgfree(group_member_entry);
    }

    res = KEETO_OK;

cleanup:
    free_attr_values_as_string(key_provider_group_dns);
    return res;
}

static int
add_direct_key_providers(LDAP *ldap_handle, struct keeto_info *info,
    struct keeto_access_profile *access_profile,
    LDAPMessage *access_profile_entry, struct keeto_key_providers *key_providers)
{
    if (ldap_handle == NULL || info == NULL || access_profile == NULL ||
        access_profile_entry == NULL || key_providers == NULL) {
        fatal("ldap_handle, info, access_profile, access_profile_entry or "
            "key_providers == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;
    log_info("processing direct key providers");

    /* add key providers */
    char **key_provider_dns = NULL;
    int rc = get_attr_values_as_string(ldap_handle, access_profile_entry,
        KEETO_AP_KEY_PROVIDER_ATTR, &key_provider_dns);
    switch (rc) {
    case KEETO_OK:
        break;
    case KEETO_NO_MEMORY:
        return rc;
    case KEETO_LDAP_NO_SUCH_ATTR:
        log_info("no direct key providers specified");
        return rc;
    default:
        log_error("failed to obtain key provider dns: attribute '%s' (%s)",
            KEETO_AP_KEY_PROVIDER_ATTR, keeto_strerror(rc));
        return rc;
    }

    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);
    char *key_provider_uid_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_uid_attr");
    char *key_provider_cert_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_cert_attr");
    char *attrs[] = { key_provider_uid_attr, key_provider_cert_attr, NULL };

    for (int i = 0; key_provider_dns[i] != NULL; i++) {
        char *key_provider_dn = key_provider_dns[i];
        log_info("processing key provider '%s'", key_provider_dn);

        LDAPMessage *key_provider_entry = NULL;
        rc = ldap_search_ext_s(ldap_handle, key_provider_dn, LDAP_SCOPE_BASE,
            NULL, attrs, 0, NULL, NULL, &search_timeout, 1,
            &key_provider_entry);
        if (rc != LDAP_SUCCESS) {
            log_error("failed to search ldap: base '%s' (%s) - skipping",
                key_provider_dn, ldap_err2string(rc));
            goto cleanup_inner;
        }

        rc = add_key_provider(ldap_handle, info, access_profile,
            key_provider_entry, key_providers);
        switch (rc) {
        case KEETO_OK:
            log_info("added key provider");
            break;
        case KEETO_NO_MEMORY:
            res = rc;
            ldap_msgfree(key_provider_entry);
            goto cleanup;
        default:
            log_info("skipped key provider (%s)", keeto_strerror(rc));
            goto cleanup_inner;
        }
    cleanup_inner:
        ldap_msgfree(key_provider_entry);
    }

    res = KEETO_OK;

cleanup:
    free_attr_values_as_string(key_provider_dns);
    return res;
}

static int
add_key_providers(LDAP *ldap_handle, struct keeto_info *info,
    LDAPMessage *access_profile_entry,
    struct keeto_access_profile *access_profile)
{
    if (ldap_handle == NULL || info == NULL || access_profile_entry == NULL ||
        access_profile == NULL) {
        fatal("ldap_handle, info, access_profile_entry or access_profile == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;
    log_info("processing key providers");

    /* create and populate keeto key providers struct */
    struct keeto_key_providers *key_providers = new_key_providers();
    if (key_providers == NULL) {
        log_error("failed to allocate memory for key providers");
        return KEETO_NO_MEMORY;
    }

    /* add direct key providers */
    int rc = add_direct_key_providers(ldap_handle, info, access_profile,
        access_profile_entry, key_providers);
    switch (rc) {
    case KEETO_OK:
    case KEETO_LDAP_NO_SUCH_ATTR:
        break;
    case KEETO_NO_MEMORY:
        res = rc;
        goto cleanup;
    default:
        log_error("failed to add direct key providers (%s)", keeto_strerror(rc));
        res = rc;
        goto cleanup;
    }

    /* add key provider groups */
    rc = add_key_provider_groups(ldap_handle, info, access_profile,
        access_profile_entry, key_providers);
    switch (rc) {
    case KEETO_OK:
    case KEETO_LDAP_NO_SUCH_ATTR:
        break;
    case KEETO_NO_MEMORY:
        res = rc;
        goto cleanup;
    default:
        log_error("failed to add key provider groups (%s)", keeto_strerror(rc));
        res = rc;
        goto cleanup;
    }

    /* check if not empty */
    if (TAILQ_EMPTY(key_providers)) {
        res = KEETO_NO_KEY_PROVIDER;
        goto cleanup;
    }
    access_profile->key_providers = key_providers;
    key_providers = NULL;
    res = KEETO_OK;

cleanup:
    if (key_providers != NULL) {
        free_key_providers(key_providers);
    }
    return res;
}

static int
add_access_profile(LDAP *ldap_handle, struct keeto_info *info,
    LDAPMessage *access_profile_entry,
    struct keeto_access_profiles *access_profiles)
{
    if (ldap_handle == NULL || info == NULL || access_profile_entry == NULL ||
        access_profiles == NULL) {
        fatal("ldap_handle, info, access_profile_dn or access_profiles == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;
    /* create and populate keeto access profile struct */
    struct keeto_access_profile *access_profile = new_access_profile();
    if (access_profile == NULL) {
        log_error("failed to allocate memory for access profile");
        return KEETO_NO_MEMORY;
    }
    access_profile->dn = ldap_get_dn(ldap_handle, access_profile_entry);
    if (access_profile->dn == NULL) {
        log_error("failed to obtain dn from access profile entry");
        res = KEETO_LDAP_ERR;
        goto cleanup_a;
    }
    int rc = get_rdn_from_dn(access_profile->dn, &access_profile->uid);
    if (rc != KEETO_OK) {
        log_error("failed to obtain rdn from dn '%s' (%s)", access_profile->dn,
            keeto_strerror(rc));
        res = KEETO_LDAP_ERR;
        goto cleanup_a;
    }

    /* add access profile type */
    rc = add_access_profile_type(ldap_handle, access_profile_entry,
        access_profile);
    switch (rc) {
    case KEETO_OK:
        break;
    case KEETO_NO_MEMORY:
        res = rc;
        goto cleanup_a;
    default:
        log_error("failed to determine access profile type (%s)",
            keeto_strerror(rc));
        res = rc;
        goto cleanup_a;
    }

    /* check access profile relevance */
    bool relevant = false;
    rc = check_access_profile_relevance(ldap_handle, info, access_profile,
        access_profile_entry, &relevant);
    switch (rc) {
    case KEETO_OK:
        break;
    case KEETO_NO_MEMORY:
        res = rc;
        goto cleanup_a;
    default:
        log_error("failed to check access profile relevance (%s)",
            keeto_strerror(rc));
        res = rc;
        goto cleanup_a;
    }
    if (!relevant) {
        res = KEETO_NOT_RELEVANT;
        goto cleanup_a;
    }

    /* add key providers */
    rc = add_key_providers(ldap_handle, info, access_profile_entry,
        access_profile);
    if (rc != KEETO_OK) {
        res = rc;
        goto cleanup_a;
    }

    /* add keystore options */
    char **keystore_options_dn = NULL;
    rc = get_attr_values_as_string(ldap_handle, access_profile_entry,
        KEETO_AP_KEYSTORE_OPTIONS_ATTR, &keystore_options_dn);
    switch (rc) {
    case KEETO_OK:
        log_info("processing keystore options '%s'", keystore_options_dn[0]);
        struct timeval search_timeout = get_ldap_search_timeout(info->cfg);
        char *attrs[] = {
            KEETO_KEYSTORE_OPTIONS_FROM_ATTR,
            KEETO_KEYSTORE_OPTIONS_CMD_ATTR,
            NULL
        };
        LDAPMessage *keystore_options_entry = NULL;
        rc = ldap_search_ext_s(ldap_handle, keystore_options_dn[0],
            LDAP_SCOPE_BASE, NULL, attrs, 0, NULL, NULL, &search_timeout, 1,
            &keystore_options_entry);
        if (rc != LDAP_SUCCESS) {
            log_error("failed to search ldap: base '%s' (%s)",
                keystore_options_dn[0], ldap_err2string(rc));
            res = KEETO_LDAP_NO_SUCH_ENTRY;
            ldap_msgfree(keystore_options_entry);
            goto cleanup_b;
        }
        rc = add_keystore_options(ldap_handle, keystore_options_entry,
            access_profile);
        switch (rc) {
        case KEETO_OK:
            log_info("added keystore options");
            break;
        case KEETO_NO_MEMORY:
            res = rc;
            ldap_msgfree(keystore_options_entry);
            goto cleanup_b;
        case KEETO_NO_KEYSTORE_OPTION:
            log_info("keystore options entry has no option set - remove "
                "keystore options from access profile?!");
            break;
        default:
            log_error("failed to add keystore options (%s)", keeto_strerror(rc));
            res = rc;
            ldap_msgfree(keystore_options_entry);
            goto cleanup_b;
        }
        ldap_msgfree(keystore_options_entry);
        break;
    case KEETO_NO_MEMORY:
        res = rc;
        goto cleanup_a;
    case KEETO_LDAP_NO_SUCH_ATTR:
        log_info("skipped keystore options (%s)", keeto_strerror(rc));
        break;
    default:
        log_error("failed to obtain keystore options dn: attribute '%s' (%s)",
            KEETO_AP_KEYSTORE_OPTIONS_ATTR, keeto_strerror(rc));
        res = rc;
        goto cleanup_a;
    }

    TAILQ_INSERT_TAIL(access_profiles, access_profile, next);
    access_profile = NULL;
    res = KEETO_OK;

cleanup_b:
    free_attr_values_as_string(keystore_options_dn);
cleanup_a:
    if (access_profile != NULL) {
        free_access_profile(access_profile);
    }
    return res;
}

static int
add_access_profiles(LDAP *ldap_handle, LDAPMessage *ssh_server_entry,
    struct keeto_info *info)
{
    if (ldap_handle == NULL || ssh_server_entry == NULL || info == NULL) {
        fatal("ldap_handle, ssh_server_entry or info == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;
    log_info("processing access profiles");

    /* get access profile dns */
    char **access_profile_dns = NULL;
    int rc = get_attr_values_as_string(ldap_handle, ssh_server_entry,
        KEETO_SSH_SERVER_AP_ATTR, &access_profile_dns);
    switch (rc) {
    case KEETO_OK:
        break;
    case KEETO_LDAP_NO_SUCH_ATTR:
        log_info("no access profile specified");
        return KEETO_NO_ACCESS_PROFILE_FOR_SSH_SERVER;
    case KEETO_NO_MEMORY:
        return rc;
    default:
        log_error("failed to obtain access profile dns: attribute '%s' (%s)",
            KEETO_SSH_SERVER_AP_ATTR, keeto_strerror(rc));
        return rc;
    }

    /* create and populate keeto access profiles struct */
    struct keeto_access_profiles *access_profiles = new_access_profiles();
    if (access_profiles == NULL) {
        log_error("failed to allocate memory for access profiles");
        res = KEETO_NO_MEMORY;
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
            log_error("failed to search ldap: base '%s' (%s) - skipping",
                access_profile_dn, ldap_err2string(rc));
            goto cleanup_inner;
        }

        rc = add_access_profile(ldap_handle, info, access_profile_entry,
            access_profiles);
        switch (rc) {
        case KEETO_OK:
            log_info("added access profile");
            break;
        case KEETO_NO_MEMORY:
            res = rc;
            ldap_msgfree(access_profile_entry);
            goto cleanup_b;
        default:
            log_info("skipped access profile (%s)", keeto_strerror(rc));
            goto cleanup_inner;
        }
    cleanup_inner:
        ldap_msgfree(access_profile_entry);
    }

    /* check if not empty */
    if (TAILQ_EMPTY(access_profiles)) {
        res = KEETO_NO_ACCESS_PROFILE_FOR_UID;
        goto cleanup_b;
    }
    info->access_profiles = access_profiles;
    access_profiles = NULL;
    res = KEETO_OK;

cleanup_b:
    if (access_profiles != NULL) {
        free_access_profiles(access_profiles);
    }
cleanup_a:
    free_attr_values_as_string(access_profile_dns);
    return res;
}

static int
add_ssh_server_entry(LDAP *ldap_handle, struct keeto_info *info,
    LDAPMessage **ret)
{
    if (ldap_handle == NULL || info == NULL || ret == NULL) {
        fatal("ldap_handle, info or ret == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;
    char *ssh_server_search_base = cfg_getstr(info->cfg,
        "ldap_ssh_server_search_base");
    int ssh_server_search_scope = cfg_getint(info->cfg,
        "ldap_ssh_server_search_scope");
    /* construct search filter */
    char filter[LDAP_SEARCH_FILTER_BUFFER_SIZE];
    char *ssh_server_uid = cfg_getstr(info->cfg, "ssh_server_uid");
    int rc = create_ldap_search_filter(KEETO_SSH_SERVER_UID_ATTR, ssh_server_uid,
        filter, sizeof filter);
    if (rc != KEETO_OK) {
        log_error("failed to create ldap search filter (%s)", keeto_strerror(rc));
        return KEETO_SYSTEM_ERR;
    }
    char *attrs[] = { KEETO_SSH_SERVER_AP_ATTR, NULL };
    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);

    /* query ldap for ssh server entry */
    LDAPMessage *ssh_server_entry = NULL;
    rc = ldap_search_ext_s(ldap_handle, ssh_server_search_base,
        ssh_server_search_scope, filter, attrs, 0, NULL, NULL, &search_timeout,
        1, &ssh_server_entry);
    if (rc != LDAP_SUCCESS) {
        log_error("failed to search ldap: base '%s' (%s)", ssh_server_search_base,
            ldap_err2string(rc));
        res = KEETO_LDAP_NO_SUCH_ENTRY;
        goto cleanup_a;
    }

    /* check if ssh server entry has been found */
    rc = ldap_count_entries(ldap_handle, ssh_server_entry);
    switch (rc) {
    case 0:
        log_error("ssh server entry not existent");
        res = KEETO_LDAP_NO_SUCH_ENTRY;
        goto cleanup_a;
    case 1:
        break;
    default:
        log_error("failed to parse ldap search result count");
        res = KEETO_LDAP_ERR;
        goto cleanup_a;
    }

    /* create and populate keeto ssh server struct */
    struct keeto_ssh_server *ssh_server = new_ssh_server();
    if (ssh_server == NULL) {
        log_error("failed to allocate memory for ssh server");
        res = KEETO_NO_MEMORY;
        goto cleanup_a;
    }

    ssh_server->dn = ldap_get_dn(ldap_handle, ssh_server_entry);
    if (ssh_server->dn == NULL) {
        log_error("failed to obtain dn from ssh server entry");
        res = KEETO_LDAP_ERR;
        goto cleanup_b;
    }
    ssh_server->uid = strdup(cfg_getstr(info->cfg, "ssh_server_uid"));
    if (ssh_server->uid == NULL) {
        log_error("failed to duplicate ssh server uid");
        res = KEETO_NO_MEMORY;
        goto cleanup_b;
    }

    *ret = ssh_server_entry;
    ssh_server_entry = NULL;
    info->ssh_server = ssh_server;
    ssh_server = NULL;
    res = KEETO_OK;

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
            return KEETO_LDAP_CONNECTION_ERR;
        }
        log_error("failed to initialize starttls");
        return KEETO_LDAP_CONNECTION_ERR;
    }
    return KEETO_OK;
}

static int
connect_to_ldap(LDAP *ldap_handle, struct keeto_info *info)
{
    if (ldap_handle == NULL || info == NULL) {
        fatal("ldap_handle or info == NULL");
    }

    int rc;
    bool ldap_starttls = cfg_getint(info->cfg, "ldap_starttls");
    if (ldap_starttls) {
        rc = init_starttls(ldap_handle);
        if (rc != KEETO_OK) {
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
        return KEETO_LDAP_CONNECTION_ERR;
    }
    return KEETO_OK;
}

static int
set_ldap_options(LDAP *ldap_handle, struct keeto_info *info)
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
        return KEETO_LDAP_ERR;
    }

    /* force validation of certificates when using ldaps */
    int req_cert = LDAP_OPT_X_TLS_HARD;
    rc = ldap_set_option(ldap_handle, LDAP_OPT_X_TLS_REQUIRE_CERT, &req_cert);
    if (rc != LDAP_OPT_SUCCESS) {
        log_error("failed to set ldap option: key 'LDAP_OPT_X_TLS_REQUIRE_CERT', "
            "value '%d'", req_cert);
        return KEETO_LDAP_ERR;
    }

    /* set path to trusted ca's */
    char *cert_store_dir = cfg_getstr(info->cfg, "cert_store_dir");
    rc = ldap_set_option(ldap_handle, LDAP_OPT_X_TLS_CACERTDIR, cert_store_dir);
    if (rc != LDAP_OPT_SUCCESS) {
        log_error("failed to set ldap option: key 'LDAP_OPT_X_TLS_CACERTDIR', "
            "value '%s'", cert_store_dir);
        return KEETO_LDAP_ERR;
    }

    /*
     * new context has to be set in order to apply options set above
     * regarding tls.
     */
    int new_ctx = KEETO_UNDEF;
    rc = ldap_set_option(ldap_handle, LDAP_OPT_X_TLS_NEWCTX, &new_ctx);
    if (rc != LDAP_OPT_SUCCESS) {
        log_error("failed to set ldap option: key 'LDAP_OPT_X_TLS_NEWCTX', "
            "value '%d'", new_ctx);
        return KEETO_LDAP_ERR;
    }
    return KEETO_OK;
}

static int
init_ldap_handle(struct keeto_info *info, LDAP **ret)
{
    if (info == NULL || ret == NULL) {
        fatal("info or ret == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;
    LDAP *ldap_handle = NULL;
    char *ldap_uri = cfg_getstr(info->cfg, "ldap_uri");
    int rc = ldap_initialize(&ldap_handle, ldap_uri);
    if (rc != LDAP_SUCCESS) {
        log_error("failed to initialize ldap handle (%s)", ldap_err2string(rc));
        return KEETO_LDAP_ERR;
    }
    rc = set_ldap_options(ldap_handle, info);
    if (rc != KEETO_OK) {
        log_error("failed to set ldap options (%s)", keeto_strerror(rc));
        res = KEETO_LDAP_ERR;
        goto cleanup;
    }
    *ret = ldap_handle;
    ldap_handle = NULL;
    res = KEETO_OK;

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
get_access_profiles_from_ldap(struct keeto_info *info)
{
    if (info == NULL) {
        fatal("info == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;
    /* init ldap handle */
    LDAP *ldap_handle = NULL;
    int rc = init_ldap_handle(info, &ldap_handle);
    if (rc != KEETO_OK) {
        return rc;
    }

    /* connect to ldap server */
    rc = connect_to_ldap(ldap_handle, info);
    if (rc != KEETO_OK) {
        res = rc;
        goto cleanup_a;
    }
    log_info("connection to ldap established");
    info->ldap_online = 1;

    /* add ssh server entry */
    LDAPMessage *ssh_server_entry = NULL;
    rc = add_ssh_server_entry(ldap_handle, info, &ssh_server_entry);
    switch (rc) {
    case KEETO_OK:
        break;
    case KEETO_NO_MEMORY:
        res = rc;
        goto cleanup_a;
    case KEETO_LDAP_NO_SUCH_ENTRY:
        res = KEETO_NO_SSH_SERVER;
        goto cleanup_a;
    default:
        log_error("failed to add ssh server (%s)", keeto_strerror(rc));
        res = rc;
        goto cleanup_a;
    }
    log_info("added ssh server '%s' (%s)", info->ssh_server->uid,
        info->ssh_server->dn);

    /* add access profiles */
    rc = add_access_profiles(ldap_handle, ssh_server_entry, info);
    if (rc != KEETO_OK) {
        res = rc;
        goto cleanup_b;
    }
    res = KEETO_OK;

cleanup_b:
    ldap_msgfree(ssh_server_entry);
cleanup_a:
    rc = ldap_unbind_ext_s(ldap_handle, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
        log_debug("ldap_unbind_ext_s(): '%s'", ldap_err2string(rc));
    }
    return res;
}

