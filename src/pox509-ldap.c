/*
 * Copyright (C) 2014-2016 Sebastian Roland <seroland86@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
free_attr_values_as_string_array(char **values)
{
    if (values == NULL) {
        log_debug("double free?");
        return;
    }

    for (int i = 0; values[i] != NULL; i++) {
        free(values[i]);
    }
    free(values);
}

static void
free_attr_values_as_binary_array(struct berval **values)
{
    if (values == NULL) {
        log_debug("double free?");
        return;
    }
    ldap_value_free_len(values);
}

static int
get_attr_values_as_string(LDAP *ldap_handle, LDAPMessage *result, char *attr,
    char ***ret)
{
    if (ldap_handle == NULL || result == NULL || attr == NULL || ret == NULL) {
        fatal("ldap_handle, result, attr or ret == NULL");
    }

    /* get attribute values */
    result = ldap_first_entry(ldap_handle, result);
    if (result == NULL) {
        log_debug("ldap_first_entry() error");
        return POX509_LDAP_ERR;
    }

    /* retrieve attribute value(s) */
    struct berval **values = ldap_get_values_len(ldap_handle, result, attr);
    if (values == NULL) {
        return POX509_LDAP_NO_SUCH_ATTR;
    }

    int res = POX509_UNKNOWN_ERR;
    /* count values so we know how wide our array has to be */
    int count = ldap_count_values_len(values);
    if (count == 0) {
        log_debug("ldap_count_values_len() returned 0");
        res = POX509_LDAP_ERR;
        goto cleanup_a;
    }

    char **values_string = malloc(sizeof(char *) * (count + 1));
    if (values_string == NULL) {
        log_debug("malloc() error");
        res = POX509_NO_MEMORY;
        goto cleanup_a;
    }

    for (int i = 0; values[i] != NULL; i++) {
        char *value = values[i]->bv_val;
        ber_len_t len = values[i]->bv_len;
        values_string[i] = strndup(value, len);
        if (values_string[i] == NULL) {
            log_debug("strndup() error");
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
        free_attr_values_as_string_array(values_string);
    }
cleanup_a:
    ldap_value_free_len(values);
    return res;
}

static int
get_attr_values_as_binary(LDAP *ldap_handle, LDAPMessage *result, char *attr,
    struct berval ***ret)
{
    if (ldap_handle == NULL || result == NULL || attr == NULL || ret == NULL) {
        fatal("ldap_handle, result, attr or ret == NULL");
    }

    /* get attribute values */
    result = ldap_first_entry(ldap_handle, result);
    if (result == NULL) {
        log_debug("ldap_first_entry() error");
        return POX509_LDAP_ERR;
    }
    *ret = ldap_get_values_len(ldap_handle, result, attr);
    if (*ret == NULL) {
        return POX509_LDAP_NO_SUCH_ATTR;
    }
    return POX509_OK;
}

static int
check_profile_enabled(LDAP *ldap_handle, LDAPMessage *result,
    bool *is_profile_enabled)
{
    if (ldap_handle == NULL || result == NULL || is_profile_enabled == NULL) {
        fatal("ldap_handle, result or is_profile_enabled == NULL");
    }

    /* determine state of access profile from POX509_AP_IS_ENABLED attribute */
    char **access_profile_state = NULL;
    int rc = get_attr_values_as_string(ldap_handle, result,
        POX509_AP_IS_ENABLED, &access_profile_state);
    if (rc != POX509_OK) {
        return rc;
    }
    *is_profile_enabled = strcmp(access_profile_state[0], LDAP_BOOL_TRUE) == 0 ?
        true : false;
    free_attr_values_as_string_array(access_profile_state);

    return POX509_OK;
}

static int
get_access_profile_type(LDAP *ldap_handle, LDAPMessage *result,
    enum pox509_access_profile_type *ret)
{
    if (ldap_handle == NULL || result == NULL || ret == NULL) {
        fatal("ldap_handle, result or ret == NULL");
    }

    /* determine access profile type from objectClass attribute */
    char **objectclasses = NULL;
    int rc = get_attr_values_as_string(ldap_handle, result, "objectClass",
        &objectclasses);
    if (rc != POX509_OK) {
        return rc;
    }

    /* search for access profile type */
    for (int i = 0; objectclasses[i] != NULL; i++) {
        char *objectclass = objectclasses[i];
        if (strcmp(objectclass, POX509_DAP_OBJCLASS) == 0) {
            *ret = DIRECT_ACCESS_PROFILE;
            break;
        } else if (strcmp(objectclass, POX509_AOBP_OBJCLASS) == 0) {
            *ret = ACCESS_ON_BEHALF_PROFILE;
            break;
        }
    }
    free_attr_values_as_string_array(objectclasses);

    return POX509_OK;
}

static int
get_group_member_entry(LDAP *ldap_handle, struct pox509_info *info, char *dn,
    char *group_member_attr, LDAPMessage **ret)
{
    if (ldap_handle == NULL || info == NULL || dn == NULL ||
        group_member_attr == NULL || ret == NULL) {

        fatal("ldap_handle, info, dn, group_member_attr or ret == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    char *attr[] = { group_member_attr, NULL };
    /* query ldap for group members */
    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);
    LDAPMessage *group_member_entry = NULL;
    int rc = ldap_search_ext_s(ldap_handle, dn, LDAP_SCOPE_BASE, NULL, attr,
        0, NULL, NULL, &search_timeout, 1, &group_member_entry);
    if (rc != LDAP_SUCCESS) {
        log_debug("ldap_search_ext_s(): base: '%s' - '%s' (%d)", dn,
            ldap_err2string(rc), rc);
        res = POX509_LDAP_ERR;
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

static void
get_target_keystore_uid(LDAP *ldap_handle, struct pox509_info *info,
    char *target_keystore_dn, char ***target_keystore_uid)
{
    if (ldap_handle == NULL || info == NULL || target_keystore_dn == NULL ||
        target_keystore_uid == NULL) {

        fatal("ldap_handle, info, target_keystore_dn or target_keystore_uid == "
            "NULL");
    }

    char *target_keystore_uid_attr =
        cfg_getstr(info->cfg, "ldap_target_keystore_uid_attr");
    char *attrs[] = {
        target_keystore_uid_attr,
        NULL
    };
    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);
    LDAPMessage *result = NULL;

    int rc = ldap_search_ext_s(ldap_handle, target_keystore_dn, LDAP_SCOPE_BASE,
        NULL, attrs, 0, NULL, NULL, &search_timeout, 1, &result);
    if (rc != LDAP_SUCCESS) {
        fatal("ldap_search_ext_s(): base: '%s' - '%s' (%d)", target_keystore_dn,
        ldap_err2string(rc), rc);
    }

    get_attr_values_as_string(ldap_handle, result, target_keystore_uid_attr,
        target_keystore_uid);
    ldap_msgfree(result);
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
        return POX509_NO_MEMORY;
    }

    char *x509 = cert->bv_val;
    ber_len_t x509_len = cert->bv_len;
    key->x509 = d2i_X509(NULL, (const unsigned char **) &x509, x509_len);
    if (key->x509 == NULL) {
        log_error("d2i_X509(): cannot decode certificate");
        res = POX509_X509_ERR;
        goto cleanup;
    }
    SIMPLEQ_INSERT_TAIL(keys, key, next);
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
    /* add certificates */
    char *key_provider_cert_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_cert_attr");
    struct berval **key_provider_certs = NULL;
    int rc = get_attr_values_as_binary(ldap_handle, key_provider_entry,
        key_provider_cert_attr, &key_provider_certs);
    if (rc != POX509_OK) {
        return rc;
    }

    struct pox509_keys *keys = new_keys();
    if (keys == NULL) {
        res = POX509_NO_MEMORY;
        goto cleanup_a;
    }

    for (int i = 0; key_provider_certs[i] != NULL; i++) {
        rc = add_key(key_provider_certs[i], keys);
        switch (rc) {
        case POX509_OK:
            log_info("found certificate");
            break;
        case POX509_NO_MEMORY:
            res = rc;
            goto cleanup_b;
        default:
            log_debug("add_key(): '%s'", pox509_strerror(rc));
        }
    }

    /* check if not empty */
    if (SIMPLEQ_EMPTY(keys)) {
        log_info("no certificates found");
        res = POX509_NO_CERTS;
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
    free_attr_values_as_binary_array(key_provider_certs);
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
    if (rc != POX509_OK) {
        return rc;
    }

    /*
     * if we are processing a direct access profile only key providers
     * are relevant that match the uid of the current user logging in
     */
    if (access_profile->type == DIRECT_ACCESS_PROFILE) {
        bool is_authorized = strcmp(key_provider_uid[0], info->uid) == 0 ?
            true : false;
        if (!is_authorized) {
            log_info("not relevant");
            res = POX509_NOT_RELEVANT;
            goto cleanup_a;
        }
    }

    /* create and populate key provider */
    struct pox509_key_provider *key_provider = new_key_provider();
    if (key_provider == NULL) {
        log_debug("malloc() error");
        res = POX509_NO_MEMORY;
        goto cleanup_a;
    }
    key_provider->dn = ldap_get_dn(ldap_handle, key_provider_entry);
    if (key_provider->dn == NULL) {
        log_debug("ldap_get_dn()) error");
        res = POX509_LDAP_ERR;
        goto cleanup_b;
    }
    key_provider->uid = strdup(key_provider_uid[0]);
    if (key_provider->uid == NULL) {
        log_debug("strdup() error");
        res = POX509_NO_MEMORY;
        goto cleanup_b;
    }
    log_info("uid: '%s'", key_provider->uid);

    /* add keys */
    rc = add_keys(ldap_handle, info, key_provider_entry, key_provider);
    if (rc != POX509_OK) {
        res = rc;
        goto cleanup_b;
    }

    SIMPLEQ_INSERT_TAIL(key_providers, key_provider, next);
    key_provider = NULL;
    res = POX509_OK;

cleanup_b:
    if (key_provider != NULL) {
        free_key_provider(key_provider);
    };
cleanup_a:
    free_attr_values_as_string_array(key_provider_uid);
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
    if (rc != POX509_OK) {
        return rc;
    }

    struct pox509_key_providers *key_providers = new_key_providers();
    if (key_providers == NULL) {
        res = POX509_NO_MEMORY;
        goto cleanup_a;
    }

    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);
    /* add key providers */
    for (int i = 0; key_provider_dns[i] != NULL; i++) {
        char *key_provider_dn = key_provider_dns[i];
        log_info("processing key provider: '%s'", key_provider_dn);

        char *key_provider_uid_attr = cfg_getstr(info->cfg,
            "ldap_key_provider_uid_attr");
        char *key_provider_cert_attr = cfg_getstr(info->cfg,
            "ldap_key_provider_cert_attr");
        char *attrs[] = { key_provider_uid_attr, key_provider_cert_attr, NULL };
        LDAPMessage *key_provider_entry = NULL;
        rc = ldap_search_ext_s(ldap_handle, key_provider_dn, LDAP_SCOPE_BASE,
            NULL, attrs, 0, NULL, NULL, &search_timeout, 1, &key_provider_entry);
        if (rc != LDAP_SUCCESS) {
            res = rc;
            log_debug("ldap_search_ext_s(): base: '%s' - '%s' (%d)",
            key_provider_dn, ldap_err2string(rc), rc);
            goto cleanup_inner;
        }

        rc = add_key_provider(ldap_handle, info, access_profile,
            key_provider_entry, key_providers);
        switch (rc) {
        case POX509_OK:
            break;
        case POX509_NO_MEMORY:
            res = rc;
            goto cleanup_b;
        default:
            continue;
        }
cleanup_inner:
        ldap_msgfree(key_provider_entry);
    }
    access_profile->key_providers = key_providers;
    key_providers = NULL;
    res = POX509_OK;

cleanup_b:
    if (key_providers != NULL) {
        free_key_providers(key_providers);
    }
cleanup_a:
    free_attr_values_as_string_array(key_provider_dns);
    return res;
}

static void
get_keystore_options(LDAP *ldap_handle, struct pox509_info *info,
    char *keystore_options_dn, struct pox509_keystore_options *options)
{
    if (ldap_handle == NULL || info == NULL || keystore_options_dn == NULL ||
        options == NULL) {

        fatal("ldap_handle, info, keystore_options_dn or options == NULL");
    }

    options->dn = strdup(keystore_options_dn);
    if (options->dn == NULL) {
        fatal("strdup()");
    }
    get_rdn_value_from_dn(keystore_options_dn, &options->uid);
    char *attrs[] = {
        POX509_KEYSTORE_OPTIONS_FROM_ATTR,
        POX509_KEYSTORE_OPTIONS_CMD_ATTR,
        NULL
    };
    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);
    LDAPMessage *result = NULL;

    int rc = ldap_search_ext_s(ldap_handle, options->dn, LDAP_SCOPE_BASE, NULL,
        attrs, 0, NULL, NULL, &search_timeout, 1, &result);
    if (rc != LDAP_SUCCESS) {
        fatal("ldap_search_ext_s(): base: '%s' - '%s' (%d)", options->dn,
        ldap_err2string(rc), rc);
    }

    /* get attribute values (can be NULL as optional) */
    char **keystore_options_from = NULL;
    get_attr_values_as_string(ldap_handle, result,
        POX509_KEYSTORE_OPTIONS_FROM_ATTR, &keystore_options_from);
    if (keystore_options_from == NULL) {
        log_info("keystore_options_from_attr == NULL");
    } else {
        options->from_option = strdup(keystore_options_from[0]);
        if (options->from_option == NULL) {
            fatal("strdup()");
        }
        free_attr_values_as_string_array(keystore_options_from);
    }

    char **keystore_options_cmd = NULL;
    get_attr_values_as_string(ldap_handle, result,
        POX509_KEYSTORE_OPTIONS_CMD_ATTR, &keystore_options_cmd);
    if (keystore_options_cmd == NULL) {
        log_info("keystore_options_cmd_attr == NULL");
    } else {
        options->command_option = strdup(keystore_options_cmd[0]);
        if (options->command_option == NULL) {
            fatal("strdup()");
        }
        free_attr_values_as_string_array(keystore_options_cmd);
    }
    ldap_msgfree(result);
}

//static bool
//is_relevant_aobp(LDAP *ldap_handle, cfg_t *cfg, struct pox509_info *info,
//    struct pox509_access_on_behalf_profile *profile)
//{
//    if (ldap_handle == NULL || cfg == NULL || info == NULL ||
//        profile == NULL) {
//
//        fatal("ldap_handle, cfg, info or profile == NULL");
//    }
//
//    if (info->uid == NULL) {
//        fatal("info->uid == NULL");
//    }
//
//    /* check target keystores */
//    char *target_keystore_group_member_attr = cfg_getstr(cfg,
//        "ldap_target_keystore_group_member_attr");
//    char **target_keystore_dns = NULL;
//    get_group_member_dns(ldap_handle, cfg, profile->target_keystore_group_dn,
//        target_keystore_group_member_attr, &target_keystore_dns);
//    if (target_keystore_dns == NULL) {
//        fatal("target_keystore_dns == NULL");
//    }
//
//    char **target_keystore_uid = NULL;
//    bool target_keystore_has_uid = false;
//    for (int i = 0; target_keystore_dns[i] != NULL && !target_keystore_has_uid;
//        i++) {
//
//        get_target_keystore_uid(ldap_handle, cfg, target_keystore_dns[i],
//            &target_keystore_uid);
//        if (target_keystore_uid == NULL) {
//            fatal("target_keystore_uid == NULL");
//        }
//
//        if(strcmp(info->uid, target_keystore_uid[0]) == 0) {
//            target_keystore_has_uid = true;
//        }
//        free_attr_values_as_string_array(target_keystore_uid);
//        target_keystore_uid = NULL;
//    }
//    free_attr_values_as_string_array(target_keystore_dns);
//    return target_keystore_has_uid;
//}

static int
check_access_profile_relevance_general(LDAP *ldap_handle,
    LDAPMessage *access_profile, bool *is_relevant)
{
    if (ldap_handle == NULL || access_profile == NULL || is_relevant == NULL) {
        fatal("ldap_handle, access_profile or is_relevant == NULL");
    }

    *is_relevant = true;
    /* check if acccess profile entry is enabled */
    bool is_profile_enabled;
    int rc = check_profile_enabled(ldap_handle, access_profile,
        &is_profile_enabled);
    if (rc != POX509_OK) {
        return rc;
    }

    if (!is_profile_enabled) {
        log_info("access profile disabled");
        *is_relevant = false;
        return POX509_OK;
    }

    /* do further checks here in the future */
    return POX509_OK;
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
    /* check relevance if access on behalf profile */
    if (access_profile->type == ACCESS_ON_BEHALF_PROFILE) {

    }

    /* add key providers */
    log_info("processing key providers");
    char **key_provider_group_dn = NULL;
    int rc = get_attr_values_as_string(ldap_handle, access_profile_entry,
        POX509_AP_KEY_PROVIDER_ATTR, &key_provider_group_dn);
    if (rc != POX509_OK) {
        return rc;
    }
    char *key_provider_group_member_attr = cfg_getstr(info->cfg,
        "ldap_key_provider_group_member_attr");
    LDAPMessage *group_member_entry = NULL;
    rc = get_group_member_entry(ldap_handle, info, key_provider_group_dn[0],
        key_provider_group_member_attr, &group_member_entry);
    if (rc != POX509_OK) {
        res = rc;
        goto cleanup_a;
    }
    log_info("processing key provider group '%s'", key_provider_group_dn[0]);

    rc = add_key_providers(ldap_handle, info, group_member_entry,
        access_profile);
    if (rc != POX509_OK) {
        res = rc;
        goto cleanup_b;
    }

    /* add keystore options */

cleanup_b:
    ldap_msgfree(group_member_entry);
cleanup_a:
    free_attr_values_as_string_array(key_provider_group_dn);
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
    bool is_access_profile_relevant;
    int rc = check_access_profile_relevance_general(ldap_handle,
        access_profile_entry, &is_access_profile_relevant);
    if (rc != POX509_OK) {
        return rc;
    }
    if (!is_access_profile_relevant) {
        log_info("skipping access profile");
        return POX509_NOT_RELEVANT;
    }

    /* create and populate access profile */
    struct pox509_access_profile *access_profile = new_access_profile();
    if (access_profile == NULL) {
        return POX509_NO_MEMORY;
    }
    enum pox509_access_profile_type access_profile_type;
    rc = get_access_profile_type(ldap_handle, access_profile_entry,
        &access_profile_type);
    if (rc != POX509_OK) {
        res = rc;
        goto cleanup;
    }
    access_profile->type = access_profile_type;
    access_profile->dn = ldap_get_dn(ldap_handle, access_profile_entry);
    if (access_profile->dn == NULL) {
        log_debug("ldap_get_dn() error");
        res = POX509_LDAP_ERR;
        goto cleanup;
    }
    rc = get_rdn_value_from_dn(access_profile->dn, &access_profile->uid);
    if (rc != POX509_OK) {
        res = rc;
        goto cleanup;
    }
    log_info("uid: '%s'", access_profile->uid);
    log_info("type: '0x%d'", access_profile->type);

    /* process access profile */
    rc = process_access_profile(ldap_handle, info, access_profile_entry,
        access_profile);
    if (rc != POX509_OK) {
        res = rc;
        goto cleanup;
    }
    SIMPLEQ_INSERT_TAIL(access_profiles, access_profile, next);
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
    char *ssh_server_access_profile_attr = cfg_getstr(info->cfg,
        "ldap_ssh_server_access_profile_attr");
    char **access_profile_dns = NULL;
    int rc = get_attr_values_as_string(ldap_handle, ssh_server_entry,
        ssh_server_access_profile_attr, &access_profile_dns);
    if (rc != POX509_OK) {
        return rc;
    }

    struct pox509_access_profiles *access_profiles = new_access_profiles();
    if (access_profiles == NULL) {
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
            res = rc;
            log_debug("ldap_search_ext_s(): base: '%s' - '%s' (%d)",
            access_profile_dn, ldap_err2string(rc), rc);
            goto cleanup_inner;
        }

        rc = add_access_profile(ldap_handle, info, access_profile_entry,
            access_profiles);
        switch (rc) {
        case POX509_OK:
            break;
        case POX509_NO_MEMORY:
            res = rc;
            goto cleanup_b;
        default:
            log_debug("add_access_profile(): '%s'", pox509_strerror(rc));
            continue;
        }
cleanup_inner:
        ldap_msgfree(access_profile_entry);
    }
    info->access_profiles = access_profiles;
    access_profiles = NULL;
    res = POX509_OK;

cleanup_b:
    if (access_profiles != NULL) {
        free_access_profiles(access_profiles);
    }
cleanup_a:
    free_attr_values_as_string_array(access_profile_dns);
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
    char *ssh_server_uid_attr = cfg_getstr(info->cfg,
        "ldap_ssh_server_uid_attr");
    char *ssh_server_uid = cfg_getstr(info->cfg, "ssh_server_uid");
    int rc = create_ldap_search_filter(ssh_server_uid_attr, ssh_server_uid,
        filter, sizeof filter);
    if (rc != POX509_OK) {
        return rc;
    }
    char *ssh_server_access_profile_attr = cfg_getstr(info->cfg,
        "ldap_ssh_server_access_profile_attr");
    char *attrs[] = { ssh_server_access_profile_attr, NULL };
    struct timeval search_timeout = get_ldap_search_timeout(info->cfg);

    /* query ldap for ssh server entry */
    LDAPMessage *ssh_server_entry = NULL;
    rc = ldap_search_ext_s(ldap_handle, ssh_server_base_dn,
        ssh_server_search_scope, filter, attrs, 0, NULL, NULL, &search_timeout,
        1, &ssh_server_entry);
    if (rc != LDAP_SUCCESS) {
        log_debug("ldap_search_ext_s(): base: '%s' - '%s' (%d)",
        ssh_server_base_dn, ldap_err2string(rc), rc);
        res = POX509_LDAP_ERR;
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
        log_debug("ldap_count_entries() error");
        res = POX509_LDAP_ERR;
        goto cleanup_a;
    }

    /* get ssh server */
    struct pox509_ssh_server *ssh_server = new_ssh_server();
    if (ssh_server == NULL) {
        res = POX509_NO_MEMORY;
        goto cleanup_a;
    }

    ssh_server->dn = ldap_get_dn(ldap_handle, ssh_server_entry);
    if (ssh_server->dn == NULL) {
        log_debug("ldap_get_dn() error");
        res = POX509_LDAP_ERR;
        goto cleanup_b;
    }
    ssh_server->uid = cfg_getstr(info->cfg, "ssh_server_uid");

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
        char *msg;
        rc = ldap_get_option(ldap_handle, LDAP_OPT_DIAGNOSTIC_MESSAGE, &msg);
        if (rc == LDAP_OPT_SUCCESS) {
            log_debug("ldap_start_tls_s(): '%s'", msg);
            ldap_memfree(msg);
            return POX509_LDAP_CONNECTION_ERR;
        }
        log_debug("ldap_start_tls_s()");
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
    int ldap_starttls = cfg_getint(info->cfg, "ldap_starttls");
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
        log_debug("ldap_sasl_bind_s(): '%s' (%d)", ldap_err2string(rc), rc);
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
        log_debug("ldap_set_option(): key: LDAP_OPT_PROTOCOL_VERSION, value: "
            "%d", ldap_version);
        return POX509_LDAP_ERR;
    }

    /* force validation of certificates when using ldaps */
    int req_cert = LDAP_OPT_X_TLS_HARD;
    rc = ldap_set_option(ldap_handle, LDAP_OPT_X_TLS_REQUIRE_CERT, &req_cert);
    if (rc != LDAP_OPT_SUCCESS) {
        log_debug("ldap_set_option(): key: LDAP_OPT_X_TLS_REQUIRE_CERT, value: "
            "%d", req_cert);
        return POX509_LDAP_ERR;
    }

    /* set trusted ca path */
    char *cacerts_dir = cfg_getstr(info->cfg, "cacerts_dir");
    rc = ldap_set_option(ldap_handle, LDAP_OPT_X_TLS_CACERTDIR, cacerts_dir);
    if (rc != LDAP_OPT_SUCCESS) {
        log_debug("ldap_set_option(): key: LDAP_OPT_X_TLS_CACERTDIR, value: %s",
            cacerts_dir);
        return POX509_LDAP_ERR;
    }

    /*
     * new context has to be set in order to apply options set above regarding
     * tls.
     */
    int new_ctx = 0x56;
    rc = ldap_set_option(ldap_handle, LDAP_OPT_X_TLS_NEWCTX, &new_ctx);
    if (rc != LDAP_OPT_SUCCESS) {
        log_debug("ldap_set_option(): key: LDAP_OPT_X_TLS_NEWCTX, value: %d",
            new_ctx);
        return POX509_LDAP_ERR;
    }
    return POX509_OK;
}

static int
init_ldap_handle(LDAP **ret, struct pox509_info *info)
{
    if (ret == NULL || info == NULL) {
        fatal("ret or info == NULL");
    }

    LDAP *ldap_handle = NULL;
    char *ldap_uri = cfg_getstr(info->cfg, "ldap_uri");
    int rc = ldap_initialize(&ldap_handle, ldap_uri);
    if (rc != LDAP_SUCCESS) {
        log_debug("ldap_initialize(): '%s' (%d)", ldap_err2string(rc), rc);
        return POX509_LDAP_ERR;
    }

    int res = POX509_UNKNOWN_ERR;
    rc = set_ldap_options(ldap_handle, info);
    if (rc != POX509_OK) {
        res = rc;
        goto cleanup;
    }
    *ret = ldap_handle;
    ldap_handle = NULL;
    res = POX509_OK;

cleanup:
    if (ldap_handle != NULL) {
        rc = ldap_unbind_ext_s(ldap_handle, NULL, NULL);
        if (rc != LDAP_SUCCESS) {
            log_debug("ldap_unbind_ext_s(): '%s' (%d)", ldap_err2string(rc),
                rc);
        }
    }
    return res;
}

int
get_keystore_data_from_ldap(struct pox509_info *info)
{
    if (info == NULL) {
        fatal("info == NULL");
    }

    /* init ldap handle */
    LDAP *ldap_handle;
    int rc = init_ldap_handle(&ldap_handle, info);
    if (rc != POX509_OK) {
        return rc;
    }

    int res = POX509_UNKNOWN_ERR;
    /* connect to ldap server */
    rc = connect_to_ldap(ldap_handle, info);
    if (rc != POX509_OK) {
        res = rc;
        goto cleanup_a;
    }
    info->ldap_online = 1;
    log_info("connection to ldap established");

    /* add ssh server entry */
    LDAPMessage *ssh_server_entry = NULL;
    rc = add_ssh_server_entry(ldap_handle, info, &ssh_server_entry); 
    if (rc != POX509_OK) {
        res = rc;
        goto cleanup_a;
    }
    log_info("ssh server entry found '%s' (%s)", info->ssh_server->uid,
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
    if (rc == LDAP_SUCCESS) {
        log_info("unbound from ldap");
    } else {
        log_debug("ldap_unbind_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
    }
    return res;
}

