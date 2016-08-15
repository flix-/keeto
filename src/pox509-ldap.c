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

#define LDAP_SEARCH_FILTER_BUFFER_SIZE 1024

static int
set_ldap_options(LDAP *ldap_handle, cfg_t *cfg)
{
    if (ldap_handle == NULL || cfg == NULL) {
        fatal("ldap_handle or cfg == NULL");
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
    char *cacerts_dir = cfg_getstr(cfg, "cacerts_dir");
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
init_ldap_handle(LDAP **ldap_handle, cfg_t *cfg)
{
    if (ldap_handle == NULL || cfg == NULL) {
        fatal("ldap_handle or cfg == NULL");
    }

    char *ldap_uri = cfg_getstr(cfg, "ldap_uri");
    int rc = ldap_initialize(ldap_handle, ldap_uri);
    if (rc != LDAP_SUCCESS) {
        log_debug("ldap_initialize(): '%s' (%d)", ldap_err2string(rc), rc);
        return POX509_LDAP_ERR;
    }

    rc = set_ldap_options(*ldap_handle, cfg);
    if (rc != POX509_OK) {
        return rc;
    }

    return POX509_OK;
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
connect_to_ldap(LDAP *ldap_handle, cfg_t *cfg)
{
    if (ldap_handle == NULL || cfg == NULL) {
        fatal("ldap_handle or cfg == NULL");
    }

    int rc;
    int ldap_starttls = cfg_getint(cfg, "ldap_starttls");
    if (ldap_starttls) {
        rc = init_starttls(ldap_handle);
        if (rc != POX509_OK) {
            return rc;
        }
    }

    char *ldap_bind_dn = cfg_getstr(cfg, "ldap_bind_dn");
    char *ldap_bind_pwd = cfg_getstr(cfg, "ldap_bind_pwd");
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

static void
get_attr_values_as_string(LDAP *ldap_handle, LDAPMessage *result, char *attr,
    char ***ret)
{
    if (ldap_handle == NULL || result == NULL || attr == NULL || ret == NULL) {
        fatal("ldap_handle, result, attr or ret == NULL");
    }

    int rc = ldap_count_entries(ldap_handle, result);
    switch (rc) {
    case 0:
        fatal("ldap_count_entries() == 0");
        break;
    case -1:
        fatal("ldap_count_entries() - internal error");
        break;
    }

    /* get attribute values */
    result = ldap_first_entry(ldap_handle, result);
    if (result == NULL) {
        fatal("ldap_first_entry() == NULL");
    }
    struct berval **values = ldap_get_values_len(ldap_handle, result, attr);
    if (values == NULL) {
        goto ret;
    }
    int count = ldap_count_values_len(values);
    if (count == 0) {
        goto ret;
    }

    *ret = malloc(sizeof(char *) * (count + 1));
    if (*ret == NULL) {
        fatal("malloc");
    }

    for (int i = 0; values[i] != NULL; i++) {
        char *value = values[i]->bv_val;
        ber_len_t len = values[i]->bv_len;
        (*ret)[i] = strndup(value, len);
        if ((*ret)[i] == NULL) {
            fatal("strndup()");
        }
    }
    (*ret)[count] = NULL;
    ldap_value_free_len(values);

    return;

ret:
    *ret = NULL;
    return;
}

static void
get_attr_values_as_binary(LDAP *ldap_handle, LDAPMessage *result, char *attr,
    struct berval ***ret)
{
    if (ldap_handle == NULL || result == NULL || attr == NULL || ret == NULL) {
        fatal("ldap_handle, result, attr or ret == NULL");
    }

    int rc = ldap_count_entries(ldap_handle, result);
    if (rc == 0) {
        log_error("ldap_count_entries() == 0");
        return;
    }

    /* get attribute values */
    result = ldap_first_entry(ldap_handle, result);
    if (result == NULL) {
        fatal("ldap_first_entry() == NULL");
    }
    *ret = ldap_get_values_len(ldap_handle, result, attr);
    if (*ret == NULL) {
        log_error("ldap_get_values_len() == NULL");
        return;
    }
}

static void
free_attr_values_as_string_array(char **values)
{
    if (values == NULL) {
        fatal("values == NULL");
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
        fatal("values == NULL");
    }

    ldap_value_free_len(values);
}

static bool
is_profile_disabled(LDAP *ldap_handle, LDAPMessage *result)
{
    if (ldap_handle == NULL || result == NULL) {
        fatal("ldap_handle or result == NULL");
    }

    char **access_profile_state = NULL;
    get_attr_values_as_string(ldap_handle, result, POX509_AP_IS_ENABLED,
        &access_profile_state);
    if (access_profile_state == NULL) {
        fatal("access_profile_state == NULL");
    }
    bool is_disabled = strcmp(access_profile_state[0], LDAP_BOOL_TRUE) ==
        0 ? false : true;
    free_attr_values_as_string_array(access_profile_state);

    return is_disabled;
}

static enum pox509_access_profile_type
get_access_profile_type(LDAP *ldap_handle, LDAPMessage *result)
{
    if (ldap_handle == NULL || result == NULL) {
        fatal("ldap_handle or result == NULL");
    }

    /* determine access profile type from objectclass */
    char **access_profile_objectclass = NULL;
    get_attr_values_as_string(ldap_handle, result, "objectClass",
        &access_profile_objectclass);
    if (access_profile_objectclass == NULL) {
        fatal("access_profile_objectclass == NULL");
    }

    enum pox509_access_profile_type profile_type = UNKNOWN;
    for (int i = 0; access_profile_objectclass[i] != NULL; i++) {
        char *objectclass = access_profile_objectclass[i];
        if (strcmp(objectclass, POX509_DAP_OBJCLASS) == 0) {
            profile_type = DIRECT_ACCESS;
            break;
        } else if (strcmp(objectclass, POX509_AOBP_OBJCLASS) == 0) {
            profile_type = ACCESS_ON_BEHALF;
            break;
        }
    }
    free_attr_values_as_string_array(access_profile_objectclass);

    return profile_type;
}

static void
get_group_member_dns(LDAP *ldap_handle, cfg_t *cfg, char *group_dn,
    char *group_member_attr, char ***group_member_dns)
{
    if (ldap_handle == NULL || cfg == NULL || group_dn == NULL ||
        group_member_attr == NULL || group_member_dns == NULL) {

        fatal("ldap_handle, cfg, group_dn, group_member_attr or "
            "group_member_dns == NULL");
    }

    char *group_member_attrs[] = {
        group_member_attr,
        NULL
    };
    struct timeval search_timeout = get_ldap_search_timeout(cfg);
    LDAPMessage *result = NULL;

    int rc = ldap_search_ext_s(ldap_handle, group_dn, LDAP_SCOPE_BASE, NULL,
        group_member_attrs, 0, NULL, NULL, &search_timeout, 1, &result);
    if (rc != LDAP_SUCCESS) {
        fatal("ldap_search_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
    }

    /* get dn's of group members*/
    get_attr_values_as_string(ldap_handle, result, group_member_attr,
        group_member_dns);
    ldap_msgfree(result);
}

static int
get_server_entry(LDAP *ldap_handle, cfg_t *cfg, struct pox509_info *pox509_info,
    LDAPMessage **result)
{
    if (ldap_handle == NULL || cfg == NULL || pox509_info == NULL ||
        result == NULL) {

        fatal("ldap_handle, cfg, pox509_info or result == NULL");
    }

    char *server_dn = cfg_getstr(cfg, "ldap_server_base_dn");
    int server_search_scope = cfg_getint(cfg, "ldap_server_search_scope");
    /* construct search filter */
    char filter[LDAP_SEARCH_FILTER_BUFFER_SIZE];
    char *server_uid_attr = cfg_getstr(cfg, "ldap_server_uid_attr");
    char *server_uid = cfg_getstr(cfg, "server_uid");
    create_ldap_search_filter(server_uid_attr, server_uid, filter,
        sizeof filter);
    char *access_profile_attr = cfg_getstr(cfg,
        "ldap_server_access_profile_attr");
    char *attrs[] = {
        access_profile_attr,
        NULL
    };
    struct timeval search_timeout = get_ldap_search_timeout(cfg);

    int rc = ldap_search_ext_s(ldap_handle, server_dn, server_search_scope,
        filter, attrs, 0, NULL, NULL, &search_timeout, 1, result);
    if (rc != LDAP_SUCCESS) {
        fatal("ldap_search_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
    }

    /* check if ssh server entry has been found */
    rc = ldap_count_entries(ldap_handle, *result);
    switch (rc) {
    case 0:
        return -1;
    case -1:
        fatal("ldap_count_entries() - internal error");
    }

    return 0;
}

static void
get_target_keystore(LDAP *ldap_handle, cfg_t *cfg, char *target_keystore_dn,
    char ***target_uid)
{
    if (ldap_handle == NULL || cfg == NULL || target_keystore_dn == NULL ||
        target_uid == NULL) {

        fatal("ldap_handle, cfg, target_keystore_dn or target_uid == NULL");
    }

    char *target_uid_attr = cfg_getstr(cfg, "ldap_target_uid_attr");
    char *attrs[] = {
        target_uid_attr,
        NULL
    };
    struct timeval search_timeout = get_ldap_search_timeout(cfg);
    LDAPMessage *result = NULL;

    int rc = ldap_search_ext_s(ldap_handle, target_keystore_dn, LDAP_SCOPE_BASE,
        NULL, attrs, 0, NULL, NULL, &search_timeout, 1, &result);
    if (rc != LDAP_SUCCESS) {
        fatal("ldap_search_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
    }

    get_attr_values_as_string(ldap_handle, result, target_uid_attr, target_uid);
    ldap_msgfree(result);
}

static void
get_key_provider(LDAP *ldap_handle, cfg_t *cfg, char *key_provider_dn,
    struct pox509_key_provider *provider)
{
    if (ldap_handle == NULL || cfg == NULL || key_provider_dn == NULL ||
        provider == NULL) {

        fatal("ldap_handle, cfg, key_provider_dn or provider == NULL");
    }

    provider->dn = strdup(key_provider_dn);
    if (provider->dn == NULL) {
        fatal("strdup()");
    }
    char *provider_uid_attr = cfg_getstr(cfg, "ldap_provider_uid_attr");
    char *provider_cert_attr = cfg_getstr(cfg, "ldap_provider_cert_attr");
    char *attrs[] = {
        provider_uid_attr,
        provider_cert_attr,
        NULL
    };
    struct timeval search_timeout = get_ldap_search_timeout(cfg);
    LDAPMessage *result = NULL;

    int rc = ldap_search_ext_s(ldap_handle, provider->dn, LDAP_SCOPE_BASE,
        NULL, attrs, 0, NULL, NULL, &search_timeout, 1, &result);
    if (rc != LDAP_SUCCESS) {
        fatal("ldap_search_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
    }

    /* get attribute values */
    char **provider_uid = NULL;
    get_attr_values_as_string(ldap_handle, result, provider_uid_attr,
        &provider_uid);
    if (provider_uid == NULL) {
        fatal("provider_uid == NULL");
    }
    provider->uid = strdup(provider_uid[0]);
    if (provider->uid == NULL) {
        fatal("strdup()");
    }
    free_attr_values_as_string_array(provider_uid);

    struct berval **provider_cert = NULL;
    get_attr_values_as_binary(ldap_handle, result, provider_cert_attr,
        &provider_cert);
    if (provider_cert == NULL) {
        fatal("provider_cert == NULL");
    }
    for (int i = 0; provider_cert[i] != NULL; i++) {
        char *value = provider_cert[i]->bv_val;
        ber_len_t len = provider_cert[i]->bv_len;
        struct pox509_key *key = malloc(sizeof(struct pox509_key));
        if (key == NULL) {
            fatal("malloc()");
        }
        init_key(key);
        key->x509 = d2i_X509(NULL, (const unsigned char **) &value, len);
        if (key->x509 == NULL) {
            log_error("d2i_X509(): cannot decode certificate");
            free_key(key);
            continue;
        }
        TAILQ_INSERT_TAIL(&provider->keys, key, keys);
    }
    free_attr_values_as_binary_array(provider_cert);
    ldap_msgfree(result);
}

static void
get_keystore_options(LDAP *ldap_handle, cfg_t *cfg, char *keystore_options_dn,
    struct pox509_keystore_options *options)
{
    if (ldap_handle == NULL || cfg == NULL || keystore_options_dn == NULL ||
        options == NULL) {

        fatal("ldap_handle, cfg, keystore_options_dn or options == NULL");
    }

    options->dn = strdup(keystore_options_dn);
    if (options->dn == NULL) {
        fatal("strdup()");
    }
    get_rdn_value_from_dn(keystore_options_dn, &options->name);
    char *attrs[] = {
        POX509_KEYSTORE_OPTIONS_FROM_ATTR,
        POX509_KEYSTORE_OPTIONS_CMD_ATTR,
        NULL
    };
    struct timeval search_timeout = get_ldap_search_timeout(cfg);
    LDAPMessage *result = NULL;

    int rc = ldap_search_ext_s(ldap_handle, options->dn, LDAP_SCOPE_BASE, NULL,
        attrs, 0, NULL, NULL, &search_timeout, 1, &result);
    if (rc != LDAP_SUCCESS) {
        fatal("ldap_search_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
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

static bool
is_relevant_aobp(LDAP *ldap_handle, cfg_t *cfg, struct pox509_info *pox509_info,
    struct pox509_access_on_behalf_profile *profile)
{
    if (ldap_handle == NULL || cfg == NULL || pox509_info == NULL ||
        profile == NULL) {

        fatal("ldap_handle, cfg, pox509_info or profile == NULL");
    }

    if (pox509_info->uid == NULL) {
        fatal("pox509_info uid == NULL");
    }

    /* check target keystores */
    char *target_group_member_attr = cfg_getstr(cfg,
        "ldap_target_group_member_attr");
    char **target_dns = NULL;
    get_group_member_dns(ldap_handle, cfg, profile->target_keystore_group_dn,
        target_group_member_attr, &target_dns);
    if (target_dns == NULL) {
        fatal("target_dns == NULL");
    }

    char **target_uid = NULL;
    bool target_has_uid = false;
    for (int i = 0; target_dns[i] != NULL && !target_has_uid; i++) {
        get_target_keystore(ldap_handle, cfg, target_dns[i], &target_uid);
        if (target_uid == NULL) {
            fatal("target_uid == NULL");
        }

        if(strcmp(pox509_info->uid, target_uid[0]) == 0) {
            target_has_uid = true;
        }
        free_attr_values_as_string_array(target_uid);
        target_uid = NULL;
    }
    free_attr_values_as_string_array(target_dns);

    return target_has_uid;
}

static void
process_access_on_behalf_profiles(LDAP *ldap_handle, cfg_t *cfg,
    struct pox509_info *pox509_info)
{
    if (ldap_handle == NULL || cfg == NULL || pox509_info == NULL) {
        fatal("ldap_handle, cfg or pox509_info == NULL");
    }

    if (TAILQ_EMPTY(&pox509_info->access_on_behalf_profiles)) {
        log_info("access on behalf profile list EMPTY");
        return;
    }

    /* iterate access on behalf profiles */
    struct pox509_access_on_behalf_profile *profile = NULL;
    struct pox509_access_on_behalf_profile *tmp = NULL;
    TAILQ_FOREACH_SAFE(profile, &pox509_info->access_on_behalf_profiles,
        profiles, tmp) {

        if (!is_relevant_aobp(ldap_handle, cfg, pox509_info, profile)) {
            TAILQ_REMOVE(&pox509_info->access_on_behalf_profiles, profile,
                profiles);
            free_access_on_behalf_profile(profile);
            continue;
        }

        /* get key provider(s) */
        char *key_provider_group_member_attr = cfg_getstr(cfg,
            "ldap_provider_group_member_attr");
        char **key_provider_dns = NULL;
        get_group_member_dns(ldap_handle, cfg, profile->key_provider_group_dn,
            key_provider_group_member_attr, &key_provider_dns);
        if (key_provider_dns == NULL) {
            fatal("key_provider_dns == NULL");
        }

        for (int i = 0; key_provider_dns[i] != NULL; i++) {
            struct pox509_key_provider *provider =
                malloc(sizeof(struct pox509_key_provider));
            if (provider == NULL) {
                fatal("malloc()");
            }
            init_key_provider(provider);
            get_key_provider(ldap_handle, cfg, key_provider_dns[i], provider);
            TAILQ_INSERT_TAIL(&profile->key_providers, provider, key_providers);
        }
        free_attr_values_as_string_array(key_provider_dns);

        /* get keystore options */
        profile->keystore_options =
            malloc(sizeof(struct pox509_keystore_options));
        if (profile->keystore_options == NULL) {
            fatal("malloc()");
        }
        init_keystore_options(profile->keystore_options);
        get_keystore_options(ldap_handle, cfg, profile->keystore_options_dn,
            profile->keystore_options);
    }
}

static void
process_direct_access_profiles(LDAP *ldap_handle, cfg_t *cfg,
    struct pox509_info *pox509_info)
{
    if (ldap_handle == NULL || cfg == NULL || pox509_info == NULL) {
        fatal("ldap_handle, cfg or pox509_info == NULL");
    }

    if (TAILQ_EMPTY(&pox509_info->direct_access_profiles)) {
        log_info("direct access profile list EMPTY");
        return;
    }

    /* iterate direct access profiles */
    struct pox509_direct_access_profile *profile = NULL;
    struct pox509_direct_access_profile *tmp = NULL;
    TAILQ_FOREACH_SAFE(profile, &pox509_info->direct_access_profiles, profiles,
        tmp) {

        /* get key providers */
        char *key_provider_group_member_attr = cfg_getstr(cfg,
            "ldap_provider_group_member_attr");
        char **key_provider_dns = NULL;
        get_group_member_dns(ldap_handle, cfg, profile->key_provider_group_dn,
            key_provider_group_member_attr, &key_provider_dns);
        if (key_provider_dns == NULL) {
            fatal("key_provider_dns == NULL");
        }

        for (int i = 0; key_provider_dns[i] != NULL; i++) {
            struct pox509_key_provider *provider =
                malloc(sizeof(struct pox509_key_provider));
            if (provider == NULL) {
                fatal("malloc()");
            }
            init_key_provider(provider);
            get_key_provider(ldap_handle, cfg, key_provider_dns[i], provider);
            bool is_authorized = strcmp(provider->uid, pox509_info->uid) == 0 ?
                true : false;
            if (is_authorized) {
                TAILQ_INSERT_TAIL(&profile->key_providers, provider,
                    key_providers);
            } else {
                free_key_provider(provider);
            }
        }
        free_attr_values_as_string_array(key_provider_dns);

        if (TAILQ_EMPTY(&profile->key_providers)) {
            TAILQ_REMOVE(&pox509_info->direct_access_profiles, profile,
                profiles);
            free_direct_access_profile(profile);
            continue;
        }

        /* get keystore options */
        profile->keystore_options =
            malloc(sizeof(struct pox509_keystore_options));
        if (profile->keystore_options == NULL) {
            fatal("malloc()");
        }
        init_keystore_options(profile->keystore_options);
        get_keystore_options(ldap_handle, cfg, profile->keystore_options_dn,
            profile->keystore_options);
    }
}

static void
get_access_on_behalf_profile(LDAP *ldap_handle, LDAPMessage *result, char *dn,
    struct pox509_info *pox509_info)
{
    if (ldap_handle == NULL || result == NULL || dn == NULL ||
        pox509_info == NULL) {

        fatal("ldap_handle, result, dn or pox509_info == NULL");
    }

    /* create new access on behalf profile */
    struct pox509_access_on_behalf_profile *profile = malloc(sizeof *profile);
    if (profile == NULL) {
        fatal("malloc()");
    }
    init_access_on_behalf_profile(profile);

    profile->dn = strdup(dn);
    if (profile->dn == NULL) {
        fatal("strdup()");
    }
    get_rdn_value_from_dn(dn, &profile->name);

    /* set target keystore group dn */
    char **target_keystore_group_dn = NULL;
    get_attr_values_as_string(ldap_handle, result,
        POX509_AOBP_TARGET_KEYSTORE_ATTR, &target_keystore_group_dn);
    if (target_keystore_group_dn == NULL) {
        fatal("target_keystore_group_dn == NULL");
    }
    profile->target_keystore_group_dn = strdup(target_keystore_group_dn[0]);
    if (profile->target_keystore_group_dn == NULL) {
        fatal("strdup()");
    }
    free_attr_values_as_string_array(target_keystore_group_dn);

    /* set key provider group dn*/
    char **key_provider_group_dn = NULL;
    get_attr_values_as_string(ldap_handle, result,
        POX509_AP_KEY_PROVIDER_ATTR, &key_provider_group_dn);
    if (key_provider_group_dn == NULL) {
        fatal("key_provider_group_dn == NULL");
    }
    profile->key_provider_group_dn = strdup(key_provider_group_dn[0]);
    if (profile->key_provider_group_dn == NULL) {
        fatal("strdup()");
    }
    free_attr_values_as_string_array(key_provider_group_dn);

    /* set keystore options */
    char **keystore_options_dn = NULL;
    get_attr_values_as_string(ldap_handle, result,
        POX509_AP_KEYSTORE_OPTIONS_ATTR, &keystore_options_dn);
    if (keystore_options_dn == NULL) {
        fatal("keystore_options_dn == NULL");
    }
    profile->keystore_options_dn = strdup(keystore_options_dn[0]);
    if (profile->keystore_options_dn == NULL) {
        fatal("strdup()");
    }
    free_attr_values_as_string_array(keystore_options_dn);

    /* add to access on behalf profile list */
    TAILQ_INSERT_TAIL(&pox509_info->access_on_behalf_profiles, profile,
        profiles);
}

static void
get_direct_access_profile(LDAP *ldap_handle, LDAPMessage *result, char *dn,
    struct pox509_info *pox509_info)
{
    if (ldap_handle == NULL || result == NULL || dn == NULL ||
        pox509_info == NULL) {

        fatal("ldap_handle, result, dn or pox509_info == NULL");
    }

    /* create new direct access profile */
    struct pox509_direct_access_profile *profile = malloc(sizeof *profile);
    if (profile == NULL) {
        fatal("malloc()");
    }
    init_direct_access_profile(profile);

    profile->dn = strdup(dn);
    if (profile->dn == NULL) {
        fatal("strdup()");
    }
    get_rdn_value_from_dn(dn, &profile->name);

    /* set key provider group dn */
    char **key_provider_group_dn = NULL;
    get_attr_values_as_string(ldap_handle, result, POX509_AP_KEY_PROVIDER_ATTR,
        &key_provider_group_dn);
    if (key_provider_group_dn == NULL) {
        fatal("key_provider_group_dn == NULL");
    }
    profile->key_provider_group_dn = strdup(key_provider_group_dn[0]);
    if (profile->key_provider_group_dn == NULL) {
        fatal("strdup()");
    }
    free_attr_values_as_string_array(key_provider_group_dn);

    /* set keystore options dn */
    char **keystore_options_dn = NULL;
    get_attr_values_as_string(ldap_handle, result,
        POX509_AP_KEYSTORE_OPTIONS_ATTR, &keystore_options_dn);
    if (keystore_options_dn == NULL) {
        fatal("keystore_options_dn == NULL");
    }
    profile->keystore_options_dn = strdup(keystore_options_dn[0]);
    if (profile->keystore_options_dn == NULL) {
        fatal("strdup()");
    }
    free_attr_values_as_string_array(keystore_options_dn);

    /* add to direct access profile list */
    TAILQ_INSERT_TAIL(&pox509_info->direct_access_profiles, profile,
        profiles);
}

static void
get_access_profiles(LDAP *ldap_handle, cfg_t *cfg,
    struct pox509_info *pox509_info)
{
    if (ldap_handle == NULL || cfg == NULL || pox509_info == NULL) {
        fatal("ldap_handle, cfg or pox509_info == NULL");
    }

    LDAPMessage *result = NULL;
    int rc = get_server_entry(ldap_handle, cfg, pox509_info, &result);
    if (rc == -1) {
        log_info("no ssh server entry has been found");
        goto cleanup;
    }

    /* set dn in dto */
    pox509_info->dn = ldap_get_dn(ldap_handle, result);
    if (pox509_info->dn == NULL) {
        fatal("ldap_get_dn()");
    }
    /* get dn's as strings */
    char **access_profile_dns = NULL;
    char *access_profile_attr = cfg_getstr(cfg,
        "ldap_server_access_profile_attr");
    get_attr_values_as_string(ldap_handle, result, access_profile_attr,
        &access_profile_dns);

    struct timeval search_timeout = get_ldap_search_timeout(cfg);
    /* iterate access profile dns */
    for (int i = 0; access_profile_dns[i] != NULL; i++) {
        char *dn = access_profile_dns[i];
        LDAPMessage *result = NULL;

        int rc = ldap_search_ext_s(ldap_handle, dn, LDAP_SCOPE_BASE, NULL, NULL,
            0, NULL, NULL, &search_timeout, 1, &result);
        if (rc != LDAP_SUCCESS) {
            fatal("ldap_search_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
        }

        /* skip if access profile is disabled */
        if (is_profile_disabled(ldap_handle, result)) {
            log_info("profile disabled (%s)", access_profile_dns[i]);
            continue;
        }
        enum pox509_access_profile_type profile_type =
            get_access_profile_type(ldap_handle, result);

        switch(profile_type) {
        case DIRECT_ACCESS:
            get_direct_access_profile(ldap_handle, result, dn, pox509_info);
            break;
        case ACCESS_ON_BEHALF:
            get_access_on_behalf_profile(ldap_handle, result, dn, pox509_info);
            break;
        case UNKNOWN:
            fatal("profile_type unknown: %d", profile_type);
            break;
        default:
            fatal("this should never happen...");
        }
        ldap_msgfree(result);
    }
    free_attr_values_as_string_array(access_profile_dns);

    return;

cleanup:
    log_info("cleanup");
    ldap_msgfree(result);
}

int
get_keystore_data_from_ldap(cfg_t *cfg, struct pox509_info *pox509_info)
{
    if (cfg == NULL || pox509_info == NULL) {
        fatal("cfg or pox509_info == NULL");
    }

    /* init ldap handle */
    LDAP *ldap_handle;
    int rc = init_ldap_handle(&ldap_handle, cfg);
    if (rc != POX509_OK) {
        return rc;
    }

    int res = POX509_UNKNOWN_ERR;
    /* connect to ldap server */
    rc = connect_to_ldap(ldap_handle, cfg);
    if (rc != POX509_OK) {
        res = rc;
        goto unbind_and_free_handle;
    }

    pox509_info->ldap_online = 1;
    log_info("connection to ldap established");

    /* retrieve data */
    get_access_profiles(ldap_handle, cfg, pox509_info);
    process_direct_access_profiles(ldap_handle, cfg, pox509_info);
    process_access_on_behalf_profiles(ldap_handle, cfg, pox509_info);

unbind_and_free_handle:
    rc = ldap_unbind_ext_s(ldap_handle, NULL, NULL);
    if (rc == LDAP_SUCCESS) {
        log_debug("ldap_unbind_ext_s()");
    } else {
        log_debug("ldap_unbind_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
    }

    return res;
}

