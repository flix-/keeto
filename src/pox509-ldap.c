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

#include "pox509-log.h"

#define LDAP_SEARCH_FILTER_BUFFER_SIZE 1024

static void
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
        fatal("ldap_set_option(): key: LDAP_OPT_PROTOCOL_VERSION, value: %d",
            ldap_version);
    }

    /* force validation of certificates when using ldaps */
    int req_cert = LDAP_OPT_X_TLS_HARD;
    rc = ldap_set_option(ldap_handle, LDAP_OPT_X_TLS_REQUIRE_CERT, &req_cert);
    if (rc != LDAP_OPT_SUCCESS) {
        fatal("ldap_set_option(): key: LDAP_OPT_X_TLS_REQUIRE_CERT, value: %d",
            req_cert);
    }

    /* set trusted ca path */
    char *cacerts_dir = cfg_getstr(cfg, "cacerts_dir");
    rc = ldap_set_option(ldap_handle, LDAP_OPT_X_TLS_CACERTDIR, cacerts_dir);
    if (rc != LDAP_OPT_SUCCESS) {
        fatal("ldap_set_option(): key: LDAP_OPT_X_TLS_CACERTDIR, value: %s",
            cacerts_dir);
    }

    /*
     * new context has to be set in order to apply options set above regarding
     * tls.
     */
    int new_ctx = 0x56;
    rc = ldap_set_option(ldap_handle, LDAP_OPT_X_TLS_NEWCTX, &new_ctx);
    if (rc != LDAP_OPT_SUCCESS) {
        fatal("ldap_set_option(): key: LDAP_OPT_X_TLS_NEWCTX, value: %d",
            new_ctx);
    }
}

static void
init_starttls(LDAP *ldap_handle)
{
    if (ldap_handle == NULL) {
        fatal("ldap_handle == NULL");
    }

    int rc = ldap_start_tls_s(ldap_handle, NULL, NULL);
    if (rc != LDAP_SUCCESS) {
        char *msg = NULL;
        rc = ldap_get_option(ldap_handle, LDAP_OPT_DIAGNOSTIC_MESSAGE, &msg);
        if (rc == LDAP_OPT_SUCCESS) {
            fatal("ldap_start_tls_s(): '%s'", msg);
        }
        fatal("ldap_start_tls_s()");
    }
}

static int
bind_to_ldap(LDAP *ldap_handle, cfg_t *cfg)
{
    if (ldap_handle == NULL || cfg == NULL) {
        fatal("ldap_handle or cfg == NULL");
    }

    char *ldap_bind_dn = cfg_getstr(cfg, "ldap_bind_dn");
    char *ldap_bind_pwd = cfg_getstr(cfg, "ldap_bind_pwd");
    size_t ldap_bind_pwd_length = strlen(ldap_bind_pwd);
    struct berval cred = {
        .bv_len = ldap_bind_pwd_length,
        .bv_val = ldap_bind_pwd
    };
    int rc = ldap_sasl_bind_s(ldap_handle, ldap_bind_dn, LDAP_SASL_SIMPLE,
        &cred, NULL, NULL, NULL);
    memset(ldap_bind_pwd, 0, ldap_bind_pwd_length);
    return rc;
}

static void
get_attr_values_as_string(LDAP *ldap_handle, LDAPMessage *result, char *attr,
    char ***ret)
{
    if (ldap_handle == NULL || result == NULL || attr == NULL || ret == NULL) {
        fatal("ldap_handle, result, attr or ret == NULL");
    }

    int rc = ldap_count_entries(ldap_handle, result);
    if (rc == 0) {
        log_fail("ldap_count_entries() == 0");
        goto error;
    }

    /* get attribute values */
    result = ldap_first_entry(ldap_handle, result);
    if (result == NULL) {
        fatal("ldap_first_entry() == NULL");
    }
    struct berval **values = ldap_get_values_len(ldap_handle, result, attr);
    if (values == NULL) {
        log_fail("ldap_get_values_len() == NULL");
        goto error;
    }
    int count = ldap_count_values_len(values);
    if (count == 0) {
        log_fail("ldap_count_values_len() == 0");
        goto error;
    }

    *ret = malloc(sizeof(char *) * (count + 1));
    if (*ret == NULL) {
        fatal("malloc");
    }

    for (int i = 0; values[i] != NULL; i++) {
        char *value = values[i]->bv_val;
        ber_len_t len = values[i]->bv_len;
        (*ret)[i] = strndup(value, len + 1);
        (*ret)[i][len] = '\0';
    }
    (*ret)[count] = NULL;
    ldap_value_free_len(values);

    return;

error:
    *ret = NULL;
    return;
}

static void
free_string_array(char **strings)
{
    if (strings == NULL) {
        fatal("strings == NULL");
    }

    for (int i = 0; strings[i] != NULL; i++) {
        free(strings[i]);
    }
    free(strings);
}

//static void
//handle_ldap_res_search_entry(LDAP *ldap_handle, LDAPMessage *ldap_result,
//    cfg_t *cfg, struct pox509_info *pox509_info, X509 **x509)
//{
//    if (ldap_handle == NULL || ldap_result == NULL || cfg == NULL ||
//        pox509_info == NULL || x509 == NULL) {
//        fatal("ldap_handle, ldap_result, cfg, pox509_info or x509 == NULL");
//    }
//
//    char *user_dn = ldap_get_dn(ldap_handle, ldap_result);
//    if (user_dn == NULL) {
//        /* cannot access ldap_handle->ld_errno as structure is opaque */
//        log_fail("ldap_get_dn(): '%s'", "user_dn == NULL");
//    } else {
//        log_msg("user_dn: %s", user_dn);
//        ldap_memfree(user_dn);
//    }
//
//    /* iterate over all requested attributes */
//    char *attr = NULL;
//    struct berelement *attributes = NULL;
//    for (attr = ldap_first_attribute(ldap_handle, ldap_result, &attributes);
//        attr != NULL;
//        attr = ldap_next_attribute(ldap_handle, ldap_result, attributes)) {
//
//        char *ldap_attr_access = cfg_getstr(cfg, "ldap_attr_access");
//        char *ldap_attr_cert = cfg_getstr(cfg, "ldap_attr_cert");
//        bool is_attr_access = strcmp(attr, ldap_attr_access) == 0 ? 1 : 0;
//        bool is_attr_cert = strcmp(attr, ldap_attr_cert) == 0 ? 1 : 0;
//
//        struct berval **attr_values = ldap_get_values_len(ldap_handle,
//            ldap_result, attr);
//        if (attr_values == NULL) {
//            fatal("ldap_get_values_len()");
//        }
//
//        /*
//         * iterate over all values for attribute
//         *
//         * result of ldap_get_values_len() is an array in order to handle
//         * mutivalued attributes
//         */
//        int i;
//        for (i = 0; attr_values[i] != NULL; i++) {
//            char *value = attr_values[i]->bv_val;
//            ber_len_t len = attr_values[i]->bv_len;
//
//            /* process group memberships */
//            if (is_attr_access) {
//                /*
//                 * check access permission based on group membership
//                 * and store result.
//                 */
//                char *ldap_group_identifier =
//                    cfg_getstr(cfg, "ldap_group_identifier");
//                /* check_access_permission(value, ldap_group_identifier,
//                    pox509_info);*/
//                /*
//                 * stop looping over group memberships when access has
//                 * been granted.
//                 */
//                 /*
//                if (pox509_info->has_access == 1) {
//                    log_msg("group membership found");
//                    log_msg("group_dn: %s", value);
//                    break;
//                }
//                */
//
//            /* process x509 certificates */
//            } else if (is_attr_cert) {
//                /* decode certificate */
//                *x509 = d2i_X509(NULL, (const unsigned char **) &value, len);
//                if (*x509 == NULL) {
//                    log_fail("d2i_X509(): cannot decode certificate");
//                    /* try next certificate if existing */
//                    continue;
//                }
//
//                /*
//                pox509_info->has_cert = 1;
//                */
//                /*
//                 * stop looping over x509 certificates when a valid one
//                 * has been found.
//                 */
//                break;
//            }
//        }
//        /* free attribute values array after each iteration */
//        ldap_value_free_len(attr_values);
//    }
//    /* free attributes structure */
//    ber_free(attributes, 0);
//}

//static void
//add_access_profiles(LDAP *ldap_handle, cfg_t *cfg,
//    struct pox509_info *pox509_info)
//{
//    if (ldap_handle == NULL || cfg == NULL || pox509_info == NULL) {
//        fatal("ldap_handle, cfg or pox509_info == NULL");
//    }
//
//    /* collect arguments for ldap search */
//    char *ldap_base = cfg_getstr(cfg, "ldap_server_base_dn");
//    int ldap_search_scope = cfg_getint(cfg, "ldap_server_search_scope");
//    /* construct search filter */
//    char filter[LDAP_SEARCH_FILTER_BUFFER_SIZE];
//    char *ldap_server_uid_attr = cfg_getstr(cfg, "ldap_server_uid_attr");
//    char *server_uid = cfg_getstr(cfg, "server_uid");
//    create_ldap_search_filter(ldap_server_uid_attr, server_uid, filter,
//        sizeof filter);
//    char *ldap_server_access_profile_attr = cfg_getstr(cfg,
//        "ldap_server_access_profile_attr");
//    char *attrs[] = {
//        ldap_server_access_profile_attr,
//        NULL
//    };
//    int ldap_search_timeout = cfg_getint(cfg, "ldap_search_timeout");
//    struct timeval search_timeout = {
//        .tv_sec = ldap_search_timeout,
//        .tv_usec = 0
//    };
//    int sizelimit = 1;
//    LDAPMessage *result = NULL;
//
//    int rc = ldap_search_ext_s(ldap_handle, ldap_base, ldap_search_scope,
//        filter, attrs, 0, NULL, NULL, &search_timeout,  sizelimit, &result);
//    if (rc != LDAP_SUCCESS) {
//        fatal("ldap_search_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
//    }
//
//    /* sizelimit == 1 */
//    rc = ldap_count_entries(ldap_handle, result);
//    if (rc == 0) {
//        log_fail("ssh server not found in ldap");
//        return;
//    }
//
//    result = ldap_first_entry(ldap_handle, result);
//    if (result == NULL) {
//        fatal("ldap_first_entry() == NULL");
//    }
//
//    struct berval **profiles = ldap_get_values_len(ldap_handle, result,
//        ldap_server_access_profile_attr);
//    if (profiles == NULL) {
//        log_msg("no access profile found");
//        return;
//    }
//
//    int i;
//    for (i = 0; profiles[i] != NULL; i++) {
//        char *dn = profiles[i]->bv_val;
//        int dn_length = profiles[i]->bv_len;
//        struct pox509_profile *access_profile =
//        malloc(sizeof(struct pox509_profile));
//        if (access_profile == NULL) {
//            fatal("malloc");
//        }
//        init_profile(access_profile);
//
//        access_profile->dn = strndup(dn, dn_length + 1);
//        access_profile->dn[dn_length] = '\0';
//        STAILQ_INSERT_TAIL(&pox509_info->profile_head, access_profile,
//            profiles);
//    }
//    ldap_value_free_len(profiles);
//}

//static void
//strip_access_profiles(LDAP *ldap_handle, cfg_t *cfg,
//    struct pox509_info *pox509_info)
//{
//    if (ldap_handle == NULL || cfg == NULL || pox509_info == NULL) {
//        fatal("ldap_handle, cfg or pox509_info == NULL");
//    }
//
//    char *ldap_target_group_attr = cfg_getstr(cfg, "ldap_target_group_attr");
//    char *ldap_target_uid_attr = cfg_getstr(cfg, "ldap_target_uid_attr");
//
//    /* iterate access profiles */
//    struct pox509_profile *ptr = NULL;
//    STAILQ_FOREACH(ptr, &pox509_info->profile_head, profiles) {
//        bool strip_profile = true;
//        /* get dn of group holdings target keystore dn's */
//        char **target_keystore_group_dn = get_attr_values_as_string(ldap_handle,
//            cfg, ptr->dn, POX509_TARGET_KEYSTORE);
//        if (target_keystore_group_dn == NULL) {
//            fatal("target_keystore_group_dn == NULL");
//        }
//
//        log_msg("target keystore group dn: %s", target_keystore_group_dn[0]);
//
//        /* get dn's of target keystore ee's */
//        char **target_keystore_ee_dns = get_attr_values_as_string(ldap_handle,
//            cfg, target_keystore_group_dn[0], ldap_target_group_attr);
//        if (target_keystore_ee_dns == NULL) {
//            fatal("target_keystore_ee_dns == NULL");
//        }
//
//        int i;
//        for (i = 0; target_keystore_ee_dns[i] != NULL && strip_profile; i++) {
//            log_msg("dn: %s", target_keystore_ee_dns[i]);
//
//            /* get ee's and compare uid to uid logging in */
//            char **target_keystore_ee_uid = get_attr_values_as_string(
//                ldap_handle, cfg, target_keystore_ee_dns[i],
//                ldap_target_uid_attr);
//            if (target_keystore_ee_uid == NULL) {
//                fatal("target_keystore_ee_uid == NULL");
//            }
//
//            log_msg("uid: %s", target_keystore_ee_uid[0]);
//            if (strcmp(target_keystore_ee_uid[0], pox509_info->uid) == 0) {
//                strip_profile = false;
//            }
//            free_string_array(target_keystore_ee_uid);
//        }
//
//        if (strip_profile) {
//            STAILQ_REMOVE(&pox509_info->profile_head, ptr, pox509_profile,
//                profiles);
//            free_profile(ptr);
//        }
//
//        /* free string arrays */
//        free_string_array(target_keystore_group_dn);
//        free_string_array(target_keystore_ee_dns);
//    }
//}

static void
get_access_profile_dns(LDAP *ldap_handle, cfg_t *cfg,
    char ***access_profile_dns)
{
    if (ldap_handle == NULL || cfg == NULL || access_profile_dns == NULL) {
        fatal("ldap_handle, cfg or access_profile_dns == NULL");
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
    int ldap_search_timeout = cfg_getint(cfg, "ldap_search_timeout");
    struct timeval search_timeout = {
        .tv_sec = ldap_search_timeout,
        .tv_usec = 0
    };
    int sizelimit = 1;
    LDAPMessage *result = NULL;
    int rc = ldap_search_ext_s(ldap_handle, server_dn, server_search_scope,
        filter, attrs, 0, NULL, NULL, &search_timeout, sizelimit, &result);
    if (rc != LDAP_SUCCESS) {
        fatal("ldap_search_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
    }
    /* get dn's as strings */
    get_attr_values_as_string(ldap_handle, result, access_profile_attr,
        access_profile_dns);
}

void
get_access_profiles(LDAP *ldap_handle, cfg_t *cfg, char **access_profile_dns)
{
    if (ldap_handle == NULL || cfg == NULL || access_profile_dns == NULL) {
        fatal("ldap_handle, cfg or access_profile_dns == NULL");
    }

    /* iterate access profiles */
    for (int i = 0; access_profile_dns[i] != NULL; i++) {
        char *dn = access_profile_dns[i];
        int ldap_search_timeout = cfg_getint(cfg, "ldap_search_timeout");
        struct timeval search_timeout = {
            .tv_sec = ldap_search_timeout,
            .tv_usec = 0
        };
        int sizelimit = 1;
        LDAPMessage *result = NULL;

        int rc = ldap_search_ext_s(ldap_handle, dn, LDAP_SCOPE_BASE, NULL, NULL,
            0, NULL, NULL, &search_timeout, sizelimit, &result);
        if (rc != LDAP_SUCCESS) {
            fatal("ldap_search_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
        }

        /* get objectclass attribute in order to decide whether we have
         * an access profile of type direct or onbehalf
         */
        char **access_profile_objectclass = NULL;
        get_attr_values_as_string(ldap_handle, result, "objectclass",
            &access_profile_objectclass);
        if (access_profile_objectclass == NULL) {
            fatal("access_profile_objectclass == NULL");
        }

        enum pox509_access_profile_type profile_type = UNKNOWN;
        for (int j = 0; access_profile_objectclass[j] != NULL; j++) {
            char *objectclass = access_profile_objectclass[j];
            if (strcmp(objectclass, POX509_DAP_OBJCLASS) == 0) {
                profile_type = DIRECT_ACCESS;
                break;
            } else if (strcmp(objectclass, POX509_AOBP_OBJCLASS) == 0) {
                profile_type = ACCESS_ON_BEHALF;
                break;
            }
        }
        free_string_array(access_profile_objectclass);

        switch(profile_type) {
        case DIRECT_ACCESS:
        {
            log_msg("got direct access profile");
            struct pox509_direct_access_profile *profile = NULL;
            profile = malloc(sizeof *profile);
            if (profile == NULL) {
                fatal("malloc()");
            }

            profile->dn = strdup(dn);
            get_rdn_value_from_dn(dn, &profile->name);

            /* set key provider */
            char **key_provider = NULL;
            get_attr_values_as_string(ldap_handle, result,
                POX509_DAP_KEY_PROVIDER_ATTR, &key_provider);
            if (key_provider == NULL) {
                fatal("key_provider == NULL");
            }
            profile->key_provider = malloc(sizeof(struct pox509_key_provider));
            if (profile->key_provider == NULL) {
                fatal("malloc()");
            }
            profile->key_provider->dn = strdup(key_provider[0]);
            free_string_array(key_provider);

            /* set keystore options */
            char **keystore_options = NULL;
            get_attr_values_as_string(ldap_handle, result,
                POX509_DAP_KEYSTORE_OPTIONS_ATTR, &keystore_options);
            if (keystore_options == NULL) {
                fatal("keystore_options == NULL");
            }
            profile->keystore_options =
                malloc(sizeof(struct pox509_keystore_options));
            if (profile->keystore_options == NULL) {
                fatal("malloc()");
            }
            profile->keystore_options->dn = strdup(keystore_options[0]);
            free_string_array(keystore_options);
            break;
        }
        case ACCESS_ON_BEHALF:
        {
            log_msg("got access on behalf profile");
            break;
        }
        case UNKNOWN:
        {
            break;
        }
        default:
            fatal("profile_type undefined: %d", profile_type);
        }

        ldap_msgfree(result);
    }
}

void
get_keystore_data_from_ldap(cfg_t *cfg, struct pox509_info *pox509_info)
{
    if (cfg == NULL || pox509_info == NULL) {
        fatal("cfg or pox509_info == NULL");
    }

    /* bind to ldap server */
    LDAP *ldap_handle = NULL;
    char *ldap_uri = cfg_getstr(cfg, "ldap_uri");
    int rc = ldap_initialize(&ldap_handle, ldap_uri);
    if (rc != LDAP_SUCCESS) {
        fatal("ldap_initialize(): '%s' (%d)", ldap_err2string(rc), rc);
    }

    set_ldap_options(ldap_handle, cfg);

    /* init STARTTLS if set */
    int ldap_starttls = cfg_getint(cfg, "ldap_starttls");
    if (ldap_starttls) {
        init_starttls(ldap_handle);
    }

    rc = bind_to_ldap(ldap_handle, cfg);
    if (rc != LDAP_SUCCESS) {
        pox509_info->ldap_online = 0;
        log_fail("bind_to_ldap(): '%s' (%d)", ldap_err2string(rc), rc);
        goto unbind_and_free_handle;
    }
    log_success("bind_to_ldap()");
    pox509_info->ldap_online = 1;

    /* get access profile dn's*/
    char **access_profile_dns = NULL;
    get_access_profile_dns(ldap_handle, cfg, &access_profile_dns);
    if (access_profile_dns == NULL) {
        fatal("access_profile_dns == NULL");
    }
    get_access_profiles(ldap_handle, cfg, access_profile_dns);

    free_string_array(access_profile_dns);

    //if (STAILQ_EMPTY(&pox509_info->profile_head)) {
    //    log_msg("access profile list == EMPTY");
    //}

unbind_and_free_handle:
    /*
     * it is important to unbind even though the bind has actually
     * failed because else the ldap_handle structure that has been
     * initialized before would never be freed leading to a memory leak.
     */
    rc = ldap_unbind_ext_s(ldap_handle, NULL, NULL);
    if (rc == LDAP_SUCCESS) {
        log_success("ldap_unbind_ext_s()");
    } else {
        log_fail("ldap_unbind_ext_s(): '%s' (%d)", ldap_err2string(rc), rc);
    }
}

