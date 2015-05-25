/*
 * Copyright (C) 2014-2015 Sebastian Roland <seroland86@gmail.com>
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

#include "pam_openssh_x509_ldap.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <confuse.h>
#include <lber.h>
#include <ldap.h>
#include <openssl/x509.h>

#include "pam_openssh_x509_util.h"

#define LDAP_SEARCH_FILTER_BUFFER_SIZE 512

static void
set_ldap_options(LDAP *ldap_handle, cfg_t *cfg)
{
    if (ldap_handle == NULL || cfg == NULL) {
        fatal("ldap_handle or cfg == NULL");
    }

    /* set protocol version */
    int ldap_version = cfg_getint(cfg, "ldap_version");
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
        } else {
            log_fail("ldap_get_option(): '%s' (%d)", ldap_err2string(rc), rc);
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
    char *ldap_pwd = cfg_getstr(cfg, "ldap_pwd");
    size_t ldap_pwd_length = strlen(ldap_pwd);
    struct berval cred = { ldap_pwd_length, ldap_pwd };
    int rc = ldap_sasl_bind_s(ldap_handle, ldap_bind_dn, LDAP_SASL_SIMPLE,
        &cred, NULL, NULL, NULL);
    memset(ldap_pwd, 0, ldap_pwd_length);
    return rc;
}

static int
search_ldap(LDAP *ldap_handle, LDAPMessage **ldap_result, cfg_t *cfg,
    struct pox509_info *x509_info)
{
    if (ldap_handle == NULL || ldap_result == NULL || cfg == NULL ||
        x509_info == NULL) {
        fatal("ldap_handle, ldap_result, cfg or x509_info == NULL");
    }

    /* collect arguments for ldap search */
    char *ldap_base = cfg_getstr(cfg, "ldap_base");
    int ldap_scope = cfg_getint(cfg, "ldap_scope");
    /* construct search filter */
    char filter[LDAP_SEARCH_FILTER_BUFFER_SIZE];
    char *ldap_attr_rdn_person = cfg_getstr(cfg, "ldap_attr_rdn_person");
    create_ldap_search_filter(ldap_attr_rdn_person, x509_info->uid, filter,
        sizeof filter);
    char *ldap_attr_access = cfg_getstr(cfg, "ldap_attr_access");
    char *ldap_attr_cert = cfg_getstr(cfg, "ldap_attr_cert");
    char *attrs[] = { ldap_attr_access, ldap_attr_cert, NULL };
    int ldap_search_timeout = cfg_getint(cfg, "ldap_search_timeout");
    struct timeval search_timeout = { ldap_search_timeout, 0 };
    int sizelimit = 1;

    /*
     * search people tree for given uid and retrieve group memberships
     * and x509 certificates.
     */
    int rc = ldap_search_ext_s(ldap_handle, ldap_base, ldap_scope, filter,
        attrs, 0, NULL, NULL, &search_timeout, sizelimit, ldap_result);
    return rc;
}

static void
handle_ldap_res_search_entry(LDAP *ldap_handle, LDAPMessage *ldap_result,
    cfg_t *cfg, struct pox509_info *x509_info, X509 **x509)
{
    if (ldap_handle == NULL || ldap_result == NULL || cfg == NULL ||
        x509_info == NULL || x509 == NULL) {
        fatal("ldap_handle, ldap_result, cfg, x509_info or x509 == NULL");
    }

    char *user_dn = ldap_get_dn(ldap_handle, ldap_result);
    if (user_dn == NULL) {
        /* cannot access ldap_handle->ld_errno as structure is opaque */
        log_fail("ldap_get_dn(): '%s'", "user_dn == NULL");
    } else {
        log_msg("user_dn: %s", user_dn);
    }

    /* iterate over all requested attributes */
    char *attr = NULL;
    struct berelement *attributes = NULL;
    for (attr = ldap_first_attribute(ldap_handle, ldap_result, &attributes);
        attr != NULL;
        attr = ldap_next_attribute(ldap_handle, ldap_result, attributes)) {

        char *ldap_attr_access = cfg_getstr(cfg, "ldap_attr_access");
        char *ldap_attr_cert = cfg_getstr(cfg, "ldap_attr_cert");
        bool is_attr_access = strcmp(attr, ldap_attr_access) == 0 ? 1 : 0;
        bool is_attr_cert = strcmp(attr, ldap_attr_cert) == 0 ? 1 : 0;

        struct berval **attr_values = ldap_get_values_len(ldap_handle,
            ldap_result, attr);
        if (attr_values == NULL) {
            fatal("ldap_get_values_len()");
        }

        /*
         * iterate over all values for attribute
         *
         * result of ldap_get_values_len() is an array in order to handle
         * mutivalued attributes
         */
        int i;
        for (i = 0; attr_values[i] != NULL; i++) {
            char *value = attr_values[i]->bv_val;
            ber_len_t len = attr_values[i]->bv_len;

            /* process group memberships */
            if (is_attr_access) {
                /*
                 * check access permission based on group membership
                 * and store result.
                 */
                log_msg("group_dn: %s", value);
                char *ldap_group_identifier =
                    cfg_getstr(cfg, "ldap_group_identifier");
                check_access_permission(value, ldap_group_identifier,
                    x509_info);
                /*
                 * stop looping over group memberships when access has
                 * been granted.
                 */
                if (x509_info->has_access == 1) {
                    break;
                }

            /* process x509 certificates */
            } else if (is_attr_cert) {
                /* decode certificate */
                *x509 = d2i_X509(NULL, (const unsigned char **) &value, len);
                if (*x509 == NULL) {
                    log_fail("d2i_X509(): cannot decode certificate");
                    /* try next certificate if existing */
                    continue;
                }

                x509_info->has_cert = 1;
                /*
                 * stop looping over x509 certificates when a valid one
                 * has been found.
                 */
                break;
            }
        }
        /* free attribute values array after each iteration */
        ldap_value_free_len(attr_values);
    }
    /* free attributes structure */
    ber_free(attributes, 0);
}

static void
handle_ldap_res_search_reference(LDAP *ldap_handle, LDAPMessage *ldap_result)
{
    if (ldap_handle == NULL || ldap_result == NULL) {
        fatal("ldap_handle or ldap_result == NULL");
    }

    log_fail("LDAP_RES_SEARCH_REFERENCE handling is not yet implemented");
}

static void
handle_ldap_res_search_result(LDAP *ldap_handle, LDAPMessage *ldap_result)
{
    if (ldap_handle == NULL || ldap_result == NULL) {
        fatal("ldap_handle or ldap_result == NULL");
    }

    int error_code;
    char *error_msg = NULL;
    int rc = ldap_parse_result(ldap_handle, ldap_result, &error_code, NULL,
        &error_msg, NULL, NULL, 0);
    if (rc != LDAP_SUCCESS) {
        log_fail("ldap_parse_result()");
        return;
    }

    /* only log errors */
    if (error_code != LDAP_SUCCESS) {
        log_fail("ldap_parse_result(): '%s' (%d)", ldap_err2string(error_code),
            error_code);
    }
    if (error_msg != NULL) {
        log_fail("ldap_parse_result(): '%s'", error_msg);
        ldap_memfree(error_msg);
    }
}

void
retrieve_authorization_and_x509_from_ldap(cfg_t *cfg,
    struct pox509_info *x509_info, X509 **x509)
{
    if (cfg == NULL || x509_info == NULL || x509 == NULL) {
        fatal("cfg, x509_info or x509 == NULL");
    }

    /* init handle */
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
        x509_info->directory_online = 0;
        log_fail("bind_to_ldap(): '%s' (%d)", ldap_err2string(rc), rc);
        goto unbind_and_free_handle;
    }

    /* connection established */
    log_success("bind_to_ldap()");
    x509_info->directory_online = 1;

    /* query ldap */
    LDAPMessage *ldap_result = NULL;
    rc = search_ldap(ldap_handle, &ldap_result, cfg, x509_info);
    if (rc != LDAP_SUCCESS) {
        log_fail("search_ldap(): '%s' (%d)", ldap_err2string(rc), rc);
        goto unbind_and_free_handle;
    }

    log_success("search_ldap()");
    /*
     * iterate over matching entries
     *
     * even though sizelimit is 1 at least 2 messages will be returned
     * (1x LDAP_RES_SEARCH_ENTRY + 1x LDAP_RES_SEARCH_RESULT) so that
     * we need to iterate over the result set instead of just retrieve
     * and process the first message.
     */
    for (ldap_result = ldap_first_message(ldap_handle, ldap_result);
        ldap_result != NULL;
        ldap_result = ldap_next_message(ldap_handle, ldap_result)) {

        int msgtype = ldap_msgtype(ldap_result);
        switch (msgtype) {
        case -1:
            fatal("ldap_msgtype()");
        case LDAP_RES_SEARCH_ENTRY:
            handle_ldap_res_search_entry(ldap_handle, ldap_result, cfg,
                x509_info, x509);
            break;
        case LDAP_RES_SEARCH_REFERENCE:
            handle_ldap_res_search_reference(ldap_handle, ldap_result);
            break;
        case LDAP_RES_SEARCH_RESULT:
            handle_ldap_res_search_result(ldap_handle, ldap_result);
            break;
        default:
            /* unlikely */
            log_fail("undefined msgtype '(0x%x)'", msgtype);
        }
    }
    /*
     * clear result structure - even if no result has been found
     * (see man page).
     */
    ldap_msgfree(ldap_result);

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

