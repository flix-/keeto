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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <confuse.h>
#include <openssl/x509.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "pox509-config.h"
#include "pox509-ldap.h"
#include "pox509-log.h"
#include "pox509-util.h"
#include "pox509-x509.h"

#define MAX_UID_LENGTH 32
#define AUTHORIZED_KEYS_FILE_BUFFER_SIZE 1024

static void
cleanup_pox509_info(pam_handle_t *pamh, void *data, int error_status)
{
    /*
     * this function should normally be called through pam_end() for
     * cleanup. unfortunately this is not happening for OpenSSH under
     * "normal" circumstances. the reasons is as follows:
     *
     * unless UNSUPPORTED_POSIX_THREADS_HACK has been defined during
     * compilation (which in most cases is not) OpenSSH creates a new
     * process(!) for pam authentication and account handling. the pam
     * handle is duplicated into the new process and every information
     * added through pam modules to the handle is only visible in the
     * new process. as the process terminates after the account handling
     * the original pam handle does not know anything about the
     * previously registered data structure and cleanup function so that
     * it cannot be taken into account during pam_end().
     *
     * not freeing the data structure results in a memory leak. as the
     * process terminates immediately and all memory is given back to
     * the operating system no further workarounds have been setup.
     *
     * still an implementation follows for the brave people who enabled
     * posix threads in OpenSSH and to be prepared for possible changes
     * in OpenSSH.
     */
    if (pamh == NULL || data == NULL) {
        fatal("pamh or data == NULL");
    }

    struct pox509_info *pox509_info = data;
    log_msg("freeing pox509_info");
    free(pox509_info->syslog_facility);
    free(pox509_info->subject);
    free(pox509_info->issuer);
    free(pox509_info->serial);
    free(pox509_info->ssh_key);
    free(pox509_info->ssh_keytype);
    free(pox509_info->authorized_keys_file);
    free(pox509_info->uid);
    free(pox509_info);
    log_msg("pox509_info freed");
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (pamh == NULL || argv == NULL) {
        fatal("pamh or argv == NULL");
    }

    /* check if argument is path to config file */
    if (argc != 1) {
        fatal("arg count != 1");
    }
    const char *cfg_file = argv[0];
    if(!is_readable_file(cfg_file)) {
        fatal("cannot open config file (%s) for reading", cfg_file);
    }

    /* initialize and parse config */
    cfg_t *cfg = NULL;
    init_and_parse_config(&cfg, cfg_file);

    /* set syslog facility */
    char *syslog_facility = cfg_getstr(cfg, "syslog_facility");
    int rc = set_syslog_facility(syslog_facility);
    if (rc == -EINVAL) {
        log_fail("set_syslog_facility(): '%s'", syslog_facility);
    }

    /* initialize data transfer object */
    struct pox509_info *pox509_info = malloc(sizeof *pox509_info);
    if (pox509_info == NULL) {
        fatal("malloc()");
    }
    init_data_transfer_object(pox509_info);

    /* make data transfer object available to module stack */
    rc = pam_set_data(pamh, "pox509_info", pox509_info, &cleanup_pox509_info);
    if (rc != PAM_SUCCESS) {
        fatal("pam_set_data()");
    }

    /* make syslog facility available in dto for downstream modules */
    pox509_info->syslog_facility = strdup(syslog_facility);
    if (pox509_info->syslog_facility == NULL) {
        fatal("strdup()");
    }

    /* retrieve uid */
    const char *uid = NULL;
    rc = pam_get_user(pamh, &uid, NULL);
    if (rc != PAM_SUCCESS) {
        fatal("pam_get_user(): (%d)", rc);
    }
    /*
     * an attacker could provide a malicious uid
     * (e.g. '../authorized_keys/foo') that can cause problems with the
     * resulting authorized_keys path after token substitution.
     * to minimize this attack vector the given uid will be tested
     * against a restrictive regular expression.
     */
    if (!is_valid_uid(uid)) {
        fatal("is_valid_uid(): uid: '%s'", uid);
    }

    /*
     * make uid available in data transfer object. do not point to value
     * in pam space because if we free our data structure we would free
     * it from global pam space as well. other modules could rely on it.
     */
    pox509_info->uid = strndup(uid, MAX_UID_LENGTH);
    if (pox509_info->uid == NULL) {
        fatal("strndup()");
    }

    /* expand authorized_keys_file option and add to dto */
    char *expanded_path = malloc(AUTHORIZED_KEYS_FILE_BUFFER_SIZE);
    if (expanded_path == NULL) {
        fatal("malloc()");
    }
    char *authorized_keys_file = cfg_getstr(cfg, "authorized_keys_file");
    substitute_token('u', pox509_info->uid, authorized_keys_file, expanded_path,
        AUTHORIZED_KEYS_FILE_BUFFER_SIZE);
    pox509_info->authorized_keys_file = expanded_path;

    /* query ldap server */
    X509 *x509 = NULL;
    retrieve_authorization_and_x509_from_ldap(cfg, pox509_info, &x509);

    /* process x509 certificate if one has been found */
    if (x509 != NULL) {
        /* validate x509 certificate */
        char *cacerts_dir = cfg_getstr(cfg, "cacerts_dir");
        validate_x509(x509, cacerts_dir, pox509_info);

        /*
         * convert public key of x509 certificate to OpenSSH
         * authorized_keys format
         */
        x509_to_authorized_keys(x509, pox509_info);

        /* extract various information from x509 certificate */
        get_serial_from_x509(x509, pox509_info);
        get_issuer_from_x509(x509, pox509_info);
        get_subject_from_x509(x509, pox509_info);

        /* free x509 structure */
        X509_free(x509);
    }

    /* free config */
    release_config(cfg);

    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

