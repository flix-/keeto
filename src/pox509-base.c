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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <confuse.h>
#include <openssl/x509.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "pox509-config.h"
#include "pox509-error.h"
#include "pox509-ldap.h"
#include "pox509-log.h"
#include "pox509-util.h"
#include "pox509-x509.h"

#define MAX_UID_LENGTH 32
#define SSH_KEYSTORE_PATH_BUFFER_SIZE 1024

static void
cleanup_info(pam_handle_t *pamh, void *data, int error_status)
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

    struct pox509_info *info = data;
    log_info("freeing info");
    free_info(info);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (pamh == NULL || argv == NULL) {
        fatal("pamh or argv == NULL");
    }

    /* check if argument is path to config file */
    if (argc != 1) {
        log_error("arg count != 1");
        return PAM_SERVICE_ERR;
    }
    const char *cfg_file = argv[0];
    if(!is_readable_file(cfg_file)) {
        log_error("cannot open config file (%s) for reading", cfg_file);
        return PAM_SERVICE_ERR;
    }

    /* initialize info object */
    struct pox509_info *info = new_info();
    if (info == NULL) {
        log_debug("new_info(): '%s'", pox509_strerror(POX509_NO_MEMORY));
        return PAM_BUF_ERR;
    }

    /* make info object available to module stack */
    int rc = pam_set_data(pamh, "pox509_info", info, &cleanup_info);
    if (rc != PAM_SUCCESS) {
        log_debug("pam_set_data(): '%s' (%d)", pam_strerror(pamh, rc), rc);
        return PAM_SYSTEM_ERR;
    }

    /* parse config */
    info->cfg = parse_config(cfg_file);
    if (info->cfg == NULL) {
        log_error("error parsing config file '%s'", cfg_file);
        return PAM_SERVICE_ERR;
    }

    /* set syslog facility */
    char *syslog_facility = cfg_getstr(info->cfg, "syslog_facility");
    rc = set_syslog_facility(syslog_facility);
    if (rc != POX509_OK) {
        log_error("error setting syslog facility '%s' (%s)", syslog_facility,
            pox509_strerror(rc));
    }

    /* retrieve uid */
    const char *uid = NULL;
    rc = pam_get_user(pamh, &uid, NULL);
    if (rc != PAM_SUCCESS) {
        log_debug("pam_get_user(): '%s' (%d)", pam_strerror(pamh, rc), rc);
        return PAM_USER_UNKNOWN;
    }
    /*
     * an attacker could provide a malicious uid
     * (e.g. '../authorized_keys/foo') that can cause problems with the
     * resulting authorized_keys path after token substitution.
     * to minimize this attack vector the given uid will be tested
     * against a restrictive regular expression.
     */
    bool is_uid_valid = false;
    rc = check_uid(uid, &is_uid_valid);
    if (rc != POX509_OK) {
        log_error("error checking uid '%s'", pox509_strerror(rc));
        return PAM_SERVICE_ERR;
    }
    if (!is_uid_valid) {
        log_error("invalid uid '%s'", uid);
        return PAM_AUTH_ERR;
    }

    /*
     * make uid available in data transfer object. do not point to value
     * in pam space because if we free our data structure we would free
     * it from global pam space as well. other modules could rely on it.
     */
    info->uid = strndup(uid, MAX_UID_LENGTH);
    if (info->uid == NULL) {
        log_debug("strndup() error");
        return PAM_BUF_ERR;
    }

    /* expand keystore path and add to dto */
    char *expanded_path = malloc(SSH_KEYSTORE_PATH_BUFFER_SIZE);
    if (expanded_path == NULL) {
        log_debug("malloc() error");
        return PAM_BUF_ERR;
    }
    char *ssh_keystore_location =
        cfg_getstr(info->cfg, "ssh_keystore_location");
    substitute_token('u', info->uid, ssh_keystore_location, expanded_path,
        SSH_KEYSTORE_PATH_BUFFER_SIZE);
    info->ssh_keystore_location = expanded_path;

    /* get access profiles from ldap */
    rc = get_keystore_data_from_ldap(info);
    switch (rc) {
    case POX509_OK:
        break;
    case POX509_NO_MEMORY:
        log_error("'%s'", pox509_strerror(rc));
        return PAM_BUF_ERR;
    case POX509_LDAP_CONNECTION_ERR:
        info->ldap_online = 0;
        log_error("connection to ldap failed");
        break;
    case POX509_NO_ACCESS_PROFILE:
        log_info("no access profile found");
        return PAM_AUTH_ERR;
    default:
        log_debug("get_keystore_data_from_ldap(): '%s'", pox509_strerror(rc));
        return PAM_SERVICE_ERR;
    }

    /* validate certificates and convert public key to OpenSSH
     * authorized_keys format
     */
    //char *cacerts_dir = cfg_getstr(info->cfg, "cacerts_dir");
    //validate_x509(x509, cacerts_dir, info);
    //x509_to_authorized_keys(x509, info);

    /* create oneliner for authorized_keys option */
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

