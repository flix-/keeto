/*
 * Copyright (C) 2014-2018 Sebastian Roland <seroland86@gmail.com>
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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <confuse.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "keeto-config.h"
#include "keeto-error.h"
#include "keeto-ldap.h"
#include "keeto-log.h"
#include "keeto-openssl.h"
#include "keeto-service.h"
#include "keeto-util.h"

#define MAX_UID_LENGTH 32
#define SSH_KEYSTORE_LOCATION_BUFFER_SIZE 1024

static void
cleanup(pam_handle_t *pamh, void *data, int error_status)
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
     * still an implementation follows for those that have enabled posix
     * threads in OpenSSH and to be prepared for possible changes in
     * OpenSSH.
     */
    if (pamh == NULL || data == NULL) {
        fatal("pamh or data == NULL");
    }

    struct keeto_info *info = data;
    log_info("cleaning up");
    free_info(info);
    cleanup_openssl();
    closelog();
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (pamh == NULL || argv == NULL) {
        fatal("pamh or argv == NULL");
    }

    /* check pam module arguments */
    if (argc != 1) {
        log_error("arg count != 1");
        return PAM_SERVICE_ERR;
    }
    const char *cfg_file = argv[0];
    if (!file_readable(cfg_file)) {
        log_error("failed to open config file '%s' for reading", cfg_file);
        return PAM_SERVICE_ERR;
    }

    /* initialize info object */
    struct keeto_info *info = new_info();
    if (info == NULL) {
        log_error("failed to allocate memory for info buffer");
        return PAM_BUF_ERR;
    }

    /* make info object available to module stack */
    int rc = pam_set_data(pamh, "keeto_info", info, &cleanup);
    if (rc != PAM_SUCCESS) {
        log_error("failed to set pam data (%s)", pam_strerror(pamh, rc));
        free_info(info);
        return PAM_SYSTEM_ERR;
    }

    init_openssl();

    /* parse config */
    info->cfg = parse_config(cfg_file);
    if (info->cfg == NULL) {
        log_error("failed to parse config file '%s'", cfg_file);
        return PAM_SERVICE_ERR;
    }

    /* set syslog facility */
    char *syslog_facility = cfg_getstr(info->cfg, "syslog_facility");
    rc = set_syslog_facility(syslog_facility);
    if (rc != KEETO_OK) {
        log_error("failed to set syslog facility '%s' (%s)", syslog_facility,
            keeto_strerror(rc));
        return PAM_SYSTEM_ERR;
    }

    /* retrieve uid */
    const char *uid = NULL;
    rc = pam_get_user(pamh, &uid, NULL);
    if (rc != PAM_SUCCESS) {
        log_error("failed to obtain uid from pam (%s)", pam_strerror(pamh, rc));
        return PAM_USER_UNKNOWN;
    }
    /*
     * an attacker could provide a malicious uid
     * (e.g. '../authorized_keys/foo') that can cause problems with the
     * resulting authorized_keys path after token substitution.
     * to minimize this attack vector the given uid will be tested
     * against a restrictive regular expression.
     */
    bool uid_valid = false;
    char *uid_regex = cfg_getstr(info->cfg, "uid_regex");
    rc = check_uid(uid_regex, uid, &uid_valid);
    if (rc != KEETO_OK) {
        log_error("failed to check uid (%s)", keeto_strerror(rc));
        return PAM_SERVICE_ERR;
    }
    if (!uid_valid) {
        log_error("invalid uid '%s'", uid);
        return PAM_AUTH_ERR;
    }

    /*
     * make uid available in info object. do not point to value in pam
     * space because if we free our data structure we would free it from
     * global pam space as well. other modules could rely on it.
     */
    info->uid = strndup(uid, MAX_UID_LENGTH);
    if (info->uid == NULL) {
        log_error("failed to duplicate uid");
        return PAM_BUF_ERR;
    }

    /* expand keystore path and add to info */
    info->ssh_keystore_location = malloc(SSH_KEYSTORE_LOCATION_BUFFER_SIZE);
    if (info->ssh_keystore_location == NULL) {
        log_error("failed to allocate memory for ssh keystore location buffer");
        return PAM_BUF_ERR;
    }
    char *ssh_keystore_location = cfg_getstr(info->cfg, "ssh_keystore_location");
    substitute_token('u', info->uid, ssh_keystore_location,
        info->ssh_keystore_location, SSH_KEYSTORE_LOCATION_BUFFER_SIZE);

    int res = PAM_ABORT;

    /*
     * get access profiles from ldap.
     *
     * only remove keystore when access permissions explicitly say so.
     */
    rc = get_access_profiles_from_ldap(info);
    switch (rc) {
    case KEETO_OK:
        break;
    case KEETO_NO_MEMORY:
        log_error("failed to obtain access profiles from ldap (%s)",
            keeto_strerror(rc));
        return PAM_BUF_ERR;
    case KEETO_LDAP_CONNECTION_ERR:
        log_error("failed to obtain access profiles from ldap (%s)",
            keeto_strerror(rc));
        info->ldap_online = 0;
        bool ldap_strict = cfg_getint(info->cfg, "ldap_strict");
        if (ldap_strict) {
            log_info("ldap strict mode active - refusing access");
            return PAM_AUTHINFO_UNAVAIL;
        }
        return PAM_SUCCESS;
    case KEETO_NO_SSH_SERVER:
        log_error("failed to obtain access profiles from ldap (%s)",
            keeto_strerror(rc));
        return PAM_AUTHINFO_UNAVAIL;
    case KEETO_NO_ACCESS_PROFILE_FOR_SSH_SERVER:
        log_info("no access profiles specified for ssh server");
        res = PAM_AUTH_ERR;
        goto cleanup_keystore;
    case KEETO_NO_ACCESS_PROFILE_FOR_UID:
        log_info("no valid access profile specified for uid '%s'", info->uid);
        res = PAM_AUTH_ERR;
        goto cleanup_keystore;
    default:
        log_error("failed to obtain access profiles from ldap (%s)",
            keeto_strerror(rc));
        return PAM_SERVICE_ERR;
    }

    /*
     * validate certificates, convert public key to OpenSSH
     * authorized_keys format and create keystore records.
     */
    log_info("post processing access profiles");
    rc = post_process_access_profiles(info);
    switch (rc) {
    case KEETO_OK:
        break;
    case KEETO_NO_MEMORY:
        log_error("failed to post process access profiles (%s)",
            keeto_strerror(rc));
        return PAM_BUF_ERR;
    case KEETO_NO_ACCESS_PROFILE_FOR_UID:
        log_info("no valid access profile specified for uid '%s'", info->uid);
        res = PAM_AUTH_ERR;
        goto cleanup_keystore;
    default:
        log_error("failed to post process access profiles (%s)",
            keeto_strerror(rc));
        return PAM_SERVICE_ERR;
    }

    /* write keystore records to keystore file */
    log_info("writing keystore file '%s'", info->ssh_keystore_location);
    rc = write_keystore(info->ssh_keystore_location, info->keystore_records);
    switch (rc) {
    case KEETO_OK:
        break;
    default:
        log_error("failed to write keystore file (%s)", keeto_strerror(rc));
        return PAM_SERVICE_ERR;
    }

    return PAM_SUCCESS;

cleanup_keystore:
    remove_keystore(info->ssh_keystore_location);
    return res;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

