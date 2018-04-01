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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>

#include <confuse.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "keeto-config.h"
#include "keeto-error.h"
#include "keeto-ldap.h"
#include "keeto-log.h"
#include "keeto-openssl.h"
#include "keeto-util.h"
#include "keeto-x509.h"

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
     * still an implementation follows for the brave people who enabled
     * posix threads in OpenSSH and to be prepared for possible changes
     * in OpenSSH.
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

static void
remove_keystore(char *keystore)
{
    if (keystore == NULL) {
        fatal("keystore == NULL");
    }

    int rc = unlink(keystore);
    if (rc == -1) {
        switch (errno) {
        case ENOENT:
            break;
        default:
            log_error("failed to remove keystore file '%s' (%s)", keystore,
                strerror(errno));
        }
        return;
    }
    log_info("removed keystore file '%s'", keystore);
}

static int
write_keystore(char *keystore, struct keeto_keystore_records *keystore_records)
{
    if (keystore == NULL || keystore_records == NULL) {
        fatal("keystore or keystore_records == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;

    /* create temporary file */
    char *template_suffix = "-XXXXXXX";
    size_t tmp_keystore_size = strlen(keystore) + strlen(template_suffix) + 1;
    char tmp_keystore[tmp_keystore_size];
    strcpy(tmp_keystore, keystore);
    strcat(tmp_keystore, template_suffix);
    /*
     * in older versions of glibc mkstemp sets permission of temp file
     * to 0666. being on the safe side...
     */
    mode_t mask = umask(S_IXUSR | S_IRWXG | S_IRWXO);
    int tmp_keystore_fd = mkstemp(tmp_keystore);
    umask(mask);
    if (tmp_keystore_fd == -1) {
        log_error("failed to create temporary keystore file '%s' (%s)",
            tmp_keystore, strerror(errno));
        return KEETO_SYSTEM_ERR;
    }

    FILE *tmp_keystore_file = fdopen(tmp_keystore_fd, "w");
    if (tmp_keystore_file == NULL) {
        log_error("failed to open temporary keystore file '%s' for writing (%s)",
            tmp_keystore, strerror(errno));
        int rc = close(tmp_keystore_fd);
        if (rc == -1) {
            log_error("failed to close file descriptor of temporary keystore "
                "file '%s' (%s)", tmp_keystore, strerror(errno));
        }
        return KEETO_SYSTEM_ERR;
    }

    struct keeto_keystore_record *keystore_record = NULL;
    SIMPLEQ_FOREACH(keystore_record, keystore_records, next) {
        bool command_option_set = keystore_record->command_option != NULL ?
            true : false;
        bool from_option_set = keystore_record->from_option != NULL ?
            true : false;
        bool option_set = false;

        if (command_option_set) {
            fprintf(tmp_keystore_file, "command=\"%s\"",
                keystore_record->command_option);
            option_set = true;
        }
        if (from_option_set) {
            if (option_set) {
                fprintf(tmp_keystore_file, ",");
            }
            fprintf(tmp_keystore_file, "from=\"%s\"",
                keystore_record->from_option);
            option_set = true;
        }
        if (option_set) {
            fprintf(tmp_keystore_file, " ");
        }
        fprintf(tmp_keystore_file, "%s %s %s\n", keystore_record->ssh_keytype,
            keystore_record->ssh_key, keystore_record->uid);
        fprintf(tmp_keystore_file, "\n");
    }
    int rc = fchmod(tmp_keystore_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (rc == -1) {
        log_error("failed to set permissions for temp keystore file '%s' (%s)",
            tmp_keystore, strerror(errno));
        res = KEETO_SYSTEM_ERR;
        goto cleanup;
    }
    rc = rename(tmp_keystore, keystore);
    if (rc == -1) {
        log_error("failed to move temp keystore file from '%s' to '%s' (%s)",
            tmp_keystore, keystore, strerror(errno));
        res = KEETO_SYSTEM_ERR;
        goto cleanup;
    }
    res = KEETO_OK;

cleanup:
    rc = fclose(tmp_keystore_file);
    if (rc != 0) {
        log_error("failed to flush stream and close file descriptor of "
            "temporary keystore file '%s' (%s)", tmp_keystore, strerror(errno));
        return KEETO_SYSTEM_ERR;
    }
    return res;
}

static int
add_keystore_record(struct keeto_key_provider *key_provider,
    struct keeto_keystore_options *keystore_options, struct keeto_key *key,
    struct keeto_keystore_records *keystore_records)
{
    if (key_provider == NULL || key == NULL || keystore_records == NULL) {
        fatal("key_provider, key or keystore_records == NULL");
    }

    struct keeto_keystore_record *keystore_record = new_keystore_record();
    if (keystore_record == NULL) {
        log_error("failed to allocate memory for keystore record buffer");
        return KEETO_NO_MEMORY;
    }

    keystore_record->uid = key_provider->uid;
    keystore_record->ssh_keytype = key->ssh_key->keytype;
    keystore_record->ssh_key = key->ssh_key->key;
    keystore_record->ssh_key_fp_md5 = key->ssh_key_fp_md5;
    keystore_record->ssh_key_fp_sha256 = key->ssh_key_fp_sha256;
    if (keystore_options != NULL) {
        keystore_record->command_option = keystore_options->command_option;
        keystore_record->from_option = keystore_options->from_option;
    }
    SIMPLEQ_INSERT_TAIL(keystore_records, keystore_record, next);

    return KEETO_OK;
}

static int
post_process_key(struct keeto_key *key)
{
    if (key == NULL) {
        fatal("key == NULL");
    }

    /* check certificate */
    bool valid = false;
    int rc = validate_x509(key->x509, &valid);
    if (rc != KEETO_OK) {
        log_error("failed to validate certificate (%s)", keeto_strerror(rc));
        return KEETO_CERT_VALIDATION_ERR;
    }
    if (!valid) {
        return KEETO_INVALID_CERT;
    }

    /* add ssh key data */
    rc = add_key_data_from_x509(key->x509, key);
    switch (rc) {
    case KEETO_OK:
        break;
    case KEETO_NO_MEMORY:
        return rc;
    default:
        log_error("failed to add key data (%s)", keeto_strerror(rc));
        return KEETO_KEY_TRANSFORM_ERR;
    }
    return KEETO_OK;
}

static int
post_process_key_provider(struct keeto_key_provider *key_provider,
    struct keeto_keystore_options *keystore_options,
    struct keeto_keystore_records *keystore_records)
{
    if (key_provider == NULL || keystore_records == NULL) {
        fatal("key_provider or keystore_records == NULL");
    }

    if (key_provider->keys == NULL) {
        fatal("key_provider->keys == NULL");
    }

    struct keeto_key *key = NULL;
    struct keeto_key *key_tmp = NULL;
    TAILQ_FOREACH_SAFE(key, key_provider->keys, next, key_tmp) {
        char *subject = NULL;
        int rc = get_subject_from_x509(key->x509, &subject);
        switch (rc) {
        case KEETO_OK:
            log_info("processing key '%s'", subject);
            free(subject);
            break;
        case KEETO_NO_MEMORY:
            return rc;
        default:
            log_error("failed to obtain subject from certificate (%s)",
                keeto_strerror(rc));
        }

        rc = post_process_key(key);
        switch (rc) {
        case KEETO_OK:
            /* add key to keystore records */
            log_info("adding keystore record");
            rc = add_keystore_record(key_provider, keystore_options, key,
                keystore_records);
            switch (rc) {
            case KEETO_OK:
                break;
            case KEETO_NO_MEMORY:
                return rc;
            default:
                log_error("failed to add keystore record");
            }
            break;
        case KEETO_NO_MEMORY:
            return rc;
        default:
            log_info("removing key (%s)", keeto_strerror(rc));
            TAILQ_REMOVE(key_provider->keys, key, next);
            free_key(key);
        }
    }
    if (TAILQ_EMPTY(key_provider->keys)) {
        return KEETO_NO_KEY;
    }
    return KEETO_OK;
}

static int
post_process_access_profile(struct keeto_access_profile *access_profile,
    struct keeto_keystore_records *keystore_records)
{
    if (access_profile == NULL || keystore_records == NULL) {
        fatal("access_profile or keystore_records == NULL");
    }

    if (access_profile->key_providers == NULL) {
        fatal("access_profile->key_providers == NULL");
    }

    struct keeto_key_provider *key_provider = NULL;
    struct keeto_key_provider *key_provider_tmp = NULL;
    TAILQ_FOREACH_SAFE(key_provider, access_profile->key_providers, next,
        key_provider_tmp) {

        log_info("processing key provider '%s'", key_provider->uid);
        int rc = post_process_key_provider(key_provider,
            access_profile->keystore_options, keystore_records);
        switch (rc) {
        case KEETO_OK:
            break;
        case KEETO_NO_MEMORY:
            return rc;
        default:
            log_info("removing key provider (%s)", keeto_strerror(rc));
            TAILQ_REMOVE(access_profile->key_providers, key_provider, next);
            free_key_provider(key_provider);
        }
    }
    if (TAILQ_EMPTY(access_profile->key_providers)) {
        return KEETO_NO_KEY_PROVIDER;
    }
    return KEETO_OK;
}

static int
post_process_access_profiles(struct keeto_info *info)
{
    if (info == NULL) {
        fatal("info == NULL");
    }

    if (info->access_profiles == NULL) {
        fatal("info->access_profiles == NULL");
    }

    int res = KEETO_UNKNOWN_ERR;

    /* init cert store for subsequent x509 validation */
    char *cert_store_dir = cfg_getstr(info->cfg, "cert_store_dir");
    bool check_crl = cfg_getint(info->cfg, "check_crl");
    int rc = init_cert_store(cert_store_dir, check_crl);
    if (rc != KEETO_OK) {
        log_error("failed to initialize cert store (%s)", keeto_strerror(rc));
        return rc;
    }

    struct keeto_keystore_records *keystore_records = new_keystore_records();
    if (keystore_records == NULL) {
        log_error("failed to allocate memory for keystore records buffer");
        res = KEETO_NO_MEMORY;
        goto cleanup_a;
    }

    struct keeto_access_profile *access_profile = NULL;
    struct keeto_access_profile *access_profile_tmp = NULL;
    TAILQ_FOREACH_SAFE(access_profile, info->access_profiles, next,
        access_profile_tmp) {

        log_info("processing access profile '%s'", access_profile->uid);
        int rc = post_process_access_profile(access_profile, keystore_records);
        switch (rc) {
        case KEETO_OK:
            break;
        case KEETO_NO_MEMORY:
            res = rc;
            goto cleanup_b;
        default:
            log_info("removing access profile (%s)", keeto_strerror(rc));
            TAILQ_REMOVE(info->access_profiles, access_profile, next);
            free_access_profile(access_profile);
        }
    }
    if (TAILQ_EMPTY(info->access_profiles)) {
        free_access_profiles(info->access_profiles);
        info->access_profiles = NULL;
        res = KEETO_NO_ACCESS_PROFILE_FOR_UID;
        goto cleanup_b;
    }
    info->keystore_records = keystore_records;
    keystore_records = NULL;
    res = KEETO_OK;

cleanup_b:
    if (keystore_records != NULL) {
        free_keystore_records(keystore_records);
    }
cleanup_a:
    free_cert_store();
    return res;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (pamh == NULL || argv == NULL) {
        fatal("pamh or argv == NULL");
    }

    /* check if argument is path to readable file */
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
     * make uid available in data transfer object. do not point to value
     * in pam space because if we free our data structure we would free
     * it from global pam space as well. other modules could rely on it.
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

    /* init openssl */
    init_openssl();

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

