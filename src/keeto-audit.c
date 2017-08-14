/*
 * Copyright (C) 2017 Sebastian Roland <seroland86@gmail.com>
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

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "queue.h"

#include "keeto-error.h"
#include "keeto-log.h"
#include "keeto-util.h"

#define PREFIX_SSH_KEY_FP_MD5 "KEETO_SSH_KEY_FP_MD5"
#define PREFIX_SSH_KEY_FP_SHA256 "KEETO_SSH_KEY_FP_SHA256"

static void
log_keeto_audit(struct keeto_info *info)
{
    if (info == NULL || info->keystore_records == NULL) {
        return;
    }

    struct keeto_keystore_record *keystore_record = NULL;
    SIMPLEQ_FOREACH(keystore_record, info->keystore_records, next) {
        log_raw("%s;%s;%s", PREFIX_SSH_KEY_FP_MD5, keystore_record->uid,
            keystore_record->ssh_key_fp_md5);
        log_raw("%s;%s;%s", PREFIX_SSH_KEY_FP_SHA256, keystore_record->uid,
            keystore_record->ssh_key_fp_sha256);
    }
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (pamh == NULL) {
        fatal("pamh == NULL");
    }

    struct keeto_info *info = NULL;
    int rc = pam_get_data(pamh, "keeto_info", (const void **) &info);
    if (rc != PAM_SUCCESS) {
        log_error("failed to get pam data (%s)", pam_strerror(pamh, rc));
        return PAM_SYSTEM_ERR;
    }

    /* set log facility */
    char *syslog_facility = cfg_getstr(info->cfg, "syslog_facility");
    if (syslog_facility == NULL) {
        return PAM_SYSTEM_ERR;
    }

    rc = set_syslog_facility(syslog_facility);
    if (rc != KEETO_OK) {
        log_error("failed to set syslog facility '%s' (%s)", syslog_facility,
            keeto_strerror(rc));
        return PAM_SYSTEM_ERR;
    }

    log_keeto_audit(info);

    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

