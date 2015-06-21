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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "pox509-log.h"
#include "pox509-util.h"

static bool
is_authorized(struct pox509_info *x509_info)
{
    if (x509_info == NULL) {
        fatal("x509_info == NULL");
    }

    return (x509_info->has_access == 1 && x509_info->has_valid_cert == 1);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (pamh == NULL) {
        fatal("pamh == NULL");
    }

    struct pox509_info *x509_info = NULL;
    int rc = pam_get_data(pamh, "x509_info", (const void **) &x509_info);
    if (rc != PAM_SUCCESS) {
        fatal("pam_get_data()");
    }

    /* set log facility */
    rc = set_syslog_facility(x509_info->syslog_facility);
    if (rc == -EINVAL) {
        log_fail("set_syslog_facility(): '%s'", x509_info->syslog_facility);
    }

    /* only modify authorized_keys file if LDAP server could be queried */
    if (x509_info->ldap_online != 1) {
        log_msg("ldap server not accessible. not changing anything");
        goto auth_success;
    }

    if (is_authorized(x509_info)) {
        log_msg("access granted!");
        log_msg("synchronizing keys");
        if (x509_info->ssh_keytype == NULL || x509_info->ssh_key == NULL) {
            fatal("cannot synchronize keys. either key or keytype not known");
        }
        /* write key to authorized_keys file */
        FILE *fd_auth_keys = fopen(x509_info->authorized_keys_file, "w");
        if (fd_auth_keys == NULL) {
            fatal("cannot open '%s' for writing",
                x509_info->authorized_keys_file);
        }
        fwrite(x509_info->ssh_keytype, strlen(x509_info->ssh_keytype), 1,
            fd_auth_keys);
        fwrite(" ", 1, 1, fd_auth_keys);
        fwrite(x509_info->ssh_key, strlen(x509_info->ssh_key), 1, fd_auth_keys);
        fwrite("\n", 1, 1, fd_auth_keys);
        fclose(fd_auth_keys);
    } else {
        log_msg("access denied!");
        log_msg("truncating authorized_keys file (%s)",
            x509_info->authorized_keys_file);
        FILE *fd_auth_keys = fopen(x509_info->authorized_keys_file, "w");
        if (fd_auth_keys == NULL) {
            log_fail("truncation of '%s' failed",
                x509_info->authorized_keys_file);
            goto auth_err;
        }
        fclose(fd_auth_keys);
    }

auth_success:
    return PAM_SUCCESS;

auth_err:
    return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

