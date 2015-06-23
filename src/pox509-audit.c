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

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "pox509-log.h"
#include "pox509-util.h"

static char *unset = "unset";

static void
log_string(char *attr, char *value)
{
    if (attr == NULL) {
        fatal("attr == NULL");
    }
    if (value == NULL) {
        value = unset;
    }
    log_msg("%s: %s", attr, value);
}

static void
log_char(char *attr, char value)
{
    if (attr == NULL) {
        fatal("attr == NULL");
    }
    char *value_string = NULL;
    if (value == 0x56) {
        value_string = unset;
    } else if (value == 1) {
        value_string = "true";
    } else {
        value_string = "false";
    }
    log_msg("%s: %s", attr, value_string);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (pamh == NULL) {
        fatal("pamh == NULL");
    }

    struct pox509_info *pox509_info = NULL;
    int rc = pam_get_data(pamh, "pox509_info", (const void **) &pox509_info);
    if (rc != PAM_SUCCESS) {
        fatal("pam_get_data()");
    }

    /* set log facility */
    rc = set_syslog_facility(pox509_info->syslog_facility);
    if (rc == -EINVAL) {
        log_fail("set_syslog_facility(): '%s'", pox509_info->syslog_facility);
    }

    log_msg("===================================================");
    log_string("uid", pox509_info->uid);
    log_string("authorized_keys_file", pox509_info->authorized_keys_file);
    log_string("ssh_keytype", pox509_info->ssh_keytype);
    log_string("ssh_key", pox509_info->ssh_key);
    log_msg(" ");
    log_char("has_cert", pox509_info->has_cert);
    log_char("has_valid_cert", pox509_info->has_valid_cert);
    log_string("serial", pox509_info->serial);
    log_string("issuer", pox509_info->issuer);
    log_string("subject", pox509_info->subject);
    log_msg(" ");
    log_char("ldap_online", pox509_info->ldap_online);
    log_char("has_access", pox509_info->has_access);
    log_msg("===================================================");

    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

