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

#include "pox509-util.h"

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include <ldap.h>
#include <regex.h>
#include <syslog.h>

#include "pox509-log.h"

#define GROUP_DN_BUFFER_SIZE 1024
#define REGEX_PATTERN_UID "^[a-z][-a-z0-9]\\{0,31\\}$"

struct pox509_str_to_enum_entry {
    char *key;
    int value;
};

static struct pox509_str_to_enum_entry syslog_facility_lt[] = {
    { "LOG_KERN", LOG_KERN },
    { "LOG_USER", LOG_USER },
    { "LOG_MAIL", LOG_MAIL },
    { "LOG_DAEMON", LOG_DAEMON },
    { "LOG_AUTH", LOG_AUTH },
    { "LOG_SYSLOG", LOG_SYSLOG },
    { "LOG_LPR", LOG_LPR },
    { "LOG_NEWS", LOG_NEWS },
    { "LOG_UUCP", LOG_UUCP },
    { "LOG_CRON", LOG_CRON },
    { "LOG_AUTHPRIV", LOG_AUTHPRIV },
    { "LOG_FTP", LOG_FTP },
    { "LOG_LOCAL0", LOG_LOCAL0 },
    { "LOG_LOCAL1", LOG_LOCAL1 },
    { "LOG_LOCAL2", LOG_LOCAL2 },
    { "LOG_LOCAL3", LOG_LOCAL3 },
    { "LOG_LOCAL4", LOG_LOCAL4 },
    { "LOG_LOCAL5", LOG_LOCAL5 },
    { "LOG_LOCAL6", LOG_LOCAL6 },
    { "LOG_LOCAL7", LOG_LOCAL7 },
    /* mark end */
    { NULL, 0 }
};

static struct pox509_str_to_enum_entry libldap_lt[] = {
    { "LDAP_SCOPE_BASE", LDAP_SCOPE_BASE },
    { "LDAP_SCOPE_BASEOBJECT", LDAP_SCOPE_BASEOBJECT },
    { "LDAP_SCOPE_ONELEVEL", LDAP_SCOPE_ONELEVEL },
    { "LDAP_SCOPE_ONE", LDAP_SCOPE_ONE },
    { "LDAP_SCOPE_SUBTREE", LDAP_SCOPE_SUBTREE },
    { "LDAP_SCOPE_SUB", LDAP_SCOPE_SUB },
    { "LDAP_SCOPE_SUBORDINATE", LDAP_SCOPE_SUBORDINATE },
    { "LDAP_SCOPE_CHILDREN", LDAP_SCOPE_CHILDREN },
    /* mark end */
    { NULL, 0 }
};

static struct pox509_str_to_enum_entry *str_to_enum_lt[] = {
    syslog_facility_lt,
    libldap_lt
};

int
str_to_enum(enum pox509_sections sec, const char *key)
{
    if (key == NULL) {
        fatal("key == NULL");
    }

    if (sec != SYSLOG && sec != LIBLDAP) {
        fatal("invalid section (%d)", sec);
    }

    struct pox509_str_to_enum_entry *str_to_enum_entry = NULL;
    for (str_to_enum_entry = str_to_enum_lt[sec];
        str_to_enum_entry->key != NULL; str_to_enum_entry++) {
        if(strcmp(str_to_enum_entry->key, key) != 0) {
            continue;
        }
        return str_to_enum_entry->value;
    }
    return -EINVAL;
}

void
init_data_transfer_object(struct pox509_info *pox509_info)
{
    if (pox509_info == NULL) {
        fatal("pox509_info == NULL");
    }

    memset(pox509_info, 0, sizeof *pox509_info);
    pox509_info->uid = NULL;
    pox509_info->authorized_keys_file = NULL;
    pox509_info->ssh_keytype = NULL;
    pox509_info->ssh_key = NULL;
    pox509_info->has_cert = 0x56;
    pox509_info->has_valid_cert = 0x56;
    pox509_info->serial = NULL;
    pox509_info->issuer = NULL;
    pox509_info->subject = NULL;
    pox509_info->ldap_online = 0x56;
    pox509_info->has_access = 0x56;
    pox509_info->syslog_facility = NULL;
}

bool
is_readable_file(const char *file)
{
    if (file == NULL) {
        fatal("file == NULL");
    }

    struct stat stat_buffer;
    int rc = stat(file, &stat_buffer);
    if (rc != 0) {
        log_fail("stat(): '%s' (%d)", strerror(errno), errno);
        goto ret_false;
    }
    /* check if we have a file */
    if (!S_ISREG(stat_buffer.st_mode)) {
        log_fail("S_ISREG");
        goto ret_false;
    }
    /* check if file is readable */
    rc = access(file, R_OK);
    if (rc != 0) {
        log_fail("access(): '%s' (%d)", strerror(errno), errno);
        goto ret_false;
    }
    return true;

ret_false:
    return false;
}

bool
is_valid_uid(const char *uid)
{
    if (uid == NULL) {
        fatal("uid == NULL");
    }

    regex_t regex_uid;
    int rc = regcomp(&regex_uid, REGEX_PATTERN_UID, REG_NOSUB);
    if (rc != 0) {
        fatal("regcomp(): could not compile regex");
    }
    rc = regexec(&regex_uid, uid, 0, NULL, 0);
    regfree(&regex_uid);

    if (rc == 0) {
        return true;
    } else {
        return false;
    }
}

void
substitute_token(char token, const char *subst, const char *src, char *dst,
    size_t dst_length)
{
    if (subst == NULL || src == NULL || dst == NULL) {
        fatal("subst, src or dst == NULL");
    }

    if (dst_length == 0) {
        fatal("dst_length must be > 0");
    }

    int cdt = 0;
    int j = 0;
    size_t strlen_subst = strlen(subst);
    int i;
    for (i = 0; (src[i] != '\0') && (j < dst_length - 1); i++) {
        if (cdt) {
            cdt = 0;
            if (src[i] == token) {
                j--;
                /* substitute token in dst buffer */
                int k;
                for (k = 0; (j < dst_length - 1) && (k < strlen_subst); k++) {
                    dst[j++] = subst[k];
                }
                continue;
            }
        }
        if (src[i] == '%') {
            cdt = 1;
        }
        /* copy char to dst buffer */
        dst[j++] = src[i];
    }
    dst[j] = '\0';
}

void
create_ldap_search_filter(const char *rdn, const char *uid, char *dst,
    size_t dst_length)
{
    if (rdn == NULL || uid == NULL || dst == NULL) {
        fatal("rdn, uid or dst == NULL");
    }

    if (dst_length == 0) {
        fatal("dst_length must be > 0");
    }

    snprintf(dst, dst_length, "%s=%s", rdn, uid);
}

void
check_access_permission(const char *group_dn, const char *identifier,
    struct pox509_info *pox509_info)
{
    if (group_dn == NULL || identifier == NULL || pox509_info == NULL) {
        fatal("group_dn, identifier or pox509_info == NULL");
    }

    size_t group_dn_length = strlen(group_dn);
    if (group_dn_length == 0) {
        fatal("group_dn must be > 0");
    }

    LDAPDN dn = NULL;
    int rc = ldap_str2dn(group_dn, &dn, LDAP_DN_FORMAT_LDAPV3);
    if (rc != LDAP_SUCCESS) {
        fatal("ldap_str2dn(): '%s' (%d)\n", ldap_err2string(rc), rc);
    }

    if (dn == NULL) {
        fatal("dn == NULL");
    }

    LDAPRDN rdn = dn[0];
    char *rdn_value = NULL;
    rc = ldap_rdn2str(rdn, &rdn_value, LDAP_DN_FORMAT_UFN);
    if (rc != LDAP_SUCCESS) {
        fatal("ldap_rdn2str(): '%s' (%d)\n", ldap_err2string(rc), rc);
    }

    rc = strcmp(rdn_value, identifier);
    if (rc == 0) {
        pox509_info->has_access = 1;
    } else {
        pox509_info->has_access = 0;
    }

    ldap_memfree(rdn_value);
    ldap_dnfree(dn);
}

