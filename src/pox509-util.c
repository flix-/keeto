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

#include "pox509-config.h"
#include "pox509-error.h"
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
str_to_enum(enum pox509_section section, const char *key)
{
    if (key == NULL) {
        fatal("key == NULL");
    }

    if (section != POX509_SYSLOG && section != POX509_LIBLDAP) {
        fatal("invalid section (%d)", section);
    }

    struct pox509_str_to_enum_entry *str_to_enum_entry;
    for (str_to_enum_entry = str_to_enum_lt[section];
        str_to_enum_entry->key != NULL; str_to_enum_entry++) {
        if(strcmp(str_to_enum_entry->key, key) != 0) {
            continue;
        }
        return str_to_enum_entry->value;
    }
    return POX509_NO_SUCH_VALUE;
}

struct timeval
get_ldap_search_timeout(cfg_t *cfg)
{
    if (cfg == NULL) {
        fatal("cfg == NULL");
    }

    int ldap_search_timeout = cfg_getint(cfg, "ldap_search_timeout");
    struct timeval search_timeout = {
        .tv_sec = ldap_search_timeout,
        .tv_usec = 0
    };
    return search_timeout;
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
        log_debug("stat(): '%s' (%d)", strerror(errno), errno);
        return false;
    }
    /* check if we have a file */
    if (!S_ISREG(stat_buffer.st_mode)) {
        log_debug("S_ISREG");
        return false;
    }
    /* check if file is readable */
    rc = access(file, R_OK);
    if (rc != 0) {
        log_debug("access(): '%s' (%d)", strerror(errno), errno);
        return false;
    }
    return true;
}

int
check_uid(const char *uid, bool *is_uid_valid)
{
    if (uid == NULL || is_uid_valid == NULL) {
        fatal("uid or is_uid_valid == NULL");
    }

    regex_t regex_uid;
    int rc = regcomp(&regex_uid, REGEX_PATTERN_UID, REG_NOSUB);
    if (rc != 0) {
        log_debug("regcomp(): could not compile regex (%d)", rc);
        return POX509_REGEX_ERR;
    }
    rc = regexec(&regex_uid, uid, 0, NULL, 0);
    regfree(&regex_uid);

    if (rc == 0) {
        *is_uid_valid = true;
    } else {
        *is_uid_valid = false;
    }
    return POX509_OK;
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
    for (int i = 0; (src[i] != '\0') && (j < dst_length - 1); i++) {
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

int
create_ldap_search_filter(const char *attr, const char *value, char *dst,
    size_t dst_length)
{
    if (attr == NULL || value == NULL || dst == NULL) {
        fatal("attr, value or dst == NULL");
    }

    if (dst_length == 0) {
        fatal("dst_length must be > 0");
    }

    int rc = snprintf(dst, dst_length, "%s=%s", attr, value);
    if (rc < 0) {
        log_debug("snprintf() error");
        return POX509_SYSTEM_ERR;
    }
    return POX509_OK;
}

int
get_rdn_value_from_dn(const char *dn, char **buffer)
{
    if (dn == NULL || buffer == NULL) {
        fatal("dn or buffer == NULL");
    }

    size_t dn_length = strlen(dn);
    if (dn_length == 0) {
        fatal("dn must be > 0");
    }

    int res = POX509_UNKNOWN_ERR;
    LDAPDN ldap_dn = NULL;
    int rc = ldap_str2dn(dn, &ldap_dn, LDAP_DN_FORMAT_LDAPV3);
    if (rc != LDAP_SUCCESS) {
        log_debug("ldap_str2dn(): '%s' (%d)", ldap_err2string(rc), rc);
        return POX509_LDAP_ERR;
    }

    LDAPRDN ldap_rdn = ldap_dn[0];
    rc = ldap_rdn2str(ldap_rdn, buffer, LDAP_DN_FORMAT_UFN);
    if (rc != LDAP_SUCCESS) {
        log_debug("ldap_rdn2str(): '%s' (%d)", ldap_err2string(rc), rc);
        res = POX509_LDAP_ERR;
        goto cleanup;
    }
    res = POX509_OK;

cleanup:
    ldap_dnfree(ldap_dn);
    return res;
}

/* constructors */
struct pox509_info *
new_info()
{
    struct pox509_info *info = malloc(sizeof *info);
    if (info == NULL) {
        return NULL;
    }
    memset(info, 0, sizeof *info);
    info->ldap_online = POX509_UNDEF;
    return info;
}

struct pox509_ssh_server *
new_ssh_server()
{
    struct pox509_ssh_server *ssh_server = malloc(sizeof *ssh_server);
    if (ssh_server == NULL) {
        return NULL;
    }
    memset(ssh_server, 0, sizeof *ssh_server);
    return ssh_server;
}

struct pox509_access_profiles *
new_access_profiles()
{
    struct pox509_access_profiles *access_profiles =
        malloc(sizeof *access_profiles);
    if (access_profiles == NULL) {
        return NULL;
    }
    TAILQ_INIT(access_profiles);
    return access_profiles;
}

struct pox509_access_profile *
new_access_profile()
{
    struct pox509_access_profile *access_profile =
        malloc(sizeof *access_profile);
    if (access_profile == NULL) {
        return NULL;
    }
    memset(access_profile, 0, sizeof *access_profile);
    access_profile->type = POX509_UNDEF;
    return access_profile;
}

struct pox509_key_providers *
new_key_providers()
{
    struct pox509_key_providers *key_providers = malloc(sizeof *key_providers);
    if (key_providers == NULL) {
        return NULL;
    }
    TAILQ_INIT(key_providers);
    return key_providers;
}

struct pox509_key_provider *
new_key_provider()
{
    struct pox509_key_provider *key_provider = malloc(sizeof *key_provider);
    if (key_provider == NULL) {
        return NULL;
    }
    memset(key_provider, 0, sizeof *key_provider);
    return key_provider;
}

struct pox509_keys *
new_keys()
{
    struct pox509_keys *keys = malloc(sizeof *keys);
    if (keys == NULL) {
        return NULL;
    }
    TAILQ_INIT(keys);
    return keys;
}

struct pox509_key *
new_key()
{
    struct pox509_key *key = malloc(sizeof *key);
    if (key == NULL) {
        return NULL;
    }
    memset(key, 0, sizeof *key);
    return key;
}

struct pox509_keystore_options *
new_keystore_options() {

    struct pox509_keystore_options *keystore_options =
        malloc(sizeof *keystore_options);
    if (keystore_options == NULL) {
        return NULL;
    }
    memset(keystore_options, 0, sizeof *keystore_options);
    return keystore_options;
}

/* destructors */
void
free_info(struct pox509_info *info)
{
    if (info == NULL) {
        return;
    }
    free(info->uid);
    free(info->ssh_keystore_location);
    free_ssh_server(info->ssh_server);
    free_access_profiles(info->access_profiles);
    free_config(info->cfg);
    free(info);
}

void
free_ssh_server(struct pox509_ssh_server *ssh_server)
{
    if (ssh_server == NULL) {
        return;
    }
    free(ssh_server->dn);
    free(ssh_server->uid);
    free(ssh_server);
}

void
free_access_profiles(struct pox509_access_profiles *access_profiles)
{
    if (access_profiles == NULL) {
        return;
    }
    struct pox509_access_profile *access_profile = NULL;
    while ((access_profile = TAILQ_FIRST(access_profiles))) {
        TAILQ_REMOVE(access_profiles, access_profile, next);
        free_access_profile(access_profile);
    }
    free(access_profiles);
}

void
free_access_profile(struct pox509_access_profile *access_profile)
{
    if (access_profile == NULL) {
        return;
    }
    free(access_profile->dn);
    free(access_profile->uid);
    free_key_providers(access_profile->key_providers);
    free_keystore_options(access_profile->keystore_options);
    free(access_profile);
}

void
free_key_providers(struct pox509_key_providers *key_providers)
{
    if (key_providers == NULL) {
        return;
    }
    struct pox509_key_provider *key_provider = NULL;
    while ((key_provider = TAILQ_FIRST(key_providers))) {
        TAILQ_REMOVE(key_providers, key_provider, next);
        free_key_provider(key_provider);
    }
    free(key_providers);
}

void
free_key_provider(struct pox509_key_provider *key_provider)
{
    if (key_provider == NULL) {
        return;
    }
    free(key_provider->dn);
    free(key_provider->uid);
    free_keys(key_provider->keys);
    free(key_provider);
}

void
free_keys(struct pox509_keys *keys)
{
    if (keys == NULL) {
        return;
    }
    struct pox509_key *key = NULL;
    while ((key = TAILQ_FIRST(keys))) {
        TAILQ_REMOVE(keys, key, next);
        free_key(key);
    }
    free(keys);
}

void
free_key(struct pox509_key *key)
{
    if (key == NULL) {
        return;
    }
    X509_free(key->x509);
    free(key->ssh_keytype);
    free(key->ssh_key);
    free(key);
}

void
free_keystore_options(struct pox509_keystore_options *options)
{
    if (options == NULL) {
        return;
    }
    free(options->dn);
    free(options->uid);
    free(options->from_option);
    free(options->command_option);
    free(options->oneliner);
    free(options);
}

