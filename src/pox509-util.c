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
#include "pox509-x509.h"

#define GROUP_DN_BUFFER_SIZE 1024

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
file_readable(const char *file)
{
    if (file == NULL) {
        fatal("file == NULL");
    }

    struct stat stat_buffer;
    int rc = stat(file, &stat_buffer);
    if (rc != 0) {
        log_error("failed to get file status: file '%s' (%s)", file,
            strerror(errno));
        return false;
    }
    /* check if we have a file */
    if (!S_ISREG(stat_buffer.st_mode)) {
        log_error("'%s' is not a regular file", file);
        return false;
    }
    /* check if file is readable */
    rc = access(file, R_OK);
    if (rc != 0) {
        log_error("'%s' is not readable", file);
        return false;
    }
    return true;
}

void
remove_keystore(char *keystore)
{
    if (keystore == NULL) {
        fatal("keystore == NULL");
    }

    if (access(keystore, F_OK) == 0) {
        int rc = unlink(keystore);
        if (rc == -1) {
            log_error("failed to remove keystore file '%s' (%s)", keystore,
                strerror(errno));
        }
        log_info("removed keystore file '%s'", keystore);
    }
}

int
check_uid(char *regex, const char *uid, bool *uid_valid)
{
    if (regex == NULL || uid == NULL || uid_valid == NULL) {
        fatal("regex, uid or uid_valid == NULL");
    }

    regex_t regex_uid;
    int rc = regcomp(&regex_uid, regex, REG_EXTENDED | REG_NOSUB);
    if (rc != 0) {
        log_error("failed to compile regex (%d)", rc);
        return POX509_REGEX_ERR;
    }
    rc = regexec(&regex_uid, uid, 0, NULL, 0);
    regfree(&regex_uid);

    if (rc == 0) {
        *uid_valid = true;
    } else {
        *uid_valid = false;
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
        log_error("failed to write to buffer");
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
        log_error("failed to parse dn '%s' (%s)", dn, ldap_err2string(rc));
        return POX509_LDAP_ERR;
    }

    LDAPRDN ldap_rdn = ldap_dn[0];
    rc = ldap_rdn2str(ldap_rdn, buffer, LDAP_DN_FORMAT_UFN);
    if (rc != LDAP_SUCCESS) {
        log_error("failed to obtain rdn from dn '%s' (%s)", dn,
            ldap_err2string(rc));
        res = POX509_LDAP_ERR;
        goto cleanup;
    }
    res = POX509_OK;

cleanup:
    ldap_dnfree(ldap_dn);
    return res;
}

int
write_keystore(char *keystore, struct pox509_keystore_records *keystore_records)
{
    if (keystore == NULL || keystore_records == NULL) {
        fatal("keystore or keystore_records == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    /* create temporary file */
    char *template_suffix = "-XXXXXXX";
    size_t tmp_keystore_size = strlen(keystore) + strlen(template_suffix) + 1;
    char tmp_keystore[tmp_keystore_size];
    strcpy(tmp_keystore, keystore);
    strcat(tmp_keystore, template_suffix);
    /*
     * in older versions of glibc mkstemp sets permission of
     * temp file to 0666. being on the safe side...
     */
    mode_t mask = umask(S_IXUSR | S_IRWXG | S_IRWXO);
    int tmp_keystore_fd = mkstemp(tmp_keystore);
    umask(mask);
    if (tmp_keystore_fd == -1) {
        log_error("failed to create temporary keystore file '%s' (%s)",
            tmp_keystore, strerror(errno));
        return POX509_SYSTEM_ERR;
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
        return POX509_SYSTEM_ERR;
    }

    struct pox509_keystore_record *keystore_record = NULL;
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
    }
    int rc = fchmod(tmp_keystore_fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (rc == -1) {
        log_error("failed to set permissions for temp keystore file '%s' (%s)",
            tmp_keystore, strerror(errno));
        res = POX509_SYSTEM_ERR;
        goto cleanup;
    }
    rc = rename(tmp_keystore, keystore);
    if (rc == -1) {
        log_error("failed to move temp keystore file from '%s' to '%s' (%s)",
            tmp_keystore, keystore, strerror(errno));
        res = POX509_SYSTEM_ERR;
        goto cleanup;
    }
    res = POX509_OK;

cleanup:
    rc = fclose(tmp_keystore_file);
    if (rc != 0) {
        log_error("failed to flush stream and close file descriptor of "
            "temporary keystore file '%s' (%s)", tmp_keystore, strerror(errno));
        return POX509_SYSTEM_ERR;
    }
    return res;
}

static int
add_keystore_record(struct pox509_key_provider *key_provider,
    struct pox509_keystore_options *keystore_options, struct pox509_key *key,
    struct pox509_keystore_records *keystore_records)
{
    if (key_provider == NULL || key == NULL || keystore_records == NULL) {
        fatal("key_provider, key or keystore_records == NULL");
    }

    struct pox509_keystore_record *keystore_record = new_keystore_record();
    if (keystore_record == NULL) {
        log_error("failed to allocate memory for keystore record");
        return POX509_NO_MEMORY;
    }

    keystore_record->uid = key_provider->uid;
    keystore_record->ssh_keytype = key->ssh_keytype;
    keystore_record->ssh_key = key->ssh_key;
    if (keystore_options != NULL) {
        keystore_record->command_option = keystore_options->command_option;
        keystore_record->from_option = keystore_options->from_option;
    }
    SIMPLEQ_INSERT_TAIL(keystore_records, keystore_record, next);

    return POX509_OK;
}

static int
post_process_key(struct pox509_info *info, struct pox509_key *key)
{
    if (info == NULL || key == NULL) {
        fatal("info or key == NULL");
    }

    /* check certificate */
    bool valid = false;
    char *cacerts_dir = cfg_getstr(info->cfg, "cacerts_dir");
    int rc = validate_x509(key->x509, cacerts_dir, &valid);
    if (rc != POX509_OK) {
        log_error("failed to validate certificate (%s)", pox509_strerror(rc));
        return POX509_CERT_VALIDATION_ERR;
    }
    if (!valid) {
        return POX509_INVALID_CERT;
    }

    /* add ssh key data */
    rc = add_ssh_key_data_from_x509(key->x509, key);
    switch (rc) {
    case POX509_OK:
        break;
    case POX509_NO_MEMORY:
        return rc;
    default:
        log_error("failed to add key data (%s)", pox509_strerror(rc));
        return POX509_KEY_TRANSFORM_ERR;
    }
    return POX509_OK;
}

static int
post_process_key_provider(struct pox509_info *info,
    struct pox509_key_provider *key_provider,
    struct pox509_keystore_options *keystore_options,
    struct pox509_keystore_records *keystore_records)
{
    if (info == NULL || key_provider == NULL || keystore_records == NULL) {
        fatal("info, key_provider or keystore_records == NULL");
    }

    if (key_provider->keys == NULL) {
        fatal("key_provider->keys == NULL");
    }

    struct pox509_key *key = NULL;
    struct pox509_key *key_tmp = NULL;
    TAILQ_FOREACH_SAFE(key, key_provider->keys, next, key_tmp) {
        log_info("processing key");
        int rc = post_process_key(info, key);
        switch (rc) {
        case POX509_OK:
            /* add key to keystore records */
            log_info("adding keystore record");
            rc = add_keystore_record(key_provider, keystore_options, key,
                keystore_records);
            switch (rc) {
            case POX509_OK:
                break;
            case POX509_NO_MEMORY:
                return rc;
            default:
                log_error("failed to add keystore record");
            }
            break;
        case POX509_NO_MEMORY:
            return rc;
        default:
            log_error("removing key (%s)", pox509_strerror(rc));
            TAILQ_REMOVE(key_provider->keys, key, next);
            free_key(key);
        }
    }
    if (TAILQ_EMPTY(key_provider->keys)) {
        return POX509_NO_KEY;
    }

    return POX509_OK;
}

static int
post_process_access_profile(struct pox509_info *info,
    struct pox509_access_profile *access_profile,
    struct pox509_keystore_records *keystore_records)
{
    if (info == NULL || access_profile == NULL || keystore_records == NULL) {
        fatal("info, access_profile or keystore_records == NULL");
    }

    if (access_profile->key_providers == NULL) {
        fatal("access_profile->key_providers == NULL");
    }

    struct pox509_key_provider *key_provider = NULL;
    struct pox509_key_provider *key_provider_tmp = NULL;
    TAILQ_FOREACH_SAFE(key_provider, access_profile->key_providers, next,
        key_provider_tmp) {

        log_info("processing key provider '%s'", key_provider->uid);
        int rc = post_process_key_provider(info, key_provider,
            access_profile->keystore_options, keystore_records);
        switch (rc) {
        case POX509_OK:
            break;
        case POX509_NO_MEMORY:
            return rc;
        default:
            log_error("removing key provider (%s)", pox509_strerror(rc));
            TAILQ_REMOVE(access_profile->key_providers, key_provider, next);
            free_key_provider(key_provider);
        }
    }
    if (TAILQ_EMPTY(access_profile->key_providers)) {
        return POX509_NO_KEY_PROVIDER;
    }
    return POX509_OK;
}

int
post_process_access_profiles(struct pox509_info *info)
{
    if (info == NULL) {
        fatal("info == NULL");
    }

    if (info->access_profiles == NULL) {
        fatal("info->access_profiles == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    struct pox509_keystore_records *keystore_records = new_keystore_records();
    if (keystore_records == NULL) {
        log_error("failed to allocate memory for keystore records");
        return POX509_NO_MEMORY;
    }

    struct pox509_access_profile *access_profile = NULL;
    struct pox509_access_profile *access_profile_tmp = NULL;
    TAILQ_FOREACH_SAFE(access_profile, info->access_profiles, next,
        access_profile_tmp) {

        log_info("processing access profile '%s'", access_profile->uid);
        int rc = post_process_access_profile(info, access_profile,
            keystore_records);
        switch (rc) {
        case POX509_OK:
            break;
        case POX509_NO_MEMORY:
            res = rc;
            goto cleanup;
        default:
            log_error("removing access profile (%s)", pox509_strerror(rc));
            TAILQ_REMOVE(info->access_profiles, access_profile, next);
            free_access_profile(access_profile);
        }
    }
    if (TAILQ_EMPTY(info->access_profiles)) {
        free_access_profiles(info->access_profiles);
        info->access_profiles = NULL;
        res = POX509_NO_ACCESS_PROFILE;
        goto cleanup;
    }
    info->keystore_records = keystore_records;
    keystore_records = NULL;
    res = POX509_OK;

cleanup:
    if (keystore_records != NULL) {
        free_keystore_records(keystore_records);
    }
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

struct pox509_keystore_records *
new_keystore_records()
{
    struct pox509_keystore_records *keystore_records =
        malloc(sizeof *keystore_records);
    if (keystore_records == NULL) {
        return NULL;
    }
    SIMPLEQ_INIT(keystore_records);
    return keystore_records;
}

struct pox509_keystore_record *
new_keystore_record()
{
    struct pox509_keystore_record *keystore_record =
        malloc(sizeof *keystore_record);
    if (keystore_record == NULL) {
        return NULL;
    }
    memset(keystore_record, 0, sizeof *keystore_record);
    return keystore_record;
}
/* destructors */
void
free_info(struct pox509_info *info)
{
    if (info == NULL) {
        return;
    }
    free_config(info->cfg);
    free(info->uid);
    free(info->ssh_keystore_location);
    free_ssh_server(info->ssh_server);
    free_access_profiles(info->access_profiles);
    free_keystore_records(info->keystore_records);
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
    free_x509(key->x509);
    free(key->ssh_keytype);
    free(key->ssh_key);
    free(key);
}

void
free_keystore_options(struct pox509_keystore_options *keystore_options)
{
    if (keystore_options == NULL) {
        return;
    }
    free(keystore_options->dn);
    free(keystore_options->uid);
    free(keystore_options->command_option);
    free(keystore_options->from_option);
    free(keystore_options);
}

void
free_keystore_records(struct pox509_keystore_records *keystore_records)
{
    if (keystore_records == NULL) {
        return;
    }
    struct pox509_keystore_record *keystore_record = NULL;
    while ((keystore_record = SIMPLEQ_FIRST(keystore_records))) {
        SIMPLEQ_REMOVE_HEAD(keystore_records, next);
        free_keystore_record(keystore_record);
    }
    free(keystore_records);
}

void
free_keystore_record(struct pox509_keystore_record *keystore_record)
{
    if (keystore_record == NULL) {
        return;
    }
    /*
     * do not free the members of the struct as they are all pointing
     * to memory that is managed and freed in other structs.
     */
    free(keystore_record);
}

