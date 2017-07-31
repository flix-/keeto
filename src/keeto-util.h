/*
 * Copyright (C) 2014-2017 Sebastian Roland <seroland86@gmail.com>
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

#ifndef KEETO_UTIL_H
#define KEETO_UTIL_H

#include "queue.h"

#include <stdbool.h>
#include <unistd.h>

#include <confuse.h>
#include <openssl/x509.h>

#define KEETO_DEBUG do { \
    int sleepy = 1; \
    while (sleepy) { \
        sleep(5); \
    } \
} while (0)

enum {
    KEETO_UNDEF = 0x56
};

enum keeto_access_profile_type {
    DIRECT_ACCESS_PROFILE = 0,
    ACCESS_ON_BEHALF_PROFILE
};

enum keeto_section {
    KEETO_SYSLOG = 0,
    KEETO_LIBLDAP
};

struct keeto_keystore_record {
    char *uid;
    char *ssh_keytype;
    char *ssh_key;
    char *command_option;
    char *from_option;
    SIMPLEQ_ENTRY(keeto_keystore_record) next;
};

struct keeto_keystore_options {
    char *dn;
    char *uid;
    char *command_option;
    char *from_option;
};

struct keeto_key {
    X509 *x509;
    char *ssh_keytype;
    char *ssh_key;
    char *ssh_key_fp_md5;
    char *ssh_key_fp_sha256;
    TAILQ_ENTRY(keeto_key) next;
};

struct keeto_key_provider {
    char *dn;
    char *uid;
    TAILQ_HEAD(keeto_keys, keeto_key) *keys;
    TAILQ_ENTRY(keeto_key_provider) next;
};

struct keeto_access_profile {
    enum keeto_access_profile_type type;
    char *dn;
    char *uid;
    TAILQ_HEAD(keeto_key_providers, keeto_key_provider) *key_providers;
    struct keeto_keystore_options *keystore_options;
    TAILQ_ENTRY(keeto_access_profile) next;
};

struct keeto_ssh_server {
    char *dn;
    char *uid;
};

struct keeto_info {
    cfg_t *cfg;
    char *uid;
    char *ssh_keystore_location;
    struct keeto_ssh_server *ssh_server;
    TAILQ_HEAD(keeto_access_profiles, keeto_access_profile)
        *access_profiles;
    char ldap_online;
    SIMPLEQ_HEAD(keeto_keystore_records, keeto_keystore_record)
        *keystore_records;
};

int str_to_enum(enum keeto_section section, const char *key);
bool file_readable(const char *file);
int check_uid(char *regex, const char *uid, bool *uid_valid);
void substitute_token(char token, const char *subst, const char *src, char *dst,
    size_t dst_length);
int get_rdn_from_dn(const char *dn, char **buffer);
struct timeval get_ldap_timeout(cfg_t *cfg);
int hex_from_hash(unsigned char *hash, size_t hash_length, char **ret);
int base64_from_hash(unsigned char *hash, size_t hash_length, char **ret);
/* constructors */
struct keeto_info *new_info();
struct keeto_ssh_server *new_ssh_server();
struct keeto_access_profiles *new_access_profiles();
struct keeto_access_profile *new_access_profile();
struct keeto_key_providers *new_key_providers();
struct keeto_key_provider *new_key_provider();
struct keeto_keys *new_keys();
struct keeto_key *new_key();
struct keeto_keystore_options *new_keystore_options();
struct keeto_keystore_records *new_keystore_records();
struct keeto_keystore_record *new_keystore_record();
/* destructors */
void free_info(struct keeto_info *info);
void free_ssh_server(struct keeto_ssh_server *ssh_server);
void free_access_profiles(struct keeto_access_profiles *access_profiles);
void free_access_profile(struct keeto_access_profile *access_profile);
void free_key_providers(struct keeto_key_providers *key_providers);
void free_key_provider(struct keeto_key_provider *key_provider);
void free_keys(struct keeto_keys *keys);
void free_key(struct keeto_key *key);
void free_keystore_options(struct keeto_keystore_options *keystore_options);
void free_keystore_records(struct keeto_keystore_records *keystore_records);
void free_keystore_record(struct keeto_keystore_record *keystore_record);

#endif /* KEETO_UTIL_H */

