/*
 * Copyright (C) 2014-2016 Sebastian Roland <seroland86@gmail.com>
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

#ifndef POX509_UTIL_H
#define POX509_UTIL_H

#include "queue.h"

#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>

#include <confuse.h>
#include <openssl/x509.h>

#include "pox509-log.h"

#define POX509_DEBUG \
int sleepy = 1; \
while (sleepy) { \
    sleep(5); \
}

enum {
    POX509_UNDEF = 0x56
};

enum pox509_access_profile_type {
    DIRECT_ACCESS_PROFILE = 0,
    ACCESS_ON_BEHALF_PROFILE,
};

enum pox509_section {
    POX509_SYSLOG = 0,
    POX509_LIBLDAP
};

struct pox509_keystore_record {
    char *uid;
    char *ssh_keytype;
    char *ssh_key;
    char *command_option;
    char *from_option;
    SIMPLEQ_ENTRY(pox509_keystore_record) next;
};

struct pox509_keystore_options {
    char *dn;
    char *uid;
    char *command_option;
    char *from_option;
};

struct pox509_key {
    X509 *x509;
    char *ssh_keytype;
    char *ssh_key;
    TAILQ_ENTRY(pox509_key) next;
};

struct pox509_key_provider {
    char *dn;
    char *uid;
    TAILQ_HEAD(pox509_keys, pox509_key) *keys;
    TAILQ_ENTRY(pox509_key_provider) next;
};

struct pox509_access_profile {
    enum pox509_access_profile_type type;
    char *dn;
    char *uid;
    TAILQ_HEAD(pox509_key_providers, pox509_key_provider) *key_providers;
    struct pox509_keystore_options *keystore_options;
    TAILQ_ENTRY(pox509_access_profile) next;
};

struct pox509_ssh_server {
    char *dn;
    char *uid;
};

struct pox509_info {
    cfg_t *cfg;
    char *uid;
    char *ssh_keystore_location;
    struct pox509_ssh_server *ssh_server;
    TAILQ_HEAD(pox509_access_profiles, pox509_access_profile)
        *access_profiles;
    char ldap_online;
    SIMPLEQ_HEAD(pox509_keystore_records, pox509_keystore_record)
        *keystore_records;
};

int str_to_enum(enum pox509_section section, const char *key);
bool file_readable(const char *file);
int check_uid(char *regex, const char *uid, bool *uid_valid);
void substitute_token(char token, const char *subst, const char *src, char *dst,
    size_t dst_length);
int create_ldap_search_filter(const char *attr, const char *value, char *dst,
    size_t dst_length);
int get_rdn_from_dn(const char *, char **buffer);
struct timeval get_ldap_search_timeout(cfg_t *cfg);
/* constructors */
struct pox509_info *new_info();
struct pox509_ssh_server *new_ssh_server();
struct pox509_access_profiles *new_access_profiles();
struct pox509_access_profile *new_access_profile();
struct pox509_key_providers *new_key_providers();
struct pox509_key_provider *new_key_provider();
struct pox509_keys *new_keys();
struct pox509_key *new_key();
struct pox509_keystore_options *new_keystore_options();
struct pox509_keystore_records *new_keystore_records();
struct pox509_keystore_record *new_keystore_record();
/* destructors */
void free_info(struct pox509_info *info);
void free_ssh_server(struct pox509_ssh_server *ssh_server);
void free_access_profiles(struct pox509_access_profiles *access_profiles);
void free_access_profile(struct pox509_access_profile *access_profile);
void free_key_providers(struct pox509_key_providers *key_providers);
void free_key_provider(struct pox509_key_provider *key_provider);
void free_keys(struct pox509_keys *keys);
void free_key(struct pox509_key *key);
void free_keystore_options(struct pox509_keystore_options *keystore_options);
void free_keystore_records(struct pox509_keystore_records *keystore_records);
void free_keystore_record(struct pox509_keystore_record *keystore_record);
#endif

