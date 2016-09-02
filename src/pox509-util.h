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

/**
 * Utility functions.
 *
 * @file pox509-util.h
 * @author Sebastian Roland <seroland86@gmail.com>
 * @date 2016-03-26
 * @see https://github.com/flix-/pam-openssh-x509
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

/**
 * Sections for config lookup table.
 */
enum pox509_section {
    /** Section holding config options regarding syslog. */
    POX509_SYSLOG = 0,
    /** Section holding config options regarding libldap. */
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
    char *uid;
    char *ssh_keystore_location;
    struct pox509_ssh_server *ssh_server;
    TAILQ_HEAD(pox509_access_profiles, pox509_access_profile)
        *access_profiles;
    char ldap_online;
    SIMPLEQ_HEAD(pox509_keystore_records, pox509_keystore_record)
        *keystore_records;
    cfg_t *cfg;
};

/**
 * Map a value from string to enum constant.
 *
 * Some configuration options have to be set to enum constants. For
 * example the syslog_facility accepts LOG_KERN, LOG_USER etc. This enum
 * constants are actually integer values. In the configuration file they
 * are passed as strings. This function maps the input string to the
 * appropriate enum constant.
 *
 * @param[in] sec Name of the section that shall be searched. Valid
 * values are: SYSLOG, LIBLDAP.
 * @param[in] key String that shall be mapped. Must not be @c NULL.
 *
 * @return Upon successful completion, the appropriate enum constant
 * shall be returned. Otherwise -EINVAL shall be returned.
 */
int str_to_enum(enum pox509_section section, const char *key);

/**
 * Check if file is a regular and readable file.
 *
 * @param[in] file Path to file. Must not be @c NULL.
 *
 * @return Shall return true if file is a regular and readable file or
 * false otherwise.
 */
bool is_readable_file(const char *file);

/**
 * Check UID against a regular expression.
 *
 * @param[in] uid UID that shall be checked. Must not be @c NULL.
 *
 * @return Shall return true if UID matches regex or false otherwise.
 */
int check_uid(const char *uid, bool *res);

/**
 * Overwrite a token in a string with a substitution value.
 *
 * The token has the form '\%token' and will be completely replaced
 * with the value pointed by subst.
 * For example the string "/usr/local/etc/ssh/authorized_keys/%u" with
 * the token 'u' and the substitution value "foo" will yield
 * "/usr/local/etc/ssh/authorized_keys/foo".
 *
 *
 * @param[in] token Token that shall be replaced.
 * @param[in] subst Substitution value for '\%@p token'. Must not be @c
 * NULL.
 * @param[in] src Input string that shall be replaced. Must not be @c
 * NULL.
 * @param[out] dst Output buffer where substituted string shall be
 * written to. Must not be @c NULL.
 * @param[in] dst_length Length of the output buffer. Must be > 0.
 *
 * @warning Before calling #substitute_token make sure that values that
 * can lead to unwanted behavior are filtered.
 *
 * @warning For example if the substitution value for the token can be
 * chosen by an attacker and the function is used for replacing tokens
 * in a path.
 *
 * @warning Consider the following path:
 * "/usr/local/etc/ssh/authorized_keys/%u"
 *
 * @warning An attacker can change the path easily if he provides the
 * following substitution value: "../authorized_keys/root"
 *
 * @warning This will lead to the following path:
 * /usr/local/etc/ssh/authorized_keys/../authorized_keys/root"
 */
void substitute_token(char token, const char *subst, const char *src, char *dst,
    size_t dst_length);

/**
 * Create LDAP search filter from RDN attribute and UID.
 *
 * @param[in] attr Attribute. Must not be @c NULL.
 * @param[in] value Value. Must not be @c NULL.
 * @param[out] dst Output buffer where result shall be written to. Must
 * not be @c NULL.
 * @param[in] dst_length Length of the output buffer. Must be > 0.
 */
int create_ldap_search_filter(const char *attr, const char *value, char *dst,
    size_t dst_length);
int get_rdn_value_from_dn(const char *, char **buffer);
struct timeval get_ldap_search_timeout(cfg_t *cfg);
int post_process_access_profiles(struct pox509_info *info);

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
