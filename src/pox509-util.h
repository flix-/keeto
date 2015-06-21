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

/**
 * Utility functions.
 *
 * @file pox509-util.h
 * @author Sebastian Roland <seroland86@gmail.com>
 * @date 2015-06-21
 * @see https://github.com/flix-/pam-openssh-x509
 */

#ifndef POX509_UTIL_H
#define POX509_UTIL_H

#include <stdbool.h>
#include <stddef.h>

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>

/**
 * (D)ata (T)ransfer (O)bject
 *
 * Structure that holds all relevant information gathered in the base
 * module. Downstream modules can obtain a pointer to it through the PAM
 * handle.
 */
struct pox509_info {
    /** UID of the user about to authenticate */
    char *uid; 
    /** Path to authorized_keys file */
    char *authorized_keys_file;
    /** Type of the OpenSSH key */
    char *ssh_keytype;
    /** String representation of the OpenSSH public key for pasting into
     *  authorized_keys file */
    char *ssh_key;

    /** Indicates whether a x509 certificate has been found or not */
    char has_cert;
    /** Indicates whether the x509 certificate is valid or not */
    char has_valid_cert;
    /** Serial number of the x509 certificate */
    char *serial;
    /** Issuer of the x509 certificate */
    char *issuer;
    /** Subject of the x509 certificate */
    char *subject;

    /** Indicates whether the LDAP server has been reached or not */
    char ldap_online;
    /** Indicates whether the user is authorized to access the server or
     *  not */
    char has_access;

    /** Syslog logging facility */
    char *syslog_facility;
};

/**
 * Sections for config lookup table.
 */
enum pox509_sections {
    /** Section holding config options regarding syslog. */
    SYSLOG = 0,
    /** Section holding config options regarding libldap. */
    LIBLDAP
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
int str_to_enum(enum pox509_sections sec, const char *key);

/**
 * Set default values of data transfer object.
 *
 * @param[out] x509_info DTO. Must not be @c NULL.
 */
void init_data_transfer_object(struct pox509_info *x509_info);

/**
 * Check if file is a regular and readable file.
 *
 * @param[in] file Path to file. Must not be @c NULL.
 *
 * @return Shall return true if file is a regular and readable file or
 * false otherwise. Process shall terminate on error.
 */
bool is_readable_file(const char *file);

/**
 * Check uid against a regular expression.
 *
 * @param[in] uid UID that shall be checked. Must not be @c NULL.
 *
 * @return Shall return true if uid matches regex or false otherwise.
 * Process shall terminate on error.
 */
bool is_valid_uid(const char *uid);

/**
 * Overwrite a token in a string with a substitution value.
 *
 * The token has the form '\%@p token' and will be completely replaced
 * with the value pointed by subst.
 * For example the string "/etc/ssh/keystore/%u/authorized_keys" with
 * the token 'u' and the substitution value "foo" will yield
 * "/etc/ssh/keystore/foo/authorized_keys".
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
 * "/etc/ssh/keystore/%u/authorized_keys"
 *
 * @warning An attacker can change the path easily if he provides the
 * following substitution value: "../../../root/.ssh"
 *
 * @warning This will lead to the following path:
 * "/etc/ssh/keystore/../../../root/.ssh/authorized_keys"
 */
void substitute_token(char token, const char *subst, const char *src, char *dst,
    size_t dst_length);

/**
 * Create LDAP search filter from rdn attribute and uid.
 *
 * @param[in] rdn RDN attribute. Must not be @c NULL.
 * @param[in] uid UID. Must not be @c NULL.
 * @param[out] dst Output buffer where result shall be written to. Must
 * not be @c NULL.
 * @param[in] dst_length Length of the output buffer. Must be > 0.
 */
void create_ldap_search_filter(const char *rdn, const char *uid,
    char *dst, size_t dst_length);

/**
 * Extract first RDN value of @p group_dn and compare to identifier.
 *
 * Every OpenSSH server has a corresponding group in the LDAP server.
 * A user has the permission to access a certain OpenSSH server if he
 * has a group membership for that OpenSSH server.
 * To identify the group of the OpenSSH server an identifier in the
 * config file of pam-openssh-x509 is set that has to correspond to the
 * first RDN value of the group dn.
 *
 * This function checks if the user has access to the OpenSSH server or
 * not and writes the result to the DTO.
 *
 * @param[in] group_dn DN of an OpenSSH server group. Must not be
 * @c NULL. Length must be > 0.
 * @param[in] identifier Identifier for the OpenSSH server.
 * @param[out] x509_info DTO
 */
void check_access_permission(const char *group_dn, const char *identifier,
    struct pox509_info *x509_info);

/**
 * Validate a x509 certificate.
 *
 * @param[in] x509 X509 certificate. Must not be @c NULL.
 * @param[in] cacerts_dir Path to directory with trusted root CA's
 * symlinked by their hash value. Must not be @c NULL.
 * @param[out] x509_info DTO. Must not be @c NULL.
 */
void validate_x509(X509 *x509, char *cacerts_dir,
    struct pox509_info *x509_info);

/**
 * Convert a public key to an OpenSSH authorized_keys file entry.
 *
 * @param[in] pkey Public Key. Must not be @c NULL.
 * @param[out] x509_info DTO. Must not be @c NULL.
 */
void pkey_to_authorized_keys(EVP_PKEY *pkey, struct pox509_info *x509_info);
#endif
