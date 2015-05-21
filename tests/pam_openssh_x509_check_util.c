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

#include "pam_openssh_x509_check.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>
#include <ldap.h>
#include <syslog.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "../src/pam_openssh_x509_util.h"

#define BUFFER_SIZE 2048

static struct pox509_substitute_token_entry substitute_token_lt[] = {
    { 'u', "foo", "/home/%u/", 1024, "/home/foo/" },
    { 'u', "foo", "/home/%u/", 3, "/h" },
    { 'u', "foo", "/home/%u%u%u/", 512, "/home/foofoofoo/" },
    { 'u', "foo", "/home/%u%u%/", 512, "/home/foofoo%/" },
    { 'u', "foo", "%u%u", 512, "foofoo" },
    { 'u', "foo", "/home/%a/%u", 512, "/home/%a/foo" },
    { '%', "%", "/home/%%%", 512, "/home/%%" },
    { 'u', "../../root", "/home/%u", 512, "/home/../../root" },
    { 'u', "$blub", "/home/%u", 512, "/home/$blub" },
    { 'u', "\\", "/home/%u", 512, "/home/\\" },
    { '$', "\\", "/home/%u", 512, "/home/%u" },
    { 'u', "bar", "%/u%uhome/%u", 512, "%/ubarhome/bar" },
    { 'u', "foo", "/home/%u/", 8, "/home/%" },
    { 'u', "foo", "/home/%u/", 9, "/home/fo" },
    { 'u', "foo", "/home/%u/", 10, "/home/foo" },
    { 'u', "foo", "/home/%u/", 0, "1.FC KOELN" },
    { 'u', "foo", "/home/%u/", 1, "" },
    { 'u', "foo", "/home/%u/", 2, "/" },
};

static struct pox509_create_ldap_search_filter_entry
    create_ldap_search_filter_lt[] = {
    { "uid", "foo", 8, "uid=foo" },
    { "uid", "foo", 7, "uid=fo" },
    { "uid", "foo", 100, "uid=foo" },
    { "uid", "foo", 0, "1.FC KOELN" },
    { "uid", "foo", 1, "" },
    { "uid", "foo", 2, "u" },
    { "uid", "foo", 5, "uid=" },
    { "uid", "foo", 6, "uid=f" },
};

static struct pox509_check_access_permission_entry
    check_access_permission_lt[] = {
    { "cn=blub,dc=abc,dc=afg", "blub", 1 },
    { "cn==blub,dc=abc,dc=afg", "=blub", 1 },
    { "cn=cn=blub,dc=abc,dc=afg", "cn=blub", 1 },
    { "cn=blub", "blub", 1 },
    { "blub", "blub", 0 },
    { "", "blub", 0 },
    { "", "", 0 },
    { " ", "", 0 },
    { " ", " ", 0 },
    { "=a,", "a", 0 },
};

static struct pox509_validate_x509_entry validate_x509_lt[] = {
    { X509CERTSDIR "/not_trusted_ca.pem", 0 },
    { X509CERTSDIR "/trusted_ca_but_expired.pem", 0 },
    { X509CERTSDIR "/trusted_and_not_expired.pem", 1 },
};

static struct pox509_is_valid_uid_entry is_valid_uid_lt[] = {
    { "pox509-test-user", true },
    { "Pox509-test-user", false },
    { "pox509-Test-user", false },
    { "pox509_test-user", false },
    { "1pox509", false },
    { "abcdefghijklmnopqrstuvwxyzaabbcc", true },
    { "abcdefghijklmnopqrstuvwxyzaabbccd", false },
    { "../keystore/foo", false },
    { "..", false },
    { "_foo", false },
};

START_TEST
(t_substitute_token_exit_subst_null)
{
    int dst_length = 1024;
    char dst[dst_length];
    substitute_token('u', NULL, "/home/%u/", dst, dst_length);
}
END_TEST

START_TEST
(t_substitute_token_exit_src_null)
{
    int dst_length = 1024;
    char dst[dst_length];
    substitute_token('u', "foo", NULL, dst, dst_length);
}
END_TEST

START_TEST
(t_substitute_token_exit_dst_null)
{
    substitute_token('u', "foo", "/home/%u/", NULL, 1024);
}
END_TEST

START_TEST
(t_substitute_token_exit_subst_src_dst_null)
{
    substitute_token('u', NULL, NULL, NULL, 1024);
}
END_TEST

START_TEST
(t_substitute_token)
{
    char token = substitute_token_lt[_i].token;
    char *subst = substitute_token_lt[_i].subst;
    char *src = substitute_token_lt[_i].src;
    size_t dst_length = substitute_token_lt[_i].dst_length;
    char *exp_result = substitute_token_lt[_i].exp_result;

    size_t dst_buffer_length = 1024;
    char dst[dst_buffer_length];
    strncpy(dst, "1.FC KOELN", dst_buffer_length);
    substitute_token(token, subst, src, dst, dst_length);
    ck_assert_str_eq(dst, exp_result);
}
END_TEST

START_TEST
(t_create_ldap_search_filter)
{
    char *rdn = create_ldap_search_filter_lt[_i].rdn;
    char *uid = create_ldap_search_filter_lt[_i].uid;
    size_t dst_length = create_ldap_search_filter_lt[_i].dst_length;
    char *exp_result = create_ldap_search_filter_lt[_i].exp_result;

    size_t dst_buffer_length = 1024;
    char dst[dst_buffer_length];
    strncpy(dst, "1.FC KOELN", dst_buffer_length);
    create_ldap_search_filter(rdn, uid, dst, dst_length);
    ck_assert_str_eq(dst, exp_result);
}
END_TEST

START_TEST
(t_pkey_to_authorized_keys_exit_pkey_null)
{
    struct pox509_info x509_info;
    pkey_to_authorized_keys(NULL, &x509_info);
}
END_TEST

START_TEST
(t_pkey_to_authorized_keys_exit_x509_info_null)
{
    EVP_PKEY pkey;
    pkey_to_authorized_keys(&pkey, NULL);
}
END_TEST

START_TEST
(t_pkey_to_authorized_keys_exit_pkey_x509_info_null)
{
    pkey_to_authorized_keys(NULL, NULL);
}
END_TEST

START_TEST
(t_pkey_to_authorized_keys)
{
    char *directory = KEYSDIR;
    char *oneliner = KEYSDIR "/ssh_rsa.txt";

    FILE *fh_oneliner = fopen(oneliner, "r");
    if (fh_oneliner == NULL) {
        ck_abort_msg("fopen() failed ('%s')", oneliner);
    }

    char line_buffer[BUFFER_SIZE];
    while (fgets(line_buffer, sizeof line_buffer, fh_oneliner) != NULL) {
        char *pem_file_rel = strtok(line_buffer, ":");
        char *ssh_rsa = strtok(NULL, "\n");
        if (pem_file_rel == NULL || ssh_rsa == NULL) {
            ck_abort_msg("parsing failure");
        }

        char pem_file_abs[BUFFER_SIZE];
        strncpy(pem_file_abs, directory, sizeof pem_file_abs);
        strncat(pem_file_abs, "/", sizeof pem_file_abs -
            strlen(pem_file_abs) - 1);
        strncat(pem_file_abs, pem_file_rel, sizeof pem_file_abs -
            strlen(pem_file_abs) - 1);
        FILE *f_pem_file = fopen(pem_file_abs, "r");
        if (f_pem_file == NULL) {
            ck_abort_msg("fopen() failed ('%s')", pem_file_abs);
        }

        EVP_PKEY *pkey = PEM_read_PUBKEY(f_pem_file, NULL, NULL, NULL);
        if (pkey == NULL) {
            ck_abort_msg("PEM_read_PUBKEY() failed ('%s')", pem_file_abs);
        }

        struct pox509_info x509_info;
        pkey_to_authorized_keys(pkey, &x509_info);
        char exp_ssh_rsa[BUFFER_SIZE];
        strncpy(exp_ssh_rsa, x509_info.ssh_keytype, sizeof exp_ssh_rsa);
        strncat(exp_ssh_rsa, " ", sizeof exp_ssh_rsa - strlen(exp_ssh_rsa) - 1);
        strncat(exp_ssh_rsa, x509_info.ssh_key, sizeof exp_ssh_rsa -
            strlen(exp_ssh_rsa) - 1);
        ck_assert_str_eq(ssh_rsa, exp_ssh_rsa);
        fclose(f_pem_file);
    }
    fclose(fh_oneliner);
}
END_TEST

START_TEST
(t_config_lookup_exit_key_null)
{
    config_lookup(SYSLOG, NULL);
}
END_TEST

START_TEST
(t_config_lookup)
{
    int rc = config_lookup(10, "foo");
    ck_assert_int_eq(rc, -EINVAL);
    rc = config_lookup(10, "LOG_FTP");
    ck_assert_int_eq(rc, -EINVAL);
    rc = config_lookup(SYSLOG, "foo");
    ck_assert_int_eq(rc, -EINVAL);
    rc = config_lookup(SYSLOG, "LOG_FTP");
    ck_assert_int_eq(rc, LOG_FTP);
    rc = config_lookup(LIBLDAP, "foo");
    ck_assert_int_eq(rc, -EINVAL);
    rc = config_lookup(LIBLDAP, "LDAP_SCOPE_BASE");
    ck_assert_int_eq(rc, LDAP_SCOPE_BASE);
}
END_TEST

START_TEST
(t_set_log_facility_exit_log_facility_NULL)
{
    set_log_facility(NULL);
}
END_TEST

START_TEST
(t_set_log_facility)
{
    int rc = set_log_facility("LOG_KERN");
    ck_assert_int_eq(rc, 0);
    rc = set_log_facility("LOG_KERNEL");
    ck_assert_int_eq(rc, -EINVAL);
}
END_TEST

START_TEST
(t_init_data_transfer_object_exit_x509_info_null)
{
    init_data_transfer_object(NULL);
}
END_TEST

START_TEST
(t_check_access_permission_exit_group_dn_null)
{
    struct pox509_info x509_info;
    check_access_permission(NULL, "foo", &x509_info);
}
END_TEST

START_TEST
(t_check_access_permission_exit_identifier_null)
{
    struct pox509_info x509_info;
    check_access_permission("cn=foo,dc=bar", NULL, &x509_info);
}
END_TEST

START_TEST
(t_check_access_permission_exit_x509_info_null)
{
    check_access_permission("cn=foo,dc=bar", "blub", NULL);
}
END_TEST

START_TEST
(t_check_access_permission_exit_group_dn_identifier_x509_info_null)
{
    check_access_permission(NULL, NULL, NULL);
}
END_TEST

START_TEST
(t_check_access_permission)
{
    char *group_dn = check_access_permission_lt[_i].group_dn;
    char *identifier = check_access_permission_lt[_i].identifier;
    char exp_result = check_access_permission_lt[_i].exp_result;

    struct pox509_info x509_info;
    x509_info.has_access = -1;
    check_access_permission(group_dn, identifier, &x509_info);
    ck_assert_int_eq(x509_info.has_access, exp_result);
}
END_TEST

START_TEST
(t_is_valid_uid_exit_uid_null)
{
    is_valid_uid(NULL);
}
END_TEST

START_TEST
(t_is_valid_uid)
{
    char *uid = is_valid_uid_lt[_i].uid;
    char exp_result = is_valid_uid_lt[_i].exp_result;

    int rc = is_valid_uid(uid);
    ck_assert_int_eq(rc, exp_result);
}
END_TEST

START_TEST
(t_validate_x509_exit_x509_null)
{
    char *ca_certs_dir = CACERTSDIR;
    struct pox509_info x509_info;
    validate_x509(NULL, ca_certs_dir, &x509_info);
}
END_TEST

START_TEST
(t_validate_x509_exit_cacerts_dir_null)
{
    X509 x509;
    struct pox509_info x509_info;
    validate_x509(&x509, NULL, &x509_info);
}
END_TEST

START_TEST
(t_validate_x509_exit_x509_info_null)
{
    X509 x509;
    char *ca_certs_dir = CACERTSDIR;
    validate_x509(&x509, ca_certs_dir, NULL);
}
END_TEST

START_TEST
(t_validate_x509_exit_x509_cacerts_dir_x509_info_null)
{
    validate_x509(NULL, NULL, NULL);
}
END_TEST

START_TEST
(t_validate_x509)
{
    char *x509_cert = validate_x509_lt[_i].file;
    char exp_result = validate_x509_lt[_i].exp_result;

    struct pox509_info x509_info;
    x509_info.has_valid_cert = -1;
    char *ca_certs_dir = CACERTSDIR;

    FILE *x509_cert_file = fopen(x509_cert, "r");
    if (x509_cert_file == NULL) {
        ck_abort_msg("fopen() failed ('%s')", x509_cert);
    }

    X509* x509 = PEM_read_X509(x509_cert_file, NULL, NULL, NULL);
    if (x509 == NULL) {
        ck_abort_msg("PEM_read_X509() failed");
    }
    fclose(x509_cert_file);
    validate_x509(x509, ca_certs_dir, &x509_info);
    ck_assert_int_eq(x509_info.has_valid_cert, exp_result);
}
END_TEST

Suite *
make_util_suite(void)
{
    Suite *s = suite_create("util");
    TCase *tc_helper = tcase_create("helper");
    TCase *tc_ssh = tcase_create("ssh");
    TCase *tc_x509 = tcase_create("x509");

    /* add test cases to suite */
    suite_add_tcase(s, tc_helper);
    suite_add_tcase(s, tc_ssh);
    suite_add_tcase(s, tc_x509);

    /* helper test cases */
    tcase_add_exit_test(tc_helper, t_substitute_token_exit_subst_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_helper, t_substitute_token_exit_src_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_helper, t_substitute_token_exit_dst_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_helper, t_substitute_token_exit_subst_src_dst_null,
        EXIT_FAILURE);
    int length_st_lt = sizeof substitute_token_lt /
        sizeof substitute_token_lt[0];
    tcase_add_loop_test(tc_helper, t_substitute_token, 0, length_st_lt);

    int length_clsf_lt = sizeof create_ldap_search_filter_lt /
        sizeof create_ldap_search_filter_lt[0];
    tcase_add_loop_test(tc_helper, t_create_ldap_search_filter, 0,
        length_clsf_lt);

    tcase_add_exit_test(tc_helper, t_config_lookup_exit_key_null, EXIT_FAILURE);
    tcase_add_test(tc_helper, t_config_lookup);

    tcase_add_exit_test(tc_helper, t_set_log_facility_exit_log_facility_NULL,
        EXIT_FAILURE);
    tcase_add_test(tc_helper, t_set_log_facility);

    tcase_add_exit_test(tc_helper,
        t_init_data_transfer_object_exit_x509_info_null, EXIT_FAILURE);

    tcase_add_exit_test(tc_helper, t_check_access_permission_exit_group_dn_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_helper,
        t_check_access_permission_exit_identifier_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_helper,
        t_check_access_permission_exit_x509_info_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_helper,
        t_check_access_permission_exit_group_dn_identifier_x509_info_null,
        EXIT_FAILURE);
    int length_cap_lt = sizeof check_access_permission_lt /
        sizeof check_access_permission_lt[0];
    tcase_add_loop_test(tc_helper, t_check_access_permission, 0, length_cap_lt);

    tcase_add_exit_test(tc_helper, t_is_valid_uid_exit_uid_null, EXIT_FAILURE);
    int length_ivu_lt = sizeof is_valid_uid_lt / sizeof is_valid_uid_lt[0];
    tcase_add_loop_test(tc_helper, t_is_valid_uid, 0, length_ivu_lt);

    /* ssh test cases */
    tcase_add_exit_test(tc_ssh, t_pkey_to_authorized_keys_exit_pkey_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_ssh, t_pkey_to_authorized_keys_exit_x509_info_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_ssh,
        t_pkey_to_authorized_keys_exit_pkey_x509_info_null, EXIT_FAILURE);
    tcase_add_test(tc_ssh, t_pkey_to_authorized_keys);

    /* x509 test cases */
    tcase_add_exit_test(tc_x509, t_validate_x509_exit_x509_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_x509, t_validate_x509_exit_cacerts_dir_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_x509, t_validate_x509_exit_x509_info_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_x509,
        t_validate_x509_exit_x509_cacerts_dir_x509_info_null, EXIT_FAILURE);
    int length_vx509_lt = sizeof validate_x509_lt /sizeof validate_x509_lt[0];
    tcase_add_loop_test(tc_x509, t_validate_x509, 0, length_vx509_lt);

    return s;
}

