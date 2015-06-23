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

#include "pox509-check-x509.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "../src/pox509-x509.c"

#define BUFFER_SIZE 2048

static struct pox509_validate_x509_entry validate_x509_lt[] = {
    { X509CERTSDIR "/not-trusted-ca.pem", 0 },
    { X509CERTSDIR "/trusted-ca-but-expired.pem", 0 },
    { X509CERTSDIR "/trusted-and-not-expired.pem", 1 }
};

/*
 * validate_x509()
 */
START_TEST
(t_validate_x509_exit_x509_null)
{
    char *ca_certs_dir = CACERTSDIR;
    struct pox509_info pox509_info;
    validate_x509(NULL, ca_certs_dir, &pox509_info);
}
END_TEST

START_TEST
(t_validate_x509_exit_cacerts_dir_null)
{
    X509 x509;
    struct pox509_info pox509_info;
    validate_x509(&x509, NULL, &pox509_info);
}
END_TEST

START_TEST
(t_validate_x509_exit_pox509_info_null)
{
    X509 x509;
    char *ca_certs_dir = CACERTSDIR;
    validate_x509(&x509, ca_certs_dir, NULL);
}
END_TEST

START_TEST
(t_validate_x509_exit_x509_cacerts_dir_pox509_info_null)
{
    validate_x509(NULL, NULL, NULL);
}
END_TEST

START_TEST
(t_validate_x509)
{
    char *x509_cert = validate_x509_lt[_i].file;
    char exp_result = validate_x509_lt[_i].exp_result;

    struct pox509_info pox509_info;
    pox509_info.has_valid_cert = -1;
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
    validate_x509(x509, ca_certs_dir, &pox509_info);
    ck_assert_int_eq(pox509_info.has_valid_cert, exp_result);
}
END_TEST

/*
 * pkey_to_authorized_keys()
 */
START_TEST
(t_pkey_to_authorized_keys_exit_pkey_null)
{
    struct pox509_info pox509_info;
    pkey_to_authorized_keys(NULL, &pox509_info);
}
END_TEST

START_TEST
(t_pkey_to_authorized_keys_exit_pox509_info_null)
{
    EVP_PKEY pkey;
    pkey_to_authorized_keys(&pkey, NULL);
}
END_TEST

START_TEST
(t_pkey_to_authorized_keys_exit_pkey_pox509_info_null)
{
    pkey_to_authorized_keys(NULL, NULL);
}
END_TEST

START_TEST
(t_pkey_to_authorized_keys)
{
    char *directory = KEYSDIR;
    char *oneliner = KEYSDIR "/ssh-rsa.txt";

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
        snprintf(pem_file_abs, sizeof pem_file_abs, "%s/%s", directory,
            pem_file_rel);
        FILE *f_pem_file = fopen(pem_file_abs, "r");
        if (f_pem_file == NULL) {
            ck_abort_msg("fopen() failed ('%s')", pem_file_abs);
        }

        EVP_PKEY *pkey = PEM_read_PUBKEY(f_pem_file, NULL, NULL, NULL);
        if (pkey == NULL) {
            ck_abort_msg("PEM_read_PUBKEY() failed ('%s')", pem_file_abs);
        }

        struct pox509_info pox509_info;
        pkey_to_authorized_keys(pkey, &pox509_info);
        char exp_ssh_rsa[BUFFER_SIZE];
        snprintf(exp_ssh_rsa, sizeof exp_ssh_rsa, "%s %s",
            pox509_info.ssh_keytype, pox509_info.ssh_key);
        ck_assert_str_eq(ssh_rsa, exp_ssh_rsa);
        fclose(f_pem_file);
    }
    fclose(fh_oneliner);
}
END_TEST

/*
 * get_serial_from_x509()
 */
START_TEST
(t_get_serial_from_x509_exit_x509_null)
{
    struct pox509_info pox509_info;
    get_serial_from_x509(NULL, &pox509_info);
}
END_TEST

START_TEST
(t_get_serial_from_x509_exit_pox509_info_null)
{
    X509 x509;
    get_serial_from_x509(&x509, NULL);
}
END_TEST

START_TEST
(t_get_serial_from_x509_exit_x509_pox509_info_null)
{
    get_serial_from_x509(NULL, NULL);
}
END_TEST

/*
 * get_issuer_from_x509()
 */
START_TEST
(t_get_issuer_from_x509_exit_x509_null)
{
    struct pox509_info pox509_info;
    get_issuer_from_x509(NULL, &pox509_info);
}
END_TEST

START_TEST
(t_get_issuer_from_x509_exit_pox509_info_null)
{
    X509 x509;
    get_issuer_from_x509(&x509, NULL);
}
END_TEST

START_TEST
(t_get_issuer_from_x509_exit_x509_pox509_info_null)
{
    get_issuer_from_x509(NULL, NULL);
}
END_TEST

/*
 * get_subject_from_x509()
 */
START_TEST
(t_get_subject_from_x509_exit_x509_null)
{
    struct pox509_info pox509_info;
    get_subject_from_x509(NULL, &pox509_info);
}
END_TEST

START_TEST
(t_get_subject_from_x509_exit_pox509_info_null)
{
    X509 x509;
    get_subject_from_x509(&x509, NULL);
}
END_TEST

START_TEST
(t_get_subject_from_x509_exit_x509_pox509_info_null)
{
    get_subject_from_x509(NULL, NULL);
}
END_TEST

Suite *
make_x509_suite(void)
{
    Suite *s = suite_create("x509");
    TCase *tc_main = tcase_create("main");

    /* add test cases to suite */
    suite_add_tcase(s, tc_main);

    /*
     * main test cases
     */

    /* validate_x509() */
    tcase_add_exit_test(tc_main, t_validate_x509_exit_x509_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_main, t_validate_x509_exit_cacerts_dir_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_main, t_validate_x509_exit_pox509_info_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_main,
        t_validate_x509_exit_x509_cacerts_dir_pox509_info_null, EXIT_FAILURE);
    int length_vx509_lt = sizeof validate_x509_lt /sizeof validate_x509_lt[0];
    tcase_add_loop_test(tc_main, t_validate_x509, 0, length_vx509_lt);

    /* pkey_to_authorized_keys() */
    tcase_add_exit_test(tc_main, t_pkey_to_authorized_keys_exit_pkey_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_main,
        t_pkey_to_authorized_keys_exit_pox509_info_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_main,
        t_pkey_to_authorized_keys_exit_pkey_pox509_info_null, EXIT_FAILURE);
    tcase_add_test(tc_main, t_pkey_to_authorized_keys);

    /* get_serial_from_x509() */
    tcase_add_exit_test(tc_main, t_get_serial_from_x509_exit_x509_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_main, t_get_serial_from_x509_exit_pox509_info_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_main,
        t_get_serial_from_x509_exit_x509_pox509_info_null, EXIT_FAILURE);

    /* get_issuer_from_x509() */
    tcase_add_exit_test(tc_main, t_get_issuer_from_x509_exit_x509_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_main, t_get_issuer_from_x509_exit_pox509_info_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_main,
        t_get_issuer_from_x509_exit_x509_pox509_info_null, EXIT_FAILURE);

    /* get_subject_from_x509() */
    tcase_add_exit_test(tc_main, t_get_subject_from_x509_exit_x509_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_main, t_get_subject_from_x509_exit_pox509_info_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_main,
        t_get_subject_from_x509_exit_x509_pox509_info_null, EXIT_FAILURE);

    return s;
}

