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

#include "keeto-check-x509.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <check.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "../src/keeto-x509.c"

#define BUFFER_SIZE 4096

static struct keeto_validate_x509_entry validate_x509_no_crl_check_lt[] = {
    { X509CERTSDIR "/revoked.pem", true },
    { X509CERTSDIR "/trusted-ca-expired.pem", false },
    { X509CERTSDIR "/trusted-ca-wrong-ku-non-critical.pem", false },
    { X509CERTSDIR "/trusted-ca-wrong-ku.pem", false },
    { X509CERTSDIR "/trusted-ca-wrong-xku-non-critical.pem", false },
    { X509CERTSDIR "/trusted-ca-wrong-xku.pem", false },
    { X509CERTSDIR "/untrusted-ca.pem", false },
    { X509CERTSDIR "/valid1.pem", true },
    { X509CERTSDIR "/valid2.pem", true },
    { X509CERTSDIR "/valid3.pem", true },
    { X509CERTSDIR "/valid4.pem", true }
};

static struct keeto_validate_x509_entry validate_x509_crl_check_lt[] = {
    { X509CERTSDIR "/revoked.pem", false },
    { X509CERTSDIR "/trusted-ca-expired.pem", false },
    { X509CERTSDIR "/trusted-ca-wrong-ku-non-critical.pem", false },
    { X509CERTSDIR "/trusted-ca-wrong-ku.pem", false },
    { X509CERTSDIR "/trusted-ca-wrong-xku-non-critical.pem", false },
    { X509CERTSDIR "/trusted-ca-wrong-xku.pem", false },
    { X509CERTSDIR "/untrusted-ca.pem", false },
    { X509CERTSDIR "/valid1.pem", true },
    { X509CERTSDIR "/valid2.pem", true },
    { X509CERTSDIR "/valid3.pem", true },
    { X509CERTSDIR "/valid4.pem", true }
};

/*
 * setup / teardown
 */
void
setup_validate_x509_no_crl_check()
{
    init_openssl();
    int rc = init_cert_store(CERTSTOREDIR, false);
    if (rc != KEETO_OK) {
        ck_abort_msg("failed to initialize cert store (%s)",
            keeto_strerror(rc));
    }
}

void
setup_validate_x509_crl_check()
{
    init_openssl();
    int rc = init_cert_store(CERTSTOREDIR, true);
    if (rc != KEETO_OK) {
        ck_abort_msg("failed to initialize cert store (%s)",
            keeto_strerror(rc));
    }
}

void
teardown()
{
    free_cert_store();
    cert_store = NULL;
    cleanup_openssl();
}

/*
 * get_ssh_key_from_rsa()
 */
START_TEST
(t_get_ssh_key_from_rsa)
{
    char *keystore_records = KEYSTORERECORDSDIR "/ssh-rsa.txt";
    char *ssh_keytype = "ssh-rsa";

    FILE *keystore_records_file = fopen(keystore_records, "r");
    if (keystore_records_file == NULL) {
        ck_abort_msg("failed to open '%s' (%s)", keystore_records,
            strerror(errno));
    }

    char keystore_record_parsed[BUFFER_SIZE];
    while (fgets(keystore_record_parsed, sizeof keystore_record_parsed,
        keystore_records_file) != NULL) {

        char *pem_file_rel = strtok(keystore_record_parsed, ":");
        char *exp_keystore_record = strtok(NULL, "\n");
        if (pem_file_rel == NULL || exp_keystore_record == NULL) {
            fclose(keystore_records_file);
            ck_abort_msg("failed to parse '%s'", keystore_records);
        }

        char pem_file_abs[BUFFER_SIZE];
        snprintf(pem_file_abs, sizeof pem_file_abs, "%s/%s", KEYSTORERECORDSDIR,
            pem_file_rel);
        FILE *pem_file = fopen(pem_file_abs, "r");
        if (pem_file == NULL) {
            fclose(keystore_records_file);
            ck_abort_msg("failed to open '%s' (%s)", pem_file_abs,
                strerror(errno));
        }

        EVP_PKEY *pkey = PEM_read_PUBKEY(pem_file, NULL, NULL, NULL);
        if (pkey == NULL) {
            fclose(pem_file);
            fclose(keystore_records_file);
            ck_abort_msg("failed to read pubkey from '%s'", pem_file_abs);
        }
        fclose(pem_file);
        char *ssh_key = NULL;
        int rc = get_ssh_key_from_rsa(pkey, ssh_keytype, &ssh_key);
        if (rc != KEETO_OK) {
            fclose(keystore_records_file);
            ck_abort_msg("failed to add key data (%s)", keeto_strerror(rc));
        }
        char keystore_record[BUFFER_SIZE];
        snprintf(keystore_record, sizeof keystore_record, "%s %s", ssh_keytype,
            ssh_key);
        ck_assert_str_eq(exp_keystore_record, keystore_record);
        free(ssh_key);
    }
    fclose(keystore_records_file);
}
END_TEST

/*
 * validate_x509()
 */
START_TEST
(t_validate_x509_no_crl_check)
{
    char *x509_path = validate_x509_no_crl_check_lt[_i].file;
    bool exp_result = validate_x509_no_crl_check_lt[_i].exp_result;

    bool valid = false;

    FILE *x509_file = fopen(x509_path, "r");
    if (x509_file == NULL) {
        ck_abort_msg("failed to open '%s' (%s)", x509_path, strerror(errno));
    }

    X509 *x509 = PEM_read_X509(x509_file, NULL, NULL, NULL);
    if (x509 == NULL) {
        fclose(x509_file);
        ck_abort_msg("failed to read x509 from pem file '%s'", x509_path);
    }
    fclose(x509_file);

    int rc = validate_x509(x509, &valid);
    if (rc != KEETO_OK) {
        free_x509(x509);
        ck_abort_msg("failed to validate certificate (%s)", keeto_strerror(rc));
    }
    free_x509(x509);

    ck_assert_int_eq(exp_result, valid);
}
END_TEST

START_TEST
(t_validate_x509_crl_check)
{
    char *x509_path = validate_x509_crl_check_lt[_i].file;
    bool exp_result = validate_x509_crl_check_lt[_i].exp_result;

    bool valid = false;

    FILE *x509_file = fopen(x509_path, "r");
    if (x509_file == NULL) {
        ck_abort_msg("failed to open '%s' (%s)", x509_path, strerror(errno));
    }

    X509 *x509 = PEM_read_X509(x509_file, NULL, NULL, NULL);
    if (x509 == NULL) {
        fclose(x509_file);
        ck_abort_msg("failed to read x509 from pem file '%s'", x509_path);
    }
    fclose(x509_file);

    int rc = validate_x509(x509, &valid);
    if (rc != KEETO_OK) {
        free_x509(x509);
        ck_abort_msg("failed to validate certificate (%s)", keeto_strerror(rc));
    }
    free_x509(x509);

    ck_assert_int_eq(exp_result, valid);
}
END_TEST

Suite *
make_x509_suite(void)
{
    Suite *s = suite_create("x509");
    TCase *tc_ssh_key_from_rsa = tcase_create("ssh_key_from_rsa");
    TCase *tc_validate_x509_no_crl_check =
        tcase_create("validate_x509_no_crl_check");
    TCase *tc_validate_x509_crl_check = tcase_create("validate_x509_crl_check");

    /* add test cases to suite */
    suite_add_tcase(s, tc_ssh_key_from_rsa);
    suite_add_tcase(s, tc_validate_x509_no_crl_check);
    suite_add_tcase(s, tc_validate_x509_crl_check);

    /*
     * ssh key from rsa test cases
     */

    /* get_ssh_key_from_rsa() */
    tcase_add_test(tc_ssh_key_from_rsa, t_get_ssh_key_from_rsa);

    /*
     * validate x509 - no crl check test cases
     */

    /* setup / teardown */
    tcase_add_unchecked_fixture(tc_validate_x509_no_crl_check,
        setup_validate_x509_no_crl_check, teardown);
    /* validate_x509() */
    int validate_x509_no_crl_check_lt_items =
        sizeof validate_x509_no_crl_check_lt /
        sizeof validate_x509_no_crl_check_lt[0];
    tcase_add_loop_test(tc_validate_x509_no_crl_check,
        t_validate_x509_no_crl_check, 0, validate_x509_no_crl_check_lt_items);

    /*
     * validate x509 - crl check test cases
     */

    /* setup / teardown */
    tcase_add_unchecked_fixture(tc_validate_x509_crl_check,
        setup_validate_x509_crl_check, teardown);
    /* validate_x509() */
    int validate_x509_crl_check_lt_items = sizeof validate_x509_crl_check_lt /
        sizeof validate_x509_crl_check_lt[0];
    tcase_add_loop_test(tc_validate_x509_crl_check, t_validate_x509_crl_check,
        0, validate_x509_crl_check_lt_items);

    return s;
}

