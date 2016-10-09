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

#include "pox509-check-util.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>
#include <ldap.h>
#include <syslog.h>
#include <bits/types.h>
#include <sys/stat.h>

#include "../src/pox509-error.h"
#include "../src/pox509-util.h"

static struct pox509_file_readable_entry file_readable_lt[] = {
    { FILEREADABLEDIR "/file-none", 0, false },
    { FILEREADABLEDIR "/file-read", S_IRUSR, true },
    { FILEREADABLEDIR "/file-read-write", S_IRUSR|S_IWUSR, true },
    { FILEREADABLEDIR "/file-read-execute", S_IRUSR|S_IXUSR, true },
    { FILEREADABLEDIR "/file-read-write-execute", S_IRUSR|S_IWUSR|S_IXUSR, true },
    { FILEREADABLEDIR "/file-write", S_IWUSR, false },
    { FILEREADABLEDIR "/file-write-execute", S_IWUSR|S_IXUSR, false },
    { FILEREADABLEDIR "/file-execute", S_IXUSR, false },
    { FILEREADABLEDIR "/dir-none", 0, false },
    { FILEREADABLEDIR "/dir-read", S_IRUSR, false },
    { FILEREADABLEDIR "/dir-read-write", S_IRUSR|S_IWUSR, false },
    { FILEREADABLEDIR "/dir-read-execute", S_IRUSR|S_IXUSR, false },
    { FILEREADABLEDIR "/dir-read-write-execute", S_IRUSR|S_IWUSR|S_IXUSR, false },
    { FILEREADABLEDIR "/dir-write", S_IWUSR, false },
    { FILEREADABLEDIR "/dir-write-execute", S_IWUSR|S_IXUSR, false },
    { FILEREADABLEDIR "/dir-execute", S_IXUSR, false }
};

static struct pox509_check_uid_entry check_uid_lt[] = {
    { "pox509-test-user", true },
    { "Pox509-test-user", false },
    { "pox509-Test-user", false },
    { "pox509_test-user", false },
    { "1pox509", false },
    { "abcdefghijklmnopqrstuvwxyzaabbcc", true },
    { "abcdefghijklmnopqrstuvwxyzaabbccd", false },
    { "../authorized_keys/root", false },
    { "..", false },
    { "", false },
    { "_foo", false }
};

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
    { 'u', "foo", "/home/%u/", 1, "" },
    { 'u', "foo", "/home/%u/", 2, "/" }
};

static struct pox509_create_ldap_search_filter_entry
    create_ldap_search_filter_lt[] = {
    { "uid", "foo", 8, "uid=foo" },
    { "uid", "foo", 7, "uid=fo" },
    { "uid", "foo", 100, "uid=foo" },
    { "uid", "foo", 1, "" },
    { "uid", "foo", 2, "u" },
    { "uid", "foo", 5, "uid=" },
    { "uid", "foo", 6, "uid=f" }
};

static struct pox509_get_rdn_from_dn_entry get_rdn_from_dn_lt[] = {
    { "cn=foo,dc=ssh,dc=hq", POX509_OK, "foo" },
    { "xyzcn=bar,dc=ssh,dc=hq", POX509_OK, "bar" },
    { "www.xy.z", POX509_LDAP_ERR, NULL }
};

/*
 * str_to_enum()
 */
START_TEST
(t_str_to_enum)
{
    int rc = str_to_enum(POX509_SYSLOG, "LOG_LOCAL1");
    ck_assert_int_eq(LOG_LOCAL1, rc);
    rc = str_to_enum(POX509_LIBLDAP, "LDAP_SCOPE_BASE");
    ck_assert_int_eq(LDAP_SCOPE_BASE, rc);
    rc = str_to_enum(POX509_SYSLOG, "LOG_FOO");
    ck_assert_int_eq(POX509_NO_SUCH_VALUE, rc);
    rc = str_to_enum(POX509_LIBLDAP, "LDAP_BAR");
    ck_assert_int_eq(POX509_NO_SUCH_VALUE, rc);
}
END_TEST

/*
 * file_readable()
 */
START_TEST
(t_file_readable_file_not_found)
{
    char *file = FILEREADABLEDIR "/not-existent";
    bool result = file_readable(file);
    ck_assert_int_eq(false, result);
}
END_TEST

START_TEST
(t_file_readable)
{
    char *file = file_readable_lt[_i].file;
    mode_t mode = file_readable_lt[_i].mode;
    bool exp_result = file_readable_lt[_i].exp_result;

    int rc = chmod(file, mode);
    if (rc == -1) {
        ck_abort_msg("failed to chmod");
    }

    bool result = file_readable(file);
    ck_assert_int_eq(exp_result, result);

    /* reset values */
    struct stat stat_buffer;
    rc = stat(file, &stat_buffer);
    if (rc != 0) {
        ck_abort_msg("failed to stat");
    }
    if (S_ISREG(stat_buffer.st_mode)) {
        rc = chmod(file, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    } else if (S_ISDIR(stat_buffer.st_mode)) {
        rc = chmod(file, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|
            S_IXOTH);
    } else {
        return;
    }
    if (rc == -1) {
        ck_abort_msg("failed to chmod");
    }
}
END_TEST

/*
 * check_uid()
 */
START_TEST
(t_check_uid)
{
    char *regex = "^[a-z][-a-z0-9]{0,31}$";
    char *uid = check_uid_lt[_i].uid;
    bool exp_result = check_uid_lt[_i].exp_result;

    bool uid_valid = false;
    int rc = check_uid(regex, uid, &uid_valid);
    if (rc != POX509_OK) {
        ck_abort_msg("failed to check uid");
    }
    ck_assert_int_eq(exp_result, uid_valid);
}
END_TEST

/*
 * substitute_token()
 */
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
    substitute_token(token, subst, src, dst, dst_length);
    ck_assert_str_eq(exp_result, dst);
}
END_TEST

/*
 * create_ldap_search_filter()
 */
START_TEST
(t_create_ldap_search_filter)
{
    char *rdn = create_ldap_search_filter_lt[_i].rdn;
    char *uid = create_ldap_search_filter_lt[_i].uid;
    size_t dst_length = create_ldap_search_filter_lt[_i].dst_length;
    char *exp_result = create_ldap_search_filter_lt[_i].exp_result;

    size_t dst_buffer_length = 1024;
    char dst[dst_buffer_length];
    create_ldap_search_filter(rdn, uid, dst, dst_length);
    ck_assert_str_eq( exp_result, dst);
}
END_TEST

/*
 * get_rdn_from_dn()
 */
START_TEST
(t_get_rdn_from_dn)
{
    char *dn = get_rdn_from_dn_lt[_i].dn;
    int exp_res = get_rdn_from_dn_lt[_i].exp_res;
    char *exp_result = get_rdn_from_dn_lt[_i].exp_result;

    char *buffer = NULL;
    int rc = get_rdn_from_dn(dn, &buffer);
    ck_assert_int_eq(exp_res, rc);
    switch (rc) {
    case POX509_OK:
        ck_assert_str_eq(exp_result, buffer);
        break;
    default:
        ck_assert(NULL == buffer);
    }
    free(buffer);
}
END_TEST

Suite *
make_util_suite(void)
{
    Suite *s = suite_create("util");
    TCase *tc_main = tcase_create("main");

    /* add test cases to suite */
    suite_add_tcase(s, tc_main);

    /*
     * main test cases
     */

    /* str_to_enum() */
    tcase_add_test(tc_main, t_str_to_enum);

    /* file_readable() */
    tcase_add_test(tc_main, t_file_readable_file_not_found);
    int file_readable_lt_items = sizeof file_readable_lt /
        sizeof file_readable_lt[0];
    tcase_add_loop_test(tc_main, t_file_readable, 0, file_readable_lt_items);

    /* check_uid() */
    int check_uid_lt_items = sizeof check_uid_lt / sizeof check_uid_lt[0];
    tcase_add_loop_test(tc_main, t_check_uid, 0, check_uid_lt_items);

    /* substitute_token() */
    int substitute_token_lt_items = sizeof substitute_token_lt /
        sizeof substitute_token_lt[0];
    tcase_add_loop_test(tc_main, t_substitute_token, 0, substitute_token_lt_items);

    /* create_ldap_search_filter() */
    int clsf_lt_items = sizeof create_ldap_search_filter_lt /
        sizeof create_ldap_search_filter_lt[0];
    tcase_add_loop_test(tc_main, t_create_ldap_search_filter, 0, clsf_lt_items);

    /* get_rdn_from_dn() */
    int get_rdn_from_dn_lt_items = sizeof get_rdn_from_dn_lt /
        sizeof get_rdn_from_dn_lt[0];
    tcase_add_loop_test(tc_main, t_get_rdn_from_dn, 0, get_rdn_from_dn_lt_items);

    return s;
}

