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

#include "pox509-check-config.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>

#include <check.h>
#include <confuse.h>

#include "../src/pox509-config.c"

static char *init_and_parse_config_exit_lt[] = {
    CONFIGSDIR "/ldap-scope-negative-0.conf",
    CONFIGSDIR "/ldap-scope-negative-1.conf",
    CONFIGSDIR "/ldap-scope-negative-2.conf",
    CONFIGSDIR "/syslog-facility-negative.conf",
    CONFIGSDIR "/ldap-uri-negative.conf",
    CONFIGSDIR "/starttls-negative-0.conf",
    CONFIGSDIR "/starttls-negative-1.conf",
    CONFIGSDIR "/ldap-search-timeout-negative.conf",
    CONFIGSDIR "/ldap-bind-dn-negative-0.conf",
    CONFIGSDIR "/ldap-bind-dn-negative-1.conf",
    CONFIGSDIR "/ldap-bind-dn-negative-2.conf",
    CONFIGSDIR "/cacerts-dir-negative-0.conf",
    CONFIGSDIR "/cacerts-dir-negative-1.conf",
    CONFIGSDIR "/cacerts-dir-negative-2.conf"
};

static char *init_and_parse_config_lt[] = {
    CONFIGSDIR "/valid.conf"
};

/*
 * main test cases
 */

/*
 * init_and_parse_config()
 */
START_TEST
(t_init_and_parse_config_exit_cfg_null)
{
    char *cfg_file = CONFIGSDIR "/valid.conf";
    init_and_parse_config(NULL, cfg_file);
}
END_TEST

START_TEST
(t_init_and_parse_config_exit_cfg_file_null)
{
    cfg_t *cfg = NULL;
    init_and_parse_config(&cfg, NULL);
}
END_TEST

START_TEST
(t_init_and_parse_config_exit_cfg_cfg_file_null)
{
    init_and_parse_config(NULL, NULL);
}
END_TEST

START_TEST
(t_init_and_parse_config_exit)
{
    char *config_file = init_and_parse_config_exit_lt[_i];

    if(!is_readable_file(config_file)) {
        ck_abort_msg("config (%s) not readable", config_file);
    }

    cfg_t *cfg = NULL;
    init_and_parse_config(&cfg, config_file);
}
END_TEST

START_TEST
(t_init_and_parse_config)
{
    char *config_file = init_and_parse_config_lt[_i];

    if(!is_readable_file(config_file)) {
        ck_abort_msg("config (%s) not readable", config_file);
    }

    cfg_t *cfg = NULL;
    init_and_parse_config(&cfg, config_file);
}
END_TEST

/*
 * release_config()
 */
START_TEST
(t_release_config_exit_cfg_null)
{
    release_config(NULL);
}
END_TEST

/*
 * callback test cases
 */

/*
 * cfg_error_handler()
 */
START_TEST
(t_cfg_error_handler_exit_cfg_null)
{
    va_list ap;
    cfg_error_handler(NULL, "foo", ap);
}
END_TEST

START_TEST
(t_cfg_error_handler_exit_fmt_null)
{
    va_list ap;
    cfg_t cfg;
    cfg_error_handler(&cfg, NULL, ap);
}
END_TEST

START_TEST
(t_cfg_error_handler_exit_cfg_fmt_null)
{
    va_list ap;
    cfg_error_handler(NULL, NULL, ap);
}
END_TEST

/*
 * cfg_str_to_int_parser_libldap()
 */
START_TEST
(t_cfg_str_to_int_parser_libldap_exit_cfg_null)
{
    cfg_opt_t opt;
    const char *value = "LDAP_SCOPE_ONE";
    long int result;
    cfg_str_to_int_parser_libldap(NULL, &opt, value, &result);
}
END_TEST

START_TEST
(t_cfg_str_to_int_parser_libldap_exit_opt_null)
{
    cfg_t cfg;
    const char *value = "LDAP_SCOPE_ONE";
    long int result;
    cfg_str_to_int_parser_libldap(&cfg, NULL, value, &result);
}
END_TEST

START_TEST
(t_cfg_str_to_int_parser_libldap_exit_value_null)
{
    cfg_t cfg;
    cfg_opt_t opt;
    long int result;
    cfg_str_to_int_parser_libldap(&cfg, &opt, NULL, &result);
}
END_TEST

START_TEST
(t_cfg_str_to_int_parser_libldap_exit_result_null)
{
    cfg_t cfg;
    cfg_opt_t opt;
    const char *value = "LDAP_SCOPE_ONE";
    cfg_str_to_int_parser_libldap(&cfg, &opt, value, NULL);
}
END_TEST

START_TEST
(t_cfg_str_to_int_parser_libldap_exit_cfg_opt_value_result_null)
{
    cfg_str_to_int_parser_libldap(NULL, NULL, NULL, NULL);
}
END_TEST

/*
 * cfg_validate_syslog_facility()
 */
START_TEST
(t_cfg_validate_syslog_facility_exit_cfg_null)
{
    cfg_opt_t opt;
    cfg_validate_syslog_facility(NULL, &opt);
}
END_TEST

START_TEST
(t_cfg_validate_syslog_facility_exit_opt_null)
{
    cfg_t cfg;
    cfg_validate_syslog_facility(&cfg, NULL);
}
END_TEST

START_TEST
(t_cfg_validate_syslog_facility_exit_cfg_opt_null)
{
    cfg_validate_syslog_facility(NULL, NULL);
}
END_TEST

/*
 * cfg_validate_ldap_uri()
 */
START_TEST
(t_cfg_validate_ldap_uri_exit_cfg_null)
{
    cfg_opt_t opt;
    cfg_validate_ldap_uri(NULL, &opt);
}
END_TEST

START_TEST
(t_cfg_validate_ldap_uri_exit_opt_null)
{
    cfg_t cfg;
    cfg_validate_ldap_uri(&cfg, NULL);
}
END_TEST

START_TEST
(t_cfg_validate_ldap_uri_exit_cfg_opt_null)
{
    cfg_validate_ldap_uri(NULL, NULL);
}
END_TEST

/*
 * cfg_validate_ldap_starttls()
 */
START_TEST
(t_cfg_validate_ldap_starttls_exit_cfg_null)
{
    cfg_opt_t opt;
    cfg_validate_ldap_starttls(NULL, &opt);
}
END_TEST

START_TEST
(t_cfg_validate_ldap_starttls_exit_opt_null)
{
    cfg_t cfg;
    cfg_validate_ldap_starttls(&cfg, NULL);
}
END_TEST

START_TEST
(t_cfg_validate_ldap_starttls_exit_cfg_opt_null)
{
    cfg_validate_ldap_starttls(NULL, NULL);
}
END_TEST

/*
 * cfg_validate_ldap_dn()
 */
START_TEST
(t_cfg_validate_ldap_dn_exit_cfg_null)
{
    cfg_opt_t opt;
    cfg_validate_ldap_dn(NULL, &opt);
}
END_TEST

START_TEST
(t_cfg_validate_ldap_dn_exit_opt_null)
{
    cfg_t cfg;
    cfg_validate_ldap_dn(&cfg, NULL);
}
END_TEST

START_TEST
(t_cfg_validate_ldap_dn_exit_cfg_opt_null)
{
    cfg_validate_ldap_dn(NULL, NULL);
}
END_TEST

/*
 * cfg_validate_ldap_search_timeout()
 */
START_TEST
(t_cfg_validate_ldap_search_timeout_exit_cfg_null)
{
    cfg_opt_t opt;
    cfg_validate_ldap_search_timeout(NULL, &opt);
}
END_TEST

START_TEST
(t_cfg_validate_ldap_search_timeout_exit_opt_null)
{
    cfg_t cfg;
    cfg_validate_ldap_search_timeout(&cfg, NULL);
}
END_TEST

START_TEST
(t_cfg_validate_ldap_search_timeout_exit_cfg_opt_null)
{
    cfg_validate_ldap_search_timeout(NULL, NULL);
}
END_TEST

/*
 * cfg_validate_cacerts_dir()
 */
START_TEST
(t_cfg_validate_cacerts_dir_exit_cfg_null)
{
    cfg_opt_t opt;
    cfg_validate_cacerts_dir(NULL, &opt);
}
END_TEST

START_TEST
(t_cfg_validate_cacerts_dir_exit_opt_null)
{
    cfg_t cfg;
    cfg_validate_cacerts_dir(&cfg, NULL);
}
END_TEST

START_TEST
(t_cfg_validate_cacerts_dir_exit_cfg_opt_null)
{
    cfg_validate_cacerts_dir(NULL, NULL);
}
END_TEST

Suite *
make_config_suite(void)
{
    Suite *s = suite_create("config");
    TCase *tc_main = tcase_create("main");
    TCase *tc_callbacks = tcase_create("callbacks");

    /* add test cases to suite */
    suite_add_tcase(s, tc_main);
    suite_add_tcase(s, tc_callbacks);

    /*
     * main test cases
     */

    /* init_and_parse_config() */
    tcase_add_exit_test(tc_callbacks, t_init_and_parse_config_exit_cfg_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks,
        t_init_and_parse_config_exit_cfg_file_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks,
        t_init_and_parse_config_exit_cfg_cfg_file_null, EXIT_FAILURE);
    int length_iapce_lt = sizeof init_and_parse_config_exit_lt /
        sizeof init_and_parse_config_exit_lt[0];
    tcase_add_loop_exit_test(tc_main, t_init_and_parse_config_exit,
        EXIT_FAILURE, 0, length_iapce_lt);
    int length_iapc_lt = sizeof init_and_parse_config_lt /
        sizeof init_and_parse_config_lt[0];
    tcase_add_loop_test(tc_main, t_init_and_parse_config, 0, length_iapc_lt);

    /* release_config() */
    tcase_add_exit_test(tc_main, t_release_config_exit_cfg_null, EXIT_FAILURE);

    /*
     * callbacks test cases
     */

    /* cfg_error_handler() */
    tcase_add_exit_test(tc_callbacks, t_cfg_error_handler_exit_cfg_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, t_cfg_error_handler_exit_fmt_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, t_cfg_error_handler_exit_cfg_fmt_null,
        EXIT_FAILURE);

    /* cfg_str_to_int_parser_libldap() */
    tcase_add_exit_test(tc_callbacks,
        t_cfg_str_to_int_parser_libldap_exit_cfg_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks,
        t_cfg_str_to_int_parser_libldap_exit_opt_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks,
        t_cfg_str_to_int_parser_libldap_exit_value_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks,
        t_cfg_str_to_int_parser_libldap_exit_result_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks,
        t_cfg_str_to_int_parser_libldap_exit_cfg_opt_value_result_null,
        EXIT_FAILURE);

    /* cfg_validate_syslog_facility() */
    tcase_add_exit_test(tc_callbacks,
        t_cfg_validate_syslog_facility_exit_cfg_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks,
        t_cfg_validate_syslog_facility_exit_opt_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks,
        t_cfg_validate_syslog_facility_exit_cfg_opt_null, EXIT_FAILURE);

    /* cfg_validate_ldap_uri() */
    tcase_add_exit_test(tc_callbacks, t_cfg_validate_ldap_uri_exit_cfg_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, t_cfg_validate_ldap_uri_exit_opt_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, t_cfg_validate_ldap_uri_exit_cfg_opt_null,
        EXIT_FAILURE);

    /* cfg_validate_ldap_starttls() */
    tcase_add_exit_test(tc_callbacks,
        t_cfg_validate_ldap_starttls_exit_cfg_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks,
        t_cfg_validate_ldap_starttls_exit_opt_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks,
        t_cfg_validate_ldap_starttls_exit_cfg_opt_null, EXIT_FAILURE);

    /* cfg_validate_ldap_dn() */
    tcase_add_exit_test(tc_callbacks, t_cfg_validate_ldap_dn_exit_cfg_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, t_cfg_validate_ldap_dn_exit_opt_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, t_cfg_validate_ldap_dn_exit_cfg_opt_null,
        EXIT_FAILURE);

    /* cfg_validate_ldap_search_timeout() */
    tcase_add_exit_test(tc_callbacks,
        t_cfg_validate_ldap_search_timeout_exit_cfg_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks,
        t_cfg_validate_ldap_search_timeout_exit_opt_null, EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks,
        t_cfg_validate_ldap_search_timeout_exit_cfg_opt_null, EXIT_FAILURE);

    /* cfg_validate_cacerts_dir() */
    tcase_add_exit_test(tc_callbacks, t_cfg_validate_cacerts_dir_exit_cfg_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks, t_cfg_validate_cacerts_dir_exit_opt_null,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_callbacks,
        t_cfg_validate_cacerts_dir_exit_cfg_opt_null, EXIT_FAILURE);

    return s;
}

