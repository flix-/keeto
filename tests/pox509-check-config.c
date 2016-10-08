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

#include "pox509-check-config.h"

#include <check.h>
#include <confuse.h>

#include "../src/pox509-config.h"
#include "../src/pox509-util.h"

static char *config_neg_lt[] = {
    CONFIGSDIR "/syslog_facility_neg.conf",
    CONFIGSDIR "/ldap_uri_neg.conf",
    CONFIGSDIR "/ldap_starttls_neg.conf",
    CONFIGSDIR "/ldap_bind_dn_neg.conf",
    CONFIGSDIR "/ldap_search_timeout_neg.conf",
    CONFIGSDIR "/ldap_strict_neg.conf",
    CONFIGSDIR "/ldap_ssh_server_base_dn_neg.conf",
    CONFIGSDIR "/ldap_ssh_server_search_scope_neg.conf",
    CONFIGSDIR "/cert_store_dir_neg.conf",
    CONFIGSDIR "/check_crl_neg.conf",
    CONFIGSDIR "/uid_regex_neg.conf",
};

/*
 * parse_config()
 */
START_TEST
(t_parse_config_file_not_found)
{
    char *config_file = CONFIGSDIR "/not-existent";
    cfg_t *cfg = parse_config(config_file);
    ck_assert_ptr_eq(NULL, cfg);
}
END_TEST

START_TEST
(t_parse_config_pos)
{
    char *config_file = CONFIGSDIR "/valid.conf";
    if (!file_readable(config_file)) {
        ck_abort_msg("config (%s) not readable", config_file);
    }
    cfg_t *cfg = parse_config(config_file);
    ck_assert_ptr_ne(NULL, cfg);
}
END_TEST

START_TEST
(t_parse_config_neg)
{
    char *config_file = config_neg_lt[_i];
    if (!file_readable(config_file)) {
        ck_abort_msg("config (%s) not readable", config_file);
    }
    cfg_t *cfg = parse_config(config_file);
    ck_assert_ptr_eq(NULL, cfg);
}
END_TEST

Suite *
make_config_suite(void)
{
    Suite *s = suite_create("config");
    TCase *tc_main = tcase_create("main");

    /* add test cases to suite */
    suite_add_tcase(s, tc_main);

    /*
     * main test cases
     */

    /* parse_config() */
    tcase_add_test(tc_main, t_parse_config_file_not_found);
    tcase_add_test(tc_main, t_parse_config_pos);
    int config_neg_lt_items = sizeof config_neg_lt / sizeof config_neg_lt[0];
    tcase_add_loop_test(tc_main, t_parse_config_neg, 0, config_neg_lt_items);

    return s;
}

