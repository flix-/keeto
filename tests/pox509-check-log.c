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

#include "pox509-check-log.h"

#include <check.h>

#include "../src/pox509-error.h"
#include "../src/pox509-log.h"

START_TEST
(t_set_syslog_facility)
{
    int rc = set_syslog_facility("LOG_KERN");
    ck_assert_int_eq(POX509_OK, rc);
    rc = set_syslog_facility("LOG_FOO");
    ck_assert_int_eq(POX509_NO_SUCH_VALUE, rc);
}
END_TEST

Suite *
make_log_suite(void)
{
    Suite *s = suite_create("log");
    TCase *tc_main = tcase_create("main");

    /* add test cases to suite */
    suite_add_tcase(s, tc_main);

    /*
     * set_syslog_facility()
     */
    tcase_add_test(tc_main, t_set_syslog_facility);

    return s;
}

