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

#include "keeto-check-log.h"

#include <check.h>

#include "../src/keeto-error.h"
#include "../src/keeto-log.h"

/*
 *set_syslog_facility
 */
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
     * main test cases
     */

     /* set_syslog_facility() */
    tcase_add_test(tc_main, t_set_syslog_facility);

    return s;
}

