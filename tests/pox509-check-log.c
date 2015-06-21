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

#include "pox509-check-log.h"

#include <errno.h>
#include <stdlib.h>

#include <check.h>

#include "../src/pox509-log.h"

/*
 * log_msg()
 */
START_TEST
(t_log_msg_exit_fmt_NULL)
{
    log_msg(NULL);
}
END_TEST

/*
 * log_success()
 */
START_TEST
(t_log_success_exit_fmt_NULL)
{
    log_success(NULL);
}
END_TEST

/*
 * pox509_log_fail()
 */
START_TEST
(t_pox509_log_fail_exit_filename_NULL)
{
    const char *function = "hello_world";
    int line = 1948;
    pox509_log_fail(NULL, function, line, "fail");
}
END_TEST

START_TEST
(t_pox509_log_fail_exit_function_NULL)
{
    const char *filename = "hello_world.c";
    int line = 1948;
    pox509_log_fail(filename, NULL, line, "fail");
}
END_TEST

START_TEST
(t_pox509_log_fail_exit_fmt_NULL)
{
    const char *function = "hello_world";
    const char *filename = "hello_world.c";
    int line = 1948;
    pox509_log_fail(filename, function, line, NULL);
}
END_TEST

START_TEST
(t_pox509_log_fail_exit_filename_function_fmt_NULL)
{
    int line = 1948;
    pox509_log_fail(NULL, NULL, line, NULL);
}
END_TEST

/*
 * pox509_log_fatal()
 */
START_TEST
(t_pox509_fatal_exit_filename_NULL)
{
    const char *function = "hello_world";
    int line = 1948;
    pox509_fatal(NULL, function, line, "fatal");
}
END_TEST

START_TEST
(t_pox509_fatal_exit_function_NULL)
{
    const char *filename = "hello_world.c";
    int line = 1948;
    pox509_fatal(filename, NULL, line, "fatal");
}
END_TEST

START_TEST
(t_pox509_fatal_exit_fmt_NULL)
{
    const char *function = "hello_world";
    const char *filename = "hello_world.c";
    int line = 1948;
    pox509_fatal(filename, function, line, NULL);
}
END_TEST

START_TEST
(t_pox509_fatal_exit_filename_function_fmt_NULL)
{
    int line = 1948;
    pox509_fatal(NULL, NULL, line, NULL);
}
END_TEST

/*
 * set_syslog_facility()
 */
START_TEST
(t_set_syslog_facility_exit_log_facility_null)
{
    set_syslog_facility(NULL);
}
END_TEST

START_TEST
(t_set_syslog_facility)
{
    int rc = set_syslog_facility("LOG_KERN");
    ck_assert_int_eq(rc, 0);
    rc = set_syslog_facility("LOG_KERNEL");
    ck_assert_int_eq(rc, -EINVAL);
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

    /* log_msg() */
    tcase_add_exit_test(tc_main, t_log_msg_exit_fmt_NULL, EXIT_FAILURE);

    /* log_success() */
    tcase_add_exit_test(tc_main, t_log_success_exit_fmt_NULL, EXIT_FAILURE);

    /* pox509_log_fail() */
    tcase_add_exit_test(tc_main, t_pox509_log_fail_exit_filename_NULL,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_main, t_pox509_log_fail_exit_function_NULL,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_main, t_pox509_log_fail_exit_fmt_NULL,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_main,
        t_pox509_log_fail_exit_filename_function_fmt_NULL, EXIT_FAILURE);

    /* pox509_fatal() */
    tcase_add_exit_test(tc_main, t_pox509_fatal_exit_filename_NULL,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_main, t_pox509_fatal_exit_function_NULL,
        EXIT_FAILURE);
    tcase_add_exit_test(tc_main, t_pox509_fatal_exit_fmt_NULL, EXIT_FAILURE);
    tcase_add_exit_test(tc_main,
        t_pox509_fatal_exit_filename_function_fmt_NULL, EXIT_FAILURE);

    /* set_syslog_facility() */
    tcase_add_exit_test(tc_main, t_set_syslog_facility_exit_log_facility_null,
        EXIT_FAILURE);
    tcase_add_test(tc_main, t_set_syslog_facility);

    return s;
}

