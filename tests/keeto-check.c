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

#include <stdlib.h>

#include <check.h>

#include "keeto-check-config.h"
#include "keeto-check-log.h"
#include "keeto-check-util.h"
#include "keeto-check-x509.h"

int
main(int argc, char **argv)
{
    SRunner *sr = srunner_create(NULL);
    srunner_add_suite(sr, make_config_suite());
    srunner_add_suite(sr, make_log_suite());
    srunner_add_suite(sr, make_util_suite());
    srunner_add_suite(sr, make_x509_suite());

    srunner_run_all(sr, CK_VERBOSE);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return(number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

