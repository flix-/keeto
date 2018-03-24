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

#ifndef KEETO_CHECK_X509_H
#define KEETO_CHECK_X509_H

#include <stdbool.h>
#include <check.h>

#include "../src/keeto-x509.h"

struct keeto_validate_x509_entry {
    char *file;
    bool exp_result;
};

struct keeto_get_ssh_key_fp_entry {
    char *digest;
    enum keeto_digests algo;
};

Suite *make_x509_suite(void);

#endif /* KEETO_CHECK_X509_H */

