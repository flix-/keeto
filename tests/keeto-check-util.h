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

#ifndef KEETO_CHECK_UTIL_H
#define KEETO_CHECK_UTIL_H

#include <stdbool.h>

#include <bits/types.h>
#include <sys/stat.h>

#include <check.h>

struct keeto_file_readable_entry {
    char *file;
    mode_t mode;
    bool exp_result;
};

struct keeto_check_uid_entry {
    char *uid;
    bool exp_result;
};

struct keeto_substitute_token_entry {
    char token;
    char *subst;
    char *src;
    size_t dst_length;
    char *exp_result;
};

struct keeto_create_ldap_search_filter_entry {
    char *rdn;
    char *uid;
    size_t dst_length;
    char *exp_result;
};

struct keeto_get_rdn_from_dn_entry {
    char *dn;
    int exp_res;
    char *exp_result;
};

Suite *make_util_suite(void);
#endif

