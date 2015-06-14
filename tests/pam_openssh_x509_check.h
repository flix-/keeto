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

#ifndef PAM_OPENSSH_X509_CHECK_H
#define PAM_OPENSSH_X509_CHECK_H

#include <stdbool.h>

#include <bits/types.h>
#include <sys/stat.h>

#include <check.h>

struct pox509_substitute_token_entry {
    char token;
    char *subst;
    char *src;
    size_t dst_length;
    char *exp_result;
};

struct pox509_create_ldap_search_filter_entry {
    char *rdn;
    char *uid;
    size_t dst_length;
    char *exp_result;
};

struct pox509_check_access_permission_entry {
    char *group_dn;
    char *identifier;
    char exp_result;
};

struct pox509_validate_x509_entry {
    char *file;
    char exp_result;
};

struct pox509_is_valid_uid_entry {
    char *uid;
    bool exp_result;
};

struct pox509_is_readable_file_entry {
    char *file;
    mode_t mode;
    bool exp_result;
};

Suite *make_config_suite(void);
Suite *make_util_suite(void);
#endif
