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

/**
 * Definition of error values.
 *
 * @file pox509-error.h
 * @author Sebastian Roland <seroland86@gmail.com>
 * @date 2016-08-13
 * @see https://github.com/flix-/pam-openssh-x509
 */

#ifndef POX509_ERROR_H
#define POX509_ERROR_H

#include <limits.h>

enum {
    POX509_OK = 0,
    POX509_SYSTEM_ERR = INT_MIN,
    POX509_NO_MEMORY,
    POX509_NO_SUCH_VALUE,
    POX509_REGEX_ERR,
    POX509_LDAP_ERR,
    POX509_LDAP_CONNECTION_ERR,
    POX509_LDAP_SCHEMA_ERR,
    POX509_LDAP_NO_SUCH_ENTRY,
    POX509_LDAP_NO_SUCH_ATTR,
    POX509_NOT_RELEVANT,
    POX509_NO_CERT,
    POX509_NO_KEY_PROVIDER,
    POX509_X509_ERR,
    POX509_NO_ACCESS_PROFILE,
    POX509_UNKNOWN_ACCESS_PROFILE_TYPE,
    POX509_NO_KEYSTORE_OPTION,
    POX509_CERT_VALIDATION_ERR,
    POX509_INVALID_CERT,
    POX509_KEY_TRANSFORM_ERR,
    POX509_NO_KEY,
    POX509_OPENSSL_ERR,
    POX509_UNSUPPORTED_KEY_TYPE,
    POX509_NO_SSH_SERVER,

    POX509_UNKNOWN_ERR
};

const char *pox509_strerror(int errnum);
#endif
