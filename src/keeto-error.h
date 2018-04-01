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

#ifndef KEETO_ERROR_H
#define KEETO_ERROR_H

#include <limits.h>

enum {
    KEETO_OK = 0,

    KEETO_SYSTEM_ERR = INT_MIN,
    KEETO_NO_MEMORY,
    KEETO_NO_SUCH_VALUE,
    KEETO_REGEX_ERR,
    KEETO_LDAP_ERR,
    KEETO_LDAP_CONNECTION_ERR,
    KEETO_LDAP_SCHEMA_ERR,
    KEETO_LDAP_NO_SUCH_ENTRY,
    KEETO_LDAP_NO_SUCH_ATTR,
    KEETO_NOT_RELEVANT,
    KEETO_NO_CERT,
    KEETO_NO_KEY_PROVIDER,
    KEETO_X509_ERR,
    KEETO_NO_ACCESS_PROFILE_FOR_SSH_SERVER,
    KEETO_NO_ACCESS_PROFILE_FOR_UID,
    KEETO_UNKNOWN_ACCESS_PROFILE_TYPE,
    KEETO_NO_KEYSTORE_OPTION,
    KEETO_CERT_VALIDATION_ERR,
    KEETO_INVALID_CERT,
    KEETO_KEY_TRANSFORM_ERR,
    KEETO_NO_KEY,
    KEETO_OPENSSL_ERR,
    KEETO_UNSUPPORTED_KEY_TYPE,
    KEETO_UNKNOWN_DIGEST_ALGO,
    KEETO_NO_SSH_SERVER,

    KEETO_UNKNOWN_ERR
};

const char *keeto_strerror(int errnum);

#endif /* KEETO_ERROR_H */

