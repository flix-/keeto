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

#include "keeto-error.h"

const char *
keeto_strerror(int errnum)
{
    switch(errnum) {
    case KEETO_OK:
        return "ok";
    case KEETO_SYSTEM_ERR:
        return "system error";
    case KEETO_NO_MEMORY:
        return "no memory";
    case KEETO_NO_SUCH_VALUE:
        return "no such value";
    case KEETO_REGEX_ERR:
        return "regex error";
    case KEETO_LDAP_ERR:
        return "ldap error";
    case KEETO_LDAP_CONNECTION_ERR:
        return "ldap connection error";
    case KEETO_LDAP_SCHEMA_ERR:
        return "ldap schema error";
    case KEETO_LDAP_NO_SUCH_ENTRY:
        return "no such ldap entry";
    case KEETO_LDAP_NO_SUCH_ATTR:
        return "no such ldap attribute";
    case KEETO_NOT_RELEVANT:
        return "not relevant";
    case KEETO_NO_CERT:
        return "no certificate";
    case KEETO_NO_KEY_PROVIDER:
        return "no key provider";
    case KEETO_X509_ERR:
        return "x509 error";
    case KEETO_NO_ACCESS_PROFILE_FOR_SSH_SERVER:
        return "no access profile for ssh server";
    case KEETO_NO_ACCESS_PROFILE_FOR_UID:
        return "no access profile for uid";
    case KEETO_UNKNOWN_ACCESS_PROFILE_TYPE:
        return "unknown access profile type";
    case KEETO_NO_KEYSTORE_OPTION:
        return "no keystore option found";
    case KEETO_CERT_VALIDATION_ERR:
        return "certificate validation error";
    case KEETO_INVALID_CERT:
        return "invalid certificate";
    case KEETO_KEY_TRANSFORM_ERR:
        return "key transformation error";
    case KEETO_NO_KEY:
        return "no key";
    case KEETO_OPENSSL_ERR:
        return "openssl error";
    case KEETO_UNSUPPORTED_KEY_TYPE:
        return "unsupported key type";
    case KEETO_NO_SSH_SERVER:
        return "no ssh server found";

    case KEETO_UNKNOWN_ERR:
        return "unknown error";
    default:
        return "undefined error";
    }
}

