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
 * @file pox509-error.c
 * @author Sebastian Roland <seroland86@gmail.com>
 * @date 2016-08-13
 * @see https://github.com/flix-/pam-openssh-x509
 */

#include "pox509-error.h"

const char *
pox509_strerror(int errnum)
{
    switch(errnum) {
    case POX509_OK:
        return "POX509_OK";
    case POX509_SYSTEM_ERR:
        return "POX509_SYSTEM_ERR";
    case POX509_NO_MEMORY:
        return "POX509_NO_MEMORY";
    case POX509_NO_SUCH_VALUE:
        return "POX509_NO_SUCH_VALUE";
    case POX509_PARSE_CONFIG_ERR:
        return "POX509_PARSE_CONFIG_ERR";
    case POX509_REGEX_ERR:
        return "POX509_REGEX_ERR";
    case POX509_LDAP_ERR:
        return "POX509_LDAP_ERR";
    case POX509_LDAP_CONNECTION_ERR:
        return "POX509_LDAP_CONNECTION_ERR";
    case POX509_LDAP_NO_SUCH_ENTRY:
        return "POX509_LDAP_NO_SUCH_ENTRY";
    case POX509_LDAP_NO_SUCH_ATTR:
        return "POX509_LDAP_NO_SUCH_ATTR";
    case POX509_LDAP_NO_SUCH_VALUE:
        return "POX509_LDAP_NO_SUCH_VALUE";
    case POX509_LDAP_INVALID_RESULT:
        return "POX509_LDAP_INVALID_RESULT";
    case POX509_NOT_RELEVANT:
        return "POX509_NOT_RELEVANT";
    case POX509_NO_CERTS:
        return "POX509_NO_CERTS";
    case POX509_X509_ERR:
        return "POX509_X509_ERR";

    case POX509_UNKNOWN_ERR:
        return "POX509_UNKNOWN_ERR";
    default:
        return "undefined error";
    }
}

