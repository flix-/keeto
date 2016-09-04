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
 * Processing of x509 certificates.
 *
 * @file pox509-x509.h
 * @author Sebastian Roland <seroland86@gmail.com>
 * @date 2015-06-22
 * @see https://github.com/flix-/pam-openssh-x509
 */

#ifndef POX509_X509_H
#define POX509_X509_H

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>

#include "pox509-util.h"

#define PUT_32BIT(cp, value)( \
    (cp)[0] = (unsigned char)((value) >> 24), \
    (cp)[1] = (unsigned char)((value) >> 16), \
    (cp)[2] = (unsigned char)((value) >> 8), \
    (cp)[3] = (unsigned char)(value) )

int validate_x509(X509 *x509, const char *cacerts_dir, bool *is_valid);
int add_ssh_key_data_from_x509(X509 *x509, struct pox509_key *key);
char *get_serial_from_x509(X509 *x509);
char *get_issuer_from_x509(X509 *x509);
char *get_subject_from_x509(X509 *x509);
void free_x509(X509 *x509);
#endif
