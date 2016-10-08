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

void init_openssl();
void cleanup_openssl();
int init_cert_store(char *cert_store_dir, bool check_crl);
void free_cert_store();
int add_ssh_key_data_from_x509(X509 *x509, struct pox509_key *key);
int validate_x509(X509 *x509, bool *valid);
char *get_serial_from_x509(X509 *x509);
int get_issuer_from_x509(X509 *x509, char **ret);
int get_subject_from_x509(X509 *x509, char **ret);
void free_x509(X509 *x509);
#endif

