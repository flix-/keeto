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

/**
 * Validate a x509 certificate.
 *
 * @param[in] x509 X509 certificate. Must not be @c NULL.
 * @param[in] cacerts_dir Path to directory with trusted root CA's
 * symlinked by their hash value. Must not be @c NULL.
 * @param[out] pox509_info DTO. Must not be @c NULL.
 */
void validate_x509(X509 *x509, const char *cacerts_dir,
    struct pox509_info *pox509_info);

/**
 * Convert a x509 certificate to an OpenSSH authorized_keys file entry.
 *
 * @param[in] x509 x509 certificate. Must not be @c NULL.
 * @param[out] pox509_info DTO. Must not be @c NULL.
 */
void x509_to_authorized_keys(X509 *x509, struct pox509_info *pox509_info);

/**
 * Get serial from x509 certificate.
 *
 * @param[in] x509 x509 certificate. Must not be @c NULL.
 * @param[out] pox509_info DTO. Must not be @c NULL.
 */
void get_serial_from_x509(X509 *x509, struct pox509_info *pox509_info);

/**
 * Get issuer from x509 certificate.
 *
 * @param[in] x509 x509 certificate. Must not be @c NULL.
 * @param[out] pox509_info DTO. Must not be @c NULL.
 */
void get_issuer_from_x509(X509 *x509, struct pox509_info *pox509_info);

/**
 * Get subject from x509 certificate.
 *
 * @param[in] x509 x509 certificate. Must not be @c NULL.
 * @param[out] pox509_info DTO. Must not be @c NULL.
 */
void get_subject_from_x509(X509 *x509, struct pox509_info *pox509_info);
#endif
