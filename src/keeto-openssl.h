/*
 * Copyright (C) 2017 Sebastian Roland <seroland86@gmail.com>
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

#ifndef KEETO_OPENSSL_H
#define KEETO_OPENSSL_H

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L /* openssl 1.0 functions */

#include <stddef.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#define init_openssl() do { \
    SSL_load_error_strings(); \
    OpenSSL_add_all_algorithms(); \
} while (0)

#define cleanup_openssl() do { \
    ERR_free_strings(); \
    CRYPTO_cleanup_all_ex_data(); \
    EVP_cleanup(); \
    ERR_remove_thread_state(NULL); \
} while (0)

void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e,
    const BIGNUM **d);

#else /* openssl 1.1 functions */

#define init_openssl() do {} while (0)
#define cleanup_openssl() do {} while (0)

#endif /* OPENSSL_VERSION_NUMBER */

#endif /* KEETO_OPENSSL_H */

