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

#include <stddef.h>

#include <openssl/bn.h>
#include <openssl/opensslv.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L /* openssl 1.0 functions */

void
RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL) {
        *n = r->n;
    }
    if (e != NULL) {
        *e = r->e;
    }
    if (d != NULL) {
        *d = r->d;
    }
}

#endif

