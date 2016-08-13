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

#include "pox509-x509.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include "pox509-log.h"

#define PUT_32BIT(cp, value)( \
    (cp)[0] = (unsigned char)((value) >> 24), \
    (cp)[1] = (unsigned char)((value) >> 16), \
    (cp)[2] = (unsigned char)((value) >> 8), \
    (cp)[3] = (unsigned char)(value) )

static bool
is_msb_set(unsigned char byte)
{
    if (byte & 0x80) {
        return true;
    } else {
        return false;
    }
}

static void
pkey_to_authorized_keys(EVP_PKEY *pkey, struct pox509_info *pox509_info)
{
    if (pkey == NULL || pox509_info == NULL) {
        fatal("pkey or pox509_info == NULL");
    }

    int pkey_type = EVP_PKEY_type(pkey->type);
    switch (pkey_type) {
    case EVP_PKEY_RSA: {
        pox509_info->ssh_keytype = strdup("ssh-rsa");
        if (pox509_info->ssh_keytype == NULL) {
            fatal("strdup()");
        }
        RSA *rsa = EVP_PKEY_get1_RSA(pkey);
        if (rsa == NULL) {
            fatal("EVP_PKEY_get1_RSA()");
        }

        /*
         * create authorized_keys entry
         */

        /* length of keytype WITHOUT the terminating null byte */
        size_t length_keytype = strlen(pox509_info->ssh_keytype);
        size_t length_exponent = BN_num_bytes(rsa->e);
        size_t length_modulus = BN_num_bytes(rsa->n);
        /*
         * the 4 bytes hold the length of the following value and the 2
         * extra bytes before the exponent and modulus are possibly
         * needed to prefix the values with leading zeroes if the most
         * significant bit of them is set. this is to avoid
         * misinterpreting the value as a negative number later.
         */
        size_t pre_length_blob = 4 + length_keytype + 4 + 1 + length_exponent +
            4 + 1 + length_modulus;
        size_t length_tmp_buffer = length_modulus > length_exponent ?
            length_modulus : length_exponent;

        unsigned char blob[pre_length_blob];
        unsigned char tmp_buffer[length_tmp_buffer];
        unsigned char *blob_p = blob;

        /* put length of keytype */
        PUT_32BIT(blob_p, length_keytype);
        blob_p += 4;
        /* put keytype */
        memcpy(blob_p, pox509_info->ssh_keytype, length_keytype);
        blob_p += length_keytype;

        /* put length of exponent */
        BN_bn2bin(rsa->e, tmp_buffer);
        if (is_msb_set(tmp_buffer[0])) {
            PUT_32BIT(blob_p, length_exponent + 1);
            blob_p += 4;
            memset(blob_p, 0, 1);
            blob_p++;
        } else {
            PUT_32BIT(blob_p, length_exponent);
            blob_p += 4;
        }
        /* put exponent */
        memcpy(blob_p, tmp_buffer, length_exponent);
        blob_p += length_exponent;

        /* put length of modulus */
        BN_bn2bin(rsa->n, tmp_buffer);
        if (is_msb_set(tmp_buffer[0])) {
            PUT_32BIT(blob_p, length_modulus + 1);
            blob_p += 4;
            memset(blob_p, 0, 1);
            blob_p++;
        } else {
            PUT_32BIT(blob_p, length_modulus);
            blob_p += 4;
        }
        /* put modulus */
        memcpy(blob_p, tmp_buffer, length_modulus);
        blob_p += length_modulus;

        /*
         * base64 encode blob and store result in dto
         */

        /* create base64 bio */
        BIO *bio_base64 = BIO_new(BIO_f_base64());
        if (bio_base64 == NULL) {
            fatal("BIO_new()");
        }
        BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL);

        /* create memory bio */
        BIO *bio_mem = BIO_new(BIO_s_mem());
        if (bio_mem == NULL) {
            fatal("BIO_new()");
        }
        /* create bio chain base64->mem */
        BIO *bio_base64_mem = BIO_push(bio_base64, bio_mem);

        /* base64 encode blob and write to memory */
        size_t post_length_blob = blob_p - blob;
        BIO_write(bio_base64_mem, blob, post_length_blob);
        int rc = BIO_flush(bio_base64_mem);
        if (rc != 1) {
            fatal("BIO_flush()");
        }

        /* store base64 encoded string in var and put null terminator */
        char *tmp_result = NULL;
        long data_out = BIO_get_mem_data(bio_mem, &tmp_result);
        pox509_info->ssh_key = malloc(data_out + 1);
        if (pox509_info->ssh_key == NULL) {
            fatal("malloc()");
        }
        memcpy(pox509_info->ssh_key, tmp_result, data_out);
        pox509_info->ssh_key[data_out] = '\0';

        /* cleanup structures */
        BIO_free_all(bio_base64_mem);
        RSA_free(rsa);

        break;
    }
    case EVP_PKEY_DSA:
        fatal("DSA is not supported yet");
    case EVP_PKEY_DH:
        fatal("DH is not supported yet");
    case EVP_PKEY_EC:
        fatal("EC is not supported yet");
    default:
        fatal("unsupported public key type (%d)", pkey->type);
    }
}

void
validate_x509(X509 *x509, const char *cacerts_dir,
    struct pox509_info *pox509_info)
{
    if (x509 == NULL || cacerts_dir == NULL || pox509_info == NULL) {
        fatal("x509, cacerts_dir or pox509_info == NULL");
    }

    /* add algorithms */
    OpenSSL_add_all_algorithms();

    /* create a new x509 store with trusted ca certificates */
    X509_STORE *store = X509_STORE_new();
    if (store == NULL) {
        fatal("X509_STORE_new()");
    }
    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if (lookup == NULL) {
        fatal("X509_STORE_add_lookup()");
    }
    int rc = X509_LOOKUP_add_dir(lookup, cacerts_dir, X509_FILETYPE_PEM);
    if (rc == 0) {
        fatal("X509_LOOKUP_add_dir()");
    }

    /* validate the user certificate against the x509 store */
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        fatal("X509_STORE_CTX_new()");
    }
    rc = X509_STORE_CTX_init(ctx, store, x509, NULL);
    if (rc == 0) {
        fatal("X509_STORE_CTX_init()");
    }
    rc = X509_verify_cert(ctx);
    if (rc != 1) {
        pox509_info->has_valid_cert = 0;
        int cert_err = X509_STORE_CTX_get_error(ctx);
        const char *cert_err_string = X509_verify_cert_error_string(cert_err);
        log_error("X509_verify_cert(): %d (%s)", cert_err, cert_err_string);
    } else {
        pox509_info->has_valid_cert = 1;
    }

    /* cleanup structures */
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    EVP_cleanup();
}

void
x509_to_authorized_keys(X509 *x509, struct pox509_info *pox509_info)
{
    if (x509 == NULL || pox509_info == NULL) {
        fatal("x509 or pox509_info == NULL");
    }

    /*
     * extract public key and convert into OpenSSH authorized_keys
     * format
     */
    EVP_PKEY *pkey = X509_get_pubkey(x509);
    if (pkey == NULL) {
        fatal("X509_get_pubkey(): unable to load public key");
    }

    pkey_to_authorized_keys(pkey, pox509_info);
    EVP_PKEY_free(pkey);
}

void
get_serial_from_x509(X509 *x509, struct pox509_info *pox509_info)
{
    if (x509 == NULL || pox509_info == NULL) {
        fatal("x509 or pox509_info == NULL");
    }

    ASN1_INTEGER *serial_asn1 = X509_get_serialNumber(x509);
    if (serial_asn1 == NULL) {
        log_error("X509_get_serialNumber()");
        return;
    }

    BIGNUM *serial_bn = ASN1_INTEGER_to_BN(serial_asn1, NULL);
    if (serial_bn == NULL) {
        log_error("ASN1_INTEGER_to_BN()");
        return;
    }

    pox509_info->serial = BN_bn2hex(serial_bn);
    if (pox509_info->serial == NULL) {
        log_error("BN_bn2hex()");
    }

    BN_free(serial_bn);
}

void
get_issuer_from_x509(X509 *x509, struct pox509_info *pox509_info)
{
    if (x509 == NULL || pox509_info == NULL) {
        fatal("x509 or pox509_info == NULL");
    }

    X509_NAME *issuer = X509_get_issuer_name(x509);
    if (issuer == NULL) {
        log_error("X509_get_issuer_name()");
        return;
    }

    pox509_info->issuer = X509_NAME_oneline(issuer, NULL, 0);
}

void
get_subject_from_x509(X509 *x509, struct pox509_info *pox509_info)
{
    if (x509 == NULL || pox509_info == NULL) {
        fatal("x509 or pox509_info == NULL");
    }

    X509_NAME *subject = X509_get_subject_name(x509);
    if (subject == NULL) {
        log_error("X509_get_subject_name()");
        return;
    }

    pox509_info->subject = X509_NAME_oneline(subject, NULL, 0);
}

