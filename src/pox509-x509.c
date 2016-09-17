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

#include "pox509-error.h"
#include "pox509-log.h"

static bool
msb_set(unsigned char byte)
{
    if (byte & 0x80) {
        return true;
    } else {
        return false;
    }
}

static int
get_ssh_key_from_rsa(EVP_PKEY *pkey, char *ssh_keytype, char **ret)
{
    if (pkey == NULL || ssh_keytype == NULL || ret == NULL) {
        fatal("pkey, ssh_keytype or ret == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        log_error("failed to obtain rsa key");
        return POX509_OPENSSL_ERR;
    }
    /* length of keytype WITHOUT the terminating null byte */
    size_t length_keytype = strlen(ssh_keytype);
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
    memcpy(blob_p, ssh_keytype, length_keytype);
    blob_p += length_keytype;

    /* put length of exponent */
    BN_bn2bin(rsa->e, tmp_buffer);
    if (msb_set(tmp_buffer[0])) {
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
    if (msb_set(tmp_buffer[0])) {
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

    /* base64 encode blob */

    /* create base64 bio */
    BIO *bio_base64 = BIO_new(BIO_f_base64());
    if (bio_base64 == NULL) {
        log_error("failed to create base64 bio");
        res = POX509_OPENSSL_ERR;
        goto cleanup_a;
    }
    BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL);

    /* create memory bio */
    BIO *bio_mem = BIO_new(BIO_s_mem());
    if (bio_mem == NULL) {
        log_error("failed to create mem bio");
        res = POX509_OPENSSL_ERR;
        goto cleanup_b;
    }
    /* create bio chain base64->mem */
    BIO *bio_base64_mem = BIO_push(bio_base64, bio_mem);

    /* base64 encode blob and write to memory */
    size_t post_length_blob = blob_p - blob;
    BIO_write(bio_base64_mem, blob, post_length_blob);
    int rc = BIO_flush(bio_base64_mem);
    if (rc != 1) {
        log_error("failed to flush bio");
        res = POX509_OPENSSL_ERR;
        goto cleanup_c;
    }

    /* store base64 encoded string in var and put null terminator */
    char *tmp_result = NULL;
    long data_out = BIO_get_mem_data(bio_mem, &tmp_result);
    char *ssh_key = malloc(data_out + 1);
    if (ssh_key == NULL) {
        log_error("failed to allocate memory for ssh key");
        res = POX509_NO_MEMORY;
        goto cleanup_c;
    }
    memcpy(ssh_key, tmp_result, data_out);
    ssh_key[data_out] = '\0';

    *ret = ssh_key;
    res = POX509_OK;

cleanup_c:
    BIO_vfree(bio_mem);
cleanup_b:
    BIO_vfree(bio_base64);
cleanup_a:
    RSA_free(rsa);
    return res;
}

int
add_ssh_key_data_from_x509(X509 *x509, struct pox509_key *key)
{
    if (x509 == NULL || key == NULL) {
        fatal("x509 or key == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    EVP_PKEY *pkey = X509_get_pubkey(x509);
    if (pkey == NULL) {
        log_error("failed to extract public key from certificate");
        return POX509_X509_ERR;
    }
    char *ssh_keytype = NULL;

    int pkey_type = EVP_PKEY_base_id(pkey);
    switch (pkey_type) {
    case EVP_PKEY_RSA:
        ssh_keytype = strdup("ssh-rsa");
        if (ssh_keytype == NULL) {
            log_error("failed to duplicate ssh keytype");
            res = POX509_NO_MEMORY;
            goto cleanup_a;
        }
        int rc = get_ssh_key_from_rsa(pkey, ssh_keytype, &key->ssh_key);
        switch (rc) {
        case POX509_OK:
            break;
        case POX509_NO_MEMORY:
            res = rc;
            goto cleanup_b;
        default:
            log_error("failed to obtain ssh key from rsa (%s)",
                pox509_strerror(rc));
            res = rc;
            goto cleanup_b;
        }
        break;
    default:
        log_error("unsupported key type (%d)", pkey_type);
        res = POX509_UNSUPPORTED_KEY_TYPE;
        goto cleanup_a;
    }
    key->ssh_keytype = ssh_keytype;
    ssh_keytype = NULL;
    res = POX509_OK;

cleanup_b:
    if (ssh_keytype != NULL) {
        free(ssh_keytype);
    }
cleanup_a:
    EVP_PKEY_free(pkey);
    return res;
}

int
validate_x509(X509 *x509, const char *cacerts_dir, bool *valid)
{
    if (x509 == NULL || cacerts_dir == NULL) {
        fatal("x509 or cacerts_dir == NULL");
    }

    int res = POX509_UNKNOWN_ERR;
    /* add algorithms */
    OpenSSL_add_all_algorithms();
    /* create a new x509 store with trusted ca certificates */
    X509_STORE *trusted_ca_store = X509_STORE_new();
    if (trusted_ca_store == NULL) {
        log_error("failed to create trusted ca store");
        res = POX509_OPENSSL_ERR;
        goto cleanup_a;
    }
    X509_LOOKUP *trusted_ca_store_lookup = X509_STORE_add_lookup(trusted_ca_store,
        X509_LOOKUP_hash_dir());
    if (trusted_ca_store_lookup == NULL) {
        log_error("failed to create lookup object for ca store");
        res = POX509_X509_ERR;
        goto cleanup_b;
    }
    int rc = X509_LOOKUP_add_dir(trusted_ca_store_lookup, cacerts_dir,
        X509_FILETYPE_PEM);
    if (rc == 0) {
        log_error("failed to read trusted ca's from '%s'", cacerts_dir);
        res = POX509_OPENSSL_ERR;
        goto cleanup_b;
    }

    /* validate the user certificate against the trusted ca store */
    X509_STORE_CTX *ctx_store = X509_STORE_CTX_new();
    if (ctx_store == NULL) {
        log_error("failed to create ctx store");
        res = POX509_OPENSSL_ERR;
        goto cleanup_b;
    }
    rc = X509_STORE_CTX_init(ctx_store, trusted_ca_store, x509, NULL);
    if (rc == 0) {
        log_error("failed to initialize ctx store");
        res = POX509_OPENSSL_ERR;
        goto cleanup_c;
    }
    rc = X509_STORE_CTX_set_purpose(ctx_store, X509_PURPOSE_SSL_CLIENT);
    if (rc == 0) {
        log_error("failed to set purpose for ctx store");
        res = POX509_OPENSSL_ERR;
        goto cleanup_c;
    }
    rc = X509_verify_cert(ctx_store);
    if (rc <= 0) {
        *valid = false;
        int cert_err = X509_STORE_CTX_get_error(ctx_store);
        log_error("certificate not valid (%s)",
            X509_verify_cert_error_string(cert_err));
    } else {
        *valid = true;
    }
    res = POX509_OK;

cleanup_c:
    X509_STORE_CTX_free(ctx_store);
cleanup_b:
    X509_STORE_free(trusted_ca_store);
cleanup_a:
    EVP_cleanup();
    return res;
}

char *
get_serial_from_x509(X509 *x509)
{
    if (x509 == NULL) {
        fatal("x509 == NULL");
    }

    ASN1_INTEGER *serial_asn1 = X509_get_serialNumber(x509);
    if (serial_asn1 == NULL) {
        log_error("failed to obtain serial number as asn1 integer");
        return NULL;
    }
    BIGNUM *serial_bn = ASN1_INTEGER_to_BN(serial_asn1, NULL);
    if (serial_bn == NULL) {
        log_error("failed to obtain big number from asn1 integer");
        return NULL;
    }
    char *serial = BN_bn2hex(serial_bn);
    if (serial == NULL) {
        log_error("failed to obtain serial from big number");
        goto cleanup;
    }

cleanup:
    BN_free(serial_bn);
    return serial;
}

char *
get_issuer_from_x509(X509 *x509)
{
    if (x509 == NULL) {
        fatal("x509 == NULL");
    }

    X509_NAME *issuer = X509_get_issuer_name(x509);
    if (issuer == NULL) {
        log_error("failed to obtain issuer from certificate");
        return NULL;
    }
    return X509_NAME_oneline(issuer, NULL, 0);
}

char *
get_subject_from_x509(X509 *x509)
{
    if (x509 == NULL) {
        fatal("x509 == NULL");
    }

    X509_NAME *subject = X509_get_subject_name(x509);
    if (subject == NULL) {
        log_error("failed to obtain subject from certificate");
        return NULL;
    }
    return X509_NAME_oneline(subject, NULL, 0);
}

void
free_x509(X509 *x509)
{
    if (x509 == NULL) {
        return;
    }
    X509_free(x509);
}

