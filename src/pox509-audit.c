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

#include <errno.h>
#include <stdlib.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "queue.h"
#include "pox509-error.h"
#include "pox509-log.h"
#include "pox509-util.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

static void
log_string(char *attr, char *value)
{
    if (attr == NULL) {
        fatal("attr == NULL");
    }
    if (value == NULL) {
        value = "unset";
    }
    log_info("%s: %s", attr, value);
}

static void
log_int(char *attr, int value)
{
    if (attr == NULL) {
        fatal("attr == NULL");
    }
    log_info("%s: %d", attr, value);
}
static void
print_keystore_options(struct pox509_keystore_options *keystore_options)
{
    if (keystore_options == NULL) {
        log_info("keystore_options empty");
        return;
    }

    log_string("keystore_options->dn", keystore_options->dn);
    log_string("keystore_options->uid", keystore_options->uid);
    log_string("keystore_options->from_option", keystore_options->from_option);
    log_string("keystore_options->command_option",
        keystore_options->command_option);
}

static void
print_key(struct pox509_key *key)
{
    if (key == NULL) {
        log_info("key empty");
        return;
    }

    X509_NAME *subject = X509_get_subject_name(key->x509);
    log_string("key->x509", X509_NAME_oneline(subject, NULL, 0));
    log_string("key->ssh_keytype", key->ssh_keytype);
    log_string("key->ssh_key", key->ssh_key);
}

static void
print_keys(struct pox509_keys *keys)
{
    if (keys == NULL) {
        log_info("keys empty");
        return;
    }

    struct pox509_key *key = NULL;
    TAILQ_FOREACH(key, keys, next) {
        print_key(key);
    }
}

static void
print_key_provider(struct pox509_key_provider *key_provider)
{
    if (key_provider == NULL) {
        log_info("key_provider empty");
        return;
    }

    log_string("key_provider->dn", key_provider->dn);
    log_string("key_provider->uid", key_provider->uid);
    print_keys(key_provider->keys);
}

static void
print_key_providers(struct pox509_key_providers *key_providers)
{
    if (key_providers == NULL) {
        log_info("key_providers empty");
        return;
    }

    struct pox509_key_provider *key_provider = NULL;
    TAILQ_FOREACH(key_provider, key_providers, next) {
        print_key_provider(key_provider);
    }
}

static void
print_access_profile(struct pox509_access_profile *access_profile)
{
    if (access_profile == NULL) {
        log_info("access_profile empty");
        return;
    }

    log_int("access_profile->type", access_profile->type);
    log_string("access_profile->dn", access_profile->dn);
    log_string("access_profile->uid", access_profile->uid);
    print_key_providers(access_profile->key_providers);
    print_keystore_options(access_profile->keystore_options);
}

static void
print_access_profiles(struct pox509_access_profiles *access_profiles)
{
    if (access_profiles == NULL) {
        log_info("access_profiles empty");
        return;
    }

    struct pox509_access_profile *access_profile = NULL;
    TAILQ_FOREACH(access_profile, access_profiles, next) {
        print_access_profile(access_profile);
        log_info(" ");
    }
}

static void
print_ssh_server(struct pox509_ssh_server *ssh_server)
{
    if (ssh_server == NULL) {
        log_info("ssh_server empty");
        return;
    }

    log_string("ssh_server->dn", ssh_server->dn);
    log_string("ssh_server->uid", ssh_server->uid);
}

static void
print_info(struct pox509_info *info)
{
    if (info == NULL) {
        log_info("info empty");
        return;
    }

    log_info(" ");
    log_string("info->uid", info->uid);
    log_string("info->ssh_keystore_location", info->ssh_keystore_location);
    log_info(" ");
    print_ssh_server(info->ssh_server);
    log_info(" ");
    print_access_profiles(info->access_profiles);
    log_int("info->ldap_online", info->ldap_online);
}


PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (pamh == NULL) {
        fatal("pamh == NULL");
    }

    struct pox509_info *info = NULL;
    int rc = pam_get_data(pamh, "pox509_info", (const void **) &info);
    if (rc != PAM_SUCCESS) {
        log_debug("pam_set_data(): '%s' (%d)", pam_strerror(pamh, rc), rc);
        return PAM_SYSTEM_ERR;
    }

    /* set log facility */
    char *syslog_facility = cfg_getstr(info->cfg, "syslog_facility");
    rc = set_syslog_facility(syslog_facility);
    if (rc != POX509_OK) {
        log_error("error setting syslog facility '%s' (%s)", syslog_facility,
            pox509_strerror(rc));
    }
    print_info(info);

    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (pamh == NULL) {
        fatal("pamh == NULL");
    }
    return PAM_SUCCESS;
}

