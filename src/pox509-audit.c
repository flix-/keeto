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

#include <stdlib.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "queue.h"

#include "pox509-error.h"
#include "pox509-log.h"
#include "pox509-util.h"
#include "pox509-x509.h"

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
log_hex(char *attr, int value)
{
    if (attr == NULL) {
        fatal("attr == NULL");
    }
    log_info("%s: 0x%02x", attr, value);
}

static void
print_keystore_record(struct pox509_keystore_record *keystore_record)
{
    if (keystore_record == NULL) {
        log_info("keystore_record empty");
        return;
    }
    log_string("keystore_record->uid", keystore_record->uid);
    log_string("keystore_record->ssh_keytype", keystore_record->ssh_keytype);
    log_string("keystore_record->ssh_key", keystore_record->ssh_key);
    log_string("keystore_record->command_option",
        keystore_record->command_option);
    log_string("keystore_record->from_option", keystore_record->from_option);
}

static void
print_keystore_records(struct pox509_keystore_records *keystore_records)
{
    if (keystore_records == NULL) {
        log_info("keystore_records empty");
        return;
    }

    struct pox509_keystore_record *keystore_record = NULL;
    SIMPLEQ_FOREACH(keystore_record, keystore_records, next) {
        print_keystore_record(keystore_record);
    }
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
    log_string("keystore_options->command_option",
        keystore_options->command_option);
    log_string("keystore_options->from_option", keystore_options->from_option);
}

static void
print_x509(X509 *x509)
{
    if (x509 == NULL) {
        log_info("x509 empty");
        return;
    }

    char *issuer = get_issuer_from_x509(x509);
    if (issuer == NULL) {
        log_error("failed to obtain issuer from x509");
    } else {
        log_string("x509->issuer", issuer);
        free(issuer);
    }

    char *serial = get_serial_from_x509(x509);
    if (serial == NULL) {
        log_error("failed to obtain serial from x509");
    } else {
        log_string("x509->serial", serial);
        free(serial);
    }

    char *subject = get_subject_from_x509(x509);
    if (subject == NULL) {
        log_error("failed to obtain subject from x509");
    } else {
        log_string("x509->subject", subject);
        free(subject);
    }
}

static void
print_key(struct pox509_key *key)
{
    if (key == NULL) {
        log_info("key empty");
        return;
    }

    log_string("key->ssh_keytype", key->ssh_keytype);
    log_string("key->ssh_key", key->ssh_key);
    print_x509(key->x509);
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

    log_hex("access_profile->type", access_profile->type);
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
print_config(cfg_t *cfg)
{
    if (cfg == NULL) {
        log_info("cfg empty");
        return;
    }

    log_string("cfg->syslog_facility", cfg_getstr(cfg, "syslog_facility"));
    log_string("cfg->ldap_uri", cfg_getstr(cfg, "ldap_uri"));
    log_int("cfg->ldap_starttls", cfg_getint(cfg, "ldap_starttls"));
    log_string("cfg->ldap_bind_dn", cfg_getstr(cfg, "ldap_bind_dn"));
    log_string("cfg->ldap_bind_pwd", cfg_getstr(cfg, "ldap_bind_pwd"));
    log_int("cfg->ldap_search_timeout", cfg_getint(cfg, "ldap_search_timeout"));
    log_string("cfg->ldap_ssh_server_base_dn", cfg_getstr(cfg,
        "ldap_ssh_server_base_dn"));
    log_int("cfg->ldap_ssh_server_search_scope", cfg_getint(cfg,
        "ldap_ssh_server_search_scope"));
    log_string("cfg->ldap_ssh_server_uid_attr", cfg_getstr(cfg,
        "ldap_ssh_server_uid_attr"));
    log_string("cfg->ldap_ssh_server_access_profile_attr", cfg_getstr(cfg,
        "ldap_ssh_server_access_profile_attr"));
    log_string("cfg->ldap_target_keystore_group_member_attr", cfg_getstr(cfg,
        "ldap_target_keystore_group_member_attr"));
    log_string("cfg->ldap_target_keystore_uid_attr", cfg_getstr(cfg,
        "ldap_target_keystore_uid_attr"));
    log_string("cfg->ldap_key_provider_group_member_attr", cfg_getstr(cfg,
        "ldap_key_provider_group_member_attr"));
    log_string("cfg->ldap_key_provider_uid_attr", cfg_getstr(cfg,
        "ldap_key_provider_uid_attr"));
    log_string("cfg->ldap_key_provider_cert_attr", cfg_getstr(cfg,
        "ldap_key_provider_cert_attr"));
    log_string("cfg->ssh_server_uid", cfg_getstr(cfg, "ssh_server_uid"));
    log_string("cfg->ssh_keystore_location", cfg_getstr(cfg,
        "ssh_keystore_location"));
    log_string("cfg->cacerts_dir", cfg_getstr(cfg, "cacerts_dir"));
    log_int("cfg->ldap_strict", cfg_getint(cfg, "ldap_strict"));
}

static void
print_info(struct pox509_info *info)
{
    if (info == NULL) {
        log_info("info empty");
        return;
    }

    log_info(" ");
    print_config(info->cfg);
    log_info(" ");
    log_string("info->uid", info->uid);
    log_string("info->ssh_keystore_location", info->ssh_keystore_location);
    log_info(" ");
    print_ssh_server(info->ssh_server);
    log_info(" ");
    print_access_profiles(info->access_profiles);
    log_int("info->ldap_online", info->ldap_online);
    log_info(" ");
    print_keystore_records(info->keystore_records);
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
        log_error("failed to get pam data (%s)", pam_strerror(pamh, rc));
        return PAM_SYSTEM_ERR;
    }

    /* set log facility */
    char *syslog_facility = cfg_getstr(info->cfg, "syslog_facility");
    rc = set_syslog_facility(syslog_facility);
    if (rc != POX509_OK) {
        log_error("failed to set syslog facility '%s' (%s)", syslog_facility,
            pox509_strerror(rc));
    }
    print_info(info);

    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

