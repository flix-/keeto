/*
 * Copyright (C) 2014-2017 Sebastian Roland <seroland86@gmail.com>
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

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "queue.h"

#include "keeto-error.h"
#include "keeto-log.h"
#include "keeto-util.h"
#include "keeto-x509.h"

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
log_bool(char *attr, int value)
{
    if (attr == NULL) {
        fatal("attr == NULL");
    }
    char *output = "unset";
    switch (value) {
    case 0:
        output = "false";
        break;
    case 1:
        output = "true";
        break;
    }
    log_info("%s: %s", attr, output);
}

static void
log_profile_type(char *attr, int value)
{
    if (attr == NULL) {
        fatal("attr == NULL");
    }
    char *output = "unset";
    switch (value) {
    case 0:
        output = "direct_access_profile";
        break;
    case 1:
        output = "access_on_behalf_profile";
        break;
    }
    log_info("%s: %s", attr, output);
}

static void
log_keystore_record(struct keeto_keystore_record *keystore_record)
{
    if (keystore_record == NULL) {
        log_info("keystore_record empty");
        return;
    }
    log_string("keystore_record->uid", keystore_record->uid);
    log_string("keystore_record->ssh_keytype", keystore_record->ssh_keytype);
    log_string("keystore_record->ssh_key", keystore_record->ssh_key);
    log_string("keystore_record->ssh_key_fp_md5", keystore_record->ssh_key_fp_md5);
    log_string("keystore_record->ssh_key_fp_sha256", keystore_record->ssh_key_fp_sha256);
    log_string("keystore_record->command_option",
        keystore_record->command_option);
    log_string("keystore_record->from_option", keystore_record->from_option);
}

static void
log_keystore_records(struct keeto_keystore_records *keystore_records)
{
    if (keystore_records == NULL) {
        log_info("keystore_records empty");
        return;
    }

    struct keeto_keystore_record *keystore_record = NULL;
    SIMPLEQ_FOREACH(keystore_record, keystore_records, next) {
        log_keystore_record(keystore_record);
    }
}
static void
log_keystore_options(struct keeto_keystore_options *keystore_options)
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
log_x509(X509 *x509)
{
    if (x509 == NULL) {
        log_info("x509 empty");
        return;
    }

    char *issuer = NULL;
    int rc = get_issuer_from_x509(x509, &issuer);
    switch (rc) {
    case KEETO_OK:
        log_string("x509->issuer", issuer);
        free(issuer);
        break;
    default:
        log_error("failed to obtain issuer from certificate (%s)",
            keeto_strerror(rc));
    }

    char *serial = get_serial_from_x509(x509);
    if (serial == NULL) {
        log_error("failed to obtain serial from certificate");
    } else {
        log_string("x509->serial", serial);
        free(serial);
    }

    char *subject = NULL;
    rc = get_subject_from_x509(x509, &subject);
    switch (rc) {
    case KEETO_OK:
        log_string("x509->subject", subject);
        free(subject);
        break;
    default:
        log_error("failed to obtain subject from certificate (%s)",
            keeto_strerror(rc));
    }
}

static void
log_key(struct keeto_key *key)
{
    if (key == NULL) {
        log_info("key empty");
        return;
    }

    log_string("key->ssh_keytype", key->ssh_keytype);
    log_string("key->ssh_key", key->ssh_key);
    log_string("key->ssh_key_fp_md5", key->ssh_key_fp_md5);
    log_string("key->ssh_key_fp_sha256", key->ssh_key_fp_sha256);
    log_x509(key->x509);
}

static void
log_keys(struct keeto_keys *keys)
{
    if (keys == NULL) {
        log_info("keys empty");
        return;
    }

    struct keeto_key *key = NULL;
    TAILQ_FOREACH(key, keys, next) {
        log_key(key);
    }
}

static void
log_key_provider(struct keeto_key_provider *key_provider)
{
    if (key_provider == NULL) {
        log_info("key_provider empty");
        return;
    }

    log_string("key_provider->dn", key_provider->dn);
    log_string("key_provider->uid", key_provider->uid);
    log_keys(key_provider->keys);
}

static void
log_key_providers(struct keeto_key_providers *key_providers)
{
    if (key_providers == NULL) {
        log_info("key_providers empty");
        return;
    }

    struct keeto_key_provider *key_provider = NULL;
    TAILQ_FOREACH(key_provider, key_providers, next) {
        log_key_provider(key_provider);
    }
}

static void
log_access_profile(struct keeto_access_profile *access_profile)
{
    if (access_profile == NULL) {
        log_info("access_profile empty");
        return;
    }

    log_profile_type("access_profile->type", access_profile->type);
    log_string("access_profile->dn", access_profile->dn);
    log_string("access_profile->uid", access_profile->uid);
    log_key_providers(access_profile->key_providers);
    log_keystore_options(access_profile->keystore_options);
}

static void
log_access_profiles(struct keeto_access_profiles *access_profiles)
{
    if (access_profiles == NULL) {
        log_info("access_profiles empty");
        return;
    }

    struct keeto_access_profile *access_profile = NULL;
    TAILQ_FOREACH(access_profile, access_profiles, next) {
        log_access_profile(access_profile);
        log_info(" ");
    }
}

static void
log_ssh_server(struct keeto_ssh_server *ssh_server)
{
    if (ssh_server == NULL) {
        log_info("ssh_server empty");
        return;
    }

    log_string("ssh_server->dn", ssh_server->dn);
    log_string("ssh_server->uid", ssh_server->uid);
}

static void
log_config(cfg_t *cfg)
{
    if (cfg == NULL) {
        log_info("cfg empty");
        return;
    }

    log_string("cfg->syslog_facility", cfg_getstr(cfg, "syslog_facility"));

    log_string("cfg->ldap_uri", cfg_getstr(cfg, "ldap_uri"));
    log_bool("cfg->ldap_starttls", cfg_getint(cfg, "ldap_starttls"));
    log_string("cfg->ldap_bind_dn", cfg_getstr(cfg, "ldap_bind_dn"));
    log_string("cfg->ldap_bind_pwd", "********");
    log_int("cfg->ldap_timeout", cfg_getint(cfg, "ldap_timeout"));
    log_bool("cfg->ldap_strict", cfg_getint(cfg, "ldap_strict"));

    log_string("cfg->ldap_ssh_server_search_base", cfg_getstr(cfg,
        "ldap_ssh_server_search_base"));
    log_int("cfg->ldap_ssh_server_search_scope", cfg_getint(cfg,
        "ldap_ssh_server_search_scope"));
    log_string("cfg->ldap_ssh_server_uid", cfg_getstr(cfg,
        "ldap_ssh_server_uid"));

    log_string("cfg->ldap_key_provider_group_member_attr", cfg_getstr(cfg,
        "ldap_key_provider_group_member_attr"));
    log_string("cfg->ldap_key_provider_uid_attr", cfg_getstr(cfg,
        "ldap_key_provider_uid_attr"));
    log_string("cfg->ldap_key_provider_cert_attr", cfg_getstr(cfg,
        "ldap_key_provider_cert_attr"));

    log_string("cfg->ldap_target_keystore_group_member_attr", cfg_getstr(cfg,
        "ldap_target_keystore_group_member_attr"));
    log_string("cfg->ldap_target_keystore_uid_attr", cfg_getstr(cfg,
        "ldap_target_keystore_uid_attr"));

    log_string("cfg->ssh_keystore_location", cfg_getstr(cfg,
        "ssh_keystore_location"));
    log_string("cfg->cert_store_dir", cfg_getstr(cfg, "cert_store_dir"));
    log_bool("cfg->check_crl", cfg_getint(cfg, "check_crl"));

    log_string("cfg->uid_regex", cfg_getstr(cfg, "uid_regex"));
}

static void
log_keeto_info(struct keeto_info *info)
{
    if (info == NULL) {
        log_info("info empty");
        return;
    }

    log_info(" ");
    log_config(info->cfg);
    log_info(" ");
    log_string("info->uid", info->uid);
    log_string("info->ssh_keystore_location", info->ssh_keystore_location);
    log_info(" ");
    log_ssh_server(info->ssh_server);
    log_info(" ");
    log_access_profiles(info->access_profiles);
    log_bool("info->ldap_online", info->ldap_online);
    log_info(" ");
    log_keystore_records(info->keystore_records);
}


PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (pamh == NULL) {
        fatal("pamh == NULL");
    }

    struct keeto_info *info = NULL;
    int rc = pam_get_data(pamh, "keeto_info", (const void **)&info);
    if (rc != PAM_SUCCESS) {
        log_error("failed to get pam data (%s)", pam_strerror(pamh, rc));
        return PAM_SYSTEM_ERR;
    }

    /* set log facility */
    char *syslog_facility = cfg_getstr(info->cfg, "syslog_facility");
    if (syslog_facility == NULL) {
        return PAM_SYSTEM_ERR;
    }

    rc = set_syslog_facility(syslog_facility);
    if (rc != KEETO_OK) {
        log_error("failed to set syslog facility '%s' (%s)", syslog_facility,
            keeto_strerror(rc));
        return PAM_SYSTEM_ERR;
    }

    log_keeto_info(info);

    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

