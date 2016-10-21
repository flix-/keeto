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

#include "keeto-config.h"

#include <errno.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <ldap.h>
#include <regex.h>

#include "keeto-error.h"
#include "keeto-log.h"
#include "keeto-util.h"

#define ERROR_MSG_BUFFER_SIZE 4096

/*
 * function is called internally by libconfuse on error.
 */
static void
cfg_error_handler(cfg_t *cfg, const char *fmt, va_list ap)
{
    if (cfg == NULL || fmt == NULL) {
        fatal("cfg or fmt == NULL");
    }

    char error_msg[ERROR_MSG_BUFFER_SIZE];
    vsnprintf(error_msg, sizeof error_msg, fmt, ap);
    log_error("%s", error_msg);
}

/*
 * note that value parsing and validation callback functions will only
 * be called during parsing when the value is obtained from the config
 * file. neither they will be incorporated when default values are being
 * used nor if the value is altered later.
 */
static int
cfg_validate_syslog_facility(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg == NULL || opt == NULL) {
        fatal("cfg or opt == NULL");
    }

    const char *syslog_facility = cfg_opt_getnstr(opt, 0);
    if (syslog_facility == NULL) {
        log_error("failed to obtain syslog_facility option");
        return -1;
    }

    int rc = str_to_enum(POX509_SYSLOG, syslog_facility);
    if (rc == POX509_NO_SUCH_VALUE) {
        log_error("failed to validate syslog facility: option '%s', value '%s' "
            "(invalid syslog facility)", cfg_opt_name(opt), syslog_facility);
        return -1;
    }
    return 0;
}

static int
cfg_validate_ldap_uri(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg == NULL || opt == NULL) {
        fatal("cfg or opt == NULL");
    }

    const char *ldap_uri = cfg_opt_getnstr(opt, 0);
    if (ldap_uri == NULL) {
        log_error("failed to obtain ldap_uri option");
        return -1;
    }

    int rc = ldap_is_ldap_url(ldap_uri);
    if (rc == 0) {
        log_error("failed to validate ldap uri: option '%s', value '%s' "
            "(invalid ldap uri)", cfg_opt_name(opt), ldap_uri);
        return -1;
    }
    return 0;
}

static int
cfg_validate_boolean(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg == NULL || opt == NULL) {
        fatal("cfg or opt == NULL");
    }

    long int value = cfg_opt_getnint(opt, 0);
    if (value != 0 && value != 1) {
        log_error("failed to validate boolean: option '%s', value '%li' "
            "(value must be either 0 or 1)", cfg_opt_name(opt), value);
        return -1;
    }
    return 0;
}

static int
cfg_validate_ldap_dn(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg == NULL || opt == NULL) {
        fatal("cfg or opt == NULL");
    }

    const char *dn_str = cfg_opt_getnstr(opt, 0);
    if (dn_str == NULL) {
        log_error("failed to obtain ldap dn option");
        return -1;
    }

    size_t dn_str_length = strlen(dn_str);
    if (dn_str_length == 0) {
        log_error("failed to validate ldap dn: option '%s', value '%s' "
            "(length of dn must be > 0)", cfg_opt_name(opt), dn_str);
        return -1;
    }

    LDAPDN dn = NULL;
    int rc = ldap_str2dn(dn_str, &dn, LDAP_DN_FORMAT_LDAPV3);
    if (rc != LDAP_SUCCESS) {
        log_error("failed to validate ldap dn: option '%s', value '%s' (%s)",
            cfg_opt_name(opt), dn_str, ldap_err2string(rc));
        return -1;
    }
    ldap_dnfree(dn);
    return 0;
}

static int
cfg_validate_ldap_search_timeout(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg == NULL || opt == NULL) {
        fatal("cfg or opt == NULL");
    }

    long int timeout = cfg_opt_getnint(opt, 0);
    if (timeout <= 0) {
        log_error("failed to validate ldap search timeout: option '%s', "
            "value '%li' (value must be > 0)", cfg_opt_name(opt), timeout);
        return -1;
    }
    return 0;
}

static int
cfg_str_to_int_cb_libldap(cfg_t *cfg, cfg_opt_t *opt, const char *value,
    void *result)
{
    if (cfg == NULL || opt == NULL || value == NULL || result == NULL) {
        fatal("cfg, opt, value or result == NULL");
    }

    int ldap_option = str_to_enum(POX509_LIBLDAP, value);
    if (ldap_option == POX509_NO_SUCH_VALUE) {
        log_error("failed to convert value: option '%s', value '%s' "
            "(invalid value)", cfg_opt_name(opt), value);
        return -1;
    }
    long int *ptr_result = result;
    *ptr_result = ldap_option;
    return 0;
}

static int
cfg_validate_cert_store_dir(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg == NULL || opt == NULL) {
        fatal("cfg or opt == NULL");
    }

    const char *cert_store_dir = cfg_opt_getnstr(opt, 0);
    if (cert_store_dir == NULL) {
        log_error("failed to obtain cert_store_dir option");
        return -1;
    }
    /* check if directory exists */
    DIR *cert_store_dir_stream = opendir(cert_store_dir);
    if (cert_store_dir_stream == NULL) {
        log_error("failed to validate cert store dir: option '%s', value '%s' "
            "(%s)", cfg_opt_name(opt), cert_store_dir, strerror(errno));
        return -1;
    }
    closedir(cert_store_dir_stream);
    return 0;
}

static int
cfg_validate_regex(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg == NULL || opt == NULL) {
        fatal("cfg or opt == NULL");
    }

    const char *regex = cfg_opt_getnstr(opt, 0);
    if (regex == NULL) {
        log_error("failed to obtain uid_regex option");
        return -1;
    }
    /* check if regex compiles */
    regex_t regex_comp;
    int rc = regcomp(&regex_comp, regex, REG_EXTENDED | REG_NOSUB);
    if (rc != 0) {
        log_error("failed to compile uid regex: option '%s', value '%s' (%d)",
            cfg_opt_name(opt), regex, rc);
        return -1;
    }
    regfree(&regex_comp);
    return 0;
}

cfg_t *
parse_config(const char *cfg_file)
{
    if (cfg_file == NULL) {
        fatal("cfg_file == NULL");
    }

    /* setup config options */
    cfg_opt_t opts[] = {
        CFG_STR("syslog_facility", "LOG_LOCAL1", CFGF_NONE),

        CFG_STR("ldap_uri", "ldap://localhost:389", CFGF_NONE),
        CFG_INT("ldap_starttls", 1, CFGF_NONE),
        CFG_STR("ldap_bind_dn", "cn=directory-manager,dc=keeto,dc=io", CFGF_NONE),
        CFG_STR("ldap_bind_pwd", "test123", CFGF_NONE),
        CFG_INT("ldap_search_timeout", 5, CFGF_NONE),
        CFG_INT("ldap_strict", 0, CFGF_NONE),

        CFG_STR("ldap_ssh_server_base_dn", "ou=server,ou=ssh,dc=keeto,dc=io",
            CFGF_NONE),
        CFG_INT_CB("ldap_ssh_server_search_scope", LDAP_SCOPE_ONE, CFGF_NONE,
            &cfg_str_to_int_cb_libldap),
        CFG_STR("ssh_server_uid", "keeto-test-server", CFGF_NONE),

        CFG_STR("ldap_target_keystore_group_member_attr", "member", CFGF_NONE),
        CFG_STR("ldap_target_keystore_uid_attr", "uid", CFGF_NONE),

        CFG_STR("ldap_key_provider_group_member_attr", "member", CFGF_NONE),
        CFG_STR("ldap_key_provider_uid_attr", "uid", CFGF_NONE),
        CFG_STR("ldap_key_provider_cert_attr", "userCertificate;binary",
            CFGF_NONE),

        CFG_STR("ssh_keystore_location", "/etc/ssh/authorized_keys/%u",
            CFGF_NONE),
        CFG_STR("cert_store_dir", "/etc/ssh/cert_store", CFGF_NONE),
        CFG_INT("check_crl", 1, CFGF_NONE),

        CFG_STR("uid_regex", "^[a-z][-a-z0-9]{0,31}$", CFGF_NONE),
        CFG_END()
    };

    /* initialize config */
    cfg_t *cfg = cfg_init(opts, CFGF_NONE);
    if (cfg == NULL) {
        log_error("failed to initialize config");
        return NULL;
    }

    /* register callbacks */
    cfg_set_error_function(cfg, &cfg_error_handler);
    cfg_set_validate_func(cfg, "syslog_facility",
        &cfg_validate_syslog_facility);
    cfg_set_validate_func(cfg, "ldap_uri", &cfg_validate_ldap_uri);
    cfg_set_validate_func(cfg, "ldap_starttls", &cfg_validate_boolean);
    cfg_set_validate_func(cfg, "ldap_bind_dn", &cfg_validate_ldap_dn);
    cfg_set_validate_func(cfg, "ldap_search_timeout",
        &cfg_validate_ldap_search_timeout);
    cfg_set_validate_func(cfg, "ldap_strict", &cfg_validate_boolean);
    cfg_set_validate_func(cfg, "ldap_ssh_server_base_dn",
        &cfg_validate_ldap_dn);
    cfg_set_validate_func(cfg, "cert_store_dir", &cfg_validate_cert_store_dir);
    cfg_set_validate_func(cfg, "check_crl", &cfg_validate_boolean);
    cfg_set_validate_func(cfg, "uid_regex", &cfg_validate_regex);

    /* parse config */
    int rc = cfg_parse(cfg, cfg_file);
    if (rc != CFG_SUCCESS) {
        free_config(cfg);
        return NULL;
    }

    return cfg;
}

void
free_config(cfg_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    cfg_free(cfg);
}

