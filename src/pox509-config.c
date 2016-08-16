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

#include "pox509-config.h"

#include <errno.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <ldap.h>

#include "pox509-error.h"
#include "pox509-log.h"
#include "pox509-util.h"

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
        log_debug("cfg_opt_getnstr() returned NULL");
        return -1;
    }

    int rc = str_to_enum(POX509_SYSLOG, syslog_facility);
    if (rc == POX509_NO_SUCH_VALUE) {
        log_error("str_to_enum(): option: '%s', value: '%s' (%s)",
            cfg_opt_name(opt), syslog_facility, pox509_strerror(rc));
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
        log_debug("cfg_opt_getnstr() returned NULL");
        return -1;
    }

    int rc = ldap_is_ldap_url(ldap_uri);
    if (rc == 0) {
        log_error("ldap_is_ldap_url(): option: '%s', value: '%s' (value is not "
            "an ldap uri)", cfg_opt_name(opt), ldap_uri);
        return -1;
    }
    return 0;
}

static int
cfg_validate_ldap_starttls(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg == NULL || opt == NULL) {
        fatal("cfg or opt == NULL");
    }

    long int starttls = cfg_opt_getnint(opt, 0);
    if (starttls != 0 && starttls != 1) {
        log_error("cfg_validate_ldap_starttls(): option: '%s', value: '%li' "
            "(value must be either 0 or 1)", cfg_opt_name(opt), starttls);
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
        log_debug("cfg_opt_getnstr() returned NULL");
        return -1;
    }

    size_t dn_str_length = strlen(dn_str);
    if (dn_str_length == 0) {
        log_error("strlen(): option: '%s', value: '%s' (length of dn must be "
            "> 0)", cfg_opt_name(opt), dn_str);
        return -1;
    }

    LDAPDN dn = NULL;
    int rc = ldap_str2dn(dn_str, &dn, LDAP_DN_FORMAT_LDAPV3);
    if (rc != LDAP_SUCCESS) {
        log_error("ldap_str2dn(): option: '%s', value: '%s' ('%s' (%d))",
            cfg_opt_name(opt), dn_str, ldap_err2string(rc), rc);
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
        log_error("cfg_opt_getnint(): option: '%s', value: '%li' (value must "
            "be > 0)", cfg_opt_name(opt), timeout);
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
        log_error("str_to_enum(): option: '%s', value: '%s' (%s)",
            cfg_opt_name(opt), value, pox509_strerror(ldap_option));
        return -1;
    }
    long int *ptr_result = result;
    *ptr_result = ldap_option;
    return 0;
}

static int
cfg_validate_cacerts_dir(cfg_t *cfg, cfg_opt_t *opt)
{
    if (cfg == NULL || opt == NULL) {
        fatal("cfg or opt == NULL");
    }

    const char *cacerts_dir = cfg_opt_getnstr(opt, 0);
    if (cacerts_dir == NULL) {
        log_debug("cfg_opt_getnstr() returned NULL");
        return -1;
    }
    /* check if directory exists */
    DIR *cacerts_dir_stream = opendir(cacerts_dir);
    if (cacerts_dir_stream == NULL) {
        log_error("opendir(): option: '%s', value: '%s' (%s)",
            cfg_opt_name(opt), cacerts_dir, strerror(errno));
        return -1;
    }
    closedir(cacerts_dir_stream);

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
        CFG_INT("ldap_starttls", 0, CFGF_NONE),
        CFG_STR("ldap_bind_dn", "cn=directory-manager,dc=ssh,dc=hq", CFGF_NONE),
        CFG_STR("ldap_bind_pwd", "test123", CFGF_NONE),
        CFG_INT("ldap_search_timeout", 5, CFGF_NONE),

        CFG_STR("ldap_ssh_server_base_dn", "ou=server,ou=ssh,dc=ssh,dc=hq",
            CFGF_NONE),
        CFG_INT_CB("ldap_ssh_server_search_scope", LDAP_SCOPE_ONE, CFGF_NONE,
            &cfg_str_to_int_cb_libldap),
        CFG_STR("ldap_ssh_server_uid_attr", "cn", CFGF_NONE),
        CFG_STR("ldap_ssh_server_access_profile_attr", "member", CFGF_NONE),

        CFG_STR("ldap_target_group_member_attr", "member", CFGF_NONE),
        CFG_STR("ldap_target_uid_attr", "uid", CFGF_NONE),

        CFG_STR("ldap_provider_group_member_attr", "member", CFGF_NONE),
        CFG_STR("ldap_provider_uid_attr", "uid", CFGF_NONE),
        CFG_STR("ldap_provider_cert_attr", "userCertificate;binary", CFGF_NONE),

        CFG_STR("ssh_server_uid", "pox509-test-server", CFGF_NONE),
        CFG_STR("keystore_location", "/usr/local/etc/ssh/authorized_keys/%u",
            CFGF_NONE),
        CFG_STR("cacerts_dir", "/usr/local/etc/ssh/cacerts", CFGF_NONE),
        CFG_END()
    };

    /* initialize config */
    cfg_t *cfg = cfg_init(opts, CFGF_NONE);
    if (cfg == NULL) {
        log_error("cfg_init() returned NULL");
        return NULL;
    }

    /* register callbacks */
    cfg_set_error_function(cfg, &cfg_error_handler);
    cfg_set_validate_func(cfg, "syslog_facility",
        &cfg_validate_syslog_facility);
    cfg_set_validate_func(cfg, "ldap_uri", &cfg_validate_ldap_uri);
    cfg_set_validate_func(cfg, "ldap_starttls", &cfg_validate_ldap_starttls);
    cfg_set_validate_func(cfg, "ldap_bind_dn", &cfg_validate_ldap_dn);
    cfg_set_validate_func(cfg, "ldap_search_timeout",
        &cfg_validate_ldap_search_timeout);
    cfg_set_validate_func(cfg, "ldap_ssh_server_base_dn",
        &cfg_validate_ldap_dn);
    cfg_set_validate_func(cfg, "cacerts_dir", &cfg_validate_cacerts_dir);

    /* parse config */
    int rc = cfg_parse(cfg, cfg_file);
    if (rc == CFG_SUCCESS) {
        return cfg;
    }

    /* error handling */
    switch(rc) {
    case CFG_FILE_ERROR:
        log_error("cfg_parse(): '%s' (%s)", cfg_file, strerror(errno));
        break;
    case CFG_PARSE_ERROR:
        log_error("cfg_parse(): 'parse error'");
        break;
    default:
        log_error("cfg_parse(): 'unknown error' (%d)", rc);
    }
    cfg_free(cfg);

    return NULL;
}

void
release_config(cfg_t *cfg)
{
    if (cfg == NULL) {
        log_debug("double free?");
        return;
    }

    /* free cfg structure */
    cfg_free(cfg);
}

