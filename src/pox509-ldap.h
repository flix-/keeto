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
 * LDAP processing.
 *
 * @file pox509-ldap.h
 * @author Sebastian Roland <seroland86@gmail.com>
 * @date 2015-06-15
 * @see https://github.com/flix-/pam-openssh-x509
 */

#ifndef POX509_LDAP_H
#define POX509_LDAP_H

#include "queue.h"
#include <confuse.h>

#include "pox509-util.h"

#define LDAP_BOOL_TRUE "TRUE"

#define POX509_DAP_OBJCLASS "pox509DirectAccessProfile"
#define POX509_AOBP_OBJCLASS "pox509AccessOnBehalfProfile"

#define POX509_AP_KEY_PROVIDER_ATTR "pox509KeyProvider"
#define POX509_AP_KEYSTORE_OPTIONS_ATTR "pox509KeystoreOptions"
#define POX509_AP_IS_ENABLED "pox509IsEnabled"
#define POX509_AOBP_TARGET_KEYSTORE_ATTR "pox509TargetKeystore"

#define POX509_KEYSTORE_OPTIONS_FROM_ATTR "pox509KeystoreOptionFrom"
#define POX509_KEYSTORE_OPTIONS_CMD_ATTR "pox509KeystoreOptionCommand"

/**FIXME
 * Obtain access permission and x509 certificate of user from LDAP.
 *
 * The user object corresponding to the given UID is searched in the
 * LDAP server and access permission as well as the x509 certificate
 * of the user will be retrieved.
 *
 * @param[in] cfg Configuration structure. Must not be @c NULL.
 * @param[out] pox509_info DTO. Access permission will be stored here.
 * Must not be @c NULL.
 * @param[out] x509 The parsed x509 certificate.
 */
int get_keystore_data_from_ldap(cfg_t *cfg, struct pox509_info *pox509_info);
#endif
