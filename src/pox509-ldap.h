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

#ifndef POX509_LDAP_H
#define POX509_LDAP_H

#include "queue.h"
#include <confuse.h>

#include "pox509-util.h"

#define LDAP_BOOL_TRUE "TRUE"

#define POX509_SSH_SERVER_UID_ATTR "uid"
#define POX509_SSH_SERVER_AP_ATTR "pox509AccessProfile"

#define POX509_DAP_OBJCLASS "pox509DirectAccessProfile"
#define POX509_AOBP_OBJCLASS "pox509AccessOnBehalfProfile"

#define POX509_AP_KEY_PROVIDER_ATTR "pox509KeyProvider"
#define POX509_AP_KEYSTORE_OPTIONS_ATTR "pox509KeystoreOptions"
#define POX509_AP_ENABLED "pox509Enabled"
#define POX509_AOBP_TARGET_KEYSTORE_ATTR "pox509TargetKeystore"

#define POX509_KEYSTORE_OPTIONS_FROM_ATTR "pox509KeystoreOptionFrom"
#define POX509_KEYSTORE_OPTIONS_CMD_ATTR "pox509KeystoreOptionCommand"

int get_access_profiles_from_ldap(struct pox509_info *info);
#endif

