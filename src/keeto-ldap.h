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

#ifndef KEETO_LDAP_H
#define KEETO_LDAP_H

#include "keeto-util.h"

#define LDAP_BOOL_TRUE "TRUE"

#define KEETO_SSH_SERVER_OBJCLASS "keetoSSHServer"
#define KEETO_AP_OBJCLASS "keetoAccessProfile"
#define KEETO_DAP_OBJCLASS "keetoDirectAccessProfile"
#define KEETO_AOBP_OBJCLASS "keetoAccessOnBehalfProfile"
#define KEETO_KEYSTORE_OPTIONS_OBJCLASS "keetoKeystoreOptions"

#define KEETO_SSH_SERVER_UID_ATTR "uid"
#define KEETO_SSH_SERVER_AP_ATTR "keetoAccessProfile"
#define KEETO_AP_KEY_PROVIDER_ATTR "keetoKeyProvider"
#define KEETO_AP_KEY_PROVIDER_GROUP_ATTR "keetoKeyProviderGroup"
#define KEETO_AP_KEYSTORE_OPTIONS_ATTR "keetoKeystoreOptions"
#define KEETO_AP_ENABLED_ATTR "keetoEnabled"
#define KEETO_AOBP_TARGET_KEYSTORE_ATTR "keetoTargetKeystore"
#define KEETO_AOBP_TARGET_KEYSTORE_GROUP_ATTR "keetoTargetKeystoreGroup"
#define KEETO_KEYSTORE_OPTIONS_FROM_ATTR "keetoKeystoreOptionFrom"
#define KEETO_KEYSTORE_OPTIONS_CMD_ATTR "keetoKeystoreOptionCommand"

int get_access_profiles_from_ldap(struct keeto_info *info);

#endif

