/*
 * Copyright (C) 2018 Sebastian Roland <seroland86@gmail.com>
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

#ifndef KEETO_SERVICE_H
#define KEETO_SERVICE_H

void remove_keystore(char *keystore);
int write_keystore(char *keystore,
    struct keeto_keystore_records *keystore_records);
int post_process_access_profiles(struct keeto_info *info);

#endif /* KEETO_SERVICE_H */

