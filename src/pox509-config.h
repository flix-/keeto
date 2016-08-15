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
 * Config file processing.
 *
 * @file pox509-config.h
 * @author Sebastian Roland <seroland86@gmail.com>
 * @date 2015-06-15
 * @see https://github.com/flix-/pam-openssh-x509
 */

#ifndef POX509_CONFIG_H
#define POX509_CONFIG_H

#include <confuse.h>

/**
 * Parse configuration file.
 *
 * @param[in] cfg_file Path to configuration file. Must not be @c NULL.
 */
cfg_t *parse_config(const char *cfg_file);

/**
 * Release allocated memory from configuration structure.
 *
 * @param[in] cfg Configuration structure. Must not be @c NULL.
 */
void release_config(cfg_t *cfg);
#endif
