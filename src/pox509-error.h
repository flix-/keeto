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
 * Definition of error values.
 *
 * @file pox509-error.h
 * @author Sebastian Roland <seroland86@gmail.com>
 * @date 2016-04-24
 * @see https://github.com/flix-/pam-openssh-x509
 */

#ifndef POX509_ERROR_H
#define POX509_ERROR_H

enum pox509_error {
    POX509_E_SUCCESS = 0,
    POX509_E_UNKNOWN

    /* last element only used for bounds checking */
    POX509_E_LAST
};
#endif
