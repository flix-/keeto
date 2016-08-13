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
 * @file pox509-result.c
 * @author Sebastian Roland <seroland86@gmail.com>
 * @date 2016-08-13
 * @see https://github.com/flix-/pam-openssh-x509
 */

#include "pox509-result.h"

const char *
result_to_string(int result)
{
    switch(result) {
    case POX509_SUCCESS:
        return "POX509_SUCCESS";

    default:
        return "POX509_UNKNOWN_ERR";
    }
}

