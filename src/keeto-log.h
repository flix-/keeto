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

#ifndef KEETO_LOG_H
#define KEETO_LOG_H

#define log_debug(...) \
do { \
if (DEBUG) pox509_log_debug(__FILE__, __func__, __LINE__, __VA_ARGS__); \
} while (0)
#define fatal(...) pox509_fatal(__FILE__, __func__, __LINE__, __VA_ARGS__)

void log_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void log_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void pox509_log_debug(const char *filename, const char *function, int line,
    const char *fmt, ...) __attribute__((format(printf, 4, 5)));
void pox509_fatal(const char *filename, const char *function, int line,
    const char *fmt, ...) __attribute__((noreturn))
    __attribute__((format(printf, 4, 5)));
int set_syslog_facility(const char *syslog_facility);
#endif

