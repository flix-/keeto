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
 * Log functions.
 *
 * @file pox509-log.h
 * @author Sebastian Roland <seroland86@gmail.com>
 * @date 2015-06-21
 * @see https://github.com/flix-/pam-openssh-x509
 */

#ifndef POX509_LOG_H
#define POX509_LOG_H

/**
 * Log message to syslog.
 *
 * The message is prefixed with '[I]'.
 *
 * @param[in] fmt Format string. Must not be @c NULL.
 * @param[in] ... Format arguments.
 *
 * @see man 3 printf.
 */
void log_info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/**
 * Log message to syslog.
 *
 * The message is prefixed with '[E]'.
 *
 * @param[in] fmt Format string. Must not be @c NULL.
 * @param[in] ... Format arguments.
 *
 * @see man 3 printf.
 */
void log_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/**
 * Wrapper for #pox509_log_debug.
 *
 * @param[in] ... Format string, Format arguments.
 * @see #pox509_log_debug.
 * @see man 3 printf.
 */
#define log_debug(...) pox509_log_debug(__FILE__, __func__, __LINE__, __VA_ARGS__)

/**
 * Wrapper for #pox509_fatal.
 *
 * @param[in] ... Format string, Format arguments.
 *
 * @see #pox509_fatal.
 * @see man 3 printf.
 */
#define fatal(...) pox509_fatal(__FILE__, __func__, __LINE__, __VA_ARGS__)

/**
 * Log message to syslog.
 *
 * The message is prefixed with '[D] [filename, function(), line]'.
 *
 * @param[in] filename Name of the source file the call took place. Must
 * not be @c NULL.
 * @param[in] function Name of the function the call took place. Must
 * not be @c NULL.
 * @param[in] line Number of the line the call took place.
 * @param[in] fmt Format string. Must not be @c NULL.
 * @param[in] ... Format arguments.
 *
 * @note Do NOT call this function directly - use #log_debug wrapper
 * macro instead.
 *
 * @see #log_debug.
 * @see man 3 printf.
 */
void pox509_log_debug(const char *filename, const char *function, int line,
    const char *fmt, ...) __attribute__((format(printf, 4, 5)));

/**
 * Log message to syslog and terminate process.
 *
 * The message is prefixed with '[!] [filename, function(), line]'.
 * After the message has been send to syslog the process will be
 * terminated.
 *
 * @param[in] filename Name of the source file the call took place. Must
 * not be @c NULL.
 * @param[in] function Name of the function the call took place. Must
 * not be @c NULL.
 * @param[in] line Number of the line the call took place.
 * @param[in] fmt Format string. Must not be @c NULL.
 * @param[in] ... Format arguments.
 *
 * @note Do NOT call this function directly - use #fatal wrapper marco
 * instead.
 *
 * @see #fatal.
 * @see man 3 printf.
 */
void pox509_fatal(const char *filename, const char *function, int line,
    const char *fmt, ...) __attribute__((noreturn))
    __attribute__((format(printf, 4, 5)));

/**
 * Set the syslog facility used by the logging functions.
 *
 * @param[in] syslog_facility Log facility name. Must not be @c NULL.
 *
 * @return Upon successful completion, 0 shall be returned with the log
 * facility set. Otherwise, -EINVAL shall be returned.
 *
 * @see man 3 syslog.
 */
int set_syslog_facility(const char *syslog_facility);
#endif
