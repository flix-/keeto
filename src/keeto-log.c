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

#include "keeto-log.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <syslog.h>

#include "keeto-error.h"
#include "keeto-util.h"

#define LOG_BUFFER_SIZE 4096
#define LOG_PREFIX_BUFFER_SIZE 1024

static int keeto_syslog_facility = LOG_LOCAL1;

static void
keeto_log(int level, char *prefix, const char *fmt, va_list ap)
{
    if (fmt == NULL) {
        fatal("fmt == NULL");
    }

    static bool initialized = false;
    if (!initialized) {
        openlog(KEETO_SYSLOG_IDENTIFIER, LOG_PID, keeto_syslog_facility);
        initialized = true;
    }
    char buffer[LOG_BUFFER_SIZE];
    vsnprintf(buffer, LOG_BUFFER_SIZE, fmt, ap);
    if (prefix == NULL) {
        syslog(keeto_syslog_facility | level, "%s\n", buffer);
    } else {
        syslog(keeto_syslog_facility | level, "%s %s\n", prefix, buffer);
    }
}

void
keeto_log_debug(const char *filename, const char *function, int line,
    const char *fmt, ...)
{
    if (filename == NULL || function == NULL || fmt == NULL) {
        fatal("filename, function or fmt == NULL");
    }

    char prefix[LOG_PREFIX_BUFFER_SIZE];
    snprintf(prefix, sizeof prefix, "[D] [%s, %s(), %d]", filename, function,
        line);
    va_list ap;
    va_start(ap, fmt);
    keeto_log(LOG_DEBUG, prefix, fmt, ap);
    va_end(ap);
}

void
log_raw(const char *fmt, ...)
{
    if (fmt == NULL) {
        fatal("fmt == NULL");
    }

    va_list ap;
    va_start(ap, fmt);
    keeto_log(LOG_INFO, NULL, fmt, ap);
    va_end(ap);
}

void
log_info(const char *fmt, ...)
{
    if (fmt == NULL) {
        fatal("fmt == NULL");
    }

    va_list ap;
    va_start(ap, fmt);
    keeto_log(LOG_INFO, "[I]", fmt, ap);
    va_end(ap);
}

void
log_error(const char *fmt, ...)
{
    if (fmt == NULL) {
        fatal("fmt == NULL");
    }

    va_list ap;
    va_start(ap, fmt);
    keeto_log(LOG_ERR, "[E]", fmt, ap);
    va_end(ap);
}

void
log_critical(const char *fmt, ...)
{
    if (fmt == NULL) {
        fatal("fmt == NULL");
    }

    va_list ap;
    va_start(ap, fmt);
    keeto_log(LOG_CRIT, "[C]", fmt, ap);
    va_end(ap);
}

void
keeto_fatal(const char *filename, const char *function, int line,
    const char *fmt, ...)
{
    if (filename == NULL || function == NULL || fmt == NULL) {
        fatal("filename, function or fmt == NULL");
    }

    char prefix[LOG_PREFIX_BUFFER_SIZE];
    snprintf(prefix, sizeof prefix, "[!] [%s, %s(), %d]", filename, function,
        line);
    va_list ap;
    va_start(ap, fmt);
    keeto_log(LOG_EMERG, prefix, fmt, ap);
    va_end(ap);
    exit(EXIT_FAILURE);
}

int
set_syslog_facility(const char *syslog_facility)
{
    if (syslog_facility == NULL) {
        fatal("syslog_facility == NULL");
    }

    int value = str_to_enum(KEETO_SYSLOG, syslog_facility);
    if (value == KEETO_NO_SUCH_VALUE) {
        return KEETO_NO_SUCH_VALUE;
    }
    keeto_syslog_facility = value;
    return KEETO_OK;
}

