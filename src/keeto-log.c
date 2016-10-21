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

static int pox509_syslog_facility = LOG_LOCAL1;

static void
pox509_log(char *prefix, const char *fmt, va_list ap)
{
    if (prefix == NULL || fmt == NULL) {
        fatal("prefix or fmt == NULL");
    }

    static bool initialized = false;
    if (!initialized) {
        openlog("keeto", LOG_PID, pox509_syslog_facility);
        initialized = true;
    }
    char buffer[LOG_BUFFER_SIZE];
    vsnprintf(buffer, LOG_BUFFER_SIZE, fmt, ap);
    syslog(pox509_syslog_facility, "%s %s\n", prefix, buffer);
}

void
log_info(const char *fmt, ...)
{
    if (fmt == NULL) {
        fatal("fmt == NULL");
    }

    va_list ap;
    va_start(ap, fmt);
    pox509_log("[I]", fmt, ap);
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
    pox509_log("[E]", fmt, ap);
    va_end(ap);
}

void
pox509_log_debug(const char *filename, const char *function, int line,
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
    pox509_log(prefix, fmt, ap);
    va_end(ap);
}

void
pox509_fatal(const char *filename, const char *function, int line,
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
    pox509_log(prefix, fmt, ap);
    va_end(ap);
    exit(EXIT_FAILURE);
}

int
set_syslog_facility(const char *syslog_facility)
{
    if (syslog_facility == NULL) {
        fatal("syslog_facility == NULL");
    }

    int value = str_to_enum(POX509_SYSLOG, syslog_facility);
    if (value == POX509_NO_SUCH_VALUE) {
        return POX509_NO_SUCH_VALUE;
    }
    pox509_syslog_facility = value;
    return POX509_OK;
}

