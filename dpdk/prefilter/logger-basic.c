/* Copyright (C) 2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Lukas Sismis <sismis@cesnet.com>
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "logger-basic.h"

#ifndef LOGGER_BASIC_C
#define LOGGER_BASIC_C

#define PF_LOG_MAX_LOG_MSG_LEN 2048

struct logger_ops logger_basic_ops = { .debug = LoggerBasicDebug,
    .info = LoggerBasicInfo,
    .notice = LoggerBasicNotice,
    .warning = LoggerBasicWarning,
    .error = LoggerBasicError };

void LoggerBasicDebug(char *format, ...)
{
    if (LogLevel > PF_DEBUG)
        return;

    char msg[PF_LOG_MAX_LOG_MSG_LEN] = "DEBUG - ";
    char *msg_text = msg + strlen(msg);
    va_list ap;
    va_start(ap, format);
    vsnprintf(msg_text, sizeof(msg) - strlen(msg), format, ap);
    va_end(ap);
    fprintf(stdout, "%s\n", msg);
}

void LoggerBasicInfo(char *format, ...)
{
    if (LogLevel > PF_INFO)
        return;

    char msg[PF_LOG_MAX_LOG_MSG_LEN] = "INFO - ";
    char *msg_text = msg + strlen(msg);
    va_list ap;
    va_start(ap, format);
    vsnprintf(msg_text, sizeof(msg) - strlen(msg), format, ap);
    va_end(ap);
    fprintf(stdout, "%s\n", msg);
}

void LoggerBasicNotice(char *format, ...)
{
    if (LogLevel > PF_NOTICE)
        return;

    char msg[PF_LOG_MAX_LOG_MSG_LEN] = "NOTICE - ";
    char *msg_text = msg + strlen(msg);
    va_list ap;
    va_start(ap, format);
    vsnprintf(msg_text, sizeof(msg) - strlen(msg), format, ap);
    va_end(ap);
    fprintf(stdout, "%s\n", msg);
}

void LoggerBasicWarning(int code, char *format, ...)
{
    if (LogLevel > PF_WARNING)
        return;

    char msg[PF_LOG_MAX_LOG_MSG_LEN] = "WARNING - ";
    char *msg_text = msg + strlen(msg);
    va_list ap;
    va_start(ap, format);
    vsnprintf(msg_text, sizeof(msg) - strlen(msg), format, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", msg);
}

void LoggerBasicError(int code, char *format, ...)
{
    if (LogLevel > PF_ERROR)
        return;

    char msg[PF_LOG_MAX_LOG_MSG_LEN] = "ERROR - ";
    char *msg_text = msg + strlen(msg);
    va_list ap;
    va_start(ap, format);
    vsnprintf(msg_text, sizeof(msg) - strlen(msg), format, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", msg);
}

#endif /* LOGGER_BASIC_C */