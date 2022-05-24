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

#include <string.h>
#include <stdio.h>
#include "logger.h"

LogLevelEnum LogLevel;
struct logger_ops logger;

LogLevelEnum LoggerGetLogLevelFromString(const char *str)
{
    if (strcmp(str, "debug") == 0) {
        return PF_DEBUG;
    } else if (strcmp(str, "info") == 0) {
        return PF_INFO;
    } else if (strcmp(str, "notice") == 0) {
        return PF_NOTICE;
    } else if (strcmp(str, "warning") == 0) {
        return PF_WARNING;
    } else if (strcmp(str, "error") == 0) {
        return PF_ERROR;
    } else {
        fprintf(stderr, "Log level \"%s\"not supported, setting to info\n", str);
        return PF_INFO;
    }
}

void LoggerInit(struct logger_ops ops, LogLevelEnum lvl)
{
    logger = ops;
    LogLevel = lvl;
}

struct logger_ops Log()
{
    return logger;
}