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

#ifndef SURICATA_LOGGER_H
#define SURICATA_LOGGER_H

typedef void (*log_debug)(char *str, ...);
typedef void (*log_info)(char *str, ...);
typedef void (*log_notice)(char *str, ...);
typedef void (*log_warning)(int code, char *str, ...);
typedef void (*log_error)(int code, char *str, ...);

typedef enum { PF_DEBUG, PF_INFO, PF_NOTICE, PF_WARNING, PF_ERROR } LogLevelEnum;
extern LogLevelEnum LogLevel;

struct logger_ops {
    log_debug debug;
    log_info info;
    log_notice notice;
    log_warning warning;
    log_error error;
};

void LoggerInit(struct logger_ops ops, LogLevelEnum lvl);
LogLevelEnum LoggerGetLogLevelFromString(const char *str);
struct logger_ops Log();

#endif // SURICATA_LOGGER_H
