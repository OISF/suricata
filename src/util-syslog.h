/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 */

#ifndef UTIL_SYSLOG_H
#define	UTIL_SYSLOG_H

#include "util-enum.h"

SCEnumCharMap *SCSyslogGetFacilityMap(void);
SCEnumCharMap *SCSyslogGetLogLevelMap(void);

#ifndef OS_WIN32
#define DEFAULT_ALERT_SYSLOG_FACILITY_STR "local0"
#define DEFAULT_ALERT_SYSLOG_FACILITY     LOG_LOCAL0
#define DEFAULT_ALERT_SYSLOG_LEVEL        LOG_ERR
#endif

#endif	/* UTIL_SYSLOG_H */
