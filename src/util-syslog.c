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
 * Syslog utility file
 *
 */

#include "suricata-common.h"
#include "util-syslog.h"

/* holds the string-enum mapping for the syslog facility in SCLogOPIfaceCtx */
SCEnumCharMap sc_syslog_facility_map[] = {
    { "auth",           LOG_AUTH },
    { "authpriv",       LOG_AUTHPRIV },
    { "cron",           LOG_CRON },
    { "daemon",         LOG_DAEMON },
    { "ftp",            LOG_FTP },
    { "kern",           LOG_KERN },
    { "lpr",            LOG_LPR },
    { "mail",           LOG_MAIL },
    { "news",           LOG_NEWS },
    { "security",       LOG_AUTH },
    { "syslog",         LOG_SYSLOG },
    { "user",           LOG_USER },
    { "uucp",           LOG_UUCP },
    { "local0",         LOG_LOCAL0 },
    { "local1",         LOG_LOCAL1 },
    { "local2",         LOG_LOCAL2 },
    { "local3",         LOG_LOCAL3 },
    { "local4",         LOG_LOCAL4 },
    { "local5",         LOG_LOCAL5 },
    { "local6",         LOG_LOCAL6 },
    { "local7",         LOG_LOCAL7 },
    { NULL,             -1         }
};

/** \brief returns the syslog facility enum map */
SCEnumCharMap *SCSyslogGetFacilityMap(void)
{
    return sc_syslog_facility_map;
}

SCEnumCharMap sc_syslog_level_map[ ] = {
    { "Emergency",      LOG_EMERG },
    { "Alert",          LOG_ALERT },
    { "Critical",       LOG_CRIT },
    { "Error",          LOG_ERR },
    { "Warning",        LOG_WARNING },
    { "Notice",         LOG_NOTICE },
    { "Info",           LOG_INFO },
    { "Debug",          LOG_DEBUG },
    { NULL,             -1 }
};

/** \brief returns the syslog facility enum map */
SCEnumCharMap *SCSyslogGetLogLevelMap(void)
{
    return sc_syslog_level_map;
}

