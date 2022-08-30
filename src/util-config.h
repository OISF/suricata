/* Copyright (C) 2020-2022 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __UTIL_CONFIG_H__
#define __UTIL_CONFIG_H__

enum ConfigAction {
    CONFIG_ACTION_UNSET = 0,
    CONFIG_ACTION_SET = 1,
};

enum ConfigSubsys {
    CONFIG_SUBSYS_LOGGING = 0,
};

enum ConfigType {
    CONFIG_TYPE_TX = 0,     /* transaction logging */
    CONFIG_TYPE_FLOW,       /* flow logging */
    CONFIG_TYPE_ALERT,      /* alert logging */
    CONFIG_TYPE_ANOMALY,    /* anomaly logging */
    CONFIG_TYPE_FILE,       /* file logging */
    CONFIG_TYPE_PCAP,       /* pcap logging */
    CONFIG_TYPE_DROP,       /* drop logging */
#define CONFIG_TYPE_DEFAULT CONFIG_TYPE_TX
};

enum ConfigScope {
    CONFIG_SCOPE_TX = 0,    /* per transaction */
    CONFIG_SCOPE_FLOW,      /* per flow */
#define CONFIG_SCOPE_DEFAULT CONFIG_SCOPE_TX
};

#endif
