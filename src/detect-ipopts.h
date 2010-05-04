/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __DETECT_IPOPTS_H__
#define __DETECT_IPOPTS_H__

#include "decode-events.h"
#include "decode-ipv4.h"

/**
 * \struct DetectIpOptsData_
 * DetectIpOptsData_ is used to store ipopts: input value
 */

/**
 * \typedef DetectIpOptsData
 * A typedef for DetectIpOptsData_
 */

typedef struct DetectIpOptsData_ {
    uint8_t ipopt;  /**< Ip option */
} DetectIpOptsData;

/**
 * Registration function for ipopts: keyword
 */

void DetectIpOptsRegister (void);

#ifdef DETECT_EVENTS

/**
 * Used to check ipopts:any
 */

#define IPV4_OPT_ANY    0xff

/**
 * \struct DetectIpOptss_
 * DetectIpOptss_ is used to store supported iptops values
 */

struct DetectIpOptss_ {
    char *ipopt_name;   /**< Ip option name */
    uint8_t code;   /**< Ip option value */
} DIpOpts[] = {
    { "rr", IPV4_OPT_RR, },
    { "lsrr", IPV4_OPT_LSRR, },
    { "eol", IPV4_OPT_EOL, },
    { "nop", IPV4_OPT_NOP, },
    { "ts", IPV4_OPT_TS, },
    { "sec", IPV4_OPT_SEC, },
    { "ssrr", IPV4_OPT_SSRR, },
    { "satid", IPV4_OPT_SID, },
    { "any", IPV4_OPT_ANY, },
    { NULL, 0 },
};
#endif /* DETECT_EVENTS */
#endif /*__DETECT_IPOPTS_H__ */

