/* Copyright (C) 2021-2024 Open Information Security Foundation
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

#ifndef SURICATA_UTIL_DATALINK_H
#define SURICATA_UTIL_DATALINK_H

#include "util-debug.h"

/* pcap provides this, but we don't want to depend on libpcap */
#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

#ifndef DLT_C_HDLC
#define DLT_C_HDLC 104
#endif

/* taken from pcap's bpf.h */
#ifndef DLT_RAW
#ifdef __OpenBSD__
#define DLT_RAW 14 /* raw IP */
#else
#define DLT_RAW 12 /* raw IP */
#endif
#endif

#ifndef DLT_NULL
#define DLT_NULL 0
#endif

/** libpcap shows us the way to linktype codes
 * \todo we need more & maybe put them in a separate file? */
#define LINKTYPE_NULL      DLT_NULL
#define LINKTYPE_ETHERNET  DLT_EN10MB
#define LINKTYPE_LINUX_SLL 113
#define LINKTYPE_PPP       9
#define LINKTYPE_RAW       DLT_RAW
/* http://www.tcpdump.org/linktypes.html defines DLT_RAW as 101, yet others don't.
 * Libpcap on at least OpenBSD returns 101 as datalink type for RAW pcaps though. */
#define LINKTYPE_RAW2        101
#define LINKTYPE_IPV4        228
#define LINKTYPE_IPV6        229
#define LINKTYPE_GRE_OVER_IP 778
#define LINKTYPE_CISCO_HDLC  DLT_C_HDLC

void DatalinkSetGlobalType(int datalink);
int DatalinkGetGlobalType(void);
bool DatalinkHasMultipleValues(void);

static inline const char *LinktypeName(const int datalink)
{
    /* call the decoder */
    switch (datalink) {
        case LINKTYPE_ETHERNET:
            return "EN10MB";
            break;
        case LINKTYPE_LINUX_SLL:
            return "LINUX_SLL";
            break;
        case LINKTYPE_PPP:
            return "PPP";
            break;
        case LINKTYPE_RAW2:
            return "RAW2";
            break;
        case LINKTYPE_RAW:
            return "RAW";
            break;
        case LINKTYPE_GRE_OVER_IP:
            return "GRE_RAW";
            break;
        case LINKTYPE_NULL:
            return "NULL";
            break;
        case LINKTYPE_CISCO_HDLC:
            return "C_HDLC";
            break;
        case LINKTYPE_IPV4:
            return "IPv4";
            break;
        case LINKTYPE_IPV6:
            return "IPv6";
            break;
        default:
            SCLogError("datalink type "
                       "%" PRId32 " not yet supported",
                    datalink);
            return "NULL";
            break;
    }
}

#endif /* SURICATA_UTIL_DATALINK_H */
