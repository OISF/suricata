/* Copyright (C) 2021 Open Information Security Foundation
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
#define LINKTYPE_LINUX_SLL2 276
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
void DatalinkTableInit(void);
void DatalinkTableDeinit(void);
const char *DatalinkValueToName(int datalink_value);

#endif /* SURICATA_UTIL_DATALINK_H */
