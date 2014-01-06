/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __ALERT_UNIFIED2_ALERT_H__
#define __ALERT_UNIFIED2_ALERT_H__

/** Unified2 Option packet action */
#define UNIFIED2_PACKET_FLAG 1
#define UNIFIED2_BLOCKED_FLAG 0x20

/** Unified2 Header Types */
#define UNIFIED2_EVENT_TYPE 1
#define UNIFIED2_PACKET_TYPE 2
#define UNIFIED2_IDS_EVENT_TYPE 7
#define UNIFIED2_EVENT_EXTENDED_TYPE 66
#define UNIFIED2_PERFORMANCE_TYPE 67
#define UNIFIED2_PORTSCAN_TYPE 68
#define UNIFIED2_IDS_EVENT_IPV6_TYPE 72
#define UNIFIED2_IDS_EVENT_MPLS_TYPE 99
#define UNIFIED2_IDS_EVENT_IPV6_MPLS_TYPE 100
#define UNIFIED2_IDS_EVENT_EXTRADATA_TYPE 110
#define UNIFIED2_EXTRADATA_CLIENT_IPV4_TYPE 1
#define UNIFIED2_EXTRADATA_CLIENT_IPV6_TYPE 1
#define UNIFIED2_EXTRADATA_TYPE_BLOB 1
#define UNIFIED2_EXTRADATA_TYPE_EXTRA_DATA 4

void TmModuleUnified2AlertRegister(void);
OutputCtx *Unified2AlertInitCtx(ConfNode *);

#endif /* __ALERT_UNIFIED2_ALERT_H__ */

