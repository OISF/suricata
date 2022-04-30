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
 */

#ifndef __UTIL_MEMCAP_H__
#define __UTIL_MEMCAP_H__

enum MemcapPolicy {
    MEMCAP_POLICY_IGNORE = 0,
    MEMCAP_POLICY_PASS_PACKET,
    MEMCAP_POLICY_PASS_FLOW,
    MEMCAP_POLICY_BYPASS_FLOW,
    MEMCAP_POLICY_DROP_PACKET,
    MEMCAP_POLICY_DROP_FLOW,
};

void MemcapPolicyApply(Packet *p, enum MemcapPolicy policy, enum PacketDropReason drop_reason);
enum MemcapPolicy MemcapPolicyParse(const char *option);

#endif
