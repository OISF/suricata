/* Copyright (C) 2022-2022 Open Information Security Foundation
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

#ifndef __UTIL_EXCEPTION_POLICY_H__
#define __UTIL_EXCEPTION_POLICY_H__

enum ExceptionPolicy {
    EXCEPTION_POLICY_IGNORE = 0,
    EXCEPTION_POLICY_PASS_PACKET,
    EXCEPTION_POLICY_PASS_FLOW,
    EXCEPTION_POLICY_BYPASS_FLOW,
    EXCEPTION_POLICY_DROP_PACKET,
    EXCEPTION_POLICY_DROP_FLOW,
};

void ExceptionPolicyApply(
        Packet *p, enum ExceptionPolicy policy, enum PacketDropReason drop_reason);
enum ExceptionPolicy ExceptionPolicyParse(const char *option, const bool support_flow);

#ifdef DEBUG
extern uint64_t g_eps_applayer_error_offset_ts;
extern uint64_t g_eps_applayer_error_offset_tc;
extern uint64_t g_eps_pcap_packet_loss;
extern uint64_t g_eps_stream_ssn_memcap;
extern uint64_t g_eps_stream_reassembly_memcap;
extern uint64_t g_eps_flow_memcap;
extern uint64_t g_eps_defrag_memcap;
extern bool g_eps_is_alert_queue_fail_mode;
#endif

int ExceptionSimulationCommandlineParser(const char *name, const char *arg);

#endif
