/* Copyright (C) 2022-2025 Open Information Security Foundation
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

#include "decode.h"
#include "util-exception-policy-types.h"

const char *ExceptionPolicyEnumToString(enum ExceptionPolicy policy, bool is_json);
const char *ExceptionPolicyTargetFlagToString(uint8_t target_flag);
enum ExceptionPolicy ExceptionPolicyTargetPolicy(uint8_t target_flag);
void SetMasterExceptionPolicy(void);
void ExceptionPolicyApply(
        Packet *p, enum ExceptionPolicy policy, enum PacketDropReason drop_reason);
enum ExceptionPolicy ExceptionPolicyParse(const char *option, const bool support_flow);
enum ExceptionPolicy ExceptionPolicyMidstreamParse(bool midstream_enabled);
void ExceptionPolicySetStatsCounters(ThreadVars *tv, ExceptionPolicyCounters *counter,
        ExceptionPolicyStatsSetts *setting, enum ExceptionPolicy conf_policy,
        const char *default_str, bool (*isExceptionPolicyValid)(enum ExceptionPolicy));

extern enum ExceptionPolicy g_eps_master_switch;
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

int ExceptionSimulationCommandLineParser(const char *name, const char *arg);

#endif
