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

#include "util-exception-policy.h"
#include "suricata-common.h"
#include "suricata.h"
#include "packet.h"
#include "util-misc.h"
#include "stream-tcp-reassemble.h"
#include "action-globals.h"
#include "conf.h"
#include "flow.h"
#include "stream-tcp.h"
#include "defrag-hash.h"
#include "app-layer-parser.h"

enum ExceptionPolicy g_eps_master_switch = EXCEPTION_POLICY_NOT_SET;
/** true if exception policy was defined in config */
static bool g_eps_have_exception_policy = false;
extern bool g_eps_stats_counters;

const char *ExceptionPolicyEnumToString(enum ExceptionPolicy policy, bool is_json)
{
    switch (policy) {
        case EXCEPTION_POLICY_NOT_SET:
            return "ignore";
        case EXCEPTION_POLICY_AUTO:
            return "auto";
        case EXCEPTION_POLICY_REJECT:
            return "reject";
        case EXCEPTION_POLICY_BYPASS_FLOW:
            return "bypass";
        case EXCEPTION_POLICY_DROP_FLOW:
            return is_json ? "drop_flow" : "drop-flow";
        case EXCEPTION_POLICY_DROP_PACKET:
            return is_json ? "drop_packet" : "drop-packet";
        case EXCEPTION_POLICY_PASS_PACKET:
            return is_json ? "pass_packet" : "pass-packet";
        case EXCEPTION_POLICY_PASS_FLOW:
            return is_json ? "pass_flow" : "pass-flow";
    }
    // TODO we shouldn't reach this, but if we do, better not to leave this as simply null...
    return "not set";
}

void SetMasterExceptionPolicy(void)
{
    g_eps_master_switch = ExceptionPolicyParse("exception-policy", true);
}

static enum ExceptionPolicy GetMasterExceptionPolicy(const char *option)
{
    return g_eps_master_switch;
}

static uint8_t ExceptionPolicyFlag(enum PacketDropReason drop_reason)
{
    switch (drop_reason) {
        case PKT_DROP_REASON_DEFRAG_MEMCAP:
            return EXCEPTION_TARGET_FLAG_DEFRAG_MEMCAP;
        case PKT_DROP_REASON_STREAM_MEMCAP:
            return EXCEPTION_TARGET_FLAG_SESSION_MEMCAP;
        case PKT_DROP_REASON_STREAM_REASSEMBLY:
            return EXCEPTION_TARGET_FLAG_REASSEMBLY_MEMCAP;
        case PKT_DROP_REASON_FLOW_MEMCAP:
            return EXCEPTION_TARGET_FLAG_FLOW_MEMCAP;
        case PKT_DROP_REASON_STREAM_MIDSTREAM:
            return EXCEPTION_TARGET_FLAG_MIDSTREAM;
        case PKT_DROP_REASON_APPLAYER_ERROR:
            return EXCEPTION_TARGET_FLAG_APPLAYER_ERROR;
        default:
            return 0;
    }

    return 0;
}

const char *ExceptionPolicyTargetFlagToString(uint8_t target_flag)
{
    switch (target_flag) {
        case EXCEPTION_TARGET_FLAG_DEFRAG_MEMCAP:
            return "defrag_memcap";
        case EXCEPTION_TARGET_FLAG_SESSION_MEMCAP:
            return "stream_memcap";
        case EXCEPTION_TARGET_FLAG_REASSEMBLY_MEMCAP:
            return "stream_reassembly_memcap";
        case EXCEPTION_TARGET_FLAG_FLOW_MEMCAP:
            return "flow_memcap";
        case EXCEPTION_TARGET_FLAG_MIDSTREAM:
            return "stream_midstream";
        case EXCEPTION_TARGET_FLAG_APPLAYER_ERROR:
            return "app_layer_error";
        default:
            return "none";
    }
}

enum ExceptionPolicy ExceptionPolicyTargetPolicy(uint8_t target_flag)
{
    switch (target_flag) {
        case EXCEPTION_TARGET_FLAG_DEFRAG_MEMCAP:
            return DefragGetMemcapExceptionPolicy();
        case EXCEPTION_TARGET_FLAG_SESSION_MEMCAP:
            return StreamTcpSsnMemcapGetExceptionPolicy();
        case EXCEPTION_TARGET_FLAG_REASSEMBLY_MEMCAP:
            return StreamTcpReassemblyMemcapGetExceptionPolicy();
        case EXCEPTION_TARGET_FLAG_FLOW_MEMCAP:
            return FlowGetMemcapExceptionPolicy();
        case EXCEPTION_TARGET_FLAG_MIDSTREAM:
            return StreamMidstreamGetExceptionPolicy();
        case EXCEPTION_TARGET_FLAG_APPLAYER_ERROR:
            return AppLayerErrorGetExceptionPolicy();
        default:
            return EXCEPTION_POLICY_NOT_SET;
    }
    return EXCEPTION_POLICY_NOT_SET;
}

void ExceptionPolicyApply(Packet *p, enum ExceptionPolicy policy, enum PacketDropReason drop_reason)
{
    SCLogDebug("start: pcap_cnt %" PRIu64 ", policy %u", p->pcap_cnt, policy);
    if (p->flow) {
        p->flow->applied_exception_policy |= ExceptionPolicyFlag(drop_reason);
    }
    switch (policy) {
        case EXCEPTION_POLICY_AUTO:
            break;
        case EXCEPTION_POLICY_NOT_SET:
            break;
        case EXCEPTION_POLICY_REJECT:
            SCLogDebug("EXCEPTION_POLICY_REJECT");
            PacketDrop(p, ACTION_REJECT, drop_reason);
            if (!EngineModeIsIPS()) {
                break;
            }
            /* fall through */
        case EXCEPTION_POLICY_DROP_FLOW:
            SCLogDebug("EXCEPTION_POLICY_DROP_FLOW");
            if (p->flow) {
                p->flow->flags |= FLOW_ACTION_DROP;
                FlowSetNoPayloadInspectionFlag(p->flow);
                FlowSetNoPacketInspectionFlag(p->flow);
                StreamTcpDisableAppLayer(p->flow);
            }
            /* fall through */
        case EXCEPTION_POLICY_DROP_PACKET:
            SCLogDebug("EXCEPTION_POLICY_DROP_PACKET");
            DecodeSetNoPayloadInspectionFlag(p);
            DecodeSetNoPacketInspectionFlag(p);
            PacketDrop(p, ACTION_DROP, drop_reason);
            break;
        case EXCEPTION_POLICY_BYPASS_FLOW:
            PacketBypassCallback(p);
            /* fall through */
        case EXCEPTION_POLICY_PASS_FLOW:
            SCLogDebug("EXCEPTION_POLICY_PASS_FLOW");
            if (p->flow) {
                p->flow->flags |= FLOW_ACTION_PASS;
                FlowSetNoPacketInspectionFlag(p->flow); // TODO util func
            }
            /* fall through */
        case EXCEPTION_POLICY_PASS_PACKET:
            SCLogDebug("EXCEPTION_POLICY_PASS_PACKET");
            DecodeSetNoPayloadInspectionFlag(p);
            DecodeSetNoPacketInspectionFlag(p);
            break;
    }
    SCLogDebug("end");
}

static enum ExceptionPolicy PickPacketAction(const char *option, enum ExceptionPolicy p)
{
    switch (p) {
        case EXCEPTION_POLICY_DROP_FLOW:
            SCLogWarning(
                    "flow actions not supported for %s, defaulting to \"drop-packet\"", option);
            return EXCEPTION_POLICY_DROP_PACKET;
        case EXCEPTION_POLICY_PASS_FLOW:
            SCLogWarning(
                    "flow actions not supported for %s, defaulting to \"pass-packet\"", option);
            return EXCEPTION_POLICY_PASS_PACKET;
        case EXCEPTION_POLICY_BYPASS_FLOW:
            SCLogWarning("flow actions not supported for %s, defaulting to \"ignore\"", option);
            return EXCEPTION_POLICY_NOT_SET;
        /* add all cases, to make sure new cases not handle will raise
         * errors */
        case EXCEPTION_POLICY_DROP_PACKET:
            break;
        case EXCEPTION_POLICY_PASS_PACKET:
            break;
        case EXCEPTION_POLICY_REJECT:
            break;
        case EXCEPTION_POLICY_NOT_SET:
            break;
        case EXCEPTION_POLICY_AUTO:
            break;
    }
    return p;
}

static enum ExceptionPolicy ExceptionPolicyConfigValueParse(
        const char *option, const char *value_str)
{
    enum ExceptionPolicy policy = EXCEPTION_POLICY_NOT_SET;
    if (strcmp(value_str, "drop-flow") == 0) {
        policy = EXCEPTION_POLICY_DROP_FLOW;
    } else if (strcmp(value_str, "pass-flow") == 0) {
        policy = EXCEPTION_POLICY_PASS_FLOW;
    } else if (strcmp(value_str, "bypass") == 0) {
        policy = EXCEPTION_POLICY_BYPASS_FLOW;
    } else if (strcmp(value_str, "drop-packet") == 0) {
        policy = EXCEPTION_POLICY_DROP_PACKET;
    } else if (strcmp(value_str, "pass-packet") == 0) {
        policy = EXCEPTION_POLICY_PASS_PACKET;
    } else if (strcmp(value_str, "reject") == 0) {
        policy = EXCEPTION_POLICY_REJECT;
    } else if (strcmp(value_str, "ignore") == 0) { // TODO name?
        policy = EXCEPTION_POLICY_NOT_SET;
    } else if (strcmp(value_str, "auto") == 0) {
        policy = EXCEPTION_POLICY_AUTO;
    } else {
        FatalErrorOnInit(
                "\"%s\" is not a valid exception policy value. Valid options are drop-flow, "
                "pass-flow, bypass, reject, drop-packet, pass-packet, ignore or auto.",
                value_str);
    }

    return policy;
}

/* Select an exception policy in case the configuration value was set to 'auto' */
static enum ExceptionPolicy ExceptionPolicyPickAuto(bool midstream_enabled, bool support_flow)
{
    enum ExceptionPolicy policy = EXCEPTION_POLICY_NOT_SET;
    if (!midstream_enabled && EngineModeIsIPS()) {
        if (support_flow) {
            policy = EXCEPTION_POLICY_DROP_FLOW;
        } else {
            policy = EXCEPTION_POLICY_DROP_PACKET;
        }
    }
    return policy;
}

static enum ExceptionPolicy ExceptionPolicyMasterParse(const char *value)
{
    enum ExceptionPolicy policy = ExceptionPolicyConfigValueParse("exception-policy", value);
    if (!EngineModeIsIPS() &&
            (policy == EXCEPTION_POLICY_DROP_PACKET || policy == EXCEPTION_POLICY_DROP_FLOW)) {
        policy = EXCEPTION_POLICY_NOT_SET;
    }
    g_eps_have_exception_policy = true;

    SCLogInfo("master exception-policy set to: %s", ExceptionPolicyEnumToString(policy, false));

    return policy;
}

static enum ExceptionPolicy ExceptionPolicyGetDefault(
        const char *option, bool support_flow, bool midstream)
{
    enum ExceptionPolicy p = EXCEPTION_POLICY_NOT_SET;
    if (g_eps_have_exception_policy) {
        p = GetMasterExceptionPolicy(option);

        if (p == EXCEPTION_POLICY_AUTO) {
            p = ExceptionPolicyPickAuto(midstream, support_flow);
        }

        if (!support_flow) {
            p = PickPacketAction(option, p);
        }
        SCLogConfig("%s: %s (defined via 'exception-policy' master switch)", option,
                ExceptionPolicyEnumToString(p, false));
        return p;
    } else if (EngineModeIsIPS() && !midstream) {
        p = EXCEPTION_POLICY_DROP_FLOW;
    }
    SCLogConfig("%s: %s (defined via 'built-in default' for %s-mode)", option,
            ExceptionPolicyEnumToString(p, false), EngineModeIsIPS() ? "IPS" : "IDS");

    return p;
}

enum ExceptionPolicy ExceptionPolicyParse(const char *option, bool support_flow)
{
    enum ExceptionPolicy policy = EXCEPTION_POLICY_NOT_SET;
    const char *value_str = NULL;

    if ((ConfGet(option, &value_str) == 1) && value_str != NULL) {
        if (strcmp(option, "exception-policy") == 0) {
            policy = ExceptionPolicyMasterParse(value_str);
        } else {
            policy = ExceptionPolicyConfigValueParse(option, value_str);
            if (policy == EXCEPTION_POLICY_AUTO) {
                policy = ExceptionPolicyPickAuto(false, support_flow);
            }
            if (!support_flow) {
                policy = PickPacketAction(option, policy);
            }
            SCLogConfig("%s: %s", option, ExceptionPolicyEnumToString(policy, false));
        }
    } else {
        policy = ExceptionPolicyGetDefault(option, support_flow, false);
    }

    return policy;
}

enum ExceptionPolicy ExceptionPolicyMidstreamParse(bool midstream_enabled)
{
    enum ExceptionPolicy policy = EXCEPTION_POLICY_NOT_SET;
    const char *value_str = NULL;
    /* policy was set directly */
    if ((ConfGet("stream.midstream-policy", &value_str)) == 1 && value_str != NULL) {
        policy = ExceptionPolicyConfigValueParse("midstream-policy", value_str);
        if (policy == EXCEPTION_POLICY_AUTO) {
            policy = ExceptionPolicyPickAuto(midstream_enabled, true);
        } else if (midstream_enabled) {
            if (policy != EXCEPTION_POLICY_NOT_SET && policy != EXCEPTION_POLICY_PASS_FLOW) {
                FatalErrorOnInit(
                        "Error parsing stream.midstream-policy from config file. \"%s\" is "
                        "not a valid exception policy when midstream is enabled. Valid options "
                        "are pass-flow and ignore.",
                        value_str);
            }
        }
        if (!EngineModeIsIPS()) {
            if (policy == EXCEPTION_POLICY_DROP_FLOW) {
                FatalErrorOnInit(
                        "Error parsing stream.midstream-policy from config file. \"%s\" is "
                        "not a valid exception policy in IDS mode. See our documentation for a "
                        "list of all possible values.",
                        value_str);
            }
        }
    } else {
        policy = ExceptionPolicyGetDefault("stream.midstream-policy", true, midstream_enabled);
    }

    if (policy == EXCEPTION_POLICY_PASS_PACKET || policy == EXCEPTION_POLICY_DROP_PACKET) {
        FatalErrorOnInit("Error parsing stream.midstream-policy from config file. \"%s\" is "
                         "not valid for this exception policy. See our documentation for a list of "
                         "all possible values.",
                value_str);
    }

    return policy;
}

void ExceptionPolicySetStatsCounters(ThreadVars *tv, ExceptionPolicyCounters *counter,
        ExceptionPolicyStatsSetts *setting, enum ExceptionPolicy conf_policy,
        const char *default_str, bool (*isExceptionPolicyValid)(enum ExceptionPolicy))
{
    if (conf_policy != EXCEPTION_POLICY_NOT_SET && g_eps_stats_counters) {
        /* set-up policy counters */
        for (enum ExceptionPolicy i = EXCEPTION_POLICY_NOT_SET + 1; i < EXCEPTION_POLICY_MAX; i++) {
            if (isExceptionPolicyValid(i)) {
                snprintf(setting->eps_name[i], sizeof(setting->eps_name[i]), "%s%s", default_str,
                        ExceptionPolicyEnumToString(i, true));
                counter->eps_id[i] = StatsRegisterCounter(setting->eps_name[i], tv);
            }
        }
    }
}

#ifndef DEBUG

int ExceptionSimulationCommandLineParser(const char *name, const char *arg)
{
    return 0;
}

#else

/* exception policy simulation (eps) handling */

uint64_t g_eps_applayer_error_offset_ts = UINT64_MAX;
uint64_t g_eps_applayer_error_offset_tc = UINT64_MAX;
uint64_t g_eps_pcap_packet_loss = UINT64_MAX;
uint64_t g_eps_stream_ssn_memcap = UINT64_MAX;
uint64_t g_eps_stream_reassembly_memcap = UINT64_MAX;
uint64_t g_eps_flow_memcap = UINT64_MAX;
uint64_t g_eps_defrag_memcap = UINT64_MAX;
bool g_eps_is_alert_queue_fail_mode = false;

/* 1: parsed, 0: not for us, -1: error */
int ExceptionSimulationCommandLineParser(const char *name, const char *arg)
{
    if (strcmp(name, "simulate-applayer-error-at-offset-ts") == 0) {
        BUG_ON(arg == NULL);
        uint64_t offset = 0;
        if (ParseSizeStringU64(arg, &offset) < 0) {
            return -1;
        }
        g_eps_applayer_error_offset_ts = offset;
    } else if (strcmp(name, "simulate-applayer-error-at-offset-tc") == 0) {
        BUG_ON(arg == NULL);
        uint64_t offset = 0;
        if (ParseSizeStringU64(arg, &offset) < 0) {
            return TM_ECODE_FAILED;
        }
        g_eps_applayer_error_offset_tc = offset;
    } else if (strcmp(name, "simulate-packet-loss") == 0) {
        BUG_ON(arg == NULL);
        uint64_t pkt_num = 0;
        if (ParseSizeStringU64(arg, &pkt_num) < 0) {
            return TM_ECODE_FAILED;
        }
        g_eps_pcap_packet_loss = pkt_num;
    } else if (strcmp(name, "simulate-packet-tcp-reassembly-memcap") == 0) {
        BUG_ON(arg == NULL);
        uint64_t pkt_num = 0;
        if (ParseSizeStringU64(arg, &pkt_num) < 0) {
            return TM_ECODE_FAILED;
        }
        g_eps_stream_reassembly_memcap = pkt_num;
    } else if (strcmp(name, "simulate-packet-tcp-ssn-memcap") == 0) {
        BUG_ON(arg == NULL);
        uint64_t pkt_num = 0;
        if (ParseSizeStringU64(arg, &pkt_num) < 0) {
            return TM_ECODE_FAILED;
        }
        g_eps_stream_ssn_memcap = pkt_num;
    } else if (strcmp(name, "simulate-packet-flow-memcap") == 0) {
        BUG_ON(arg == NULL);
        uint64_t pkt_num = 0;
        if (ParseSizeStringU64(arg, &pkt_num) < 0) {
            return TM_ECODE_FAILED;
        }
        g_eps_flow_memcap = pkt_num;
    } else if (strcmp(name, "simulate-packet-defrag-memcap") == 0) {
        BUG_ON(arg == NULL);
        uint64_t pkt_num = 0;
        if (ParseSizeStringU64(arg, &pkt_num) < 0) {
            return TM_ECODE_FAILED;
        }
        g_eps_defrag_memcap = pkt_num;
    } else if (strcmp(name, "simulate-alert-queue-realloc-failure") == 0) {
        g_eps_is_alert_queue_fail_mode = true;
    } else {
        // not for us
        return 0;
    }
    return 1;
}
#endif
