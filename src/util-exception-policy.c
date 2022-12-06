/* Copyright (C) 2022 Open Information Security Foundation
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

#include "suricata-common.h"
#include "suricata.h"
#include "packet.h"
#include "util-exception-policy.h"
#include "util-misc.h"
#include "stream-tcp-reassemble.h"
#include "action-globals.h"

ExceptionPolicyMasterSwitch g_eps_master_switch = EXCEPTION_POLICY_SWITCH_DEFAULT;

void ExceptionPolicyApply(Packet *p, enum ExceptionPolicy policy, enum PacketDropReason drop_reason)
{
    SCLogDebug("start: pcap_cnt %" PRIu64 ", policy %u", p->pcap_cnt, policy);
    if (EngineModeIsIPS()) {
        switch (policy) {
            case EXCEPTION_POLICY_IGNORE:
                break;
            case EXCEPTION_POLICY_REJECT:
                SCLogDebug("EXCEPTION_POLICY_REJECT");
                PacketDrop(p, ACTION_REJECT, drop_reason);
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
    }
    SCLogDebug("end");
}

/* Should I make a separate enum for this? With a separate function?
   This seems to make sense in my head right now, as then things would be more logically containted,
   and then I could call the master-switch function from within the ExceptionPolicyParse function...
 */

void setMasterExceptionPolicy()
{
    const char *switch_str = NULL;
    if (EngineModeIsIPS()) {
        g_eps_master_switch = EXCEPTION_POLICY_SWITCH_DEFAULT;
        if (ConfGet("exception-policy-master-switch", &switch_str) == 1 && switch_str != NULL) {
            if (strcmp(switch_str, "auto") == 0) {
                SCLogConfig("Exception Policies set to 'drop-packet/drop-flow' via "
                            "master switch: 'auto' mode");
                g_eps_master_switch = EXCEPTION_POLICY_SWITCH_DEFAULT;
            } else if (strcmp(switch_str, "performance") == 0) {
                SCLogConfig("Exception Policies set to 'bypass-flow' via master switch: "
                            "'performance' mode");
                g_eps_master_switch = EXCEPTION_POLICY_SWITCH_PERFORMANCE;
            } else if (strcmp(switch_str, "disabled") == 0) {
                SCLogConfig("master switch for exception policies is disabled, "
                            "exception policies should be configured individually.");
                g_eps_master_switch = EXCEPTION_POLICY_SWITCH_DISABLED;
            } else {
                FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT,
                        "\"%s\" is not a valid master switch value for the exception policy."
                        " Valid options are auto, performance or disabled.",
                        switch_str);
            }
        } else {
            /* not enabled, we won't change the master exception policy,
             for now */
            SCLogWarning(SC_ERR_CONF_YAML_ERROR,
                    "exception-policy-master-switch value not set, so ignoring it."
                    " This behavior will change in Suricata 8, so please update your"
                    " config. See ticket #5219 for more details.");
            g_eps_master_switch = EXCEPTION_POLICY_SWITCH_DISABLED;
        }
    }
}

/** brief Set a master Exception Policy, if one has been defined
 *
 *  \retval true if the master Exception Policy has been set
 *  \retval false if the master switch is disabled and no policy was set
 */
static bool getMasterExceptionPolicy(const char *option, enum ExceptionPolicy *policy)
{
    bool is_master_policy = true;
    if (EngineModeIsIPS()) {
        switch (g_eps_master_switch) {
            case EXCEPTION_POLICY_SWITCH_DEFAULT:
                SCLogConfig("%s set to 'drop-packet/drop-flow' via master"
                            "switch: 'auto' mode",
                        option);
                *policy = EXCEPTION_POLICY_DROP_FLOW;
                is_master_policy = true;
                break;
            case EXCEPTION_POLICY_SWITCH_PERFORMANCE:
                SCLogConfig("%s set to 'bypass-flow' via master switch: "
                            "'performance' mode",
                        option);
                *policy = EXCEPTION_POLICY_BYPASS_FLOW;
                is_master_policy = true;
                break;
            case EXCEPTION_POLICY_SWITCH_DISABLED:
                is_master_policy = false;
                break;
            default:
                is_master_policy = false;
        }
    } else {
        is_master_policy = false;
    }
    return is_master_policy;
}

enum ExceptionPolicy ExceptionPolicyParse(const char *option, const bool support_flow)
{
    enum ExceptionPolicy policy = EXCEPTION_POLICY_IGNORE;
    const char *value_str = NULL;
    if ((ConfGet(option, &value_str)) == 1 && value_str != NULL) {
        if (strcmp(value_str, "drop-flow") == 0) {
            policy = EXCEPTION_POLICY_DROP_FLOW;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "pass-flow") == 0) {
            policy = EXCEPTION_POLICY_PASS_FLOW;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "bypass") == 0) {
            policy = EXCEPTION_POLICY_BYPASS_FLOW;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "drop-packet") == 0) {
            policy = EXCEPTION_POLICY_DROP_PACKET;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "pass-packet") == 0) {
            policy = EXCEPTION_POLICY_PASS_PACKET;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "reject") == 0) {
            policy = EXCEPTION_POLICY_REJECT;
            SCLogConfig("%s: %s", option, value_str);
        } else if (strcmp(value_str, "ignore") == 0) { // TODO name?
            policy = EXCEPTION_POLICY_IGNORE;
            SCLogConfig("%s: %s", option, value_str);
        } else {
            FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT,
                    "\"%s\" is not a valid exception policy value. Valid options are drop-flow, "
                    "pass-flow, bypass, drop-packet, pass-packet or ignore.",
                    value_str);
        }

        if (!support_flow) {
            if (policy == EXCEPTION_POLICY_DROP_FLOW || policy == EXCEPTION_POLICY_PASS_FLOW ||
                    policy == EXCEPTION_POLICY_BYPASS_FLOW) {
                SCLogWarning(SC_WARN_COMPATIBILITY,
                        "flow actions not supported for %s, defaulting to \"ignore\"", option);
                policy = EXCEPTION_POLICY_IGNORE;
            }
        }

    } else {
        /* Exception Policy was not defined individually */
        enum ExceptionPolicy master_policy;
        bool hasMasterPolicy = getMasterExceptionPolicy(option, &master_policy);
        if (!hasMasterPolicy) {
            SCLogConfig("%s: ignore", option);
        } else {
            /* If the master switch was set and the Exception Policy option was not
            individually set, use the defined master Exception Policy */
            SCLogConfig("%s: defined via Exception Policy master switch", option);
            policy = master_policy;
        }
    }
    return policy;
}

#ifndef DEBUG

int ExceptionSimulationCommandlineParser(const char *name, const char *arg)
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
int ExceptionSimulationCommandlineParser(const char *name, const char *arg)
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
