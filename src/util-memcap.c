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

#include "suricata-common.h"
#include "decode.h"
#include "util-memcap.h"

void MemcapPolicyApply(Packet *p, enum MemcapPolicy policy, enum PacketDropReason drop_reason)
{
    SCLogDebug("start: pcap_cnt %"PRIu64", policy %u", p->pcap_cnt, policy);
    if (EngineModeIsIPS()) {
        switch (policy) {
            case MEMCAP_POLICY_IGNORE:
                break;
            case MEMCAP_POLICY_DROP_FLOW:
                SCLogDebug("MEMCAP_POLICY_DROP_FLOW");
                if (p->flow) {
                    p->flow->flags |= FLOW_ACTION_DROP;
                }
                /* fall through */
            case MEMCAP_POLICY_DROP_PACKET:
                SCLogDebug("MEMCAP_POLICY_DROP_PACKET");
                DecodeSetNoPacketInspectionFlag(p); // TODO move into `PacketDrop`?
                PacketDrop(p, drop_reason);
                break;
            case MEMCAP_POLICY_BYPASS_FLOW:
                PacketBypassCallback(p);
                /* fall through */
            case MEMCAP_POLICY_PASS_FLOW:
                SCLogDebug("MEMCAP_POLICY_PASS_FLOW");
                if (p->flow) {
                    p->flow->flags |= FLOW_ACTION_PASS;
                    FlowSetNoPacketInspectionFlag(p->flow); // TODO util func
                }
                /* fall through */
            case MEMCAP_POLICY_PASS_PACKET:
                SCLogDebug("MEMCAP_POLICY_PASS_PACKET");
                DecodeSetNoPacketInspectionFlag(p); // TODO util func
                PacketSetAction(p, ACTION_PASS);
                break;
        }
    }
    SCLogDebug("end");
}

enum MemcapPolicy MemcapPolicyParse(const char *option)
{
    enum MemcapPolicy policy = MEMCAP_POLICY_IGNORE;
    const char *value_str = NULL;
    if ((ConfGetValue(option, &value_str)) == 1 && value_str != NULL) {
        if (strcmp(value_str, "drop-flow") == 0) {
            policy = MEMCAP_POLICY_DROP_FLOW;
            SCLogNotice("%s: %s", option, value_str);
        } else if (strcmp(value_str, "pass-flow") == 0) {
            policy = MEMCAP_POLICY_PASS_FLOW;
            SCLogNotice("%s: %s", option, value_str);
        } else if ((strcmp(value_str, "bypass") == 0) ||
                   (strcmp(value_str, "bypass-flow") == 0)) {
            policy = MEMCAP_POLICY_BYPASS_FLOW;
            SCLogNotice("%s: %s", option, value_str);
        } else if (strcmp(value_str, "drop-packet") == 0) {
            policy = MEMCAP_POLICY_DROP_PACKET;
            SCLogNotice("%s: %s", option, value_str);
        } else if (strcmp(value_str, "pass-packet") == 0) {
            policy = MEMCAP_POLICY_PASS_PACKET;
            SCLogNotice("%s: %s", option, value_str);
        } else if (strcmp(value_str, "ignore") == 0) { // TODO name?
            policy = MEMCAP_POLICY_IGNORE;
            SCLogNotice("%s: %s", option, value_str);
        } else {
            SCLogNotice("%s: ignore", option);
        }
    } else {
        SCLogNotice("%s: ignore", option);
    }
    return policy;
}
