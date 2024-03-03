/* Copyright (C) 2024 Open Information Security Foundation
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
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 * Implement JSON/eve logging for ARP Protocol.
 */

#include "suricata-common.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "util-debug.h"

#include "decode-ipv4.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-reference.h"

#include "output.h"
#include "output-json.h"
#include "output-json-arp.h"

#include "util-classification-config.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "util-buffer.h"

static const char *OpcodeToString(uint16_t opcode)
{
    switch (opcode) {
        case 0:
        case 65535:
            return "reserved";
        case 1:
            return "request";
        case 2:
            return "reply";
        case 3:
            return "request_reverse";
        case 4:
            return "reply_reverse";
        case 5:
            return "drarp_request";
        case 6:
            return "drarp_reply";
        case 7:
            return "drarp_error";
        case 8:
            return "inarp_request";
        case 9:
            return "inarp_reply";
        case 10:
            return "arp_nak";
        default:
            return "unknown";
    }
}

static int JsonArpLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    OutputJsonThreadCtx *thread = thread_data;
    char srcip[JSON_ADDR_LEN] = "";
    char dstip[JSON_ADDR_LEN] = "";
    const ARPHdr *arph = PacketGetARP(p);

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_PACKET, "arp", NULL, thread->ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_OK;
    }

    PrintInet(AF_INET, arph->source_ip, srcip, sizeof(srcip));
    PrintInet(AF_INET, arph->dest_ip, dstip, sizeof(dstip));

    jb_open_object(jb, "arp");
    jb_set_string(jb, "hw_type", "ethernet");
    jb_set_string(jb, "proto_type", "ipv4");
    jb_set_string(jb, "opcode", OpcodeToString(ntohs(arph->opcode)));
    JSONFormatAndAddMACAddr(jb, "src_mac", arph->source_mac, false);
    jb_set_string(jb, "src_ip", srcip);
    JSONFormatAndAddMACAddr(jb, "dest_mac", arph->dest_mac, false);
    jb_set_string(jb, "dest_ip", dstip);
    jb_close(jb); /* arp */
    OutputJsonBuilderBuffer(jb, thread);
    jb_free(jb);

    return TM_ECODE_OK;
}

static bool JsonArpLogCondition(ThreadVars *tv, void *thread_data, const Packet *p)
{
    return PacketIsARP(p);
}

void JsonArpLogRegister(void)
{
    OutputRegisterPacketSubModule(LOGGER_JSON_ARP, "eve-log", "JsonArpLog", "eve-log.arp",
            OutputJsonLogInitSub, JsonArpLogger, JsonArpLogCondition, JsonLogThreadInit,
            JsonLogThreadDeinit, NULL);

    SCLogDebug("ARP JSON logger registered.");
}
