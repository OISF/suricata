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
#include "detect-engine-mpm.h"
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

static const char *HwtypeToString(uint16_t hwtype)
{
    switch (hwtype) {
        case 0:
            return "reserved";
        case 1:
            return "ethernet";
        case 2:
            return "experimental_ethernet";
        case 3:
            return "amateur_radio_ax25";
        case 4:
            return "proteon_token_ring";
        case 5:
            return "chaos";
        case 6:
            return "ieee802";
        case 7:
            return "arcnet";
        case 8:
            return "hyperchannel";
        case 9:
            return "lanstar";
        case 10:
            return "autonet_short_address";
        case 11:
            return "localtalk";
        case 12:
            return "localnet";
        case 13:
            return "ultralink";
        case 14:
            return "smds";
        case 15:
            return "framerelay";
        case 16:
        case 19:
        case 21:
            return "atm";
        case 17:
            return "hdlc";
        case 18:
            return "fibre_channel";
        case 20:
            return "serial_line";
        case 22:
            return "mil_std_188_220";
        case 23:
            return "metricom";
        case 24:
            return "ieee1394.1995";
        case 25:
            return "mapos";
        case 26:
            return "twinaxial";
        case 27:
            return "eui64";
        case 28:
            return "hiparp";
        case 29:
            return "ip_over_arp";
        case 30:
            return "arpsec";
        case 31:
            return "ipsec";
        case 32:
            return "infiniband";
        case 33:
            return "cai";
        case 34:
            return "wiegand_interface";
        case 35:
            return "pure_ip";
        case 36:
            return "hw_exp1";
        case 37:
            return "hw_exp2";
        case 38:
            return "unified_bus";
        case 256:
            return "hw_exp2";
        case 257:
            return "aethernet";
        default:
            return "unknown";
    }
}

static const char *PrototypeToString(uint16_t proto)
{
    switch (proto) {
        case 0x0800:
            return "ipv4";
        default:
            return "unknown";
    }
}

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
        case 11:
            return "mars_request";
        case 12:
            return "mars_multi";
        case 13:
            return "mars_mserv";
        case 14:
            return "mars_join";
        case 15:
            return "mars_leave";
        case 16:
            return "mars_nak";
        case 17:
            return "mars_unserv";
        case 18:
            return "mars_sjoin";
        case 19:
            return "mars_sleave";
        case 20:
            return "mars_grouplist_request";
        case 21:
            return "mars_grouplist_reply";
        case 22:
            return "mars_redirect_map";
        case 23:
            return "mapos_unarp";
        case 24:
            return "op_exp1";
        case 25:
            return "op_exp2";
        default:
            return "unknown";
    }
}

static int JsonArpLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    OutputJsonThreadCtx *thread = thread_data;
    char srcip[46] = "";
    char dstip[46] = "";
    const ARPHdr *arph = PacketGetARP(p);

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_PACKET, "arp", NULL, thread->ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_OK;
    }

    PrintInet(AF_INET, arph->source_ip, srcip, sizeof(srcip));
    PrintInet(AF_INET, arph->dest_ip, dstip, sizeof(dstip));

    jb_open_object(jb, "arp");
    jb_set_string(jb, "hw_type", HwtypeToString(ntohs(arph->hw_type)));
    jb_set_string(jb, "proto_type", PrototypeToString(ntohs(arph->proto_type)));
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
