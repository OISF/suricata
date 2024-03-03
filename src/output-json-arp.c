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

/**
 * \file
 *
 * \author Giuseppe Longo <giuseppe.longo@cylera.com>
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

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-classification-config.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "util-buffer.h"

#define MODULE_NAME "JsonArpLog"

typedef struct JsonArpOutputCtx_ {
    LogFileCtx *file_ctx;
    uint16_t flags;
    uint32_t payload_buffer_size;
    OutputJsonCtx *eve_ctx;
} JsonArpOutputCtx;

typedef struct JsonArpLogThread_ {
    MemBuffer *payload_buffer;
    JsonArpOutputCtx *json_output_ctx;
    OutputJsonThreadCtx *ctx;
} JsonArpLogThread;

static const char *hwtype2str(uint16_t hwtype)
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
        default:
            return "unknown";
    }
}

static const char *prototype2str(uint16_t proto)
{
    switch (proto) {
        case 0x0800:
            return "ipv4";
        default:
            return "unknown";
    }
}

static const char *opcode2str(uint16_t opcode)
{
    switch (opcode) {
        case 0:
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

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonArpLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonArpLogThread *aft = SCMalloc(sizeof(JsonArpLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(*aft));

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogArp.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /** Use the Output Context (file pointer and mutex) */
    JsonArpOutputCtx *json_output_ctx = ((OutputCtx *)initdata)->data;

    aft->payload_buffer = MemBufferCreateNew(json_output_ctx->payload_buffer_size);
    if (aft->payload_buffer == NULL) {
        goto error_exit;
    }
    aft->ctx = CreateEveThreadCtx(t, json_output_ctx->eve_ctx);
    if (!aft->ctx) {
        goto error_exit;
    }

    aft->json_output_ctx = json_output_ctx;

    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    if (aft->payload_buffer != NULL) {
        MemBufferFree(aft->payload_buffer);
    }
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode JsonArpLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonArpLogThread *aft = (JsonArpLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->payload_buffer);

    /* clear memory */
    memset(aft, 0, sizeof(*aft));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonArpLogDeInitCtxSub(OutputCtx *output_ctx)
{
    JsonArpOutputCtx *arp_ctx = output_ctx->data;
    SCFree(arp_ctx);
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    SCFree(output_ctx);
}

static OutputInitResult JsonArpLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    const char *enabled = ConfNodeLookupChildValue(conf, "enabled");
    if (enabled != NULL && !ConfValIsTrue(enabled)) {
        result.ok = true;
        return result;
    }

    OutputJsonCtx *ajt = parent_ctx->data;
    JsonArpOutputCtx *json_output_ctx = NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        return result;
    }

    json_output_ctx = SCMalloc(sizeof(JsonArpOutputCtx));
    if (unlikely(json_output_ctx == NULL)) {
        goto error;
    }
    memset(json_output_ctx, 0, sizeof(JsonArpOutputCtx));

    json_output_ctx->file_ctx = ajt->file_ctx;
    json_output_ctx->eve_ctx = ajt;

    output_ctx->data = json_output_ctx;
    output_ctx->DeInit = JsonArpLogDeInitCtxSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;

error:
    if (json_output_ctx != NULL) {
        SCFree(json_output_ctx);
    }
    if (output_ctx != NULL) {
        SCFree(output_ctx);
    }
    return result;
}

static int JsonArpLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonArpLogThread *thread = (JsonArpLogThread *)thread_data;
    JsonArpOutputCtx *json_output_ctx = thread->json_output_ctx;
    char srcip[46] = "";
    char dstip[46] = "";

    JsonBuilder *jb =
            CreateEveHeader((Packet *)p, LOG_DIR_PACKET, "arp", NULL, json_output_ctx->eve_ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_OK;
    }

    PrintInet(AF_INET, p->arph->source_ip, srcip, sizeof(srcip));
    PrintInet(AF_INET, p->arph->dest_ip, dstip, sizeof(dstip));

    jb_open_object(jb, "arp");
    jb_set_string(jb, "hw_type", hwtype2str(ntohs(p->arph->hw_type)));
    jb_set_string(jb, "proto_type", prototype2str(ntohs(p->arph->proto_type)));
    jb_set_string(jb, "opcode", opcode2str(ntohs(p->arph->opcode)));
    JSONFormatAndAddMACAddr(jb, "src_mac", p->arph->source_mac, false);
    jb_set_string(jb, "src_ip", srcip);
    JSONFormatAndAddMACAddr(jb, "dest_mac", p->arph->dest_mac, false);
    jb_set_string(jb, "dest_ip", dstip);
    jb_close(jb); /* arp */
    OutputJsonBuilderBuffer(jb, thread->ctx);
    MemBufferReset(thread->payload_buffer);
    jb_free(jb);

    return TM_ECODE_OK;
}

static bool JsonArpLogCondition(ThreadVars *tv, void *thread_data, const Packet *p)
{
    return PKT_IS_ARP(p);
}

void JsonArpLogRegister(void)
{
    OutputRegisterPacketSubModule(LOGGER_JSON_ARP, "eve-log", "JsonArpLog", "eve-log.arp",
            JsonArpLogInitCtxSub, JsonArpLogger, JsonArpLogCondition, JsonArpLogThreadInit,
            JsonArpLogThreadDeinit, NULL);

    SCLogDebug("ARP JSON logger registered.");
}
