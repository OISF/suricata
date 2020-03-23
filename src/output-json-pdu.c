/* Copyright (C) 2013-2021 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Logs pdus in JSON format.
 *
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "util-debug.h"

#include "util-logopenfile.h"
#include "util-misc.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"
#include "detect-metadata.h"
#include "app-layer-parser.h"
#include "app-layer-dnp3.h"
#include "app-layer-htp.h"
#include "app-layer-htp-xff.h"
#include "app-layer-ftp.h"
#include "util-classification-config.h"
#include "util-syslog.h"
#include "util-logopenfile.h"

#include "output.h"
#include "output-json.h"
#include "output-json-pdu.h"

#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-crypt.h"
#include "util-validate.h"

#define MODULE_NAME "JsonPduLog"

#define JSON_STREAM_BUFFER_SIZE 4096

typedef struct PduJsonOutputCtx_ {
    LogFileCtx *file_ctx;
    uint16_t flags;
    uint32_t payload_buffer_size;
    OutputJsonCtx *eve_ctx;
} PduJsonOutputCtx;

typedef struct JsonPduLogThread_ {
    MemBuffer *payload_buffer;
    PduJsonOutputCtx *json_output_ctx;
    OutputJsonThreadCtx *ctx;
} JsonPduLogThread;

static inline bool NeedsAsHex(uint8_t c)
{
    if (!isprint(c))
        return true;

    switch (c) {
        case '/':
        case ';':
        case ':':
        case '\\':
        case ' ':
        case '|':
        case '"':
        case '`':
        case '\'':
            return true;
    }
    return false;
}

static void PayloadAsHex(const uint8_t *data, uint32_t data_len, char *str, size_t str_len)
{
    bool hex = false;
    for (uint32_t i = 0; i < data_len; i++) {
        if (NeedsAsHex(data[i])) {
            char hex_str[4];
            snprintf(hex_str, sizeof(hex_str), "%s%02X", !hex ? "|" : " ", data[i]);
            strlcat(str, hex_str, str_len);
            hex = true;
        } else {
            char p_str[3];
            snprintf(p_str, sizeof(p_str), "%s%c", hex ? "|" : "", data[i]);
            strlcat(str, p_str, str_len);
            hex = false;
        }
    }
    if (hex) {
        strlcat(str, "|", str_len);
    }
}

static void PduAddPayload(
        PduJsonOutputCtx *json_output_ctx, JsonBuilder *js, TcpStream *stream, const StreamPDU *pdu)
{
    uint32_t data_len = 0;
    const uint8_t *data = NULL;

    uint64_t offset = pdu->rel_offset + STREAM_BASE_OFFSET(stream);
    SCLogDebug("offset %" PRIu64, offset);

    if (StreamingBufferGetDataAtOffset(&stream->sb, &data, &data_len, offset) == 0) {
        SCLogDebug("NO DATA1");
        return;
    }
    if (data == NULL || data_len == 0) {
        SCLogDebug("NO DATA2");
        return;
    }
    data_len = MIN(pdu->len, (int32_t)data_len);

    jb_set_bool(js, "complete", ((int32_t)data_len >= pdu->len));

    data_len = MIN(data_len, 256);

    unsigned long len = BASE64_BUFFER_SIZE(data_len);
    uint8_t encoded[len];
    if (Base64Encode(data, data_len, encoded, &len) == SC_BASE64_OK) {
        jb_set_string(js, "payload", (char *)encoded);
    }

    uint8_t printable_buf[data_len + 1];
    uint32_t o = 0;
    PrintStringsToBuffer(printable_buf, &o, data_len + 1, data, data_len);
    printable_buf[data_len] = '\0';
    jb_set_string(js, "payload_printable", (char *)printable_buf);

    char pretty_buf[data_len * 4 + 1];
    pretty_buf[0] = '\0';
    PayloadAsHex(data, data_len, pretty_buf, data_len * 4 + 1);
    // SCLogNotice("HEX %s", pretty_buf);
    jb_set_string(js, "payload_hex", pretty_buf);
}

#include "app-layer-records.h"
// TODO dedup various uses
static StreamPDU *GetPDUFromStream(TcpStream *stream, StreamPDUs *pdus, uint32_t idx)
{
    assert(stream);
    assert(pdus);

    SCLogDebug("stream %p idx %u Stream->pdus.cnt %u", stream, idx, stream->pdus.cnt);

    if (idx >= pdus->cnt) {
        return 0;
    }

    StreamPDU *pdu = StreamPDUGetByIndex(pdus, idx);
    return pdu;
}

static int PduJson(ThreadVars *tv, JsonPduLogThread *aft, const Packet *p)
{
    // MemBuffer *payload = aft->payload_buffer;
    PduJsonOutputCtx *json_output_ctx = aft->json_output_ctx;

    assert(p->proto == IPPROTO_TCP);
    assert(p->flow);
    assert(p->flow->protoctx);

    TcpSession *ssn = p->flow->protoctx;
    TcpStream *stream;
    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
    } else {
        stream = &ssn->server;
    }

    for (uint32_t idx = 0; idx < stream->pdus.cnt; idx++) {
        StreamPDU *pdu = GetPDUFromStream(stream, &stream->pdus, idx);
        if (pdu != NULL && pdu->rel_offset >= 0) {
            /* First initialize the address info (5-tuple). */
            JsonAddrInfo addr = json_addr_info_zero;
            JsonAddrInfoInit(p, LOG_DIR_PACKET, &addr);

            JsonBuilder *jb =
                    CreateEveHeader(p, LOG_DIR_PACKET, "pdu", &addr, json_output_ctx->eve_ctx);
            if (unlikely(jb == NULL))
                return TM_ECODE_OK;

            uint64_t abs_offset = (uint64_t)pdu->rel_offset + (uint64_t)STREAM_BASE_OFFSET(stream);

            jb_open_object(jb, "pdu");
            jb_set_uint(jb, "type", pdu->type);
            jb_set_uint(jb, "offset", abs_offset);
            jb_set_uint(jb, "length", pdu->len);
            jb_set_string(jb, "direction", PKT_IS_TOSERVER(p) ? "toserver" : "toclient");
            PduAddPayload(json_output_ctx, jb, stream, pdu);
            jb_close(jb);

            OutputJsonBuilderBuffer(jb, aft->ctx);
            jb_free(jb);
        }
    }
    return TM_ECODE_OK;
}

static int JsonPduLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonPduLogThread *aft = thread_data;
    return PduJson(tv, aft, p);
}

static int JsonPduLogCondition(ThreadVars *tv, const Packet *p)
{
    if (p->flow == NULL || p->flow->alproto == ALPROTO_UNKNOWN)
        return FALSE;

    if (p->proto == IPPROTO_TCP) {
        TcpSession *ssn = p->flow->protoctx;
        TcpStream *stream;
        if (PKT_IS_TOSERVER(p)) {
            stream = &ssn->client;
        } else {
            stream = &ssn->server;
        }
        return (stream->pdus.cnt != 0);
    }
    return FALSE;
}

static TmEcode JsonPduLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonPduLogThread *aft = SCCalloc(1, sizeof(JsonPduLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogPdu.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /** Use the Output Context (file pointer and mutex) */
    PduJsonOutputCtx *json_output_ctx = ((OutputCtx *)initdata)->data;

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

static TmEcode JsonPduLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonPduLogThread *aft = (JsonPduLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->payload_buffer);
    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(JsonPduLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonPduLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);

    PduJsonOutputCtx *json_output_ctx = (PduJsonOutputCtx *)output_ctx->data;

    if (json_output_ctx != NULL) {
        SCFree(json_output_ctx);
    }
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "pdu.json"

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
static OutputInitResult JsonPduLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;
    PduJsonOutputCtx *json_output_ctx = NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return result;

    json_output_ctx = SCMalloc(sizeof(PduJsonOutputCtx));
    if (unlikely(json_output_ctx == NULL)) {
        goto error;
    }
    memset(json_output_ctx, 0, sizeof(PduJsonOutputCtx));

    json_output_ctx->file_ctx = ajt->file_ctx;
    json_output_ctx->eve_ctx = ajt;

    output_ctx->data = json_output_ctx;
    output_ctx->DeInit = JsonPduLogDeInitCtxSub;

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

void JsonPduLogRegister(void)
{
    OutputRegisterPacketSubModule(LOGGER_JSON_PDU, "eve-log", MODULE_NAME, "eve-log.pdu",
            JsonPduLogInitCtxSub, JsonPduLogger, JsonPduLogCondition, JsonPduLogThreadInit,
            JsonPduLogThreadDeinit, NULL);
}
