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
 * Logs records in JSON format.
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
#include "app-layer-records.h"
#include "app-layer-dnp3.h"
#include "app-layer-htp.h"
#include "app-layer-htp-xff.h"
#include "app-layer-ftp.h"
#include "util-classification-config.h"
#include "util-syslog.h"
#include "util-logopenfile.h"

#include "output.h"
#include "output-json.h"
#include "output-json-record.h"

#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-crypt.h"
#include "util-validate.h"

#define MODULE_NAME "JsonRecordLog"

#define JSON_STREAM_BUFFER_SIZE 4096

typedef struct RecordJsonOutputCtx_ {
    LogFileCtx *file_ctx;
    uint16_t flags;
    uint32_t payload_buffer_size;
    OutputJsonCtx *eve_ctx;
} RecordJsonOutputCtx;

typedef struct JsonRecordLogThread_ {
    MemBuffer *payload_buffer;
    RecordJsonOutputCtx *json_output_ctx;
    OutputJsonThreadCtx *ctx;
} JsonRecordLogThread;

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

void RecordAddPayload(JsonBuilder *js, TcpStream *stream, const Record *rec);
void RecordAddPayload(JsonBuilder *js, TcpStream *stream, const Record *rec)
{
    uint32_t data_len = 0;
    const uint8_t *data = NULL;

    uint64_t offset = rec->rel_offset + STREAM_BASE_OFFSET(stream);
    SCLogDebug("offset %" PRIu64, offset);

    if (StreamingBufferGetDataAtOffset(&stream->sb, &data, &data_len, offset) == 0) {
        SCLogDebug("NO DATA1");
        return;
    }
    if (data == NULL || data_len == 0) {
        SCLogDebug("NO DATA2");
        return;
    }
    data_len = MIN(rec->len, (int32_t)data_len);

    jb_set_bool(js, "complete", ((int32_t)data_len >= rec->len));

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

static int RecordJson(ThreadVars *tv, JsonRecordLogThread *aft, const Packet *p)
{
    // MemBuffer *payload = aft->payload_buffer;
    RecordJsonOutputCtx *json_output_ctx = aft->json_output_ctx;

    assert(p->proto == IPPROTO_TCP);
    assert(p->flow);
    assert(p->flow->protoctx);

    RecordsContainer *records_container = AppLayerRecordsGetContainer(p->flow);
    if (records_container == NULL)
        return TM_ECODE_OK;

    Records *recs;
    TcpSession *ssn = p->flow->protoctx;
    TcpStream *stream;
    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        recs = &records_container->toserver;
    } else {
        stream = &ssn->server;
        recs = &records_container->toclient;
    }

    for (uint32_t idx = 0; idx < recs->cnt; idx++) {
        Record *rec = RecordGetByIndex(recs, idx);
        if (rec != NULL && rec->rel_offset >= 0) {
            /* First initialize the address info (5-tuple). */
            JsonAddrInfo addr = json_addr_info_zero;
            JsonAddrInfoInit(p, LOG_DIR_PACKET, &addr);

            JsonBuilder *jb =
                    CreateEveHeader(p, LOG_DIR_PACKET, "record", &addr, json_output_ctx->eve_ctx);
            if (unlikely(jb == NULL))
                return TM_ECODE_OK;

            uint64_t abs_offset = (uint64_t)rec->rel_offset + (uint64_t)STREAM_BASE_OFFSET(stream);

            jb_open_object(jb, "record");
            jb_set_string(jb, "type", AppLayerParserGetRecordNameById(p->proto, p->flow->alproto, rec->type));
            jb_set_uint(jb, "id", rec->id);
            jb_set_uint(jb, "offset", abs_offset);
            jb_set_uint(jb, "length", rec->len);
            jb_set_string(jb, "direction", PKT_IS_TOSERVER(p) ? "toserver" : "toclient");
            RecordAddPayload(jb, stream, rec);
            jb_close(jb);

            OutputJsonBuilderBuffer(jb, aft->ctx);
            jb_free(jb);
        }
    }
    return TM_ECODE_OK;
}

static int JsonRecordLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonRecordLogThread *aft = thread_data;
    return RecordJson(tv, aft, p);
}

static int JsonRecordLogCondition(ThreadVars *tv, const Packet *p)
{
    if (p->flow == NULL || p->flow->alproto == ALPROTO_UNKNOWN)
        return FALSE;

    if (p->proto == IPPROTO_TCP && p->flow->alparser != NULL) {
        RecordsContainer *records_container = AppLayerRecordsGetContainer(p->flow);
        if (records_container == NULL)
            return FALSE;

        Records *recs;
        if (PKT_IS_TOSERVER(p)) {
            recs = &records_container->toserver;
        } else {
            recs = &records_container->toclient;
        }
        return (recs->cnt != 0);
    }
    return FALSE;
}

static TmEcode JsonRecordLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonRecordLogThread *aft = SCCalloc(1, sizeof(JsonRecordLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogRecord.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /** Use the Output Context (file pointer and mutex) */
    RecordJsonOutputCtx *json_output_ctx = ((OutputCtx *)initdata)->data;

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

static TmEcode JsonRecordLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonRecordLogThread *aft = (JsonRecordLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->payload_buffer);
    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(JsonRecordLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonRecordLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);

    RecordJsonOutputCtx *json_output_ctx = (RecordJsonOutputCtx *)output_ctx->data;

    if (json_output_ctx != NULL) {
        SCFree(json_output_ctx);
    }
    SCFree(output_ctx);
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
static OutputInitResult JsonRecordLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;
    RecordJsonOutputCtx *json_output_ctx = NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return result;

    json_output_ctx = SCMalloc(sizeof(RecordJsonOutputCtx));
    if (unlikely(json_output_ctx == NULL)) {
        goto error;
    }
    memset(json_output_ctx, 0, sizeof(RecordJsonOutputCtx));

    json_output_ctx->file_ctx = ajt->file_ctx;
    json_output_ctx->eve_ctx = ajt;

    output_ctx->data = json_output_ctx;
    output_ctx->DeInit = JsonRecordLogDeInitCtxSub;

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

void JsonRecordLogRegister(void)
{
    OutputRegisterPacketSubModule(LOGGER_JSON_RECORD, "eve-log", MODULE_NAME, "eve-log.record",
            JsonRecordLogInitCtxSub, JsonRecordLogger, JsonRecordLogCondition, JsonRecordLogThreadInit,
            JsonRecordLogThreadDeinit, NULL);
}
