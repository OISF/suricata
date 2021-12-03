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
 * Logs frames in JSON format.
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
#include "app-layer-frames.h"
#include "app-layer-dnp3.h"
#include "app-layer-htp.h"
#include "app-layer-htp-xff.h"
#include "app-layer-ftp.h"
#include "util-classification-config.h"
#include "util-syslog.h"
#include "util-logopenfile.h"

#include "output.h"
#include "output-json.h"
#include "output-json-frame.h"

#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-crypt.h"
#include "util-validate.h"

#define MODULE_NAME "JsonFrameLog"

#define JSON_STREAM_BUFFER_SIZE 4096

typedef struct FrameJsonOutputCtx_ {
    LogFileCtx *file_ctx;
    uint16_t flags;
    uint32_t payload_buffer_size;
    OutputJsonCtx *eve_ctx;
} FrameJsonOutputCtx;

typedef struct JsonFrameLogThread_ {
    MemBuffer *payload_buffer;
    FrameJsonOutputCtx *json_output_ctx;
    OutputJsonThreadCtx *ctx;
} JsonFrameLogThread;

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

static void FrameAddPayload(JsonBuilder *js, const TcpStream *stream, const Frame *frame)
{
    uint32_t data_len = 0;
    const uint8_t *data = NULL;

    uint64_t offset = frame->rel_offset + STREAM_BASE_OFFSET(stream);
    SCLogDebug("offset %" PRIu64, offset);

    if (StreamingBufferGetDataAtOffset(&stream->sb, &data, &data_len, offset) == 0) {
        SCLogDebug("NO DATA1");
        return;
    }
    if (data == NULL || data_len == 0) {
        SCLogDebug("NO DATA2");
        return;
    }
    data_len = MIN(frame->len, (int32_t)data_len);

    jb_set_bool(js, "complete", ((int32_t)data_len >= frame->len));

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
    jb_set_string(js, "payload_hex", pretty_buf);
}

void FrameJsonLogOneFrame(const Frame *frame, const Flow *f, const TcpStream *stream,
        const Packet *p, JsonBuilder *jb)
{
    uint64_t abs_offset = (uint64_t)frame->rel_offset + (uint64_t)STREAM_BASE_OFFSET(stream);

    jb_open_object(jb, "frame");
    jb_set_string(jb, "type", AppLayerParserGetFrameNameById(f->proto, f->alproto, frame->type));
    jb_set_uint(jb, "id", frame->id);
    jb_set_uint(jb, "offset", abs_offset);
    jb_set_uint(jb, "length", frame->len);
    jb_set_string(jb, "direction", PKT_IS_TOSERVER(p) ? "toserver" : "toclient");
    if (frame->flags & FRAME_FLAG_TX_ID_SET) {
        jb_set_uint(jb, "tx_id", frame->tx_id);
    }
    FrameAddPayload(jb, stream, frame);
    jb_close(jb);
}

static int FrameJson(ThreadVars *tv, JsonFrameLogThread *aft, const Packet *p)
{
    FrameJsonOutputCtx *json_output_ctx = aft->json_output_ctx;

    BUG_ON(p->proto != IPPROTO_TCP);
    BUG_ON(p->flow == NULL);
    BUG_ON(p->flow->protoctx == NULL);

    FramesContainer *frames_container = AppLayerFramesGetContainer(p->flow);
    if (frames_container == NULL)
        return TM_ECODE_OK;

    Frames *frames;
    TcpSession *ssn = p->flow->protoctx;
    TcpStream *stream;
    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        frames = &frames_container->toserver;
    } else {
        stream = &ssn->server;
        frames = &frames_container->toclient;
    }

    for (uint32_t idx = 0; idx < frames->cnt; idx++) {
        Frame *frame = FrameGetByIndex(frames, idx);
        if (frame != NULL && frame->rel_offset >= 0) {
            /* First initialize the address info (5-tuple). */
            JsonAddrInfo addr = json_addr_info_zero;
            JsonAddrInfoInit(p, LOG_DIR_PACKET, &addr);

            JsonBuilder *jb =
                    CreateEveHeader(p, LOG_DIR_PACKET, "frame", &addr, json_output_ctx->eve_ctx);
            if (unlikely(jb == NULL))
                return TM_ECODE_OK;

            FrameJsonLogOneFrame(frame, p->flow, stream, p, jb);
            OutputJsonBuilderBuffer(jb, aft->ctx);
            jb_free(jb);
        }
    }
    return TM_ECODE_OK;
}

static int JsonFrameLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonFrameLogThread *aft = thread_data;
    return FrameJson(tv, aft, p);
}

static int JsonFrameLogCondition(ThreadVars *tv, const Packet *p)
{
    if (p->flow == NULL || p->flow->alproto == ALPROTO_UNKNOWN)
        return FALSE;

    if (p->proto == IPPROTO_TCP && p->flow->alparser != NULL) {
        FramesContainer *frames_container = AppLayerFramesGetContainer(p->flow);
        if (frames_container == NULL)
            return FALSE;

        Frames *frames;
        if (PKT_IS_TOSERVER(p)) {
            frames = &frames_container->toserver;
        } else {
            frames = &frames_container->toclient;
        }
        return (frames->cnt != 0);
    }
    return FALSE;
}

static TmEcode JsonFrameLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonFrameLogThread *aft = SCCalloc(1, sizeof(JsonFrameLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogFrame.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /** Use the Output Context (file pointer and mutex) */
    FrameJsonOutputCtx *json_output_ctx = ((OutputCtx *)initdata)->data;

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

static TmEcode JsonFrameLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonFrameLogThread *aft = (JsonFrameLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->payload_buffer);
    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(JsonFrameLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonFrameLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);

    FrameJsonOutputCtx *json_output_ctx = (FrameJsonOutputCtx *)output_ctx->data;

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
static OutputInitResult JsonFrameLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;
    FrameJsonOutputCtx *json_output_ctx = NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return result;

    json_output_ctx = SCMalloc(sizeof(FrameJsonOutputCtx));
    if (unlikely(json_output_ctx == NULL)) {
        goto error;
    }
    memset(json_output_ctx, 0, sizeof(FrameJsonOutputCtx));

    json_output_ctx->file_ctx = ajt->file_ctx;
    json_output_ctx->eve_ctx = ajt;

    output_ctx->data = json_output_ctx;
    output_ctx->DeInit = JsonFrameLogDeInitCtxSub;

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

void JsonFrameLogRegister(void)
{
    OutputRegisterPacketSubModule(LOGGER_JSON_FRAME, "eve-log", MODULE_NAME, "eve-log.frame",
            JsonFrameLogInitCtxSub, JsonFrameLogger, JsonFrameLogCondition, JsonFrameLogThreadInit,
            JsonFrameLogThreadDeinit, NULL);
}
