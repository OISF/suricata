/* Copyright (C) 2013-2022 Open Information Security Foundation
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
#include "stream-tcp.h"

#include "output.h"
#include "output-json.h"
#include "output-json-frame.h"

#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
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

#if 0 // TODO see if this is useful in some way
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
#endif

static void FrameAddPayloadTCP(JsonBuilder *js, const TcpStream *stream, const Frame *frame)
{
    uint32_t sb_data_len = 0;
    const uint8_t *data = NULL;
    uint64_t data_offset = 0;

    // TODO consider ACK'd

    if (frame->rel_offset < 0) {
        if (StreamingBufferGetData(&stream->sb, &data, &sb_data_len, &data_offset) == 0) {
            SCLogDebug("NO DATA1");
            return;
        }
    } else {
        data_offset = (uint64_t)(frame->rel_offset + (int64_t)STREAM_BASE_OFFSET(stream));
        SCLogDebug("data_offset %" PRIu64, data_offset);
        if (StreamingBufferGetDataAtOffset(
                    &stream->sb, &data, &sb_data_len, (uint64_t)data_offset) == 0) {
            SCLogDebug("NO DATA1");
            return;
        }
    }
    if (data == NULL || sb_data_len == 0) {
        SCLogDebug("NO DATA2");
        return;
    }

    if (frame->len >= 0) {
        sb_data_len = MIN(frame->len, (int32_t)sb_data_len);
    }
    SCLogDebug("frame data_offset %" PRIu64 ", data_len %u frame len %" PRIi64, data_offset,
            sb_data_len, frame->len);

    // TODO update to work with large frames
    jb_set_bool(js, "complete", ((int64_t)sb_data_len >= frame->len));

    uint32_t data_len = MIN(sb_data_len, 256);
    jb_set_base64(js, "payload", data, data_len);

    uint8_t printable_buf[data_len + 1];
    uint32_t o = 0;
    PrintStringsToBuffer(printable_buf, &o, data_len + 1, data, data_len);
    printable_buf[data_len] = '\0';
    jb_set_string(js, "payload_printable", (char *)printable_buf);
#if 0
    char pretty_buf[data_len * 4 + 1];
    pretty_buf[0] = '\0';
    PayloadAsHex(data, data_len, pretty_buf, data_len * 4 + 1);
    jb_set_string(js, "payload_hex", pretty_buf);
#endif
}

static void FrameAddPayloadUDP(JsonBuilder *js, const Packet *p, const Frame *frame)
{
    DEBUG_VALIDATE_BUG_ON(frame->rel_offset >= p->payload_len);
    if (frame->rel_offset >= p->payload_len)
        return;

    int frame_len = frame->len != -1 ? frame->len : p->payload_len - frame->rel_offset;

    if (frame->rel_offset + frame_len > p->payload_len) {
        frame_len = p->payload_len - frame->rel_offset;
        JB_SET_FALSE(js, "complete");
    } else {
        JB_SET_TRUE(js, "complete");
    }
    const uint8_t *data = p->payload + frame->rel_offset;
    const uint32_t data_len = frame_len;

    const uint32_t log_data_len = MIN(data_len, 256);
    jb_set_base64(js, "payload", data, log_data_len);

    uint8_t printable_buf[log_data_len + 1];
    uint32_t o = 0;
    PrintStringsToBuffer(printable_buf, &o, log_data_len + 1, data, log_data_len);
    printable_buf[log_data_len] = '\0';
    jb_set_string(js, "payload_printable", (char *)printable_buf);
#if 0
    char pretty_buf[data_len * 4 + 1];
    pretty_buf[0] = '\0';
    PayloadAsHex(data, data_len, pretty_buf, data_len * 4 + 1);
    jb_set_string(js, "payload_hex", pretty_buf);
#endif
}

// TODO separate between stream_offset and frame_offset
/** \brief log a single frame
 *  \note ipproto argument is passed to assist static code analyzers
 */
void FrameJsonLogOneFrame(const uint8_t ipproto, const Frame *frame, const Flow *f,
        const TcpStream *stream, const Packet *p, JsonBuilder *jb)
{
    DEBUG_VALIDATE_BUG_ON(ipproto != p->proto);
    DEBUG_VALIDATE_BUG_ON(ipproto != f->proto);

    jb_open_object(jb, "frame");
    jb_set_string(jb, "type", AppLayerParserGetFrameNameById(ipproto, f->alproto, frame->type));
    jb_set_uint(jb, "id", frame->id);
    jb_set_string(jb, "direction", PKT_IS_TOSERVER(p) ? "toserver" : "toclient");

    if (ipproto == IPPROTO_TCP) {
        DEBUG_VALIDATE_BUG_ON(stream == NULL);
        int64_t abs_offset = frame->rel_offset + (int64_t)STREAM_BASE_OFFSET(stream);
        jb_set_uint(jb, "stream_offset", (uint64_t)abs_offset);

        if (frame->len < 0) {
            uint64_t usable = StreamTcpGetUsable(stream, true);
            uint64_t len = usable - abs_offset;
            jb_set_uint(jb, "length", len);
        } else {
            jb_set_uint(jb, "length", frame->len);
        }
        FrameAddPayloadTCP(jb, stream, frame);
    } else {
        jb_set_uint(jb, "length", frame->len);
        FrameAddPayloadUDP(jb, p, frame);
    }
    if (frame->flags & FRAME_FLAG_TX_ID_SET) {
        jb_set_uint(jb, "tx_id", frame->tx_id);
    }
    jb_close(jb);
}

static int FrameJsonUdp(
        JsonFrameLogThread *aft, const Packet *p, Flow *f, FramesContainer *frames_container)
{
    FrameJsonOutputCtx *json_output_ctx = aft->json_output_ctx;

    Frames *frames;
    if (PKT_IS_TOSERVER(p)) {
        frames = &frames_container->toserver;
    } else {
        frames = &frames_container->toclient;
    }

    for (uint32_t idx = 0; idx < frames->cnt; idx++) {
        Frame *frame = FrameGetByIndex(frames, idx);
        if (frame == NULL || frame->flags & FRAME_FLAG_LOGGED)
            continue;

        /* First initialize the address info (5-tuple). */
        JsonAddrInfo addr = json_addr_info_zero;
        JsonAddrInfoInit(p, LOG_DIR_PACKET, &addr);

        JsonBuilder *jb =
                CreateEveHeader(p, LOG_DIR_PACKET, "frame", &addr, json_output_ctx->eve_ctx);
        if (unlikely(jb == NULL))
            return TM_ECODE_OK;

        jb_set_string(jb, "app_proto", AppProtoToString(f->alproto));
        FrameJsonLogOneFrame(IPPROTO_UDP, frame, p->flow, NULL, p, jb);
        OutputJsonBuilderBuffer(jb, aft->ctx);
        jb_free(jb);
        frame->flags |= FRAME_FLAG_LOGGED;
    }
    return TM_ECODE_OK;
}

static int FrameJson(ThreadVars *tv, JsonFrameLogThread *aft, const Packet *p)
{
    FrameJsonOutputCtx *json_output_ctx = aft->json_output_ctx;

    BUG_ON(p->flow == NULL);

    FramesContainer *frames_container = AppLayerFramesGetContainer(p->flow);
    if (frames_container == NULL)
        return TM_ECODE_OK;

    if (p->proto == IPPROTO_UDP) {
        return FrameJsonUdp(aft, p, p->flow, frames_container);
    }

    BUG_ON(p->proto != IPPROTO_TCP);
    BUG_ON(p->flow->protoctx == NULL);

    /* TODO can we set these EOF flags once per packet? We have them in detect, tx, file, filedata,
     * etc */
    const bool last_pseudo = (p->flowflags & FLOW_PKT_LAST_PSEUDO) != 0;
    Frames *frames;
    TcpSession *ssn = p->flow->protoctx;
    bool eof = (ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    TcpStream *stream;
    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        frames = &frames_container->toserver;
        SCLogDebug("TOSERVER base %" PRIu64 ", app %" PRIu64, STREAM_BASE_OFFSET(stream),
                STREAM_APP_PROGRESS(stream));
        eof |= AppLayerParserStateIssetFlag(p->flow->alparser, APP_LAYER_PARSER_EOF_TS) != 0;
    } else {
        stream = &ssn->server;
        frames = &frames_container->toclient;
        eof |= AppLayerParserStateIssetFlag(p->flow->alparser, APP_LAYER_PARSER_EOF_TC) != 0;
    }
    eof |= last_pseudo;
    SCLogDebug("eof %s", eof ? "true" : "false");

    for (uint32_t idx = 0; idx < frames->cnt; idx++) {
        Frame *frame = FrameGetByIndex(frames, idx);
        if (frame != NULL && frame->rel_offset >= 0) {
            if (frame->flags & FRAME_FLAG_LOGGED)
                continue;

            int64_t abs_offset = (int64_t)frame->rel_offset + (int64_t)STREAM_BASE_OFFSET(stream);
            int64_t win = STREAM_APP_PROGRESS(stream) - abs_offset;
            //            SCLogDebug("abs_offset %" PRIi64 ", frame->rel_offset %" PRIi64
            //                       ", frames->progress_rel %d win %" PRIi64,
            //                    abs_offset, frame->rel_offset, frames->progress_rel, win);

            if (!eof && win < frame->len && win < 2500) {
                SCLogDebug("frame id %" PRIi64 " len %" PRIi64 ", win %" PRIi64
                           ", skipping logging",
                        frame->id, frame->len, win);
                continue;
            }

            /* First initialize the address info (5-tuple). */
            JsonAddrInfo addr = json_addr_info_zero;
            JsonAddrInfoInit(p, LOG_DIR_PACKET, &addr);

            JsonBuilder *jb =
                    CreateEveHeader(p, LOG_DIR_PACKET, "frame", &addr, json_output_ctx->eve_ctx);
            if (unlikely(jb == NULL))
                return TM_ECODE_OK;

            jb_set_string(jb, "app_proto", AppProtoToString(p->flow->alproto));
            FrameJsonLogOneFrame(IPPROTO_TCP, frame, p->flow, stream, p, jb);
            OutputJsonBuilderBuffer(jb, aft->ctx);
            jb_free(jb);
            frame->flags |= FRAME_FLAG_LOGGED;
        } else if (frame != NULL) {
            SCLogDebug("frame %p id %" PRIi64, frame, frame->id);
        }
    }
    return TM_ECODE_OK;
}

static int JsonFrameLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonFrameLogThread *aft = thread_data;
    return FrameJson(tv, aft, p);
}

static int JsonFrameLogCondition(ThreadVars *tv, void *thread_data, const Packet *p)
{
    if (p->flow == NULL || p->flow->alproto == ALPROTO_UNKNOWN)
        return FALSE;

    if ((p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP) && p->flow->alparser != NULL) {
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
