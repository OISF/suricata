/* Copyright (C) 2023 Open Information Security Foundation
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
#include "packet.h"
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
#include "output-json-flow.h"
#include "output-eve-stream.h"

#include "stream-tcp.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-classification-config.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "util-buffer.h"

#include "action-globals.h"

#define MODULE_NAME "EveStreamLog"

#define LOG_DROP_ALERTS 1

typedef struct EveStreamOutputCtx_ {
    uint16_t trigger_flags; /**< presence of flags in packet trigger logging. 0xffff for all. */
    OutputJsonCtx *eve_ctx;
} EveStreamOutputCtx;

typedef struct EveStreamLogThread_ {
    EveStreamOutputCtx *stream_ctx;
    OutputJsonThreadCtx *ctx;
} EveStreamLogThread;

static TmEcode EveStreamLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    EveStreamLogThread *aft = SCCalloc(1, sizeof(EveStreamLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogDrop.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /** Use the Output Context (file pointer and mutex) */
    aft->stream_ctx = ((OutputCtx *)initdata)->data;
    aft->ctx = CreateEveThreadCtx(t, aft->stream_ctx->eve_ctx);
    if (!aft->ctx) {
        goto error_exit;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode EveStreamLogThreadDeinit(ThreadVars *t, void *data)
{
    EveStreamLogThread *aft = (EveStreamLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(*aft));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void EveStreamOutputCtxFree(EveStreamOutputCtx *ctx)
{
    if (ctx != NULL) {
        SCFree(ctx);
    }
}

static void EveStreamLogDeInitCtxSub(OutputCtx *output_ctx)
{
    OutputDropLoggerDisable();

    EveStreamOutputCtx *ctx = output_ctx->data;
    SCFree(ctx);
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    SCFree(output_ctx);
}

static uint16_t SetFlag(ConfNode *conf, const char *opt, const uint16_t inflag)
{
    const char *v = ConfNodeLookupChildValue(conf, opt);
    if (v != NULL && ConfValIsTrue(v)) {
        return inflag;
    }
    return 0;
}

static OutputInitResult EveStreamLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    EveStreamOutputCtx *ctx = SCCalloc(1, sizeof(*ctx));
    if (ctx == NULL)
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        EveStreamOutputCtxFree(ctx);
        return result;
    }

    if (conf) {
        // TODO add all flags

        ctx->trigger_flags |= SetFlag(conf, "event-set", STREAM_PKT_FLAG_EVENTSET);
        ctx->trigger_flags |= SetFlag(conf, "state-update", STREAM_PKT_FLAG_STATE_UPDATE);
        ctx->trigger_flags |=
                SetFlag(conf, "spurious-retransmission", STREAM_PKT_FLAG_SPURIOUS_RETRANSMISSION);

        ctx->trigger_flags |= SetFlag(conf, "all", 0xFFFF);
        SCLogDebug("trigger_flags %04x", ctx->trigger_flags);
    }
    ctx->eve_ctx = ajt;

    output_ctx->data = ctx;
    output_ctx->DeInit = EveStreamLogDeInitCtxSub;

    result.ctx = output_ctx;
    result.ok = true;

    SCLogWarning("eve.stream facility is EXPERIMENTAL and can change w/o notice");
    return result;
}

void EveAddFlowTcpStreamFlags(const TcpStream *stream, const char *name, JsonBuilder *jb)
{
    jb_open_array(jb, name);
    if (stream->flags & STREAMTCP_STREAM_FLAG_HAS_GAP)
        jb_append_string(jb, "has_gap");
    if (stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)
        jb_append_string(jb, "noreassembly");
    if (stream->flags & STREAMTCP_STREAM_FLAG_KEEPALIVE)
        jb_append_string(jb, "keepalive");
    if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED)
        jb_append_string(jb, "depth_reached");
    if (stream->flags & STREAMTCP_STREAM_FLAG_TRIGGER_RAW)
        jb_append_string(jb, "trigger_raw");
    if (stream->flags & STREAMTCP_STREAM_FLAG_TIMESTAMP)
        jb_append_string(jb, "timestamp");
    if (stream->flags & STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP)
        jb_append_string(jb, "zero_timestamp");
    if (stream->flags & STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_COMPLETED)
        jb_append_string(jb, "appproto_detection_completed");
    if (stream->flags & STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_SKIPPED)
        jb_append_string(jb, "appproto_detection_skipped");
    if (stream->flags & STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED)
        jb_append_string(jb, "new_raw_disabled");
    if (stream->flags & STREAMTCP_STREAM_FLAG_DISABLE_RAW)
        jb_append_string(jb, "disable_raw");
    if (stream->flags & STREAMTCP_STREAM_FLAG_RST_RECV)
        jb_append_string(jb, "rst_recv");
    jb_close(jb);
}

void EveAddFlowTcpFlags(const TcpSession *ssn, const char *name, JsonBuilder *jb)
{
    jb_open_object(jb, "flags");

    jb_open_array(jb, name);
    if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
        jb_append_string(jb, "midstream");
    }
    if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED) {
        jb_append_string(jb, "midstream_established");
    }
    if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK) {
        jb_append_string(jb, "midstream_synack");
    }
    if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
        jb_append_string(jb, "timestamp");
    }
    if (ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) {
        jb_append_string(jb, "server_wscale");
    }
    if (ssn->flags & STREAMTCP_FLAG_CLOSED_BY_RST) {
        jb_append_string(jb, "closed_by_rst");
    }
    if (ssn->flags & STREAMTCP_FLAG_4WHS) {
        jb_append_string(jb, "4whs");
    }
    if (ssn->flags & STREAMTCP_FLAG_DETECTION_EVASION_ATTEMPT) {
        jb_append_string(jb, "detect_evasion_attempt");
    }
    if (ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) {
        jb_append_string(jb, "client_sackok");
    }
    if (ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) {
        jb_append_string(jb, "sackok");
    }
    if (ssn->flags & STREAMTCP_FLAG_3WHS_CONFIRMED) {
        jb_append_string(jb, "3whs_confirmed");
    }
    if (ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) {
        jb_append_string(jb, "app_layer_disabled");
    }
    if (ssn->flags & STREAMTCP_FLAG_BYPASS) {
        jb_append_string(jb, "bypass");
    }
    if (ssn->flags & STREAMTCP_FLAG_TCP_FAST_OPEN) {
        jb_append_string(jb, "tcp_fast_open");
    }
    if (ssn->flags & STREAMTCP_FLAG_TFO_DATA_IGNORED) {
        jb_append_string(jb, "tfo_data_ignored");
    }
    jb_close(jb);
    jb_close(jb);
}

static void LogStream(const TcpStream *stream, JsonBuilder *js)
{
    jb_set_uint(js, "isn", stream->isn);
    jb_set_uint(js, "next_seq", stream->next_seq);
    jb_set_uint(js, "last_ack", stream->last_ack);
    jb_set_uint(js, "next_win", stream->next_win);
    if (!(stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        jb_set_uint(js, "base_seq", stream->base_seq);
        jb_set_uint(js, "segs_right_edge", stream->segs_right_edge);
    }
    jb_set_uint(js, "window", stream->window);
    jb_set_uint(js, "wscale", stream->wscale);

    EveAddFlowTcpStreamFlags(stream, "flags", js);
}

/**
 * \brief   Log the stream packets
 *
 * \param tv    Pointer the current thread variables
 * \param data  Pointer to the EveStreamLogThread struct
 * \param p     Pointer the packet which is being logged
 *
 * \retval 0 on succes
 */
static int EveStreamLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    EveStreamLogThread *td = thread_data;
    EveStreamOutputCtx *ctx = td->stream_ctx;

    JsonAddrInfo addr = json_addr_info_zero;
    JsonAddrInfoInit(p, LOG_DIR_PACKET, &addr);

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_PACKET, "stream_tcp", &addr, ctx->eve_ctx);
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    if (p->flow != NULL) {
        if (p->flowflags & FLOW_PKT_TOSERVER) {
            jb_set_string(js, "direction", "to_server");
        } else {
            jb_set_string(js, "direction", "to_client");
        }
    }

    jb_open_object(js, "stream_tcp");
    jb_open_object(js, "packet");

    if (PKT_IS_IPV4(p)) {
        jb_set_uint(js, "len", IPV4_GET_IPLEN(p));
        jb_set_uint(js, "tos", IPV4_GET_IPTOS(p));
        jb_set_uint(js, "ttl", IPV4_GET_IPTTL(p));
        jb_set_uint(js, "ipid", IPV4_GET_IPID(p));
    } else if (PKT_IS_IPV6(p)) {
        jb_set_uint(js, "len", IPV6_GET_PLEN(p));
        jb_set_uint(js, "tc", IPV6_GET_CLASS(p));
        jb_set_uint(js, "hoplimit", IPV6_GET_HLIM(p));
        jb_set_uint(js, "flowlbl", IPV6_GET_FLOW(p));
    }
    if (PKT_IS_TCP(p)) {
        jb_set_uint(js, "tcpseq", TCP_GET_SEQ(p));
        jb_set_uint(js, "tcpack", TCP_GET_ACK(p));
        jb_set_uint(js, "tcpwin", TCP_GET_WINDOW(p));
        jb_set_bool(js, "syn", TCP_ISSET_FLAG_SYN(p) ? true : false);
        jb_set_bool(js, "ack", TCP_ISSET_FLAG_ACK(p) ? true : false);
        jb_set_bool(js, "psh", TCP_ISSET_FLAG_PUSH(p) ? true : false);
        jb_set_bool(js, "rst", TCP_ISSET_FLAG_RST(p) ? true : false);
        jb_set_bool(js, "urg", TCP_ISSET_FLAG_URG(p) ? true : false);
        jb_set_bool(js, "fin", TCP_ISSET_FLAG_FIN(p) ? true : false);
        jb_set_uint(js, "tcpres", TCP_GET_RAW_X2(p->tcph));
        jb_set_uint(js, "tcpurgp", TCP_GET_URG_POINTER(p));

        jb_open_array(js, "flags");
        if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_RETRANSMISSION)
            jb_append_string(js, "retransmission");
        if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_SPURIOUS_RETRANSMISSION)
            jb_append_string(js, "spurious_retransmission");
        if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_KEEPALIVE)
            jb_append_string(js, "keepalive");
        if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_KEEPALIVEACK)
            jb_append_string(js, "keepalive_ack");
        if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_WINDOWUPDATE)
            jb_append_string(js, "window_update");

        if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_EVENTSET)
            jb_append_string(js, "event_set");
        if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_STATE_UPDATE)
            jb_append_string(js, "state_update");
        if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_DUP_ACK)
            jb_append_string(js, "dup_ack");
        if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_DSACK)
            jb_append_string(js, "dsack");
        if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_ACK_UNSEEN_DATA)
            jb_append_string(js, "ack_unseen_data");
        if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_TCP_PORT_REUSE)
            jb_append_string(js, "tcp_port_reuse");
        if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_TCP_ZERO_WIN_PROBE)
            jb_append_string(js, "zero_window_probe");
        if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_TCP_ZERO_WIN_PROBE_ACK)
            jb_append_string(js, "zero_window_probe_ack");
        jb_close(js);
    }
    jb_close(js);

    jb_open_object(js, "session");
    if (p->flow != NULL && p->flow->protoctx != NULL) {
        const TcpSession *ssn = p->flow->protoctx;
        const char *tcp_state = StreamTcpStateAsString(ssn->state);
        if (tcp_state != NULL)
            jb_set_string(js, "state", tcp_state);
        if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_STATE_UPDATE) {
            const char *tcp_pstate = StreamTcpStateAsString(ssn->pstate);
            if (tcp_pstate != NULL)
                jb_set_string(js, "pstate", tcp_pstate);
        }
        EveAddFlowTcpFlags(ssn, "flags", js);

        jb_open_object(js, "client");
        LogStream(&ssn->client, js);
        jb_close(js);
        jb_open_object(js, "server");
        LogStream(&ssn->server, js);
        jb_close(js);
    }
    jb_close(js);

    if (p->tcpvars.stream_pkt_flags & STREAM_PKT_FLAG_EVENTSET) {
        jb_open_array(js, "events");
        for (int i = 0; i < p->events.cnt; i++) {
            uint8_t event_code = p->events.events[i];
            bool is_decode = EVENT_IS_DECODER_PACKET_ERROR(event_code);
            if (is_decode)
                continue;
            if (event_code >= DECODE_EVENT_MAX)
                continue;
            const char *event = DEvents[event_code].event_name;
            if (event == NULL)
                continue;
            jb_append_string(js, event);
        }
        jb_close(js);
    }

    if (p->drop_reason != 0) {
        const char *str = PacketDropReasonToString(p->drop_reason);
        jb_set_string(js, "reason", str);
    }

    /* Close stream. */
    jb_close(js);

    OutputJsonBuilderBuffer(js, td->ctx);
    jb_free(js);

    return TM_ECODE_OK;
}

/**
 * \brief Check if we need to log this packet
 *
 * \param tv    Pointer the current thread variables
 * \param p     Pointer the packet which is tested
 *
 * \retval bool TRUE or FALSE
 */
static int EveStreamLogCondition(ThreadVars *tv, void *data, const Packet *p)
{
    EveStreamLogThread *td = data;
    EveStreamOutputCtx *ctx = td->stream_ctx;

    return (p->proto == IPPROTO_TCP &&
            (ctx->trigger_flags == 0xffff ||
                    (p->tcpvars.stream_pkt_flags & ctx->trigger_flags) != 0));
}

void EveStreamLogRegister(void)
{
    OutputRegisterPacketSubModule(LOGGER_JSON_STREAM, "eve-log", MODULE_NAME, "eve-log.stream",
            EveStreamLogInitCtxSub, EveStreamLogger, EveStreamLogCondition, EveStreamLogThreadInit,
            EveStreamLogThreadDeinit, NULL);
}
