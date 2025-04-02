/* Copyright (C) 2023-2024 Open Information Security Foundation
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

static uint16_t SetFlag(SCConfNode *conf, const char *opt, const uint16_t inflag)
{
    const char *v = SCConfNodeLookupChildValue(conf, opt);
    if (v != NULL && SCConfValIsTrue(v)) {
        return inflag;
    }
    return 0;
}

static OutputInitResult EveStreamLogInitCtxSub(SCConfNode *conf, OutputCtx *parent_ctx)
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
        ctx->trigger_flags |= SetFlag(conf, "tcp-session-reuse", STREAM_PKT_FLAG_TCP_SESSION_REUSE);

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

void EveAddFlowTcpStreamFlags(const TcpStream *stream, const char *name, SCJsonBuilder *jb)
{
    SCJbOpenArray(jb, name);
    if (stream->flags & STREAMTCP_STREAM_FLAG_HAS_GAP)
        SCJbAppendString(jb, "has_gap");
    if (stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)
        SCJbAppendString(jb, "noreassembly");
    if (stream->flags & STREAMTCP_STREAM_FLAG_KEEPALIVE)
        SCJbAppendString(jb, "keepalive");
    if (stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED)
        SCJbAppendString(jb, "depth_reached");
    if (stream->flags & STREAMTCP_STREAM_FLAG_TRIGGER_RAW)
        SCJbAppendString(jb, "trigger_raw");
    if (stream->flags & STREAMTCP_STREAM_FLAG_TIMESTAMP)
        SCJbAppendString(jb, "timestamp");
    if (stream->flags & STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP)
        SCJbAppendString(jb, "zero_timestamp");
    if (stream->flags & STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_COMPLETED)
        SCJbAppendString(jb, "appproto_detection_completed");
    if (stream->flags & STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_SKIPPED)
        SCJbAppendString(jb, "appproto_detection_skipped");
    if (stream->flags & STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED)
        SCJbAppendString(jb, "new_raw_disabled");
    if (stream->flags & STREAMTCP_STREAM_FLAG_DISABLE_RAW)
        SCJbAppendString(jb, "disable_raw");
    if (stream->flags & STREAMTCP_STREAM_FLAG_RST_RECV)
        SCJbAppendString(jb, "rst_recv");
    SCJbClose(jb);
}

void EveAddFlowTcpFlags(const TcpSession *ssn, const char *name, SCJsonBuilder *jb)
{
    SCJbOpenObject(jb, "flags");

    SCJbOpenArray(jb, name);
    if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
        SCJbAppendString(jb, "midstream");
    }
    if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED) {
        SCJbAppendString(jb, "midstream_established");
    }
    if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK) {
        SCJbAppendString(jb, "midstream_synack");
    }
    if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
        SCJbAppendString(jb, "timestamp");
    }
    if (ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) {
        SCJbAppendString(jb, "server_wscale");
    }
    if (ssn->flags & STREAMTCP_FLAG_CLOSED_BY_RST) {
        SCJbAppendString(jb, "closed_by_rst");
    }
    if (ssn->flags & STREAMTCP_FLAG_4WHS) {
        SCJbAppendString(jb, "4whs");
    }
    if (ssn->flags & STREAMTCP_FLAG_DETECTION_EVASION_ATTEMPT) {
        SCJbAppendString(jb, "detect_evasion_attempt");
    }
    if (ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) {
        SCJbAppendString(jb, "client_sackok");
    }
    if (ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) {
        SCJbAppendString(jb, "sackok");
    }
    if (ssn->flags & STREAMTCP_FLAG_3WHS_CONFIRMED) {
        SCJbAppendString(jb, "3whs_confirmed");
    }
    if (ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) {
        SCJbAppendString(jb, "app_layer_disabled");
    }
    if (ssn->flags & STREAMTCP_FLAG_BYPASS) {
        SCJbAppendString(jb, "bypass");
    }
    if (ssn->flags & STREAMTCP_FLAG_TCP_FAST_OPEN) {
        SCJbAppendString(jb, "tcp_fast_open");
    }
    if (ssn->flags & STREAMTCP_FLAG_TFO_DATA_IGNORED) {
        SCJbAppendString(jb, "tfo_data_ignored");
    }
    SCJbClose(jb);
    SCJbClose(jb);
}

static void LogStreamSB(const StreamingBuffer *sb, SCJsonBuilder *js)
{
    SCJbSetUint(js, "sb_region_size", sb->region.buf_size);
}

static void LogStream(const TcpStream *stream, SCJsonBuilder *js)
{
    SCJbSetUint(js, "isn", stream->isn);
    SCJbSetUint(js, "next_seq", stream->next_seq);
    SCJbSetUint(js, "last_ack", stream->last_ack);
    SCJbSetUint(js, "next_win", stream->next_win);
    if (!(stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        SCJbSetUint(js, "base_seq", stream->base_seq);
        SCJbSetUint(js, "segs_right_edge", stream->segs_right_edge);
    }
    SCJbSetUint(js, "window", stream->window);
    SCJbSetUint(js, "wscale", stream->wscale);

    EveAddFlowTcpStreamFlags(stream, "flags", js);

    TcpSegment *s;
    uint32_t segs = 0;
    RB_FOREACH(s, TCPSEG, (struct TCPSEG *)&stream->seg_tree)
    {
        segs++;
    }
    SCJbSetUint(js, "seg_cnt", segs);
    LogStreamSB(&stream->sb, js);
}

/**
 * \brief   Log the stream packets
 *
 * \param tv    Pointer the current thread variables
 * \param data  Pointer to the EveStreamLogThread struct
 * \param p     Pointer the packet which is being logged
 *
 * \retval 0 on success
 */
static int EveStreamLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    EveStreamLogThread *td = thread_data;
    EveStreamOutputCtx *ctx = td->stream_ctx;

    JsonAddrInfo addr = json_addr_info_zero;
    JsonAddrInfoInit(p, LOG_DIR_PACKET, &addr);

    SCJsonBuilder *js = CreateEveHeader(p, LOG_DIR_PACKET, "stream_tcp", &addr, ctx->eve_ctx);
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    if (p->flow != NULL) {
        if (p->flowflags & FLOW_PKT_TOSERVER) {
            SCJbSetString(js, "direction", "to_server");
        } else {
            SCJbSetString(js, "direction", "to_client");
        }
    }

    SCJbOpenObject(js, "stream_tcp");
    SCJbOpenObject(js, "packet");

    if (PacketIsIPv4(p)) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        SCJbSetUint(js, "len", IPV4_GET_RAW_IPLEN(ip4h));
        SCJbSetUint(js, "tos", IPV4_GET_RAW_IPTOS(ip4h));
        SCJbSetUint(js, "ttl", IPV4_GET_RAW_IPTTL(ip4h));
        SCJbSetUint(js, "ipid", IPV4_GET_RAW_IPID(ip4h));
    } else if (PacketIsIPv6(p)) {
        const IPV6Hdr *ip6h = PacketGetIPv6(p);
        SCJbSetUint(js, "len", IPV6_GET_RAW_PLEN(ip6h));
        SCJbSetUint(js, "tc", IPV6_GET_RAW_CLASS(ip6h));
        SCJbSetUint(js, "hoplimit", IPV6_GET_RAW_HLIM(ip6h));
        SCJbSetUint(js, "flowlbl", IPV6_GET_RAW_FLOW(ip6h));
    }
    if (PacketIsTCP(p)) {
        const TCPHdr *tcph = PacketGetTCP(p);
        SCJbSetUint(js, "tcpseq", TCP_GET_RAW_SEQ(tcph));
        SCJbSetUint(js, "tcpack", TCP_GET_RAW_ACK(tcph));
        SCJbSetUint(js, "tcpwin", TCP_GET_RAW_WINDOW(tcph));
        SCJbSetBool(js, "syn", TCP_ISSET_FLAG_RAW_SYN(tcph) ? true : false);
        SCJbSetBool(js, "ack", TCP_ISSET_FLAG_RAW_ACK(tcph) ? true : false);
        SCJbSetBool(js, "psh", TCP_ISSET_FLAG_RAW_PUSH(tcph) ? true : false);
        SCJbSetBool(js, "rst", TCP_ISSET_FLAG_RAW_RST(tcph) ? true : false);
        SCJbSetBool(js, "urg", TCP_ISSET_FLAG_RAW_URG(tcph) ? true : false);
        SCJbSetBool(js, "fin", TCP_ISSET_FLAG_RAW_FIN(tcph) ? true : false);
        SCJbSetUint(js, "tcpres", TCP_GET_RAW_X2(tcph));
        SCJbSetUint(js, "tcpurgp", TCP_GET_RAW_URG_POINTER(tcph));

        SCJbOpenArray(js, "flags");
        if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_RETRANSMISSION)
            SCJbAppendString(js, "retransmission");
        if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_SPURIOUS_RETRANSMISSION)
            SCJbAppendString(js, "spurious_retransmission");
        if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_KEEPALIVE)
            SCJbAppendString(js, "keepalive");
        if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_KEEPALIVEACK)
            SCJbAppendString(js, "keepalive_ack");
        if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_WINDOWUPDATE)
            SCJbAppendString(js, "window_update");

        if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_EVENTSET)
            SCJbAppendString(js, "event_set");
        if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_STATE_UPDATE)
            SCJbAppendString(js, "state_update");
        if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_DUP_ACK)
            SCJbAppendString(js, "dup_ack");
        if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_DSACK)
            SCJbAppendString(js, "dsack");
        if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_ACK_UNSEEN_DATA)
            SCJbAppendString(js, "ack_unseen_data");
        if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_TCP_SESSION_REUSE)
            SCJbAppendString(js, "tcp_session_reuse");
        if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_TCP_ZERO_WIN_PROBE)
            SCJbAppendString(js, "zero_window_probe");
        if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_TCP_ZERO_WIN_PROBE_ACK)
            SCJbAppendString(js, "zero_window_probe_ack");
        SCJbClose(js);
    }
    SCJbClose(js);

    SCJbOpenObject(js, "session");
    if (p->flow != NULL && p->flow->protoctx != NULL) {
        const TcpSession *ssn = p->flow->protoctx;
        const char *tcp_state = StreamTcpStateAsString(ssn->state);
        if (tcp_state != NULL)
            SCJbSetString(js, "state", tcp_state);
        if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_STATE_UPDATE) {
            const char *tcp_pstate = StreamTcpStateAsString(ssn->pstate);
            if (tcp_pstate != NULL)
                SCJbSetString(js, "pstate", tcp_pstate);
        }
        EveAddFlowTcpFlags(ssn, "flags", js);

        SCJbOpenObject(js, "client");
        LogStream(&ssn->client, js);
        SCJbClose(js);
        SCJbOpenObject(js, "server");
        LogStream(&ssn->server, js);
        SCJbClose(js);
    }
    SCJbClose(js);

    if (p->l4.vars.tcp.stream_pkt_flags & STREAM_PKT_FLAG_EVENTSET) {
        SCJbOpenArray(js, "events");
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
            SCJbAppendString(js, event);
        }
        SCJbClose(js);
    }

    if (p->drop_reason != 0) {
        const char *str = PacketDropReasonToString(p->drop_reason);
        SCJbSetString(js, "reason", str);
    }

    /* Close stream. */
    SCJbClose(js);

    OutputJsonBuilderBuffer(tv, p, p->flow, js, td->ctx);
    SCJbFree(js);

    return TM_ECODE_OK;
}

/**
 * \brief Check if we need to log this packet
 *
 * \param tv    Pointer the current thread variables
 * \param p     Pointer the packet which is tested
 *
 * \retval bool true or false
 */
static bool EveStreamLogCondition(ThreadVars *tv, void *data, const Packet *p)
{
    EveStreamLogThread *td = data;
    EveStreamOutputCtx *ctx = td->stream_ctx;

    return (p->proto == IPPROTO_TCP &&
            (ctx->trigger_flags == 0xffff ||
                    (p->l4.vars.tcp.stream_pkt_flags & ctx->trigger_flags) != 0));
}

void EveStreamLogRegister(void)
{
    OutputPacketLoggerFunctions output_logger_functions = {
        .LogFunc = EveStreamLogger,
        .FlushFunc = OutputJsonLogFlush,
        .ConditionFunc = EveStreamLogCondition,
        .ThreadInitFunc = EveStreamLogThreadInit,
        .ThreadDeinitFunc = EveStreamLogThreadDeinit,
        .ThreadExitPrintStatsFunc = NULL,
    };

    OutputRegisterPacketSubModule(LOGGER_JSON_STREAM, "eve-log", MODULE_NAME, "eve-log.stream",
            EveStreamLogInitCtxSub, &output_logger_functions);
}
