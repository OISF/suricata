/* Copyright (C) 2013-2024 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * Logs alerts in JSON format.
 *
 */

#include "suricata-common.h"
#include "packet.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "stream.h"
#include "threadvars.h"
#include "util-debug.h"
#include "stream-tcp.h"

#include "util-logopenfile.h"
#include "util-misc.h"
#include "util-time.h"

#include "detect-engine.h"
#include "detect-metadata.h"
#include "app-layer-parser.h"
#include "app-layer-htp-xff.h"
#include "app-layer-ftp.h"
#include "app-layer-frames.h"
#include "log-pcap.h"

#include "output.h"
#include "output-json.h"
#include "output-json-alert.h"
#include "output-json-http.h"
#include "rust.h"
#include "output-json-smtp.h"
#include "output-json-email-common.h"
#include "output-json-nfs.h"
#include "output-json-smb.h"
#include "output-json-flow.h"
#include "output-json-ike.h"
#include "output-json-frame.h"

#include "util-print.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-reference-config.h"
#include "util-validate.h"

#include "action-globals.h"

#define MODULE_NAME "JsonAlertLog"

#define LOG_JSON_PAYLOAD           BIT_U16(0)
#define LOG_JSON_PACKET            BIT_U16(1)
#define LOG_JSON_PAYLOAD_BASE64    BIT_U16(2)
#define LOG_JSON_TAGGED_PACKETS    BIT_U16(3)
#define LOG_JSON_APP_LAYER         BIT_U16(4)
#define LOG_JSON_FLOW              BIT_U16(5)
#define LOG_JSON_HTTP_BODY         BIT_U16(6)
#define LOG_JSON_HTTP_BODY_BASE64  BIT_U16(7)
#define LOG_JSON_RULE_METADATA     BIT_U16(8)
#define LOG_JSON_RULE              BIT_U16(9)
#define LOG_JSON_VERDICT           BIT_U16(10)
#define LOG_JSON_WEBSOCKET_PAYLOAD        BIT_U16(11)
#define LOG_JSON_WEBSOCKET_PAYLOAD_BASE64 BIT_U16(12)
#define LOG_JSON_PAYLOAD_LENGTH           BIT_U16(13)
#define LOG_JSON_REFERENCE                BIT_U16(14)

#define METADATA_DEFAULTS ( LOG_JSON_FLOW |                        \
            LOG_JSON_APP_LAYER  |                                  \
            LOG_JSON_RULE_METADATA)

#define JSON_BODY_LOGGING                                                                          \
    (LOG_JSON_HTTP_BODY | LOG_JSON_HTTP_BODY_BASE64 | LOG_JSON_WEBSOCKET_PAYLOAD |                 \
            LOG_JSON_WEBSOCKET_PAYLOAD_BASE64)

#define JSON_STREAM_BUFFER_SIZE 4096

typedef struct AlertJsonOutputCtx_ {
    LogFileCtx* file_ctx;
    uint16_t flags;
    uint32_t payload_buffer_size;
    HttpXFFCfg *xff_cfg;
    HttpXFFCfg *parent_xff_cfg;
    OutputJsonCtx *eve_ctx;
} AlertJsonOutputCtx;

typedef struct JsonAlertLogThread_ {
    MemBuffer *payload_buffer;
    AlertJsonOutputCtx* json_output_ctx;
    OutputJsonThreadCtx *ctx;
} JsonAlertLogThread;

static void AlertJsonSourceTarget(
        const Packet *p, const PacketAlert *pa, SCJsonBuilder *js, JsonAddrInfo *addr)
{
    SCJbOpenObject(js, "source");
    if (pa->s->flags & SIG_FLAG_DEST_IS_TARGET) {
        SCJbSetString(js, "ip", addr->src_ip);
        switch (p->proto) {
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                break;
            case IPPROTO_UDP:
            case IPPROTO_TCP:
            case IPPROTO_SCTP:
                SCJbSetUint(js, "port", addr->sp);
                break;
        }
    } else if (pa->s->flags & SIG_FLAG_SRC_IS_TARGET) {
        SCJbSetString(js, "ip", addr->dst_ip);
        switch (p->proto) {
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                break;
            case IPPROTO_UDP:
            case IPPROTO_TCP:
            case IPPROTO_SCTP:
                SCJbSetUint(js, "port", addr->dp);
                break;
        }
    }
    SCJbClose(js);

    SCJbOpenObject(js, "target");
    if (pa->s->flags & SIG_FLAG_DEST_IS_TARGET) {
        SCJbSetString(js, "ip", addr->dst_ip);
        switch (p->proto) {
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                break;
            case IPPROTO_UDP:
            case IPPROTO_TCP:
            case IPPROTO_SCTP:
                SCJbSetUint(js, "port", addr->dp);
                break;
        }
    } else if (pa->s->flags & SIG_FLAG_SRC_IS_TARGET) {
        SCJbSetString(js, "ip", addr->src_ip);
        switch (p->proto) {
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                break;
            case IPPROTO_UDP:
            case IPPROTO_TCP:
            case IPPROTO_SCTP:
                SCJbSetUint(js, "port", addr->sp);
                break;
        }
    }
    SCJbClose(js);
}

static void AlertJsonReference(const PacketAlert *pa, SCJsonBuilder *jb)
{
    if (!pa->s->references) {
        return;
    }

    const DetectReference *kv = pa->s->references;
    SCJbOpenArray(jb, "references");
    while (kv) {
        /* Note that the key and reference sizes have been bound
         * checked during parsing
         * add +2 to safisfy gcc 15 + -Wformat-truncation=2
         */
        const size_t size_needed = kv->key_len + kv->reference_len + 3;
        char kv_store[size_needed];
        snprintf(kv_store, size_needed, "%s%s", kv->key, kv->reference);
        SCJbAppendString(jb, kv_store);
        kv = kv->next;
    }
    SCJbClose(jb);
}

static void AlertJsonMetadata(const PacketAlert *pa, SCJsonBuilder *js)
{
    if (pa->s->metadata && pa->s->metadata->json_str) {
        SCJbSetFormatted(js, pa->s->metadata->json_str);
    }
}

void AlertJsonHeader(const Packet *p, const PacketAlert *pa, SCJsonBuilder *js, uint16_t flags,
        JsonAddrInfo *addr, char *xff_buffer)
{
    const char *action = "allowed";
    /* use packet action if rate_filter modified the action */
    if (unlikely(pa->flags & PACKET_ALERT_FLAG_RATE_FILTER_MODIFIED)) {
        if (PacketCheckAction(p, ACTION_DROP_REJECT)) {
            action = "blocked";
        }
    } else {
        if (pa->action & ACTION_REJECT_ANY) {
            action = "blocked";
        } else if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
            action = "blocked";
        }
    }

    /* Add tx_id to root element for correlation with other events. */
    /* json_object_del(js, "tx_id"); */
    if (pa->flags & PACKET_ALERT_FLAG_TX) {
        SCJbSetUint(js, "tx_id", pa->tx_id);
    }
    if (pa->flags & PACKET_ALERT_FLAG_TX_GUESSED) {
        SCJbSetBool(js, "tx_guessed", true);
    }

    SCJbOpenObject(js, "alert");

    SCJbSetString(js, "action", action);
    SCJbSetUint(js, "gid", pa->s->gid);
    SCJbSetUint(js, "signature_id", pa->s->id);
    SCJbSetUint(js, "rev", pa->s->rev);
    /* TODO: SCJsonBuilder should handle unprintable characters like
     * SCJsonString. */
    SCJbSetString(js, "signature", pa->s->msg ? pa->s->msg : "");
    SCJbSetString(js, "category", pa->s->class_msg ? pa->s->class_msg : "");
    SCJbSetUint(js, "severity", pa->s->prio);

    if (p->tenant_id > 0) {
        SCJbSetUint(js, "tenant_id", p->tenant_id);
    }

    if (addr && pa->s->flags & SIG_FLAG_HAS_TARGET) {
        AlertJsonSourceTarget(p, pa, js, addr);
    }

    if ((flags & LOG_JSON_REFERENCE)) {
        AlertJsonReference(pa, js);
    }

    if (flags & LOG_JSON_RULE_METADATA) {
        AlertJsonMetadata(pa, js);
    }

    if (pa->json_info != NULL) {
        SCJbOpenObject(js, "context");
        const struct PacketContextData *json_info = pa->json_info;
        while (json_info) {
            SCLogDebug("JSON string '{%s}'", json_info->json_string);
            /* The string is valid json as it is validated by JANSSON
               during parsing and included later via a format string */
            SCJbSetFormatted(js, json_info->json_string);
            json_info = json_info->next;
        }
        SCJbClose(js);
    }
    if (flags & LOG_JSON_RULE) {
        SCJbSetString(js, "rule", pa->s->sig_str);
    }
    if (xff_buffer && xff_buffer[0]) {
        SCJbSetString(js, "xff", xff_buffer);
    }

    SCJbClose(js);
}

static void AlertJsonTunnel(const Packet *p, SCJsonBuilder *js)
{
    if (p->root == NULL) {
        return;
    }

    SCJbOpenObject(js, "tunnel");

    enum PktSrcEnum pkt_src;
    uint64_t pcap_cnt;
    JsonAddrInfo addr = json_addr_info_zero;
    JsonAddrInfoInit(p->root, 0, &addr);
    pcap_cnt = p->root->pcap_cnt;
    pkt_src = p->root->pkt_src;

    SCJbSetString(js, "src_ip", addr.src_ip);
    SCJbSetUint(js, "src_port", addr.sp);
    SCJbSetString(js, "dest_ip", addr.dst_ip);
    SCJbSetUint(js, "dest_port", addr.dp);
    SCJbSetString(js, "proto", addr.proto);

    SCJbSetUint(js, "depth", p->recursion_level);
    if (pcap_cnt != 0) {
        SCJbSetUint(js, "pcap_cnt", pcap_cnt);
    }
    SCJbSetString(js, "pkt_src", PktSrcToString(pkt_src));
    SCJbClose(js);
}

static void AlertAddPayload(AlertJsonOutputCtx *json_output_ctx, SCJsonBuilder *js, const Packet *p)
{
    if (json_output_ctx->flags & LOG_JSON_PAYLOAD_BASE64) {
        SCJbSetBase64(js, "payload", p->payload, p->payload_len);
    }
    if (json_output_ctx->flags & LOG_JSON_PAYLOAD_LENGTH) {
        SCJbSetUint(js, "payload_length", p->payload_len);
    }

    if (json_output_ctx->flags & LOG_JSON_PAYLOAD) {
        SCJbSetPrintAsciiString(js, "payload_printable", p->payload, p->payload_len);
    }
}

static void AlertAddAppLayer(
        const Packet *p, SCJsonBuilder *jb, const uint64_t tx_id, const uint16_t option_flags)
{
    const AppProto proto = FlowGetAppProtocol(p->flow);
    EveJsonSimpleAppLayerLogger *al = SCEveJsonSimpleGetLogger(proto);
    SCJsonBuilderMark mark = { 0, 0, 0 };
    if (al && al->LogTx) {
        void *state = FlowGetAppState(p->flow);
        if (state) {
            void *tx = AppLayerParserGetTx(p->flow->proto, proto, state, tx_id);
            if (tx) {
                const int ts =
                        AppLayerParserGetStateProgress(p->flow->proto, proto, tx, STREAM_TOSERVER);
                const int tc =
                        AppLayerParserGetStateProgress(p->flow->proto, proto, tx, STREAM_TOCLIENT);
                SCJbSetString(jb, "ts_progress",
                        AppLayerParserGetStateNameById(p->flow->proto, proto, ts, STREAM_TOSERVER));
                SCJbSetString(jb, "tc_progress",
                        AppLayerParserGetStateNameById(p->flow->proto, proto, tc, STREAM_TOCLIENT));
                SCJbGetMark(jb, &mark);
                switch (proto) {
                    // first check some protocols need special options for alerts logging
                    case ALPROTO_WEBSOCKET:
                        if (option_flags &
                                (LOG_JSON_WEBSOCKET_PAYLOAD | LOG_JSON_WEBSOCKET_PAYLOAD_BASE64)) {
                            bool pp = (option_flags & LOG_JSON_WEBSOCKET_PAYLOAD) != 0;
                            bool pb64 = (option_flags & LOG_JSON_WEBSOCKET_PAYLOAD_BASE64) != 0;
                            if (!SCWebSocketLogDetails(tx, jb, pp, pb64)) {
                                SCJbRestoreMark(jb, &mark);
                            }
                            // nothing more to log or do
                            return;
                        }
                }
                if (!al->LogTx(tx, jb)) {
                    SCJbRestoreMark(jb, &mark);
                }
            }
        }
        return;
    }
    void *state = FlowGetAppState(p->flow);
    if (state) {
        void *tx = AppLayerParserGetTx(p->flow->proto, proto, state, tx_id);
        if (tx) {
            const int ts =
                    AppLayerParserGetStateProgress(p->flow->proto, proto, tx, STREAM_TOSERVER);
            const int tc =
                    AppLayerParserGetStateProgress(p->flow->proto, proto, tx, STREAM_TOCLIENT);
            SCJbSetString(jb, "ts_progress",
                    AppLayerParserGetStateNameById(p->flow->proto, proto, ts, STREAM_TOSERVER));
            SCJbSetString(jb, "tc_progress",
                    AppLayerParserGetStateNameById(p->flow->proto, proto, tc, STREAM_TOCLIENT));
        }
    }
    switch (proto) {
        case ALPROTO_HTTP1:
            // TODO: Could result in an empty http object being logged.
            SCJbOpenObject(jb, "http");
            if (EveHttpAddMetadata(p->flow, tx_id, jb)) {
                if (option_flags & LOG_JSON_HTTP_BODY) {
                    EveHttpLogJSONBodyPrintable(jb, p->flow, tx_id);
                }
                if (option_flags & LOG_JSON_HTTP_BODY_BASE64) {
                    EveHttpLogJSONBodyBase64(jb, p->flow, tx_id);
                }
            }
            SCJbClose(jb);
            break;
        case ALPROTO_SMTP:
            SCJbGetMark(jb, &mark);
            SCJbOpenObject(jb, "smtp");
            if (EveSMTPAddMetadata(p->flow, tx_id, jb)) {
                SCJbClose(jb);
            } else {
                SCJbRestoreMark(jb, &mark);
            }
            SCJbGetMark(jb, &mark);
            SCJbOpenObject(jb, "email");
            if (EveEmailAddMetadata(p->flow, tx_id, jb)) {
                SCJbClose(jb);
            } else {
                SCJbRestoreMark(jb, &mark);
            }
            break;
        case ALPROTO_NFS:
            /* rpc */
            SCJbGetMark(jb, &mark);
            SCJbOpenObject(jb, "rpc");
            if (EveNFSAddMetadataRPC(p->flow, tx_id, jb)) {
                SCJbClose(jb);
            } else {
                SCJbRestoreMark(jb, &mark);
            }
            /* nfs */
            SCJbGetMark(jb, &mark);
            SCJbOpenObject(jb, "nfs");
            if (EveNFSAddMetadata(p->flow, tx_id, jb)) {
                SCJbClose(jb);
            } else {
                SCJbRestoreMark(jb, &mark);
            }
            break;
        case ALPROTO_SMB:
            SCJbGetMark(jb, &mark);
            SCJbOpenObject(jb, "smb");
            if (EveSMBAddMetadata(p->flow, tx_id, jb)) {
                SCJbClose(jb);
            } else {
                SCJbRestoreMark(jb, &mark);
            }
            break;
        case ALPROTO_IKE:
            SCJbGetMark(jb, &mark);
            if (!EveIKEAddMetadata(p->flow, tx_id, jb)) {
                SCJbRestoreMark(jb, &mark);
            }
            break;
        case ALPROTO_DCERPC: {
            if (state) {
                void *tx = AppLayerParserGetTx(p->flow->proto, proto, state, tx_id);
                if (tx) {
                    SCJbGetMark(jb, &mark);
                    SCJbOpenObject(jb, "dcerpc");
                    if (p->proto == IPPROTO_TCP) {
                        if (!SCDcerpcLogJsonRecordTcp(state, tx, jb)) {
                            SCJbRestoreMark(jb, &mark);
                        }
                    } else {
                        if (!SCDcerpcLogJsonRecordUdp(state, tx, jb)) {
                            SCJbRestoreMark(jb, &mark);
                        }
                    }
                    SCJbClose(jb);
                }
            }
            break;
        }
        default:
            break;
    }
}

static void AlertAddFiles(const Packet *p, SCJsonBuilder *jb, const uint64_t tx_id)
{
    const uint8_t direction =
            (p->flowflags & FLOW_PKT_TOSERVER) ? STREAM_TOSERVER : STREAM_TOCLIENT;
    FileContainer *ffc = NULL;
    if (p->flow->alstate != NULL) {
        void *tx = AppLayerParserGetTx(p->flow->proto, p->flow->alproto, p->flow->alstate, tx_id);
        if (tx) {
            AppLayerGetFileState files = AppLayerParserGetTxFiles(p->flow, tx, direction);
            ffc = files.fc;
        }
    }
    if (ffc != NULL) {
        File *file = ffc->head;
        bool isopen = false;
        while (file) {
            if (!isopen) {
                isopen = true;
                SCJbOpenArray(jb, "files");
            }
            SCJbStartObject(jb);
            EveFileInfo(jb, file, tx_id, file->flags);
            SCJbClose(jb);
            file = file->next;
        }
        if (isopen) {
            SCJbClose(jb);
        }
    }
}

static void AlertAddFrame(
        const Packet *p, const int64_t frame_id, SCJsonBuilder *jb, MemBuffer *buffer)
{
    if (p->flow == NULL || (p->proto == IPPROTO_TCP && p->flow->protoctx == NULL))
        return;

    FramesContainer *frames_container = AppLayerFramesGetContainer(p->flow);
    if (frames_container == NULL)
        return;

    Frames *frames = NULL;
    TcpStream *stream = NULL;
    if (p->proto == IPPROTO_TCP) {
        TcpSession *ssn = p->flow->protoctx;
        if (PKT_IS_TOSERVER(p)) {
            stream = &ssn->client;
            frames = &frames_container->toserver;
        } else {
            stream = &ssn->server;
            frames = &frames_container->toclient;
        }
        Frame *frame = FrameGetById(frames, frame_id);
        if (frame != NULL) {
            FrameJsonLogOneFrame(IPPROTO_TCP, frame, p->flow, stream, p, jb, buffer);
        }
    } else if (p->proto == IPPROTO_UDP) {
        if (PKT_IS_TOSERVER(p)) {
            frames = &frames_container->toserver;
        } else {
            frames = &frames_container->toclient;
        }
        Frame *frame = FrameGetById(frames, frame_id);
        if (frame != NULL) {
            FrameJsonLogOneFrame(IPPROTO_UDP, frame, p->flow, NULL, p, jb, buffer);
        }
    }
}

/**
 * \brief    Build verdict object
 *
 * \param p  Pointer to Packet current being logged
 * \param alert_action action bitfield from the alert: only used for ACTION_PASS
 */
void EveAddVerdict(SCJsonBuilder *jb, const Packet *p, const uint8_t alert_action)
{
    SCJbOpenObject(jb, "verdict");

    const uint8_t packet_action = PacketGetAction(p);
    SCLogDebug("%" PRIu64 ": packet_action %02x alert_action %02x", p->pcap_cnt, packet_action,
            alert_action);
    /* add verdict info */
    if (packet_action & ACTION_REJECT_ANY) {
        // check rule to define type of reject packet sent
        if (EngineModeIsIPS()) {
            JB_SET_STRING(jb, "action", "drop");
        } else {
            JB_SET_STRING(jb, "action", "alert");
        }
        if (packet_action & ACTION_REJECT) {
            JB_SET_STRING(jb, "reject-target", "to_client");
        } else if (packet_action & ACTION_REJECT_DST) {
            JB_SET_STRING(jb, "reject-target", "to_server");
        } else if (packet_action & ACTION_REJECT_BOTH) {
            JB_SET_STRING(jb, "reject-target", "both");
        }
        SCJbOpenArray(jb, "reject");
        switch (p->proto) {
            case IPPROTO_UDP:
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                SCJbAppendString(jb, "icmp-prohib");
                break;
            case IPPROTO_TCP:
                SCJbAppendString(jb, "tcp-reset");
                break;
        }
        SCJbClose(jb);

    } else if ((packet_action & ACTION_DROP) && EngineModeIsIPS()) {
        JB_SET_STRING(jb, "action", "drop");
    } else if (packet_action & ACTION_ACCEPT) {
        JB_SET_STRING(jb, "action", "accept");
    } else if (alert_action & ACTION_PASS) {
        JB_SET_STRING(jb, "action", "pass");
    } else {
        // TODO make sure we don't have a situation where this wouldn't work
        JB_SET_STRING(jb, "action", "alert");
    }

    /* Close verdict */
    SCJbClose(jb);
}

struct AlertJsonStreamDataCallbackData {
    MemBuffer *payload;
    uint64_t last_re;
};

static int AlertJsonStreamDataCallback(
        void *cb_data, const uint8_t *input, const uint32_t input_len, const uint64_t input_offset)
{
    struct AlertJsonStreamDataCallbackData *cbd = cb_data;
    if (input_offset > cbd->last_re) {
        MemBufferWriteString(
                cbd->payload, "[%" PRIu64 " bytes missing]", input_offset - cbd->last_re);
    }

    int done = 0;
    uint32_t written = MemBufferWriteRaw(cbd->payload, input, input_len);
    if (written < input_len)
        done = 1;
    cbd->last_re = input_offset + input_len;
    return done;
}

/** \internal
 *  \brief try to log stream data into payload/payload_printable
 *  \retval true stream data logged
 *  \retval false stream data not logged
 */
static bool AlertJsonStreamData(const AlertJsonOutputCtx *json_output_ctx, JsonAlertLogThread *aft,
        Flow *f, const Packet *p, SCJsonBuilder *jb)
{
    TcpSession *ssn = f->protoctx;
    TcpStream *stream = (PKT_IS_TOSERVER(p)) ? &ssn->client : &ssn->server;

    MemBufferReset(aft->payload_buffer);
    struct AlertJsonStreamDataCallbackData cbd = { .payload = aft->payload_buffer,
        .last_re = STREAM_BASE_OFFSET(stream) };
    uint64_t unused = 0;
    StreamReassembleLog(ssn, stream, AlertJsonStreamDataCallback, &cbd, STREAM_BASE_OFFSET(stream),
            &unused, false);
    if (cbd.payload->offset) {
        if (json_output_ctx->flags & LOG_JSON_PAYLOAD_BASE64) {
            SCJbSetBase64(jb, "payload", cbd.payload->buffer, cbd.payload->offset);
        }
        if (json_output_ctx->flags & LOG_JSON_PAYLOAD_LENGTH) {
            SCJbSetUint(jb, "payload_length", cbd.payload->offset);
        }

        if (json_output_ctx->flags & LOG_JSON_PAYLOAD) {
            SCJbSetPrintAsciiString(
                    jb, "payload_printable", cbd.payload->buffer, cbd.payload->offset);
        }
        return true;
    }
    return false;
}

static int AlertJson(ThreadVars *tv, JsonAlertLogThread *aft, const Packet *p)
{
    AlertJsonOutputCtx *json_output_ctx = aft->json_output_ctx;

    if (p->alerts.cnt == 0 && !(p->flags & PKT_HAS_TAG))
        return TM_ECODE_OK;

    const uint8_t final_action = p->alerts.cnt > 0 ? p->alerts.alerts[p->alerts.cnt - 1].action : 0;
    for (int i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL || (pa->action & ACTION_ALERT) == 0)) {
            continue;
        }

        /* First initialize the address info (5-tuple). */
        JsonAddrInfo addr = json_addr_info_zero;
        JsonAddrInfoInit(p, LOG_DIR_PACKET, &addr);

        /* Check for XFF, overwriting address info if needed. */
        HttpXFFCfg *xff_cfg = json_output_ctx->xff_cfg != NULL ? json_output_ctx->xff_cfg
                                                               : json_output_ctx->parent_xff_cfg;
        int have_xff_ip = 0;
        char xff_buffer[XFF_MAXLEN];
        xff_buffer[0] = 0;
        if ((xff_cfg != NULL) && !(xff_cfg->flags & XFF_DISABLED) && p->flow != NULL) {
            if (FlowGetAppProtocol(p->flow) == ALPROTO_HTTP1) {
                if (pa->flags & PACKET_ALERT_FLAG_TX) {
                    have_xff_ip = HttpXFFGetIPFromTx(p->flow, pa->tx_id, xff_cfg,
                            xff_buffer, XFF_MAXLEN);
                } else {
                    have_xff_ip = HttpXFFGetIP(p->flow, xff_cfg, xff_buffer,
                            XFF_MAXLEN);
                }
            }

            if (have_xff_ip && xff_cfg->flags & XFF_OVERWRITE) {
                if (p->flowflags & FLOW_PKT_TOCLIENT) {
                    strlcpy(addr.dst_ip, xff_buffer, JSON_ADDR_LEN);
                } else {
                    strlcpy(addr.src_ip, xff_buffer, JSON_ADDR_LEN);
                }
                /* Clear have_xff_ip so the xff field does not get
                 * logged below. */
                have_xff_ip = false;
            }
            if (have_xff_ip && !(xff_cfg->flags & XFF_EXTRADATA)) {
                // reset xff_buffer so as not to log it
                xff_buffer[0] = 0;
            }
        }

        SCJsonBuilder *jb =
                CreateEveHeader(p, LOG_DIR_PACKET, "alert", &addr, json_output_ctx->eve_ctx);
        if (unlikely(jb == NULL))
            return TM_ECODE_OK;


        /* alert */
        AlertJsonHeader(p, pa, jb, json_output_ctx->flags, &addr, xff_buffer);

        if (PacketIsTunnel(p)) {
            AlertJsonTunnel(p, jb);
        }

        if (p->flow != NULL) {
            if (pa->flags & PACKET_ALERT_FLAG_TX) {
                if (json_output_ctx->flags & LOG_JSON_APP_LAYER) {
                    AlertAddAppLayer(p, jb, pa->tx_id, json_output_ctx->flags);
                }
                /* including fileinfo data is configured by the metadata setting */
                if (json_output_ctx->flags & LOG_JSON_RULE_METADATA) {
                    AlertAddFiles(p, jb, pa->tx_id);
                }
            }

            EveAddAppProto(p->flow, jb);

            if (p->flowflags & FLOW_PKT_TOSERVER) {
                SCJbSetString(jb, "direction", "to_server");
            } else {
                SCJbSetString(jb, "direction", "to_client");
            }

            if (json_output_ctx->flags & LOG_JSON_FLOW) {
                SCJbOpenObject(jb, "flow");
                EveAddFlow(p->flow, jb);
                if (p->flowflags & FLOW_PKT_TOCLIENT) {
                    SCJbSetString(jb, "src_ip", addr.dst_ip);
                    SCJbSetString(jb, "dest_ip", addr.src_ip);
                    if (addr.sp > 0) {
                        SCJbSetUint(jb, "src_port", addr.dp);
                        SCJbSetUint(jb, "dest_port", addr.sp);
                    }
                } else {
                    SCJbSetString(jb, "src_ip", addr.src_ip);
                    SCJbSetString(jb, "dest_ip", addr.dst_ip);
                    if (addr.sp > 0) {
                        SCJbSetUint(jb, "src_port", addr.sp);
                        SCJbSetUint(jb, "dest_port", addr.dp);
                    }
                }
                SCJbClose(jb);
            }
        }

        /* payload */
        if (json_output_ctx->flags &
                (LOG_JSON_PAYLOAD | LOG_JSON_PAYLOAD_BASE64 | LOG_JSON_PAYLOAD_LENGTH)) {
            int stream = (p->proto == IPPROTO_TCP) ?
                         (pa->flags & (PACKET_ALERT_FLAG_STATE_MATCH | PACKET_ALERT_FLAG_STREAM_MATCH) ?
                         1 : 0) : 0;
            // should be impossible, as stream implies flow
            DEBUG_VALIDATE_BUG_ON(stream && p->flow == NULL);

            /* Is this a stream?  If so, pack part of it into the payload field */
            if (stream && p->flow != NULL) {
                const bool stream_data_logged =
                        AlertJsonStreamData(json_output_ctx, aft, p->flow, p, jb);
                if (!stream_data_logged && p->payload_len) {
                    /* Fallback on packet payload */
                    AlertAddPayload(json_output_ctx, jb, p);
                }
            } else {
                /* This is a single packet and not a stream */
                AlertAddPayload(json_output_ctx, jb, p);
            }

            SCJbSetUint(jb, "stream", stream);
        }

        if (pa->flags & PACKET_ALERT_FLAG_FRAME) {
            AlertAddFrame(p, pa->frame_id, jb, aft->payload_buffer);
        }

        /* base64-encoded full packet */
        if (json_output_ctx->flags & LOG_JSON_PACKET) {
            EvePacket(p, jb, 0);
        }

        char *pcap_filename = PcapLogGetFilename();
        if (pcap_filename != NULL) {
            SCJbSetString(jb, "capture_file", pcap_filename);
        }

        if (json_output_ctx->flags & LOG_JSON_VERDICT) {
            EveAddVerdict(jb, p, final_action & ACTION_PASS);
        }

        OutputJsonBuilderBuffer(tv, p, p->flow, jb, aft->ctx);
        SCJbFree(jb);
    }

    if ((p->flags & PKT_HAS_TAG) && (json_output_ctx->flags &
            LOG_JSON_TAGGED_PACKETS)) {
        SCJsonBuilder *packetjs =
                CreateEveHeader(p, LOG_DIR_PACKET, "packet", NULL, json_output_ctx->eve_ctx);
        if (unlikely(packetjs != NULL)) {
            EvePacket(p, packetjs, 0);
            OutputJsonBuilderBuffer(tv, p, p->flow, packetjs, aft->ctx);
            SCJbFree(packetjs);
        }
    }

    return TM_ECODE_OK;
}

static int AlertJsonDecoderEvent(ThreadVars *tv, JsonAlertLogThread *aft, const Packet *p)
{
    AlertJsonOutputCtx *json_output_ctx = aft->json_output_ctx;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    const uint8_t final_action = p->alerts.alerts[p->alerts.cnt - 1].action;
    for (int i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL || (pa->action & ACTION_ALERT) == 0)) {
            continue;
        }

        SCJsonBuilder *jb =
                CreateEveHeader(p, LOG_DIR_PACKET, "alert", NULL, json_output_ctx->eve_ctx);
        if (unlikely(jb == NULL))
            return TM_ECODE_OK;

        AlertJsonHeader(p, pa, jb, json_output_ctx->flags, NULL, NULL);

        if (PacketIsTunnel(p)) {
            AlertJsonTunnel(p, jb);
        }

        /* base64-encoded full packet */
        if (json_output_ctx->flags & LOG_JSON_PACKET) {
            EvePacket(p, jb, 0);
        }

        char *pcap_filename = PcapLogGetFilename();
        if (pcap_filename != NULL) {
            SCJbSetString(jb, "capture_file", pcap_filename);
        }

        if (json_output_ctx->flags & LOG_JSON_VERDICT) {
            EveAddVerdict(jb, p, final_action & ACTION_PASS);
        }

        OutputJsonBuilderBuffer(tv, p, p->flow, jb, aft->ctx);
        SCJbFree(jb);
    }

    return TM_ECODE_OK;
}

static int JsonAlertFlush(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonAlertLogThread *aft = thread_data;
    SCLogDebug("%s flushing %s", tv->name, ((LogFileCtx *)(aft->ctx->file_ctx))->filename);
    OutputJsonFlush(aft->ctx);
    return 0;
}

static int JsonAlertLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonAlertLogThread *aft = thread_data;

    if (PacketIsIPv4(p) || PacketIsIPv6(p)) {
        return AlertJson(tv, aft, p);
    } else if (p->alerts.cnt > 0) {
        return AlertJsonDecoderEvent(tv, aft, p);
    }
    return 0;
}

static bool JsonAlertLogCondition(ThreadVars *tv, void *thread_data, const Packet *p)
{
    return (p->alerts.cnt || (p->flags & PKT_HAS_TAG));
}

static TmEcode JsonAlertLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonAlertLogThread *aft = SCCalloc(1, sizeof(JsonAlertLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if (initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogAlert.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /** Use the Output Context (file pointer and mutex) */
    AlertJsonOutputCtx *json_output_ctx = ((OutputCtx *)initdata)->data;

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

static TmEcode JsonAlertLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonAlertLogThread *aft = (JsonAlertLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->payload_buffer);
    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(JsonAlertLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonAlertLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);

    AlertJsonOutputCtx *json_output_ctx = (AlertJsonOutputCtx *) output_ctx->data;

    if (json_output_ctx != NULL) {
        HttpXFFCfg *xff_cfg = json_output_ctx->xff_cfg;
        if (xff_cfg != NULL) {
            SCFree(xff_cfg);
        }
        SCFree(json_output_ctx);
    }
    SCFree(output_ctx);
}

static void SetFlag(const SCConfNode *conf, const char *name, uint16_t flag, uint16_t *out_flags)
{
    DEBUG_VALIDATE_BUG_ON(conf == NULL);
    const char *setting = SCConfNodeLookupChildValue(conf, name);
    if (setting != NULL) {
        if (SCConfValIsTrue(setting)) {
            *out_flags |= flag;
        } else {
            *out_flags &= ~flag;
        }
    }
}

static void JsonAlertLogSetupMetadata(AlertJsonOutputCtx *json_output_ctx, SCConfNode *conf)
{
    static bool warn_no_meta = false;
    uint32_t payload_buffer_size = JSON_STREAM_BUFFER_SIZE;
    uint16_t flags = METADATA_DEFAULTS;

    if (conf != NULL) {
        /* Check for metadata to enable/disable. */
        SCConfNode *metadata = SCConfNodeLookupChild(conf, "metadata");
        if (metadata != NULL) {
            if (metadata->val != NULL && SCConfValIsFalse(metadata->val)) {
                flags &= ~METADATA_DEFAULTS;
            } else if (SCConfNodeHasChildren(metadata)) {
                SCConfNode *rule_metadata = SCConfNodeLookupChild(metadata, "rule");
                if (rule_metadata) {
                    SetFlag(rule_metadata, "raw", LOG_JSON_RULE, &flags);
                    SetFlag(rule_metadata, "metadata", LOG_JSON_RULE_METADATA,
                            &flags);
                    SetFlag(rule_metadata, "reference", LOG_JSON_REFERENCE, &flags);
                }
                SetFlag(metadata, "flow", LOG_JSON_FLOW, &flags);
                SetFlag(metadata, "app-layer", LOG_JSON_APP_LAYER, &flags);
            }
        }

        /* Non-metadata toggles. */
        SetFlag(conf, "payload", LOG_JSON_PAYLOAD_BASE64, &flags);
        SetFlag(conf, "packet", LOG_JSON_PACKET, &flags);
        SetFlag(conf, "tagged-packets", LOG_JSON_TAGGED_PACKETS, &flags);
        SetFlag(conf, "payload-printable", LOG_JSON_PAYLOAD, &flags);
        SetFlag(conf, "http-body-printable", LOG_JSON_HTTP_BODY, &flags);
        SetFlag(conf, "http-body", LOG_JSON_HTTP_BODY_BASE64, &flags);
        SetFlag(conf, "websocket-payload-printable", LOG_JSON_WEBSOCKET_PAYLOAD, &flags);
        SetFlag(conf, "websocket-payload", LOG_JSON_WEBSOCKET_PAYLOAD_BASE64, &flags);
        SetFlag(conf, "verdict", LOG_JSON_VERDICT, &flags);
        SetFlag(conf, "payload-length", LOG_JSON_PAYLOAD_LENGTH, &flags);

        /* Check for obsolete flags and warn that they have no effect. */
        static const char *deprecated_flags[] = { "http", "tls", "ssh", "smtp", "dnp3", "app-layer",
            "flow", NULL };
        for (int i = 0; deprecated_flags[i] != NULL; i++) {
            if (SCConfNodeLookupChildValue(conf, deprecated_flags[i]) != NULL) {
                SCLogWarning("Found deprecated eve-log.alert flag \"%s\", this flag has no effect",
                        deprecated_flags[i]);
            }
        }

        const char *payload_buffer_value = SCConfNodeLookupChildValue(conf, "payload-buffer-size");

        if (payload_buffer_value != NULL) {
            uint32_t value;
            if (ParseSizeStringU32(payload_buffer_value, &value) < 0) {
                SCLogError("Error parsing "
                           "payload-buffer-size - %s. Killing engine",
                        payload_buffer_value);
                exit(EXIT_FAILURE);
            } else if (value == 0) {
                // you should not ask for payload if you want 0 of it
                SCLogError("Error payload-buffer-size should not be 0");
                exit(EXIT_FAILURE);
            } else {
                payload_buffer_size = value;
            }
        }

        if (!warn_no_meta && flags & JSON_BODY_LOGGING) {
            if (((flags & LOG_JSON_APP_LAYER) == 0)) {
                SCLogWarning("HTTP body logging has been configured, however, "
                             "metadata logging has not been enabled. HTTP body logging will be "
                             "disabled.");
                flags &= ~JSON_BODY_LOGGING;
                warn_no_meta = true;
            }
        }
    }

    if (flags & LOG_JSON_RULE_METADATA) {
        DetectEngineSetParseMetadata();
    }

    json_output_ctx->payload_buffer_size = payload_buffer_size;
    json_output_ctx->flags |= flags;
}

static HttpXFFCfg *JsonAlertLogGetXffCfg(SCConfNode *conf)
{
    HttpXFFCfg *xff_cfg = NULL;
    if (conf != NULL && SCConfNodeLookupChild(conf, "xff") != NULL) {
        xff_cfg = SCCalloc(1, sizeof(HttpXFFCfg));
        if (likely(xff_cfg != NULL)) {
            HttpXFFGetCfg(conf, xff_cfg);
        }
    }
    return xff_cfg;
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
static OutputInitResult JsonAlertLogInitCtxSub(SCConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;
    AlertJsonOutputCtx *json_output_ctx = NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return result;

    json_output_ctx = SCCalloc(1, sizeof(AlertJsonOutputCtx));
    if (unlikely(json_output_ctx == NULL)) {
        goto error;
    }

    json_output_ctx->file_ctx = ajt->file_ctx;
    json_output_ctx->eve_ctx = ajt;

    JsonAlertLogSetupMetadata(json_output_ctx, conf);
    json_output_ctx->xff_cfg = JsonAlertLogGetXffCfg(conf);
    if (json_output_ctx->xff_cfg == NULL) {
        json_output_ctx->parent_xff_cfg = ajt->xff_cfg;
    }

    output_ctx->data = json_output_ctx;
    output_ctx->DeInit = JsonAlertLogDeInitCtxSub;

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

void JsonAlertLogRegister (void)
{
    OutputPacketLoggerFunctions output_logger_functions = {
        .LogFunc = JsonAlertLogger,
        .FlushFunc = JsonAlertFlush,
        .ConditionFunc = JsonAlertLogCondition,
        .ThreadInitFunc = JsonAlertLogThreadInit,
        .ThreadDeinitFunc = JsonAlertLogThreadDeinit,
        .ThreadExitPrintStatsFunc = NULL,
    };

    OutputRegisterPacketSubModule(LOGGER_JSON_ALERT, "eve-log", MODULE_NAME, "eve-log.alert",
            JsonAlertLogInitCtxSub, &output_logger_functions);
}
