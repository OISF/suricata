/* Copyright (C) 2013-2023 Open Information Security Foundation
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
#include "app-layer-dnp3.h"
#include "app-layer-htp-xff.h"
#include "app-layer-ftp.h"
#include "app-layer-frames.h"
#include "log-pcap.h"

#include "output.h"
#include "output-json.h"
#include "output-json-alert.h"
#include "output-json-dnp3.h"
#include "output-json-dns.h"
#include "output-json-http.h"
#include "output-json-tls.h"
#include "rust.h"
#include "output-json-smtp.h"
#include "output-json-email-common.h"
#include "output-json-nfs.h"
#include "output-json-smb.h"
#include "output-json-flow.h"
#include "output-json-mqtt.h"
#include "output-json-ike.h"
#include "output-json-frame.h"

#include "util-print.h"
#include "util-optimize.h"
#include "util-buffer.h"
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

static void AlertJsonSourceTarget(const Packet *p, const PacketAlert *pa,
                                  JsonBuilder *js, JsonAddrInfo *addr)
{
    jb_open_object(js, "source");
    if (pa->s->flags & SIG_FLAG_DEST_IS_TARGET) {
        jb_set_string(js, "ip", addr->src_ip);
        switch (p->proto) {
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                break;
            case IPPROTO_UDP:
            case IPPROTO_TCP:
            case IPPROTO_SCTP:
                jb_set_uint(js, "port", addr->sp);
                break;
        }
    } else if (pa->s->flags & SIG_FLAG_SRC_IS_TARGET) {
        jb_set_string(js, "ip", addr->dst_ip);
        switch (p->proto) {
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                break;
            case IPPROTO_UDP:
            case IPPROTO_TCP:
            case IPPROTO_SCTP:
                jb_set_uint(js, "port", addr->dp);
                break;
        }
    }
    jb_close(js);

    jb_open_object(js, "target");
    if (pa->s->flags & SIG_FLAG_DEST_IS_TARGET) {
        jb_set_string(js, "ip", addr->dst_ip);
        switch (p->proto) {
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                break;
            case IPPROTO_UDP:
            case IPPROTO_TCP:
            case IPPROTO_SCTP:
                jb_set_uint(js, "port", addr->dp);
                break;
        }
    } else if (pa->s->flags & SIG_FLAG_SRC_IS_TARGET) {
        jb_set_string(js, "ip", addr->src_ip);
        switch (p->proto) {
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                break;
            case IPPROTO_UDP:
            case IPPROTO_TCP:
            case IPPROTO_SCTP:
                jb_set_uint(js, "port", addr->sp);
                break;
        }
    }
    jb_close(js);
}

static void AlertJsonMetadata(AlertJsonOutputCtx *json_output_ctx,
        const PacketAlert *pa, JsonBuilder *js)
{
    if (pa->s->metadata && pa->s->metadata->json_str) {
        jb_set_formatted(js, pa->s->metadata->json_str);
    }
}

void AlertJsonHeader(void *ctx, const Packet *p, const PacketAlert *pa, JsonBuilder *js,
        uint16_t flags, JsonAddrInfo *addr, char *xff_buffer)
{
    AlertJsonOutputCtx *json_output_ctx = (AlertJsonOutputCtx *)ctx;
    const char *action = "allowed";
    /* use packet action if rate_filter modified the action */
    if (unlikely(pa->flags & PACKET_ALERT_RATE_FILTER_MODIFIED)) {
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
        jb_set_uint(js, "tx_id", pa->tx_id);
    }

    jb_open_object(js, "alert");

    jb_set_string(js, "action", action);
    jb_set_uint(js, "gid", pa->s->gid);
    jb_set_uint(js, "signature_id", pa->s->id);
    jb_set_uint(js, "rev", pa->s->rev);
    /* TODO: JsonBuilder should handle unprintable characters like
     * SCJsonString. */
    jb_set_string(js, "signature", pa->s->msg ? pa->s->msg: "");
    jb_set_string(js, "category", pa->s->class_msg ? pa->s->class_msg: "");
    jb_set_uint(js, "severity", pa->s->prio);

    if (p->tenant_id > 0) {
        jb_set_uint(js, "tenant_id", p->tenant_id);
    }

    if (addr && pa->s->flags & SIG_FLAG_HAS_TARGET) {
        AlertJsonSourceTarget(p, pa, js, addr);
    }

    if ((json_output_ctx != NULL) && (flags & LOG_JSON_RULE_METADATA)) {
        AlertJsonMetadata(json_output_ctx, pa, js);
    }

    if (flags & LOG_JSON_RULE) {
        jb_set_string(js, "rule", pa->s->sig_str);
    }
    if (xff_buffer && xff_buffer[0]) {
        jb_set_string(js, "xff", xff_buffer);
    }

    jb_close(js);
}

static void AlertJsonTunnel(const Packet *p, JsonBuilder *js)
{
    if (p->root == NULL) {
        return;
    }

    jb_open_object(js, "tunnel");

    enum PktSrcEnum pkt_src;
    uint64_t pcap_cnt;
    JsonAddrInfo addr = json_addr_info_zero;
    JsonAddrInfoInit(p->root, 0, &addr);
    pcap_cnt = p->root->pcap_cnt;
    pkt_src = p->root->pkt_src;

    jb_set_string(js, "src_ip", addr.src_ip);
    jb_set_uint(js, "src_port", addr.sp);
    jb_set_string(js, "dest_ip", addr.dst_ip);
    jb_set_uint(js, "dest_port", addr.dp);
    jb_set_string(js, "proto", addr.proto);

    jb_set_uint(js, "depth", p->recursion_level);
    if (pcap_cnt != 0) {
        jb_set_uint(js, "pcap_cnt", pcap_cnt);
    }
    jb_set_string(js, "pkt_src", PktSrcToString(pkt_src));
    jb_close(js);
}

static void AlertAddPayload(AlertJsonOutputCtx *json_output_ctx, JsonBuilder *js, const Packet *p)
{
    if (json_output_ctx->flags & LOG_JSON_PAYLOAD_BASE64) {
        jb_set_base64(js, "payload", p->payload, p->payload_len);
    }

    if (json_output_ctx->flags & LOG_JSON_PAYLOAD) {
        uint8_t printable_buf[p->payload_len + 1];
        uint32_t offset = 0;
        PrintStringsToBuffer(printable_buf, &offset,
                p->payload_len + 1,
                p->payload, p->payload_len);
        printable_buf[p->payload_len] = '\0';
        jb_set_string(js, "payload_printable", (char *)printable_buf);
    }
}

static void AlertAddAppLayer(const Packet *p, JsonBuilder *jb,
        const uint64_t tx_id, const uint16_t option_flags)
{
    const AppProto proto = FlowGetAppProtocol(p->flow);
    EveJsonSimpleAppLayerLogger *al = SCEveJsonSimpleGetLogger(proto);
    JsonBuilderMark mark = { 0, 0, 0 };
    if (al && al->LogTx) {
        void *state = FlowGetAppState(p->flow);
        if (state) {
            void *tx = AppLayerParserGetTx(p->flow->proto, proto, state, tx_id);
            if (tx) {
                jb_get_mark(jb, &mark);
                switch (proto) {
                    // first check some protocols need special options for alerts logging
                    case ALPROTO_WEBSOCKET:
                        if (option_flags &
                                (LOG_JSON_WEBSOCKET_PAYLOAD | LOG_JSON_WEBSOCKET_PAYLOAD_BASE64)) {
                            bool pp = (option_flags & LOG_JSON_WEBSOCKET_PAYLOAD) != 0;
                            bool pb64 = (option_flags & LOG_JSON_WEBSOCKET_PAYLOAD_BASE64) != 0;
                            if (!SCWebSocketLogDetails(tx, jb, pp, pb64)) {
                                jb_restore_mark(jb, &mark);
                            }
                            // nothing more to log or do
                            return;
                        }
                }
                if (!al->LogTx(tx, jb)) {
                    jb_restore_mark(jb, &mark);
                }
            }
        }
        return;
    }
    switch (proto) {
        case ALPROTO_HTTP1:
            // TODO: Could result in an empty http object being logged.
            jb_open_object(jb, "http");
            if (EveHttpAddMetadata(p->flow, tx_id, jb)) {
                if (option_flags & LOG_JSON_HTTP_BODY) {
                    EveHttpLogJSONBodyPrintable(jb, p->flow, tx_id);
                }
                if (option_flags & LOG_JSON_HTTP_BODY_BASE64) {
                    EveHttpLogJSONBodyBase64(jb, p->flow, tx_id);
                }
            }
            jb_close(jb);
            break;
        case ALPROTO_SMTP:
            jb_get_mark(jb, &mark);
            jb_open_object(jb, "smtp");
            if (EveSMTPAddMetadata(p->flow, tx_id, jb)) {
                jb_close(jb);
            } else {
                jb_restore_mark(jb, &mark);
            }
            jb_get_mark(jb, &mark);
            jb_open_object(jb, "email");
            if (EveEmailAddMetadata(p->flow, tx_id, jb)) {
                jb_close(jb);
            } else {
                jb_restore_mark(jb, &mark);
            }
            break;
        case ALPROTO_NFS:
            /* rpc */
            jb_get_mark(jb, &mark);
            jb_open_object(jb, "rpc");
            if (EveNFSAddMetadataRPC(p->flow, tx_id, jb)) {
                jb_close(jb);
            } else {
                jb_restore_mark(jb, &mark);
            }
            /* nfs */
            jb_get_mark(jb, &mark);
            jb_open_object(jb, "nfs");
            if (EveNFSAddMetadata(p->flow, tx_id, jb)) {
                jb_close(jb);
            } else {
                jb_restore_mark(jb, &mark);
            }
            break;
        case ALPROTO_SMB:
            jb_get_mark(jb, &mark);
            jb_open_object(jb, "smb");
            if (EveSMBAddMetadata(p->flow, tx_id, jb)) {
                jb_close(jb);
            } else {
                jb_restore_mark(jb, &mark);
            }
            break;
        case ALPROTO_IKE:
            jb_get_mark(jb, &mark);
            if (!EveIKEAddMetadata(p->flow, tx_id, jb)) {
                jb_restore_mark(jb, &mark);
            }
            break;
        default:
            break;
    }
}

static void AlertAddFiles(const Packet *p, JsonBuilder *jb, const uint64_t tx_id)
{
    const uint8_t direction =
            (p->flowflags & FLOW_PKT_TOSERVER) ? STREAM_TOSERVER : STREAM_TOCLIENT;
    FileContainer *ffc = NULL;
    if (p->flow->alstate != NULL) {
        void *tx = AppLayerParserGetTx(p->flow->proto, p->flow->alproto, p->flow->alstate, tx_id);
        if (tx) {
            AppLayerGetFileState files =
                    AppLayerParserGetTxFiles(p->flow, p->flow->alstate, tx, direction);
            ffc = files.fc;
        }
    }
    if (ffc != NULL) {
        File *file = ffc->head;
        bool isopen = false;
        while (file) {
            if (!isopen) {
                isopen = true;
                jb_open_array(jb, "files");
            }
            jb_start_object(jb);
            EveFileInfo(jb, file, tx_id, file->flags);
            jb_close(jb);
            file = file->next;
        }
        if (isopen) {
            jb_close(jb);
        }
    }
}

static void AlertAddFrame(
        const Packet *p, const int64_t frame_id, JsonBuilder *jb, MemBuffer *buffer)
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
 *
 */
void EveAddVerdict(JsonBuilder *jb, const Packet *p)
{
    jb_open_object(jb, "verdict");

    /* add verdict info */
    if (PacketCheckAction(p, ACTION_REJECT_ANY)) {
        // check rule to define type of reject packet sent
        if (EngineModeIsIPS()) {
            JB_SET_STRING(jb, "action", "drop");
        } else {
            JB_SET_STRING(jb, "action", "alert");
        }
        if (PacketCheckAction(p, ACTION_REJECT)) {
            JB_SET_STRING(jb, "reject-target", "to_client");
        } else if (PacketCheckAction(p, ACTION_REJECT_DST)) {
            JB_SET_STRING(jb, "reject-target", "to_server");
        } else if (PacketCheckAction(p, ACTION_REJECT_BOTH)) {
            JB_SET_STRING(jb, "reject-target", "both");
        }
        jb_open_array(jb, "reject");
        switch (p->proto) {
            case IPPROTO_UDP:
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                jb_append_string(jb, "icmp-prohib");
                break;
            case IPPROTO_TCP:
                jb_append_string(jb, "tcp-reset");
                break;
        }
        jb_close(jb);

    } else if (PacketCheckAction(p, ACTION_DROP) && EngineModeIsIPS()) {
        JB_SET_STRING(jb, "action", "drop");
    } else if (p->alerts.alerts[p->alerts.cnt].action & ACTION_PASS) {
        JB_SET_STRING(jb, "action", "pass");
    } else {
        // TODO make sure we don't have a situation where this wouldn't work
        JB_SET_STRING(jb, "action", "alert");
    }

    /* Close verdict */
    jb_close(jb);
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
        Flow *f, const Packet *p, JsonBuilder *jb)
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
            jb_set_base64(jb, "payload", cbd.payload->buffer, cbd.payload->offset);
        }

        if (json_output_ctx->flags & LOG_JSON_PAYLOAD) {
            uint8_t printable_buf[cbd.payload->offset + 1];
            uint32_t offset = 0;
            PrintStringsToBuffer(printable_buf, &offset, sizeof(printable_buf), cbd.payload->buffer,
                    cbd.payload->offset);
            jb_set_string(jb, "payload_printable", (char *)printable_buf);
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

    for (int i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
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

        JsonBuilder *jb =
                CreateEveHeader(p, LOG_DIR_PACKET, "alert", &addr, json_output_ctx->eve_ctx);
        if (unlikely(jb == NULL))
            return TM_ECODE_OK;


        /* alert */
        AlertJsonHeader(json_output_ctx, p, pa, jb, json_output_ctx->flags, &addr, xff_buffer);

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
                jb_set_string(jb, "direction", "to_server");
            } else {
                jb_set_string(jb, "direction", "to_client");
            }

            if (json_output_ctx->flags & LOG_JSON_FLOW) {
                jb_open_object(jb, "flow");
                EveAddFlow(p->flow, jb);
                if (p->flowflags & FLOW_PKT_TOCLIENT) {
                    jb_set_string(jb, "src_ip", addr.dst_ip);
                    jb_set_string(jb, "dest_ip", addr.src_ip);
                    if (addr.sp > 0) {
                        jb_set_uint(jb, "src_port", addr.dp);
                        jb_set_uint(jb, "dest_port", addr.sp);
                    }
                } else {
                    jb_set_string(jb, "src_ip", addr.src_ip);
                    jb_set_string(jb, "dest_ip", addr.dst_ip);
                    if (addr.sp > 0) {
                        jb_set_uint(jb, "src_port", addr.sp);
                        jb_set_uint(jb, "dest_port", addr.dp);
                    }
                }
                jb_close(jb);
            }
        }

        /* payload */
        if (json_output_ctx->flags & (LOG_JSON_PAYLOAD | LOG_JSON_PAYLOAD_BASE64)) {
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

            jb_set_uint(jb, "stream", stream);
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
            jb_set_string(jb, "capture_file", pcap_filename);
        }

        if (json_output_ctx->flags & LOG_JSON_VERDICT) {
            EveAddVerdict(jb, p);
        }

        OutputJsonBuilderBuffer(jb, aft->ctx);
        jb_free(jb);
    }

    if ((p->flags & PKT_HAS_TAG) && (json_output_ctx->flags &
            LOG_JSON_TAGGED_PACKETS)) {
        JsonBuilder *packetjs =
                CreateEveHeader(p, LOG_DIR_PACKET, "packet", NULL, json_output_ctx->eve_ctx);
        if (unlikely(packetjs != NULL)) {
            EvePacket(p, packetjs, 0);
            OutputJsonBuilderBuffer(packetjs, aft->ctx);
            jb_free(packetjs);
        }
    }

    return TM_ECODE_OK;
}

static int AlertJsonDecoderEvent(ThreadVars *tv, JsonAlertLogThread *aft, const Packet *p)
{
    AlertJsonOutputCtx *json_output_ctx = aft->json_output_ctx;
    char timebuf[64];

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    CreateIsoTimeString(p->ts, timebuf, sizeof(timebuf));

    for (int i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        JsonBuilder *jb = jb_new_object();
        if (unlikely(jb == NULL)) {
            return TM_ECODE_OK;
        }

        /* just the timestamp, no tuple */
        jb_set_string(jb, "timestamp", timebuf);

        AlertJsonHeader(json_output_ctx, p, pa, jb, json_output_ctx->flags, NULL, NULL);

        OutputJsonBuilderBuffer(jb, aft->ctx);
        jb_free(jb);
    }

    return TM_ECODE_OK;
}

static int JsonAlertLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    JsonAlertLogThread *aft = thread_data;

    if (PKT_IS_IPV4(p) || PKT_IS_IPV6(p)) {
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

static void SetFlag(const ConfNode *conf, const char *name, uint16_t flag, uint16_t *out_flags)
{
    DEBUG_VALIDATE_BUG_ON(conf == NULL);
    const char *setting = ConfNodeLookupChildValue(conf, name);
    if (setting != NULL) {
        if (ConfValIsTrue(setting)) {
            *out_flags |= flag;
        } else {
            *out_flags &= ~flag;
        }
    }
}

static void JsonAlertLogSetupMetadata(AlertJsonOutputCtx *json_output_ctx,
        ConfNode *conf)
{
    static bool warn_no_meta = false;
    uint32_t payload_buffer_size = JSON_STREAM_BUFFER_SIZE;
    uint16_t flags = METADATA_DEFAULTS;

    if (conf != NULL) {
        /* Check for metadata to enable/disable. */
        ConfNode *metadata = ConfNodeLookupChild(conf, "metadata");
        if (metadata != NULL) {
            if (metadata->val != NULL && ConfValIsFalse(metadata->val)) {
                flags &= ~METADATA_DEFAULTS;
            } else if (ConfNodeHasChildren(metadata)) {
                ConfNode *rule_metadata = ConfNodeLookupChild(metadata, "rule");
                if (rule_metadata) {
                    SetFlag(rule_metadata, "raw", LOG_JSON_RULE, &flags);
                    SetFlag(rule_metadata, "metadata", LOG_JSON_RULE_METADATA,
                            &flags);
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

        /* Check for obsolete flags and warn that they have no effect. */
        static const char *deprecated_flags[] = { "http", "tls", "ssh", "smtp", "dnp3", "app-layer",
            "flow", NULL };
        for (int i = 0; deprecated_flags[i] != NULL; i++) {
            if (ConfNodeLookupChildValue(conf, deprecated_flags[i]) != NULL) {
                SCLogWarning("Found deprecated eve-log.alert flag \"%s\", this flag has no effect",
                        deprecated_flags[i]);
            }
        }

        const char *payload_buffer_value = ConfNodeLookupChildValue(conf, "payload-buffer-size");

        if (payload_buffer_value != NULL) {
            uint32_t value;
            if (ParseSizeStringU32(payload_buffer_value, &value) < 0) {
                SCLogError("Error parsing "
                           "payload-buffer-size - %s. Killing engine",
                        payload_buffer_value);
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

static HttpXFFCfg *JsonAlertLogGetXffCfg(ConfNode *conf)
{
    HttpXFFCfg *xff_cfg = NULL;
    if (conf != NULL && ConfNodeLookupChild(conf, "xff") != NULL) {
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
static OutputInitResult JsonAlertLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
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
    OutputRegisterPacketSubModule(LOGGER_JSON_ALERT, "eve-log", MODULE_NAME,
        "eve-log.alert", JsonAlertLogInitCtxSub, JsonAlertLogger,
        JsonAlertLogCondition, JsonAlertLogThreadInit, JsonAlertLogThreadDeinit,
        NULL);
}
