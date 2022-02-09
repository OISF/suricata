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
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * Logs alerts in JSON format.
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
#include "app-layer-frames.h"
#include "util-classification-config.h"
#include "util-syslog.h"
#include "util-logopenfile.h"

#include "output.h"
#include "output-json.h"
#include "output-json-alert.h"
#include "output-json-dnp3.h"
#include "output-json-dns.h"
#include "output-json-http.h"
#include "output-json-tls.h"
#include "output-json-ssh.h"
#include "rust.h"
#include "output-json-smtp.h"
#include "output-json-email-common.h"
#include "output-json-nfs.h"
#include "output-json-smb.h"
#include "output-json-flow.h"
#include "output-json-sip.h"
#include "output-json-rfb.h"
#include "output-json-mqtt.h"
#include "output-json-ike.h"
#include "output-json-modbus.h"
#include "output-json-frame.h"
#include "output-json-quic.h"

#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-validate.h"

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

#define METADATA_DEFAULTS ( LOG_JSON_FLOW |                        \
            LOG_JSON_APP_LAYER  |                                  \
            LOG_JSON_RULE_METADATA)

#define JSON_BODY_LOGGING  (LOG_JSON_HTTP_BODY | LOG_JSON_HTTP_BODY_BASE64)

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

/* Callback function to pack payload contents from a stream into a buffer
 * so we can report them in JSON output. */
static int AlertJsonDumpStreamSegmentCallback(const Packet *p, void *data, const uint8_t *buf, uint32_t buflen)
{
    MemBuffer *payload = (MemBuffer *)data;
    MemBufferWriteRaw(payload, buf, buflen);

    return 1;
}

static void AlertJsonTls(const Flow *f, JsonBuilder *js)
{
    SSLState *ssl_state = (SSLState *)FlowGetAppState(f);
    if (ssl_state) {
        jb_open_object(js, "tls");

        JsonTlsLogJSONExtended(js, ssl_state);

        jb_close(js);
    }

    return;
}

static void AlertJsonSsh(const Flow *f, JsonBuilder *js)
{
    void *ssh_state = FlowGetAppState(f);
    if (ssh_state) {
        JsonBuilderMark mark = { 0, 0, 0 };
        void *tx_ptr = rs_ssh_state_get_tx(ssh_state, 0);
        jb_get_mark(js, &mark);
        jb_open_object(js, "ssh");
        if (rs_ssh_log_json(tx_ptr, js)) {
            jb_close(js);
        } else {
            jb_restore_mark(js, &mark);
        }
    }

    return;
}

static void AlertJsonHttp2(const Flow *f, const uint64_t tx_id, JsonBuilder *js)
{
    void *h2_state = FlowGetAppState(f);
    if (h2_state) {
        void *tx_ptr = rs_http2_state_get_tx(h2_state, tx_id);
        if (tx_ptr) {
            JsonBuilderMark mark = { 0, 0, 0 };
            jb_get_mark(js, &mark);
            jb_open_object(js, "http");
            if (rs_http2_log_json(tx_ptr, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
        }
    }

    return;
}

static void AlertJsonDnp3(const Flow *f, const uint64_t tx_id, JsonBuilder *js)
{
    DNP3State *dnp3_state = (DNP3State *)FlowGetAppState(f);
    if (dnp3_state) {
        DNP3Transaction *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_DNP3,
            dnp3_state, tx_id);
        if (tx) {
            JsonBuilderMark mark = { 0, 0, 0 };
            jb_get_mark(js, &mark);
            bool logged = false;
            jb_open_object(js, "dnp3");
            if (tx->has_request && tx->request_done) {
                jb_open_object(js, "request");
                JsonDNP3LogRequest(js, tx);
                jb_close(js);
                logged = true;
            }
            if (tx->has_response && tx->response_done) {
                jb_open_object(js, "response");
                JsonDNP3LogResponse(js, tx);
                jb_close(js);
                logged = true;
            }
            if (logged) {
                /* Close dnp3 object. */
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
        }
    }
}

static void AlertJsonDns(const Flow *f, const uint64_t tx_id, JsonBuilder *js)
{
    void *dns_state = (void *)FlowGetAppState(f);
    if (dns_state) {
        void *txptr = AppLayerParserGetTx(f->proto, ALPROTO_DNS,
                                          dns_state, tx_id);
        if (txptr) {
            jb_open_object(js, "dns");
            JsonBuilder *qjs = JsonDNSLogQuery(txptr, tx_id);
            if (qjs != NULL) {
                jb_set_object(js, "query", qjs);
                jb_free(qjs);
            }
            JsonBuilder *ajs = JsonDNSLogAnswer(txptr, tx_id);
            if (ajs != NULL) {
                jb_set_object(js, "answer", ajs);
                jb_free(ajs);
            }
            jb_close(js);
        }
    }
    return;
}

static void AlertJsonSNMP(const Flow *f, const uint64_t tx_id, JsonBuilder *js)
{
    void *snmp_state = (void *)FlowGetAppState(f);
    if (snmp_state != NULL) {
        void *tx = AppLayerParserGetTx(f->proto, ALPROTO_SNMP, snmp_state,
                tx_id);
        if (tx != NULL) {
            jb_open_object(js, "snmp");
            rs_snmp_log_json_response(js, snmp_state, tx);
            jb_close(js);
        }
    }
}

static void AlertJsonRDP(const Flow *f, const uint64_t tx_id, JsonBuilder *js)
{
    void *rdp_state = (void *)FlowGetAppState(f);
    if (rdp_state != NULL) {
        void *tx = AppLayerParserGetTx(f->proto, ALPROTO_RDP, rdp_state,
                tx_id);
        if (tx != NULL) {
            JsonBuilderMark mark = { 0, 0, 0 };
            jb_get_mark(js, &mark);
            if (!rs_rdp_to_json(tx, js)) {
                jb_restore_mark(js, &mark);
            }
        }
    }
}

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

void AlertJsonHeader(void *ctx, const Packet *p, const PacketAlert *pa,
        JsonBuilder *js, uint16_t flags, JsonAddrInfo *addr)
{
    AlertJsonOutputCtx *json_output_ctx = (AlertJsonOutputCtx *)ctx;
    const char *action = "allowed";
    /* use packet action if rate_filter modified the action */
    if (unlikely(pa->flags & PACKET_ALERT_RATE_FILTER_MODIFIED)) {
        if (PacketTestAction(
                    p, (ACTION_DROP | ACTION_REJECT | ACTION_REJECT_DST | ACTION_REJECT_BOTH))) {
            action = "blocked";
        }
    } else {
        if (pa->action & (ACTION_REJECT|ACTION_REJECT_DST|ACTION_REJECT_BOTH)) {
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

    jb_close(js);
}

static void AlertJsonTunnel(const Packet *p, JsonBuilder *js)
{
    if (p->root == NULL) {
        return;
    }

    jb_open_object(js, "tunnel");

    /* get a lock to access root packet fields */
    SCMutex *m = &p->root->tunnel_mutex;

    JsonAddrInfo addr = json_addr_info_zero;
    SCMutexLock(m);
    JsonAddrInfoInit(p->root, 0, &addr);
    SCMutexUnlock(m);

    jb_set_string(js, "src_ip", addr.src_ip);
    jb_set_uint(js, "src_port", addr.sp);
    jb_set_string(js, "dest_ip", addr.dst_ip);
    jb_set_uint(js, "dest_port", addr.dp);
    jb_set_string(js, "proto", addr.proto);

    jb_set_uint(js, "depth", p->recursion_level);

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
    JsonBuilderMark mark = { 0, 0, 0 };
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
        case ALPROTO_TLS:
            AlertJsonTls(p->flow, jb);
            break;
        case ALPROTO_SSH:
            AlertJsonSsh(p->flow, jb);
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
        case ALPROTO_SIP:
            JsonSIPAddMetadata(jb, p->flow, tx_id);
            break;
        case ALPROTO_RFB:
            jb_get_mark(jb, &mark);
            if (!JsonRFBAddMetadata(p->flow, tx_id, jb)) {
                jb_restore_mark(jb, &mark);
            }
            break;
        case ALPROTO_FTPDATA:
            jb_get_mark(jb, &mark);
            jb_open_object(jb, "ftp_data");
            EveFTPDataAddMetadata(p->flow, jb);
            jb_close(jb);
            break;
        case ALPROTO_DNP3:
            AlertJsonDnp3(p->flow, tx_id, jb);
            break;
        case ALPROTO_HTTP2:
            AlertJsonHttp2(p->flow, tx_id, jb);
            break;
        case ALPROTO_DNS:
            AlertJsonDns(p->flow, tx_id, jb);
            break;
        case ALPROTO_IKE:
            jb_get_mark(jb, &mark);
            if (!EveIKEAddMetadata(p->flow, tx_id, jb)) {
                jb_restore_mark(jb, &mark);
            }
            break;
        case ALPROTO_MQTT:
            jb_get_mark(jb, &mark);
            if (!JsonMQTTAddMetadata(p->flow, tx_id, jb)) {
                jb_restore_mark(jb, &mark);
            }
            break;
        case ALPROTO_QUIC:
            jb_get_mark(jb, &mark);
            if (!JsonQuicAddMetadata(p->flow, tx_id, jb)) {
                jb_restore_mark(jb, &mark);
            }
            break;
        case ALPROTO_SNMP:
            AlertJsonSNMP(p->flow, tx_id, jb);
            break;
        case ALPROTO_RDP:
            AlertJsonRDP(p->flow, tx_id, jb);
            break;
        case ALPROTO_MODBUS:
            jb_get_mark(jb, &mark);
            if (!JsonModbusAddMetadata(p->flow, tx_id, jb)) {
                jb_restore_mark(jb, &mark);
            }
            break;
        default:
            break;
    }
}

static void AlertAddFiles(const Packet *p, JsonBuilder *jb, const uint64_t tx_id)
{
    FileContainer *ffc = AppLayerParserGetFiles(p->flow,
            p->flowflags & FLOW_PKT_TOSERVER ? STREAM_TOSERVER:STREAM_TOCLIENT);
    if (ffc != NULL) {
        File *file = ffc->head;
        bool isopen = false;
        while (file) {
            if (tx_id == file->txid) {
                if (!isopen) {
                    isopen = true;
                    jb_open_array(jb, "files");
                }
                jb_start_object(jb);
                EveFileInfo(jb, file, file->flags & FILE_STORED);
                jb_close(jb);
            }
            file = file->next;
        }
        if (isopen) {
            jb_close(jb);
        }
    }
}

static void AlertAddFrame(const Packet *p, JsonBuilder *jb, const int64_t frame_id)
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
            FrameJsonLogOneFrame(IPPROTO_TCP, frame, p->flow, stream, p, jb);
        }
    } else if (p->proto == IPPROTO_UDP) {
        if (PKT_IS_TOSERVER(p)) {
            frames = &frames_container->toserver;
        } else {
            frames = &frames_container->toclient;
        }
        Frame *frame = FrameGetById(frames, frame_id);
        if (frame != NULL) {
            FrameJsonLogOneFrame(IPPROTO_UDP, frame, p->flow, NULL, p, jb);
        }
    }
}

static int AlertJson(ThreadVars *tv, JsonAlertLogThread *aft, const Packet *p)
{
    MemBuffer *payload = aft->payload_buffer;
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
        HttpXFFCfg *xff_cfg = json_output_ctx->xff_cfg != NULL ?
            json_output_ctx->xff_cfg : json_output_ctx->parent_xff_cfg;;
        int have_xff_ip = 0;
        char xff_buffer[XFF_MAXLEN];
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
        }

        JsonBuilder *jb =
                CreateEveHeader(p, LOG_DIR_PACKET, "alert", &addr, json_output_ctx->eve_ctx);
        if (unlikely(jb == NULL))
            return TM_ECODE_OK;


        /* alert */
        AlertJsonHeader(json_output_ctx, p, pa, jb, json_output_ctx->flags,
                &addr);

        if (IS_TUNNEL_PKT(p)) {
            AlertJsonTunnel(p, jb);
        }

        if (p->flow != NULL) {
            if (json_output_ctx->flags & LOG_JSON_APP_LAYER) {
                AlertAddAppLayer(p, jb, pa->tx_id, json_output_ctx->flags);
            }
            /* including fileinfo data is configured by the metadata setting */
            if (json_output_ctx->flags & LOG_JSON_RULE_METADATA) {
                AlertAddFiles(p, jb, pa->tx_id);
            }

            EveAddAppProto(p->flow, jb);
            if (json_output_ctx->flags & LOG_JSON_FLOW) {
                jb_open_object(jb, "flow");
                EveAddFlow(p->flow, jb);
                jb_close(jb);
            }
        }

        /* payload */
        if (json_output_ctx->flags & (LOG_JSON_PAYLOAD | LOG_JSON_PAYLOAD_BASE64)) {
            int stream = (p->proto == IPPROTO_TCP) ?
                         (pa->flags & (PACKET_ALERT_FLAG_STATE_MATCH | PACKET_ALERT_FLAG_STREAM_MATCH) ?
                         1 : 0) : 0;

            /* Is this a stream?  If so, pack part of it into the payload field */
            if (stream) {
                uint8_t flag;

                MemBufferReset(payload);

                if (p->flowflags & FLOW_PKT_TOSERVER) {
                    flag = FLOW_PKT_TOCLIENT;
                } else {
                    flag = FLOW_PKT_TOSERVER;
                }

                StreamSegmentForEach((const Packet *)p, flag,
                                    AlertJsonDumpStreamSegmentCallback,
                                    (void *)payload);
                if (payload->offset) {
                    if (json_output_ctx->flags & LOG_JSON_PAYLOAD_BASE64) {
                        jb_set_base64(jb, "payload", payload->buffer, payload->offset);
                    }

                    if (json_output_ctx->flags & LOG_JSON_PAYLOAD) {
                        uint8_t printable_buf[payload->offset + 1];
                        uint32_t offset = 0;
                        PrintStringsToBuffer(printable_buf, &offset,
                                sizeof(printable_buf),
                                payload->buffer, payload->offset);
                        jb_set_string(jb, "payload_printable", (char *)printable_buf);
                    }
                } else if (p->payload_len) {
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
            AlertAddFrame(p, jb, pa->frame_id);
        }

        /* base64-encoded full packet */
        if (json_output_ctx->flags & LOG_JSON_PACKET) {
            EvePacket(p, jb, 0);
        }

        if (have_xff_ip && xff_cfg->flags & XFF_EXTRADATA) {
            jb_set_string(jb, "xff", xff_buffer);
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

    CreateIsoTimeString(&p->ts, timebuf, sizeof(timebuf));

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

        AlertJsonHeader(json_output_ctx, p, pa, jb, json_output_ctx->flags, NULL);

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

static int JsonAlertLogCondition(ThreadVars *tv, const Packet *p)
{
    if (p->alerts.cnt || (p->flags & PKT_HAS_TAG)) {
        return TRUE;
    }
    return FALSE;
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

#define DEFAULT_LOG_FILENAME "alert.json"

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

        /* Check for obsolete configuration flags to enable specific
         * protocols. These are now just aliases for enabling
         * app-layer logging. */
        SetFlag(conf, "http", LOG_JSON_APP_LAYER, &flags);
        SetFlag(conf, "tls",  LOG_JSON_APP_LAYER,  &flags);
        SetFlag(conf, "ssh",  LOG_JSON_APP_LAYER,  &flags);
        SetFlag(conf, "smtp", LOG_JSON_APP_LAYER, &flags);
        SetFlag(conf, "dnp3", LOG_JSON_APP_LAYER, &flags);

        /* And check for obsolete configuration flags for enabling
         * app-layer and flow as these have been moved under the
         * metadata key. */
        SetFlag(conf, "app-layer", LOG_JSON_APP_LAYER, &flags);
        SetFlag(conf, "flow", LOG_JSON_FLOW, &flags);

        const char *payload_buffer_value = ConfNodeLookupChildValue(conf, "payload-buffer-size");

        if (payload_buffer_value != NULL) {
            uint32_t value;
            if (ParseSizeStringU32(payload_buffer_value, &value) < 0) {
                SCLogError(SC_ERR_ALERT_PAYLOAD_BUFFER, "Error parsing "
                           "payload-buffer-size - %s. Killing engine",
                           payload_buffer_value);
                exit(EXIT_FAILURE);
            } else {
                payload_buffer_size = value;
            }
        }

        if (!warn_no_meta && flags & JSON_BODY_LOGGING) {
            if (((flags & LOG_JSON_APP_LAYER) == 0)) {
                SCLogWarning(SC_WARN_ALERT_CONFIG, "HTTP body logging has been configured, however, "
                             "metadata logging has not been enabled. HTTP body logging will be disabled.");
                flags &= ~JSON_BODY_LOGGING;
                warn_no_meta = true;
            }
        }

        json_output_ctx->payload_buffer_size = payload_buffer_size;
    }

    if (flags & LOG_JSON_RULE_METADATA) {
        DetectEngineSetParseMetadata();
    }

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

    json_output_ctx = SCMalloc(sizeof(AlertJsonOutputCtx));
    if (unlikely(json_output_ctx == NULL)) {
        goto error;
    }
    memset(json_output_ctx, 0, sizeof(AlertJsonOutputCtx));

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
