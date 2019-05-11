/* Copyright (C) 2013-2014 Open Information Security Foundation
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
#include "app-layer-dns-common.h"
#include "app-layer-htp.h"
#include "app-layer-htp-xff.h"
#include "app-layer-ftp.h"
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
#include "output-json-smtp.h"
#include "output-json-email-common.h"
#include "output-json-nfs.h"
#include "output-json-smb.h"
#include "output-json-flow.h"

#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-crypt.h"
#include "util-validate.h"

#define MODULE_NAME "JsonAlertLog"

#ifdef HAVE_LIBJANSSON

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

#define JSON_STREAM_BUFFER_SIZE 4096

typedef struct AlertJsonOutputCtx_ {
    LogFileCtx* file_ctx;
    uint16_t flags;
    uint32_t payload_buffer_size;
    HttpXFFCfg *xff_cfg;
    HttpXFFCfg *parent_xff_cfg;
    OutputJsonCommonSettings cfg;
} AlertJsonOutputCtx;

typedef struct JsonAlertLogThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
    MemBuffer *json_buffer;
    MemBuffer *payload_buffer;
    AlertJsonOutputCtx* json_output_ctx;
} JsonAlertLogThread;

/* Callback function to pack payload contents from a stream into a buffer
 * so we can report them in JSON output. */
static int AlertJsonDumpStreamSegmentCallback(const Packet *p, void *data, const uint8_t *buf, uint32_t buflen)
{
    MemBuffer *payload = (MemBuffer *)data;
    MemBufferWriteRaw(payload, buf, buflen);

    return 1;
}

static void AlertJsonTls(const Flow *f, json_t *js)
{
    SSLState *ssl_state = (SSLState *)FlowGetAppState(f);
    if (ssl_state) {
        json_t *tjs = json_object();
        if (unlikely(tjs == NULL))
            return;

        JsonTlsLogJSONBasic(tjs, ssl_state);
        JsonTlsLogJSONExtended(tjs, ssl_state);

        json_object_set_new(js, "tls", tjs);
    }

    return;
}

static void AlertJsonSsh(const Flow *f, json_t *js)
{
    SshState *ssh_state = (SshState *)FlowGetAppState(f);
    if (ssh_state) {
        json_t *tjs = json_object();
        if (unlikely(tjs == NULL))
            return;

        JsonSshLogJSON(tjs, ssh_state);

        json_object_set_new(js, "ssh", tjs);
    }

    return;
}

static void AlertJsonDnp3(const Flow *f, const uint64_t tx_id, json_t *js)
{
    DNP3State *dnp3_state = (DNP3State *)FlowGetAppState(f);
    if (dnp3_state) {
        DNP3Transaction *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_DNP3,
            dnp3_state, tx_id);
        if (tx) {
            json_t *dnp3js = json_object();
            if (likely(dnp3js != NULL)) {
                if (tx->has_request && tx->request_done) {
                    json_t *request = JsonDNP3LogRequest(tx);
                    if (request != NULL) {
                        json_object_set_new(dnp3js, "request", request);
                    }
                }
                if (tx->has_response && tx->response_done) {
                    json_t *response = JsonDNP3LogResponse(tx);
                    if (response != NULL) {
                        json_object_set_new(dnp3js, "response", response);
                    }
                }
                json_object_set_new(js, "dnp3", dnp3js);
            }
        }
    }

    return;
}

static void AlertJsonDns(const Flow *f, const uint64_t tx_id, json_t *js)
{
    RSDNSState *dns_state = (RSDNSState *)FlowGetAppState(f);
    if (dns_state) {
        void *txptr = AppLayerParserGetTx(f->proto, ALPROTO_DNS,
                                          dns_state, tx_id);
        if (txptr) {
            json_t *dnsjs = json_object();
            if (unlikely(dnsjs == NULL)) {
                return;
            }
            json_t *qjs = JsonDNSLogQuery(txptr, tx_id);
            if (qjs != NULL) {
                json_object_set_new(dnsjs, "query", qjs);
            }
            json_t *ajs = JsonDNSLogAnswer(txptr, tx_id);
            if (ajs != NULL) {
                json_object_set_new(dnsjs, "answer", ajs);
            }
            json_object_set_new(js, "dns", dnsjs);
        }
    }
    return;
}

static void AlertJsonSourceTarget(const Packet *p, const PacketAlert *pa,
                                  json_t *js, json_t* ajs)
{
    json_t *sjs = json_object();
    if (sjs == NULL) {
        return;
    }

    json_t *tjs = json_object();
    if (tjs == NULL) {
        json_decref(sjs);
        return;
    }

    if (pa->s->flags & SIG_FLAG_DEST_IS_TARGET) {
        json_object_set(sjs, "ip", json_object_get(js, "src_ip"));
        json_object_set(tjs, "ip", json_object_get(js, "dest_ip"));
        switch (p->proto) {
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                break;
            case IPPROTO_UDP:
            case IPPROTO_TCP:
            case IPPROTO_SCTP:
                json_object_set(sjs, "port", json_object_get(js, "src_port"));
                json_object_set(tjs, "port", json_object_get(js, "dest_port"));
                break;
        }
    } else if (pa->s->flags & SIG_FLAG_SRC_IS_TARGET) {
        json_object_set(sjs, "ip", json_object_get(js, "dest_ip"));
        json_object_set(tjs, "ip", json_object_get(js, "src_ip"));
        switch (p->proto) {
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                break;
            case IPPROTO_UDP:
            case IPPROTO_TCP:
            case IPPROTO_SCTP:
                json_object_set(sjs, "port", json_object_get(js, "dest_port"));
                json_object_set(tjs, "port", json_object_get(js, "src_port"));
                break;
        }
    }
    json_object_set_new(ajs, "source", sjs);
    json_object_set_new(ajs, "target", tjs);
}

static void AlertJsonMetadata(AlertJsonOutputCtx *json_output_ctx, const PacketAlert *pa, json_t *ajs)
{
    if (pa->s->metadata) {
        const DetectMetadata* kv = pa->s->metadata;
        json_t *mjs = json_object();
        if (unlikely(mjs == NULL)) {
            return;
        }
        while (kv) {
            json_t *jkey = json_object_get(mjs, kv->key);
            if (jkey == NULL) {
                jkey = json_array();
                if (unlikely(jkey == NULL))
                    break;
                json_array_append_new(jkey, json_string(kv->value));
                json_object_set_new(mjs, kv->key, jkey);
            } else {
                json_array_append_new(jkey, json_string(kv->value));
            }

            kv = kv->next;
        }

        if (json_object_size(mjs) == 0) {
            json_decref(mjs);
        } else {
            json_object_set_new(ajs, "metadata", mjs);
        }
    }
}


void AlertJsonHeader(void *ctx, const Packet *p, const PacketAlert *pa, json_t *js,
                     uint16_t flags)
{
    AlertJsonOutputCtx *json_output_ctx = (AlertJsonOutputCtx *)ctx;
    const char *action = "allowed";
    /* use packet action if rate_filter modified the action */
    if (unlikely(pa->flags & PACKET_ALERT_RATE_FILTER_MODIFIED)) {
        if (PACKET_TEST_ACTION(p, (ACTION_DROP|ACTION_REJECT|
                                   ACTION_REJECT_DST|ACTION_REJECT_BOTH))) {
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
    json_object_del(js, "tx_id");
    if (pa->flags & PACKET_ALERT_FLAG_TX)
        json_object_set_new(js, "tx_id", json_integer(pa->tx_id));

    json_t *ajs = json_object();
    if (ajs == NULL) {
        return;
    }

    json_object_set_new(ajs, "action", json_string(action));
    json_object_set_new(ajs, "gid", json_integer(pa->s->gid));
    json_object_set_new(ajs, "signature_id", json_integer(pa->s->id));
    json_object_set_new(ajs, "rev", json_integer(pa->s->rev));
    json_object_set_new(ajs, "signature",
            SCJsonString((pa->s->msg) ? pa->s->msg : ""));
    json_object_set_new(ajs, "category",
            SCJsonString((pa->s->class_msg) ? pa->s->class_msg : ""));
    json_object_set_new(ajs, "severity", json_integer(pa->s->prio));

    if (p->tenant_id > 0)
        json_object_set_new(ajs, "tenant_id", json_integer(p->tenant_id));

    if (pa->s->flags & SIG_FLAG_HAS_TARGET) {
        AlertJsonSourceTarget(p, pa, js, ajs);
    }

    if ((json_output_ctx != NULL) && (flags & LOG_JSON_RULE_METADATA)) {
        AlertJsonMetadata(json_output_ctx, pa, ajs);
    }

    /* alert */
    json_object_set_new(js, "alert", ajs);
}

static void AlertJsonTunnel(const Packet *p, json_t *js)
{
    json_t *tunnel = json_object();
    if (tunnel == NULL)
        return;

    if (p->root == NULL) {
        json_decref(tunnel);
        return;
    }

    /* get a lock to access root packet fields */
    SCMutex *m = &p->root->tunnel_mutex;

    SCMutexLock(m);
    JsonFiveTuple((const Packet *)p->root, 0, tunnel);
    SCMutexUnlock(m);

    json_object_set_new(tunnel, "depth", json_integer(p->recursion_level));

    json_object_set_new(js, "tunnel", tunnel);
}

static void AlertAddPayload(AlertJsonOutputCtx *json_output_ctx, json_t *js, const Packet *p)
{
    if (json_output_ctx->flags & LOG_JSON_PAYLOAD_BASE64) {
        unsigned long len = p->payload_len * 2 + 1;
        uint8_t encoded[len];
        if (Base64Encode(p->payload, p->payload_len, encoded, &len) == SC_BASE64_OK) {
            json_object_set_new(js, "payload", json_string((char *)encoded));
        }
    }

    if (json_output_ctx->flags & LOG_JSON_PAYLOAD) {
        uint8_t printable_buf[p->payload_len + 1];
        uint32_t offset = 0;
        PrintStringsToBuffer(printable_buf, &offset,
                p->payload_len + 1,
                p->payload, p->payload_len);
        printable_buf[p->payload_len] = '\0';
        json_object_set_new(js, "payload_printable", json_string((char *)printable_buf));
    }
}

static int AlertJson(ThreadVars *tv, JsonAlertLogThread *aft, const Packet *p)
{
    MemBuffer *payload = aft->payload_buffer;
    AlertJsonOutputCtx *json_output_ctx = aft->json_output_ctx;
    json_t *hjs = NULL;

    int i;

    if (p->alerts.cnt == 0 && !(p->flags & PKT_HAS_TAG))
        return TM_ECODE_OK;

    json_t *js = CreateJSONHeader(p, LOG_DIR_PACKET, "alert");
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    JsonAddCommonOptions(&json_output_ctx->cfg, p, p->flow, js);

    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        MemBufferReset(aft->json_buffer);

        /* alert */
        AlertJsonHeader(json_output_ctx, p, pa, js, json_output_ctx->flags);

        if (IS_TUNNEL_PKT(p)) {
            AlertJsonTunnel(p, js);
        }

        if (json_output_ctx->flags & LOG_JSON_APP_LAYER && p->flow != NULL) {
            uint16_t proto = FlowGetAppProtocol(p->flow);

            /* http alert */
            if (proto == ALPROTO_HTTP) {
                hjs = JsonHttpAddMetadata(p->flow, pa->tx_id);
                if (hjs) {
                    if (json_output_ctx->flags & LOG_JSON_HTTP_BODY) {
                        JsonHttpLogJSONBodyPrintable(hjs, p->flow, pa->tx_id);
                    }
                    if (json_output_ctx->flags & LOG_JSON_HTTP_BODY_BASE64) {
                        JsonHttpLogJSONBodyBase64(hjs, p->flow, pa->tx_id);
                    }
                    json_object_set_new(js, "http", hjs);
                }
            }

            /* tls alert */
            if (proto == ALPROTO_TLS) {
                AlertJsonTls(p->flow, js);
            }

            /* ssh alert */
            if (proto == ALPROTO_SSH) {
                AlertJsonSsh(p->flow, js);
            }

            /* smtp alert */
            if (proto == ALPROTO_SMTP) {
                hjs = JsonSMTPAddMetadata(p->flow, pa->tx_id);
                if (hjs) {
                    json_object_set_new(js, "smtp", hjs);
                }

                hjs = JsonEmailAddMetadata(p->flow, pa->tx_id);
                if (hjs) {
                    json_object_set_new(js, "email", hjs);
                }
            }

#ifdef HAVE_RUST
            if (proto == ALPROTO_NFS) {
                hjs = JsonNFSAddMetadataRPC(p->flow, pa->tx_id);
                if (hjs)
                    json_object_set_new(js, "rpc", hjs);
                hjs = JsonNFSAddMetadata(p->flow, pa->tx_id);
                if (hjs)
                    json_object_set_new(js, "nfs", hjs);
            } else if (proto == ALPROTO_SMB) {
                hjs = JsonSMBAddMetadata(p->flow, pa->tx_id);
                if (hjs)
                    json_object_set_new(js, "smb", hjs);
            }
#endif
            if (proto == ALPROTO_FTPDATA) {
                hjs = JsonFTPDataAddMetadata(p->flow);
                if (hjs)
                    json_object_set_new(js, "ftp-data", hjs);
            }

            /* dnp3 alert */
            if (proto == ALPROTO_DNP3) {
                AlertJsonDnp3(p->flow, pa->tx_id, js);
            }

            if (proto == ALPROTO_DNS) {
                AlertJsonDns(p->flow, pa->tx_id, js);
            }
        }

        if (p->flow) {
            if (json_output_ctx->flags & LOG_JSON_FLOW) {
                hjs = json_object();
                if (hjs != NULL) {
                    JsonAddFlow(p->flow, js, hjs);
                    json_object_set_new(js, "flow", hjs);
                }
            } else {
                json_object_set_new(js, "app_proto",
                        json_string(AppProtoToString(p->flow->alproto)));
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
                        unsigned long len = json_output_ctx->payload_buffer_size * 2;
                        uint8_t encoded[len];
                        Base64Encode(payload->buffer, payload->offset, encoded, &len);
                        json_object_set_new(js, "payload", json_string((char *)encoded));
                    }

                    if (json_output_ctx->flags & LOG_JSON_PAYLOAD) {
                        uint8_t printable_buf[payload->offset + 1];
                        uint32_t offset = 0;
                        PrintStringsToBuffer(printable_buf, &offset,
                                sizeof(printable_buf),
                                payload->buffer, payload->offset);
                        json_object_set_new(js, "payload_printable",
                                json_string((char *)printable_buf));
                    }
                } else if (p->payload_len) {
                    /* Fallback on packet payload */
                    AlertAddPayload(json_output_ctx, js, p);
                }
            } else {
                /* This is a single packet and not a stream */
                AlertAddPayload(json_output_ctx, js, p);
            }

            json_object_set_new(js, "stream", json_integer(stream));
        }

        /* base64-encoded full packet */
        if (json_output_ctx->flags & LOG_JSON_PACKET) {
            JsonPacket(p, js, 0);
        }

        /* signature text */
        if (json_output_ctx->flags & LOG_JSON_RULE) {
            hjs = json_object_get(js, "alert");
            if (json_is_object(hjs))
                json_object_set_new(hjs, "rule", json_string(pa->s->sig_str));
        }

        HttpXFFCfg *xff_cfg = json_output_ctx->xff_cfg != NULL ?
            json_output_ctx->xff_cfg : json_output_ctx->parent_xff_cfg;;

        /* xff header */
        if ((xff_cfg != NULL) && !(xff_cfg->flags & XFF_DISABLED) && p->flow != NULL) {
            int have_xff_ip = 0;
            char buffer[XFF_MAXLEN];

            if (FlowGetAppProtocol(p->flow) == ALPROTO_HTTP) {
                if (pa->flags & PACKET_ALERT_FLAG_TX) {
                    have_xff_ip = HttpXFFGetIPFromTx(p->flow, pa->tx_id, xff_cfg, buffer, XFF_MAXLEN);
                } else {
                    have_xff_ip = HttpXFFGetIP(p->flow, xff_cfg, buffer, XFF_MAXLEN);
                }
            }

            if (have_xff_ip) {
                if (xff_cfg->flags & XFF_EXTRADATA) {
                    json_object_set_new(js, "xff", json_string(buffer));
                }
                else if (xff_cfg->flags & XFF_OVERWRITE) {
                    if (p->flowflags & FLOW_PKT_TOCLIENT) {
                        json_object_set(js, "dest_ip", json_string(buffer));
                    } else {
                        json_object_set(js, "src_ip", json_string(buffer));
                    }
                }
            }
        }

        OutputJSONBuffer(js, aft->file_ctx, &aft->json_buffer);
        json_object_del(js, "alert");
    }
    json_object_clear(js);
    json_decref(js);

    if ((p->flags & PKT_HAS_TAG) && (json_output_ctx->flags &
            LOG_JSON_TAGGED_PACKETS)) {
        MemBufferReset(aft->json_buffer);
        json_t *packetjs = CreateJSONHeader(p, LOG_DIR_PACKET, "packet");
        if (unlikely(packetjs != NULL)) {
            JsonPacket(p, packetjs, 0);
            OutputJSONBuffer(packetjs, aft->file_ctx, &aft->json_buffer);
            json_decref(packetjs);
        }
    }

    return TM_ECODE_OK;
}

static int AlertJsonDecoderEvent(ThreadVars *tv, JsonAlertLogThread *aft, const Packet *p)
{
    int i;
    char timebuf[64];
    json_t *js;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    CreateIsoTimeString(&p->ts, timebuf, sizeof(timebuf));

    for (i = 0; i < p->alerts.cnt; i++) {
        MemBufferReset(aft->json_buffer);

        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        const char *action = "allowed";
        if (pa->action & (ACTION_REJECT|ACTION_REJECT_DST|ACTION_REJECT_BOTH)) {
            action = "blocked";
        } else if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
            action = "blocked";
        }

        js = json_object();
        if (js == NULL)
            return TM_ECODE_OK;

        json_t *ajs = json_object();
        if (ajs == NULL) {
            json_decref(js);
            return TM_ECODE_OK;
        }

        /* time & tx */
        json_object_set_new(js, "timestamp", json_string(timebuf));

        /* tuple */
        //json_object_set_new(js, "srcip", json_string(srcip));
        //json_object_set_new(js, "sp", json_integer(p->sp));
        //json_object_set_new(js, "dstip", json_string(dstip));
        //json_object_set_new(js, "dp", json_integer(p->dp));
        //json_object_set_new(js, "proto", json_integer(proto));

        json_object_set_new(ajs, "action", json_string(action));
        json_object_set_new(ajs, "gid", json_integer(pa->s->gid));
        json_object_set_new(ajs, "signature_id", json_integer(pa->s->id));
        json_object_set_new(ajs, "rev", json_integer(pa->s->rev));
        json_object_set_new(ajs, "signature",
                            json_string((pa->s->msg) ? pa->s->msg : ""));
        json_object_set_new(ajs, "category",
                            json_string((pa->s->class_msg) ? pa->s->class_msg : ""));
        json_object_set_new(ajs, "severity", json_integer(pa->s->prio));

        if (p->tenant_id > 0)
            json_object_set_new(ajs, "tenant_id", json_integer(p->tenant_id));

        /* alert */
        json_object_set_new(js, "alert", ajs);
        OutputJSONBuffer(js, aft->file_ctx, &aft->json_buffer);
        json_object_clear(js);
        json_decref(js);
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

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonAlertLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonAlertLogThread *aft = SCMalloc(sizeof(JsonAlertLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonAlertLogThread));
    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogAlert.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->json_buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->json_buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /** Use the Output Context (file pointer and mutex) */
    AlertJsonOutputCtx *json_output_ctx = ((OutputCtx *)initdata)->data;
    aft->file_ctx = json_output_ctx->file_ctx;
    aft->json_output_ctx = json_output_ctx;

    aft->payload_buffer = MemBufferCreateNew(json_output_ctx->payload_buffer_size);
    if (aft->payload_buffer == NULL) {
        MemBufferFree(aft->json_buffer);
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonAlertLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonAlertLogThread *aft = (JsonAlertLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->json_buffer);
    MemBufferFree(aft->payload_buffer);

    /* clear memory */
    memset(aft, 0, sizeof(JsonAlertLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonAlertLogDeInitCtx(OutputCtx *output_ctx)
{
    AlertJsonOutputCtx *json_output_ctx = (AlertJsonOutputCtx *) output_ctx->data;
    if (json_output_ctx != NULL) {
        HttpXFFCfg *xff_cfg = json_output_ctx->xff_cfg;
        if (xff_cfg != NULL) {
            SCFree(xff_cfg);
        }
        LogFileFreeCtx(json_output_ctx->file_ctx);
        SCFree(json_output_ctx);
    }
    SCFree(output_ctx);
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
static OutputInitResult JsonAlertLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    AlertJsonOutputCtx *json_output_ctx = NULL;
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("AlertFastLogInitCtx2: Could not create new LogFileCtx");
        return result;
    }

    if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return result;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(logfile_ctx);
        return result;
    }

    json_output_ctx = SCMalloc(sizeof(AlertJsonOutputCtx));
    if (unlikely(json_output_ctx == NULL)) {
        LogFileFreeCtx(logfile_ctx);
        SCFree(output_ctx);
        return result;
    }
    memset(json_output_ctx, 0, sizeof(AlertJsonOutputCtx));

    json_output_ctx->file_ctx = logfile_ctx;

    JsonAlertLogSetupMetadata(json_output_ctx, conf);
    json_output_ctx->xff_cfg = JsonAlertLogGetXffCfg(conf);

    output_ctx->data = json_output_ctx;
    output_ctx->DeInit = JsonAlertLogDeInitCtx;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
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
    json_output_ctx->cfg = ajt->cfg;

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
    OutputRegisterPacketModule(LOGGER_JSON_ALERT, MODULE_NAME, "alert-json-log",
        JsonAlertLogInitCtx, JsonAlertLogger, JsonAlertLogCondition,
        JsonAlertLogThreadInit, JsonAlertLogThreadDeinit, NULL);
    OutputRegisterPacketSubModule(LOGGER_JSON_ALERT, "eve-log", MODULE_NAME,
        "eve-log.alert", JsonAlertLogInitCtxSub, JsonAlertLogger,
        JsonAlertLogCondition, JsonAlertLogThreadInit, JsonAlertLogThreadDeinit,
        NULL);
}

#else

void JsonAlertLogRegister (void)
{
}

#endif

