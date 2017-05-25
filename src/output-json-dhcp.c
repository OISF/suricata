/* Copyright (C) 2016 Open Information Security Foundation
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

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-dhcp.h"
#include "output-json-dhcp.h"

//#define PRINT

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

typedef struct LogDHCPFileCtx_ {
    LogFileCtx *file_ctx;
    bool extended;
} LogDHCPFileCtx;

typedef struct LogDHCPLogThread_ {
    LogDHCPFileCtx *dhcplog_ctx;
    uint32_t        count;
    MemBuffer       *buffer;
} LogDHCPLogThread;

static void OutputDHCPConfigure(LogDHCPFileCtx *ctx, ConfNode *conf);

static inline int JsonDHCPOptEnd(DHCPOpt *dhcp_opt)
{
    return (dhcp_opt->code == DHCP_OPT_END) ? 1 : 0;
}

static inline void JsonDHCPSetMacAddr(json_t *js, const char *name, uint8_t *ptr)
{
    char addr[6 * 3];
    snprintf(addr, sizeof(addr),
            "%02x:%02x:%02x:%02x:%02x:%02x",
            ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
    json_object_set_new(js, name, json_string(addr));
}

static inline void JsonDHCPSetIpAddr(json_t *js, const char *name, uint8_t *ptr)
{
    char addr[4 * 4];
    snprintf(addr, sizeof(addr), "%u.%u.%u.%u",
            ptr[0], ptr[1], ptr[2], ptr[3]);
    json_object_set_new(js, name, json_string(addr));
}

static inline void JsonDHCPAppendIpAddr(json_t *js, uint8_t *ptr)
{
    char addr[4 * 4];
    snprintf(addr, sizeof(addr), "%u.%u.%u.%u",
            ptr[0], ptr[1], ptr[2], ptr[3]);
    json_array_append_new(js, json_string(addr));
}

static inline void JsonDHCPSetUint32(json_t *js, const char *name, uint8_t *ptr)
{
    uint32_t value = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
    json_object_set_new(js, name, json_integer(value));
}

/**
 * \brief Add the request parameters to an array named "params".
 */
static void JsonDHCPLogParams(json_t *js, DHCPOpt *opt)
{
    json_t *parmsjs = json_array();
    if (unlikely(parmsjs == NULL)) {
        return;
    }

    for (uint8_t i = 0; i < opt->len; i++) {
        switch (opt->args[i]) {
            case DHCP_PARAM_SUBNET_MASK:
                json_array_append_new(parmsjs,
                        json_string("subnet_mask"));
                break;
            case DHCP_PARAM_ROUTER:
                json_array_append_new(parmsjs,
                        json_string("router"));
                break;
            case DHCP_PARAM_DNS_SERVER:
                json_array_append_new(parmsjs,
                        json_string("dns_server"));
                break;
            case DHCP_PARAM_DOMAIN:
                json_array_append_new(parmsjs,
                        json_string("domain"));
                break;
            case DHCP_PARAM_ARP_TIMEOUT:
                json_array_append_new(parmsjs,
                        json_string("arp_timeout"));
                break;
            case DHCP_PARAM_NTP_SERVER:
                json_array_append_new(parmsjs,
                        json_string("ntp_server"));
                break;
            case DHCP_PARAM_TFTP_SERVER_NAME:
                json_array_append_new(parmsjs,
                        json_string("tftp_server_name"));
                break;
            case DHCP_PARAM_TFTP_SERVER_IP:
                json_array_append_new(parmsjs,
                        json_string("tftp_server_ip"));
                break;
        }
    }
    json_object_set_new(js, "params", parmsjs);
}

static void JsonDHCPLogRequest(json_t *js, DHCPTransaction *tx, bool extended)
{
    DHCPOpt *dhcp_opt;
    uint32_t offset, option_size;
    json_t *reqjs = NULL;
    uint8_t request_type = 0;

    if (tx->request_buffer == NULL || tx->request_buffer_len == 0) {
        return;
    }

    if (extended) {
        reqjs = json_object();
        if (unlikely(reqjs == NULL)) {
            return;
        }
    }

    for (offset = 0; offset <= tx->request_buffer_len; offset += option_size) {

        if (tx->request_buffer_len - offset < sizeof(DHCPOpt)) {
            break;
        }

        dhcp_opt = (DHCPOpt *)&tx->request_buffer[offset];

        if (unlikely(JsonDHCPOptEnd(dhcp_opt) == 0)) {
            option_size = offsetof(DHCPOpt, args) + dhcp_opt->len;
            if (offset + option_size > tx->request_buffer_len) {
                break;
            }
        } else {
            option_size = offsetof(DHCPOpt, len);
        }

        /* First handle options that are logged in normal and extended
         * modes. */
        switch (dhcp_opt->code) {
            case DHCP_OPT_TYPE:
                request_type = dhcp_opt->args[0];
                break;
            case DHCP_OPT_HOSTNAME:
                if (dhcp_opt->len) {
                    char *val = BytesToString(dhcp_opt->args, dhcp_opt->len);
                    if (val != NULL) {
                        json_object_set_new(js, "hostname", json_string(val));
                        if (extended) {
                            json_object_set_new(reqjs, "hostname",
                                    json_string(val));
                        }
                        SCFree(val);
                    }
                }
                break;
            case DHCP_OPT_CLIENT_ID:
                if ((option_size - offsetof(DHCPOpt, args) > 1) &&
                    (dhcp_opt->args[0] == BOOTP_ETHERNET)) {
                     if (option_size - offsetof(DHCPOpt, args) >= 7) {
                         JsonDHCPSetMacAddr(js, "client_id", &dhcp_opt->args[1]);
                         if (extended) {
                             JsonDHCPSetMacAddr(reqjs, "client_id",
                                     &dhcp_opt->args[1]);
                         }
                    }
                }
                break;
            default:
                break;
        }

        if (!extended) {
            continue;
        }

        switch (dhcp_opt->code) {
            case DHCP_OPT_TYPE: {
                request_type = dhcp_opt->args[0];
                const char *s = "";
                switch (request_type) {
                    case DHCP_DISCOVER:
                        s = "discover";
                        break;
                    case DHCP_REQUEST:
                        s = "request";
                        break;
                    case DHCP_INFORM:
                        s = "inform";
                        break;
                    case DHCP_RELEASE:
                        s = "release";
                        break;
                    case DHCP_DECLINE:
                        s = "decline";
                        break;
                }
                json_object_set_new(reqjs, "type", json_string(s));
                if (request_type == DHCP_INFORM) {
                    JsonDHCPSetIpAddr(reqjs, "client_ip",
                            tx->request_client_ip_bytes);
                }
            }
                break;
            case DHCP_OPT_VENDOR_CLASS:
                if (dhcp_opt->len) {
                    char *val = BytesToString(dhcp_opt->args, dhcp_opt->len);
                    if (val != NULL) {
                        json_object_set_new(reqjs, "vendor_class",
                                json_string(val));
                        SCFree(val);
                    }
                }
                break;
            case DHCP_OPT_REQUESTED_IP:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    JsonDHCPSetIpAddr(reqjs, "requested_ip", dhcp_opt->args);
                }
                break;
            case DHCP_OPT_SERVER_ID:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    JsonDHCPSetIpAddr(reqjs, "server_ip", dhcp_opt->args);
                }
                break;
            case DHCP_OPT_PARAM_REQ_LIST:
                JsonDHCPLogParams(reqjs, dhcp_opt);
                break;
            default:
                break;
        }

    }

    if (extended) {
        json_object_set_new(js, "request", reqjs);
    }
}

static void JsonDHCPLogResponse(json_t *js, DHCPTransaction *tx, bool extended)
{
    DHCPOpt *dhcp_opt;
    uint32_t offset, option_size;
    json_t *rspjs = NULL;

    if (tx->response_buffer == NULL || tx->response_buffer_len == 0) {
        return;
    }

    if (extended) {
        rspjs = json_object();
        if (unlikely(rspjs == NULL)) {
            return;
        }
    }

    for (offset = 0; offset <= tx->response_buffer_len; offset += option_size) {

        if (tx->response_buffer_len - offset < sizeof(DHCPOpt)) {
            break;
        }

        dhcp_opt = (DHCPOpt *)&tx->response_buffer[offset];

        if (unlikely(JsonDHCPOptEnd(dhcp_opt) == 0)) {
            option_size = offsetof(DHCPOpt, args) + dhcp_opt->len;
            if (offset + option_size > tx->response_buffer_len) {
                break;
            }
        } else {
            option_size = offsetof(DHCPOpt, len);
        }

        /* First handle options that are logged in normal and extended. */
        switch (dhcp_opt->code) {
            case DHCP_OPT_TYPE:
                if (dhcp_opt->args[0] == DHCP_ACK) {
                    JsonDHCPSetIpAddr(js, "client_ip",
                            tx->response_client_ip_bytes);
                }
                break;
            case DHCP_OPT_IP_LEASE_TIME:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    JsonDHCPSetUint32(js, "lease_time", dhcp_opt->args);
                }

                /* If not doing extended logging now, we can get out
                 * of this loop now. */
                if (!extended) {
                    goto end;
                }
                break;
            default:
                break;
        }

        if (!extended) {
            continue;
        }

        switch (dhcp_opt->code) {
            case DHCP_OPT_TYPE: {
                const char *s = "";
                switch (dhcp_opt->args[0]) {
                    case DHCP_OFFER:
                        s = "offer";
                        break;
                    case DHCP_ACK:
                        s = "ack";
                        break;
                    case DHCP_NACK:
                        s = "nak";
                        break;
                }
                json_object_set_new(rspjs, "type", json_string(s));

                /* purposely placed here to place in metadata after "type" */
                if (dhcp_opt->args[0] == DHCP_ACK) {
                    JsonDHCPSetIpAddr(rspjs, "client_ip",
                            tx->response_client_ip_bytes);
                }
            }
                break;
            case DHCP_OPT_ROUTER_IP:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    size_t off = offsetof(DHCPOpt, args);
                    uint8_t *ptr = dhcp_opt->args;
                    json_t *js_addrs = json_array();
                    while (option_size - off >= 4) {
                        JsonDHCPAppendIpAddr(js_addrs, ptr);
                        off += 4;
                        ptr += 4;
                    }
                    json_object_set_new(rspjs, "routers", js_addrs);
                }
                break;
            case DHCP_OPT_DNS_IP:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    size_t off = offsetof(DHCPOpt, args);
                    uint8_t *ptr = dhcp_opt->args;
                    json_t *js_addrs = json_array();
                    while (option_size - off >= 4) {
                        JsonDHCPAppendIpAddr(js_addrs, ptr);
                        off += 4;
                        ptr += 4;
                    }
                    json_object_set_new(rspjs, "dns", js_addrs);
                }
                break;
            case DHCP_OPT_TFTP_IP:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    JsonDHCPSetIpAddr(rspjs, "tftp_ip", dhcp_opt->args);
                }
                break;
            case DHCP_OPT_IP_RENEWAL_TIME:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    JsonDHCPSetUint32(rspjs, "renewal_time", dhcp_opt->args);
                }
                break;
            case DHCP_OPT_IP_REBINDING_TIME:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    JsonDHCPSetUint32(rspjs, "rebinding_time", dhcp_opt->args);
                }
                break;
            case DHCP_OPT_IP_LEASE_TIME:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    JsonDHCPSetUint32(rspjs, "lease_time", dhcp_opt->args);
                }
                break;
            case DHCP_OPT_SERVER_ID:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    JsonDHCPSetIpAddr(rspjs, "server_ip", dhcp_opt->args);
                }
                break;
            case DHCP_OPT_SUBNET_MASK:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    JsonDHCPSetIpAddr(rspjs, "subnet_mask", dhcp_opt->args);
                }
                break;
            case DHCP_OPT_END:
                break;
            default:
                break;
        }
    }

end:
    if (extended) {
        json_object_set_new(js, "response", rspjs);
    }
}

static int JsonDHCPLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    DHCPTransaction *dhcptx = tx;
    LogDHCPLogThread *thread = thread_data;
    DHCPGlobalState *dhcpState = ((DHCPState *)state)->global;
    MemBuffer *buffer = thread->buffer;
    json_t *js = NULL, *dhcpjs = NULL;
    bool extended = thread->dhcplog_ctx->extended;

    SCLogDebug("Logging DHCP transaction %"PRIu64".", dhcptx->tx_id);
    if (dhcpState->log_id > tx_id) {
        SCLogDebug("Already logged DHCP transaction %"PRIu64".", dhcptx->tx_id);
        return TM_ECODE_OK;
    }
    if (dhcptx->logged) {
        SCLogDebug("Already logged DHCP transaction %"PRIu64".", dhcptx->tx_id);
        return TM_ECODE_OK;
    }
    if (unlikely(dhcptx->request_buffer == NULL)) {
        if (unlikely((dhcptx->response_unneeded == 0) &&
                     (dhcptx->response_buffer == NULL))) {
            goto error;
        }
    }

    js = CreateJSONHeader(p,
            dhcptx->reverse_flow ? DIRECTION_REVERSE : DIRECTION_PACKET,
            "dhcp");
    if (unlikely(js == NULL)) {
        goto error;
    }

    dhcpjs = json_object();
    if (unlikely(dhcpjs == NULL)) {
        goto error;
    }

    JsonDHCPLogRequest(dhcpjs, dhcptx, extended);

    if (dhcptx->response_unneeded == 0) {
        JsonDHCPLogResponse(dhcpjs, dhcptx, extended);
    }

    dhcptx->logged = 1;
    json_object_set_new(dhcpjs, "id", json_integer(ntohl(dhcptx->xid)));
    json_object_set_new(js, "dhcp", dhcpjs);

    MemBufferReset(buffer);
    OutputJSONBuffer(js, thread->dhcplog_ctx->file_ctx, &thread->buffer);

#ifdef PRINT
    char *js_s = json_dumps(js, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII|JSON_ESCAPE_SLASH);
    printf("%s\n", js_s);
    free(js_s);
#endif

    json_object_clear(js);
    json_decref(js);

    dhcpState->log_id++;

    return TM_ECODE_OK;

error:
    if (dhcpjs != NULL) {
        json_decref(dhcpjs);
    }
    if (js != NULL) {
        json_decref(js);
    }
    return TM_ECODE_FAILED;
}

static void OutputDHCPLogDeInitCtx(OutputCtx *output_ctx)
{
    LogDHCPFileCtx *dhcplog_ctx = (LogDHCPFileCtx *)output_ctx->data;
    if (dhcplog_ctx != NULL) {
        LogFileFreeCtx(dhcplog_ctx->file_ctx);
        SCFree(dhcplog_ctx);
    }
    SCFree(output_ctx);
}

static void OutputDHCPLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogDHCPFileCtx *dhcplog_ctx = (LogDHCPFileCtx *)output_ctx->data;
    if (dhcplog_ctx != NULL) {
        SCFree(dhcplog_ctx);
    }
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "dhcp.json"
static OutputCtx *OutputDHCPLogInit(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_SMTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogDHCPFileCtx *dhcp_ctx = SCCalloc(1, sizeof(*dhcp_ctx));
    if (unlikely(dhcp_ctx == NULL)) {
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dhcp_ctx);
        return NULL;
    }
    dhcp_ctx->file_ctx = file_ctx;

    output_ctx->data = dhcp_ctx;
    output_ctx->DeInit = OutputDHCPLogDeInitCtx;

    OutputDHCPConfigure(dhcp_ctx, conf);

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DHCP);

    return output_ctx;
}

static OutputCtx *OutputDHCPLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputJsonCtx *ojc = parent_ctx->data;

    LogDHCPFileCtx *dhcplog_ctx = SCCalloc(1, sizeof(*dhcplog_ctx));
    if (unlikely(dhcplog_ctx == NULL)) {
        return NULL;
    }
    dhcplog_ctx->file_ctx = ojc->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dhcplog_ctx);
        return NULL;
    }
    output_ctx->data = dhcplog_ctx;
    output_ctx->DeInit = OutputDHCPLogDeInitCtxSub;

    OutputDHCPConfigure(dhcplog_ctx, conf);

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DHCP);

    return output_ctx;
}

static void OutputDHCPConfigure(LogDHCPFileCtx *ctx, ConfNode *conf)
{
    int extended = 0;

    if (ConfGetChildValueBool(conf, "extended", &extended)) {
        ctx->extended = true ? extended : false;
    }
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonDHCPLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDHCPLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for DHCP.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->dhcplog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonDHCPLogThreadDeinit(ThreadVars *t, void *data)
{
    LogDHCPLogThread *thread = (LogDHCPLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonDHCPLogRegister(void)
{
    /* register as separate module */
    OutputRegisterTxModule(LOGGER_JSON_DHCP, "JsonDHCPLog", "dhcp-json-log",
        OutputDHCPLogInit, ALPROTO_DHCP, JsonDHCPLogger, JsonDHCPLogThreadInit,
        JsonDHCPLogThreadDeinit, NULL);

    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_DHCP, "eve-log", "JsonDHCPLog",
        "eve-log.dhcp", OutputDHCPLogInitSub, ALPROTO_DHCP, JsonDHCPLogger,
        JsonDHCPLogThreadInit, JsonDHCPLogThreadDeinit, NULL);
}

#else /* No JSON support. */

void JsonDHCPLogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON */
