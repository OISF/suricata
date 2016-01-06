/* Copyright (C) 2015 Open Information Security Foundation
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

//#define PRINT

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

typedef struct LogDHCPFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogDHCPFileCtx;

typedef struct LogDHCPLogThread_ {
    LogDHCPFileCtx *dhcplog_ctx;
    uint32_t        count;
    MemBuffer       *buffer;
} LogDHCPLogThread;

static inline int JsonDHCPOptEnd(DHCPOpt *dhcp_opt)
{
    return (dhcp_opt->code == DHCP_OPT_END) ? 1 : 0;
}

static int JsonDHCPLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    DHCPTransaction *dhcptx = tx;
    LogDHCPLogThread *thread = thread_data;
    DHCPState *dhcpState = state;
    MemBuffer *buffer = thread->buffer;
    json_t *js = NULL, *dhcpjs = NULL, *reqjs = NULL, *rspjs = NULL;
    uint8_t request_type = 0;

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
    
    js = CreateJSONHeader((Packet *)p, 0, "dhcp");
    if (unlikely(js == NULL)) {
        goto error;
    }

    dhcpjs = json_object();
    if (unlikely(dhcpjs == NULL)) {
        goto error;
    }
    reqjs = json_object();
    if (unlikely(reqjs == NULL)) {
        goto error;
    }
    if (dhcptx->response_unneeded == 0) {
        rspjs = json_object();
        if (unlikely(rspjs == NULL)) {
            goto error;
        }
    }

    uint32_t offset, option_size;
    DHCPOpt *dhcp_opt = (DHCPOpt *)dhcptx->request_buffer;
    for (offset = 0;
         JsonDHCPOptEnd(dhcp_opt) == 0 && offset <= dhcptx->request_buffer_len;
         offset += option_size) {

        dhcp_opt = (DHCPOpt *)&dhcptx->request_buffer[offset];

        if (unlikely(JsonDHCPOptEnd(dhcp_opt) == 0)) {
            option_size = offsetof(DHCPOpt, args) + dhcp_opt->len;
            if (offset + option_size > dhcptx->request_buffer_len) {
                goto error;
            }
        } else {
            option_size = offsetof(DHCPOpt, len);
        }

        switch (dhcp_opt->code) {
            case DHCP_OPT_TYPE: {
                char *s = "";
                request_type = dhcp_opt->args[0];
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
                    char ipaddr[4*4+1];
                    snprintf(ipaddr, sizeof(ipaddr),
                                     "%d.%d.%d.%d",
                                     dhcptx->request_client_ip_bytes[0],
                                     dhcptx->request_client_ip_bytes[1],
                                     dhcptx->request_client_ip_bytes[2],
                                     dhcptx->request_client_ip_bytes[3]);
                    json_object_set_new(reqjs, "client_ip", json_string(ipaddr));
                }
                }
                break;
            case DHCP_OPT_HOSTNAME: {
                char *s = BytesToString(dhcp_opt->args, dhcp_opt->len);
                json_object_set_new(reqjs, "host_name", json_string(s));
                SCFree(s);
                }
                break;
            case DHCP_OPT_VENDOR_CLASS: {
                char *s = BytesToString(dhcp_opt->args, dhcp_opt->len);
                json_object_set_new(reqjs, "vendor_class", json_string(s));
                SCFree(s);
                }
                break;
            case DHCP_OPT_CLIENT_ID:
                if ((option_size - offsetof(DHCPOpt, args) > 1) &&
                    (dhcp_opt->args[0] == BOOTP_ETHERNET)) {

                     if (option_size - offsetof(DHCPOpt, args) >= 7) {
                         char macaddr[6*3+1];
                         snprintf(macaddr, sizeof(macaddr),
                                  "%02x:%02x:%02x:%02x:%02x:%02x",
                                  dhcp_opt->args[1],
                                  dhcp_opt->args[2],
                                  dhcp_opt->args[3],
                                  dhcp_opt->args[4],
                                  dhcp_opt->args[5],
                                  dhcp_opt->args[6]);
                         json_object_set_new(reqjs, "client_id",
                                             json_string(macaddr));
                    }
                }
                break;
            case DHCP_OPT_REQUESTED_IP:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    char ipaddr[4*4+1];
                    snprintf(ipaddr, sizeof(ipaddr),
                             "%d.%d.%d.%d",
                             dhcp_opt->args[0],
                             dhcp_opt->args[1],
                             dhcp_opt->args[2],
                             dhcp_opt->args[3]);
                    json_object_set_new(reqjs, "client_ip",
                                        json_string(ipaddr));
                }
                break;
            case DHCP_OPT_SERVER_ID:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    char ipaddr[4*4+1];
                    snprintf(ipaddr, sizeof(ipaddr),
                             "%d.%d.%d.%d",
                             dhcp_opt->args[0],
                             dhcp_opt->args[1],
                             dhcp_opt->args[2],
                             dhcp_opt->args[3]);
                    json_object_set_new(reqjs, "server_ip",
                                        json_string(ipaddr));
                }
                break;
            case DHCP_OPT_PARAM_REQ_LIST: {
                json_t *parmsjs = json_array();
                if (likely(parmsjs != NULL)) {
                    uint8_t i;
                    for (i = 0; i < dhcp_opt->len; i++) {
                        switch (dhcp_opt->args[i]) {
                            case DHCP_PARAM_SUBNET_MASK:
                                 json_array_append(parmsjs, json_string("subnet_mask"));
                                 break;
                            case DHCP_PARAM_ROUTER:
                                 json_array_append(parmsjs, json_string("router"));
                                 break;
                            case DHCP_PARAM_DNS_SERVER:
                                 json_array_append(parmsjs, json_string("dns_server"));
                                 break;
                            case DHCP_PARAM_DOMAIN:
                                 json_array_append(parmsjs, json_string("domain"));
                                 break;
                            case DHCP_PARAM_ARP_TIMEOUT:
                                 json_array_append(parmsjs, json_string("arp_timeout"));
                                 break;
                            case DHCP_PARAM_NTP_SERVER:
                                 json_array_append(parmsjs, json_string("ntp_server"));
                                 break;
                            case DHCP_PARAM_TFTP_SERVER_NAME:
                                 json_array_append(parmsjs, json_string("tftp_server_name"));
                                 break;
                            case DHCP_PARAM_TFTP_SERVER_IP:
                                 json_array_append(parmsjs, json_string("tftp_server_ip"));
                                 break;
                        }
                    }
                    json_object_set_new(reqjs, "params", parmsjs);
                }
                }
                break;
            case DHCP_OPT_END:
                break;
        }
    }

    if (dhcptx->response_unneeded == 0) {
    dhcp_opt = (DHCPOpt *)dhcptx->response_buffer;
    for (offset = 0;
         JsonDHCPOptEnd(dhcp_opt) == 0 && offset <= dhcptx->response_buffer_len;
         offset += option_size) {

        dhcp_opt = (DHCPOpt *)&dhcptx->response_buffer[offset];

        if (unlikely(JsonDHCPOptEnd(dhcp_opt) == 0)) {
            option_size = offsetof(DHCPOpt, args) + dhcp_opt->len;
            if (offset + option_size > dhcptx->response_buffer_len) {
                goto error;
            }
        } else {
            option_size = offsetof(DHCPOpt, len);
        }

        switch (dhcp_opt->code) {
            case DHCP_OPT_TYPE: {
                char *s = "";
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
                if ((request_type == DHCP_REQUEST) &&
                    (dhcp_opt->args[0] == DHCP_ACK)) {
                    char ipaddr[4*4+1];
                    snprintf(ipaddr, sizeof(ipaddr),
                                     "%d.%d.%d.%d",
                                     dhcptx->response_client_ip_bytes[0],
                                     dhcptx->response_client_ip_bytes[1],
                                     dhcptx->response_client_ip_bytes[2],
                                     dhcptx->response_client_ip_bytes[3]);
                    json_object_set_new(rspjs, "client_ip", json_string(ipaddr));
                }
                }
                break;
            case DHCP_OPT_ROUTER_IP:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    char ipaddr[4*4+1];
                    snprintf(ipaddr, sizeof(ipaddr),
                             "%d.%d.%d.%d",
                             dhcp_opt->args[0],
                             dhcp_opt->args[1],
                             dhcp_opt->args[2],
                             dhcp_opt->args[3]);
                    json_object_set_new(rspjs, "router_ip",
                                        json_string(ipaddr));
                }
                break;
            case DHCP_OPT_DNS_IP:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    char ipaddr[4*4+1];
                    snprintf(ipaddr, sizeof(ipaddr),
                             "%d.%d.%d.%d",
                             dhcp_opt->args[0],
                             dhcp_opt->args[1],
                             dhcp_opt->args[2],
                             dhcp_opt->args[3]);
                    json_object_set_new(rspjs, "dns_ip", json_string(ipaddr));
                }
                break;
            case DHCP_OPT_TFTP_IP:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    char ipaddr[4*4+1];
                    snprintf(ipaddr, sizeof(ipaddr),
                             "%d.%d.%d.%d",
                             dhcp_opt->args[0],
                             dhcp_opt->args[1],
                             dhcp_opt->args[2],
                             dhcp_opt->args[3]);
                    json_object_set_new(rspjs, "tftp_ip", json_string(ipaddr));
                }
                break;
            case DHCP_OPT_IP_RENEWAL_TIME:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    json_object_set_new(rspjs, "renewal_time",
                                        json_integer((int)dhcp_opt->args[0]<<24|
                                                     (int)dhcp_opt->args[1]<<16|
                                                     (int)dhcp_opt->args[2]<<8|
                                                     (int)dhcp_opt->args[3]));
                }
                break;
            case DHCP_OPT_IP_REBINDING_TIME:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    json_object_set_new(rspjs, "rebinding_time",
                                        json_integer((int)dhcp_opt->args[0]<<24|
                                                     (int)dhcp_opt->args[1]<<16|
                                                     (int)dhcp_opt->args[2]<<8|
                                                     (int)dhcp_opt->args[3]));
                }
                break;
            case DHCP_OPT_IP_LEASE_TIME:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    json_object_set_new(rspjs, "lease_time",
                                        json_integer((int)dhcp_opt->args[0]<<24|
                                                     (int)dhcp_opt->args[1]<<16|
                                                     (int)dhcp_opt->args[2]<<8|
                                                     (int)dhcp_opt->args[3]));
                }
                break;
            case DHCP_OPT_SERVER_ID:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    char ipaddr[4*4+1];
                    snprintf(ipaddr, sizeof(ipaddr),
                             "%d.%d.%d.%d",
                             dhcp_opt->args[0],
                             dhcp_opt->args[1],
                             dhcp_opt->args[2],
                             dhcp_opt->args[3]);
                    json_object_set_new(rspjs, "server_ip", json_string(ipaddr));
                }
                break;
            case DHCP_OPT_SUBNET_MASK:
                if (option_size - offsetof(DHCPOpt, args) >= 4) {
                    char mask[4*4+1];
                    snprintf(mask, sizeof(mask),
                             "%d.%d.%d.%d",
                             dhcp_opt->args[0],
                             dhcp_opt->args[1],
                             dhcp_opt->args[2],
                             dhcp_opt->args[3]);
                    json_object_set_new(rspjs, "subnet_mask", json_string(mask));
                }
                break;
            case DHCP_OPT_END:
                break;
        }
    }
    }

    dhcptx->logged = 1;
    json_object_set_new(dhcpjs, "id", json_integer(ntohl(dhcptx->xid)));
    /* match wireshark
    * char buf[16];
    * sprintf(buf, "0x%x", ntohl(dhcptx->xid));
    * json_object_set_new(dhcpjs, "xid", json_string(buf));
    */
    json_object_set_new(dhcpjs, "request", reqjs);
    if (dhcptx->response_unneeded == 0) {
        json_object_set_new(dhcpjs, "response", rspjs);
    }
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
    if (rspjs != NULL) {
        json_decref(rspjs);
    }
    if (reqjs != NULL) {
        json_decref(reqjs);
    }
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

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DHCP);

    return output_ctx;
}

static OutputCtx *OutputDHCPLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
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

    SCLogNotice("dhcp log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DHCP);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonDHCPLogThreadInit(ThreadVars *t, void *initdata, void **data)
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
