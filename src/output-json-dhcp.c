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

typedef struct LogdhcpFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogdhcpFileCtx;

typedef struct LogdhcpLogThread_ {
    LogdhcpFileCtx *dhcplog_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogdhcpLogThread;

static int JsondhcpLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    dhcpTransaction *dhcptx = tx;
    LogdhcpLogThread *thread = thread_data;
    dhcpState *dhcpState = state;
    json_t *js, *dhcpjs;

    SCLogDebug("Logging dhcp transaction %"PRIu64".", dhcptx->tx_id);
    if (dhcpState->log_id > tx_id) {
        SCLogDebug("Already logged dhcp transaction %"PRIu64".", dhcptx->tx_id);
        return TM_ECODE_OK;
    }
    if (dhcptx->logged) {
        SCLogDebug("Already logged dhcp transaction %"PRIu64".", dhcptx->tx_id);
        return TM_ECODE_OK;
    }
    
    js = CreateJSONHeader((Packet *)p, 0, "dhcp");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    dhcpjs = json_object();
    if (unlikely(dhcpjs == NULL)) {
        goto error;
    }
    json_t *reqjs = json_object();
    if (unlikely(reqjs == NULL)) {
        goto error;
    }
    json_t *rspjs = json_object();
    if (unlikely(rspjs == NULL)) {
        goto error;
    }

    uint32_t offset;
    /* TBD: harden this loop against bad len values */
    DHCPOpt *dhcp_opt = (DHCPOpt *)dhcptx->request_buffer;
    for (offset = 0; offset < dhcptx->request_buffer_len; offset += (2 + dhcp_opt->len)) {
        dhcp_opt = (DHCPOpt *)&dhcptx->request_buffer[offset];
        switch (dhcp_opt->code) {
            case 53: {
                char *s = "";
                switch (dhcp_opt->args[0]) {
                    case 3:
                        s = "request";
                        break;
                    case 8:
                        s = "inform";
                        break;
                }
                json_object_set_new(reqjs, "type", json_string(s));
                }
                break;
            case 12: {
                char *s = BytesToString(dhcp_opt->args, dhcp_opt->len);
                json_object_set_new(reqjs, "host_name", json_string(s));
                SCFree(s);
                }
                break;
            case 60: {
                char *s = BytesToString(dhcp_opt->args, dhcp_opt->len);
                json_object_set_new(reqjs, "vendor_class", json_string(s));
                SCFree(s);
                }
                break;
            case 61: {
                if (dhcp_opt->args[0] == 1) {
                char macaddr[6*3+1];
                sprintf(macaddr, "%02x:%02x:%02x:%02x:%02x:%02x",
                         dhcp_opt->args[1],
                         dhcp_opt->args[2],
                         dhcp_opt->args[3],
                         dhcp_opt->args[4],
                         dhcp_opt->args[5],
                         dhcp_opt->args[6]);
                json_object_set_new(reqjs, "client_id", json_string(macaddr));
                }
                }
                break;
            case 50: {
                char ipaddr[4*4+1];
                sprintf(ipaddr, "%d.%d.%d.%d",
                        dhcp_opt->args[0],
                        dhcp_opt->args[1],
                        dhcp_opt->args[2],
                        dhcp_opt->args[3]);
                json_object_set_new(reqjs, "client_ip", json_string(ipaddr));
                }
                break;
            case 54: {
                char ipaddr[4*4+1];
                sprintf(ipaddr, "%d.%d.%d.%d",
                        dhcp_opt->args[0],
                        dhcp_opt->args[1],
                        dhcp_opt->args[2],
                        dhcp_opt->args[3]);
                json_object_set_new(reqjs, "server_ip", json_string(ipaddr));
                }
                break;
            case 55: {
                json_t *parmsjs = json_array();
                if (likely(parmsjs != NULL)) {
                    uint8_t i;
                    for (i = 0; i < dhcp_opt->len; i++) {
                        switch (dhcp_opt->args[i]) {
                            case 1:
                                 json_array_append(parmsjs, json_string("subnet_mask"));
                                 break;
                            case 3:
                                 json_array_append(parmsjs, json_string("router"));
                                 break;
                            case 6:
                                 json_array_append(parmsjs, json_string("dns_server"));
                                 break;
                            case 15:
                                 json_array_append(parmsjs, json_string("domain"));
                                 break;
                            case 35:
                                 json_array_append(parmsjs, json_string("arp_timeout"));
                                 break;
                            case 42:
                                 json_array_append(parmsjs, json_string("ntp_server"));
                                 break;
                            case 66:
                                 json_array_append(parmsjs, json_string("tftp_server_name"));
                                 break;
                            case 150:
                                 json_array_append(parmsjs, json_string("tftp_server_ip"));
                                 break;
                        }
                    }
                    json_object_set_new(reqjs, "params", parmsjs);
                }
                }
                break;
        }
    }
    /* TBD: harden this loop against bad len values */
    dhcp_opt = (DHCPOpt *)dhcptx->response_buffer;
    for (offset = 0; offset < dhcptx->response_buffer_len; offset += (2 + dhcp_opt->len)) {
        dhcp_opt = (DHCPOpt *)&dhcptx->response_buffer[offset];
        switch (dhcp_opt->code) {
            case 53: {
                char *s = "";
                switch (dhcp_opt->args[0]) {
                    case 5:
                        s = "ack";
                        break;
                    case 6:
                        s = "nak";
                        break;
                }
                json_object_set_new(rspjs, "type", json_string(s));
                }
                break;
            case 3: {
                char ipaddr[4*4+1];
                sprintf(ipaddr, "%d.%d.%d.%d",
                        dhcp_opt->args[0],
                        dhcp_opt->args[1],
                        dhcp_opt->args[2],
                        dhcp_opt->args[3]);
                json_object_set_new(rspjs, "router_ip", json_string(ipaddr));
                }
                break;
            case 6: {
                char ipaddr[4*4+1];
                sprintf(ipaddr, "%d.%d.%d.%d",
                        dhcp_opt->args[0],
                        dhcp_opt->args[1],
                        dhcp_opt->args[2],
                        dhcp_opt->args[3]);
                json_object_set_new(rspjs, "dns_ip", json_string(ipaddr));
                }
                break;
            case 66: {
                char ipaddr[4*4+1];
                sprintf(ipaddr, "%d.%d.%d.%d",
                        dhcp_opt->args[0],
                        dhcp_opt->args[1],
                        dhcp_opt->args[2],
                        dhcp_opt->args[3]);
                json_object_set_new(rspjs, "tftp_ip", json_string(ipaddr));
                }
                break;
            case 58:
                json_object_set_new(rspjs, "renewal_time",
                                    json_integer((int)dhcp_opt->args[0]<<24|
                                                 (int)dhcp_opt->args[1]<<16|
                                                 (int)dhcp_opt->args[2]<<8|
                                                 (int)dhcp_opt->args[3]));
                break;
            case 59:
                json_object_set_new(rspjs, "rebinding_time",
                                    json_integer((int)dhcp_opt->args[0]<<24|
                                                 (int)dhcp_opt->args[1]<<16|
                                                 (int)dhcp_opt->args[2]<<8|
                                                 (int)dhcp_opt->args[3]));
                break;
            case 51:
                json_object_set_new(rspjs, "lease_time",
                                    json_integer((int)dhcp_opt->args[0]<<24|
                                                 (int)dhcp_opt->args[1]<<16|
                                                 (int)dhcp_opt->args[2]<<8|
                                                 (int)dhcp_opt->args[3]));
                break;
            case 54: {
                char ipaddr[4*4+1];
                sprintf(ipaddr, "%d.%d.%d.%d",
                        dhcp_opt->args[0],
                        dhcp_opt->args[1],
                        dhcp_opt->args[2],
                        dhcp_opt->args[3]);
                json_object_set_new(rspjs, "server_ip", json_string(ipaddr));
                }
                break;
            case 1: {
                char mask[4*4+1];
                sprintf(mask, "%d.%d.%d.%d",
                        dhcp_opt->args[0],
                        dhcp_opt->args[1],
                        dhcp_opt->args[2],
                        dhcp_opt->args[3]);
                json_object_set_new(rspjs, "subnet_mask", json_string(mask));
                }
                break;
        }
    }

    dhcptx->logged = 1;
    json_object_set_new(dhcpjs, "xid", json_integer(ntohl(dhcptx->xid)));
    /* match wireshark
    * char buf[16];
    * sprintf(buf, "0x%x", ntohl(dhcptx->xid));
    * json_object_set_new(dhcpjs, "xid", json_string(buf));
    */
    json_object_set_new(dhcpjs, "client", reqjs);
    json_object_set_new(dhcpjs, "server", rspjs);
    json_object_set_new(js, "dhcp", dhcpjs);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->dhcplog_ctx->file_ctx, &thread->buffer);

#ifdef PRINT
    char *js_s = json_dumps(js, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII|JSON_ESCAPE_SLASH);
    printf("%s\n", js_s);
    free(js_s);
#endif

    json_decref(js);

    dhcpState->log_id++;

    return TM_ECODE_OK;
    
error:
    if (dhcpjs != NULL) {
        json_decref(dhcpjs);
    }
    json_decref(js);
    return TM_ECODE_FAILED;
}

static void OutputdhcpLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogdhcpFileCtx *dhcplog_ctx = (LogdhcpFileCtx *)output_ctx->data;
    SCFree(dhcplog_ctx);
    SCFree(output_ctx);
}

static OutputCtx *OutputdhcpLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    LogdhcpFileCtx *dhcplog_ctx = SCCalloc(1, sizeof(*dhcplog_ctx));
    if (unlikely(dhcplog_ctx == NULL)) {
        return NULL;
    }
    dhcplog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dhcplog_ctx);
        return NULL;
    }
    output_ctx->data = dhcplog_ctx;
    output_ctx->DeInit = OutputdhcpLogDeInitCtxSub;

    SCLogNotice("dhcp log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DHCP);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsondhcpLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogdhcpLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for dhcp.  \"initdata\" is NULL.");
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

static TmEcode JsondhcpLogThreadDeinit(ThreadVars *t, void *data)
{
    LogdhcpLogThread *thread = (LogdhcpLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void TmModuleJsondhcpLogRegister(void)
{
    if (ConfGetNode("app-layer.protocols.dhcp") == NULL) {
        return;
    }

    tmm_modules[TMM_JSONDHCPLOG].name = "JsondhcpLog";
    tmm_modules[TMM_JSONDHCPLOG].ThreadInit = JsondhcpLogThreadInit;
    tmm_modules[TMM_JSONDHCPLOG].ThreadDeinit = JsondhcpLogThreadDeinit;
    tmm_modules[TMM_JSONDHCPLOG].RegisterTests = NULL;
    tmm_modules[TMM_JSONDHCPLOG].cap_flags = 0;
    tmm_modules[TMM_JSONDHCPLOG].flags = TM_FLAG_LOGAPI_TM;

    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule("eve-log", "JsondhcpLog", "eve-log.dhcp",
        OutputdhcpLogInitSub, ALPROTO_DHCP, JsondhcpLogger);

    SCLogNotice("dhcp JSON logger registered.");
}

#else /* No JSON support. */

static TmEcode JsondhcpLogThreadInit(ThreadVars *t, void *initdata,
    void **data)
{
    SCLogInfo("Cannot initialize JSON output for dhcp. "
        "JSON support was disabled during build.");
    return TM_ECODE_FAILED;
}

void TmModuleJsondhcpLogRegister(void)
{
    tmm_modules[TMM_JSONDHCPLOG].name = "JsondhcpLog";
    tmm_modules[TMM_JSONDHCPLOG].ThreadInit = JsondhcpLogThreadInit;
}

#endif /* HAVE_LIBJANSSON */
