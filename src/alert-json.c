/* Copyright (C) 2007-2013 Open Information Security Foundation
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

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"
#include "util-classification-config.h"
#include "util-syslog.h"

#include "output.h"
#include "output-dnslog.h"
#include "output-httplog.h"
#include "output-tlslog.h"

#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-logopenfile.h"

#include "alert-json.h"

/*#undef HAVE_LIBJANSSON for testing without messing with config */
#ifndef HAVE_LIBJANSSON
/** Handle the case where no JSON support is compiled in.
 *
 */

TmEcode AlertJson (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertJsonThreadInit(ThreadVars *, void *, void **);
TmEcode AlertJsonThreadDeinit(ThreadVars *, void *);
int AlertJsonOpenFileCtx(LogFileCtx *, char *);
void AlertJsonRegisterTests(void);

void TmModuleAlertJsonRegister (void) {
    tmm_modules[TMM_ALERTJSON].name = "AlertJSON";
    tmm_modules[TMM_ALERTJSON].ThreadInit = AlertJsonThreadInit;
    tmm_modules[TMM_ALERTJSON].Func = AlertJson;
    tmm_modules[TMM_ALERTJSON].ThreadDeinit = AlertJsonThreadDeinit;
    tmm_modules[TMM_ALERTJSON].RegisterTests = AlertJsonRegisterTests;

    /* enable the logger for the app layer */
    AppLayerRegisterLogger(ALPROTO_DNS_UDP);
    AppLayerRegisterLogger(ALPROTO_DNS_TCP);

    AppLayerRegisterLogger(ALPROTO_HTTP);

OutputCtx *AlertJsonInitCtx(ConfNode *conf)
{
    SCLogDebug("Can't init JSON output - JSON support was disabled during build.");
    return NULL;
}

TmEcode AlertJsonThreadInit(ThreadVars *t, void *initdata, void **data)
{
    SCLogDebug("Can't init JSON output thread - JSON support was disabled during build.");
    return TM_ECODE_FAILED;
}

TmEcode AlertJson (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return TM_ECODE_OK;
}

TmEcode AlertJsonThreadDeinit(ThreadVars *t, void *data)
{
    return TM_ECODE_FAILED;
}

void AlertJsonRegisterTests (void) {
}

#else /* implied we do have JSON support */

#include <jansson.h>

#define DEFAULT_LOG_FILENAME "eve.json"
#define DEFAULT_ALERT_SYSLOG_FACILITY_STR       "local0"
#define DEFAULT_ALERT_SYSLOG_FACILITY           LOG_LOCAL0
#define DEFAULT_ALERT_SYSLOG_LEVEL              LOG_INFO
#define MODULE_NAME "AlertJSON"

#define OUTPUT_BUFFER_SIZE 65535

extern uint8_t engine_mode;
#ifndef OS_WIN32
static int alert_syslog_level = DEFAULT_ALERT_SYSLOG_LEVEL;
#endif /* OS_WIN32 */

TmEcode AlertJson (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertJsonIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertJsonIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode AlertJsonThreadInit(ThreadVars *, void *, void **);
TmEcode AlertJsonThreadDeinit(ThreadVars *, void *);
void AlertJsonExitPrintStats(ThreadVars *, void *);
void AlertJsonRegisterTests(void);
static void AlertJsonDeInitCtx(OutputCtx *);

void TmModuleAlertJsonRegister (void) {
    tmm_modules[TMM_ALERTJSON].name = MODULE_NAME;
    tmm_modules[TMM_ALERTJSON].ThreadInit = AlertJsonThreadInit;
    tmm_modules[TMM_ALERTJSON].Func = AlertJson;
    tmm_modules[TMM_ALERTJSON].ThreadExitPrintStats = AlertJsonExitPrintStats;
    tmm_modules[TMM_ALERTJSON].ThreadDeinit = AlertJsonThreadDeinit;
    tmm_modules[TMM_ALERTJSON].RegisterTests = AlertJsonRegisterTests;
    tmm_modules[TMM_ALERTJSON].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "eve-log", AlertJsonInitCtx);
}

/* Default Sensor ID value */
static int64_t sensor_id = -1; /* -1 = not defined */

enum json_output { ALERT_FILE,
                   ALERT_SYSLOG,
                   ALERT_UNIX_DGRAM,
                   ALERT_UNIX_STREAM };
static enum json_output json_out = ALERT_FILE;

#define OUTPUT_ALERTS (1<<0)
#define OUTPUT_DNS    (1<<1)
#define OUTPUT_HTTP   (1<<2)
#define OUTPUT_TLS    (1<<3)

static uint32_t outputFlags = 0;

enum json_format { COMPACT, INDENT };
static enum json_format format = COMPACT;

json_t *CreateJSONHeader(Packet *p, int direction_sensative)
{
    char timebuf[64];
    char srcip[46], dstip[46];
    Port sp, dp;

    json_t *js = json_object();
    if (unlikely(js == NULL))
        return NULL;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    srcip[0] = '\0';
    dstip[0] = '\0';
    if (direction_sensative) {
        if ((PKT_IS_TOCLIENT(p))) {
            if (PKT_IS_IPV4(p)) {
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
            } else if (PKT_IS_IPV6(p)) {
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
            }
            sp = p->sp;
            dp = p->dp;
        } else {
            if (PKT_IS_IPV4(p)) {
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), dstip, sizeof(dstip));
            } else if (PKT_IS_IPV6(p)) {
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), dstip, sizeof(dstip));
            }
            sp = p->dp;
            dp = p->sp;
        }
    } else {
        if (PKT_IS_IPV4(p)) {
            PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
            PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
        } else if (PKT_IS_IPV6(p)) {
            PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
            PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
        }
        sp = p->sp;
        dp = p->dp;
    }

    char proto[16] = "";
    if (SCProtoNameValid(IPV4_GET_IPPROTO(p)) == TRUE) {
        strlcpy(proto, known_proto[IPV4_GET_IPPROTO(p)], sizeof(proto));
    } else {
        snprintf(proto, sizeof(proto), "PROTO:%03" PRIu32, IPV4_GET_IPPROTO(p));
    }

    /* time & tx */
    json_object_set_new(js, "time", json_string(timebuf));

    /* sensor id */
    if (sensor_id >= 0)
        json_object_set_new(js, "sensor-id", json_integer(sensor_id));
     
    /* pcap_cnt */
    if (p->pcap_cnt != 0) {
        json_object_set_new(js, "pcap_cnt", json_integer(p->pcap_cnt));
    }

    /* vlan */
    if (p->vlan_idx > 0) {
        json_t *js_vlan;
        switch (p->vlan_idx) {
        case 1:
            json_object_set_new(js, "vlan",
                                json_integer(ntohs(GET_VLAN_ID(p->vlanh[0]))));
            break;
        case 2:
            js_vlan = json_array();
            if (unlikely(js != NULL)) {
                json_array_append_new(js_vlan,
                                json_integer(ntohs(GET_VLAN_ID(p->vlanh[0]))));
                json_array_append_new(js_vlan,
                                json_integer(ntohs(GET_VLAN_ID(p->vlanh[1]))));
                json_object_set_new(js, "vlan", js_vlan);
            }
            break;
        default:
            /* shouldn't get here */
            break;
        }
    }

    /* tuple */
    json_object_set_new(js, "srcip", json_string(srcip));
    switch(p->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            json_object_set_new(js, "sp", json_integer(sp));
            break;
    }
    json_object_set_new(js, "dstip", json_string(dstip));
    switch(p->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            json_object_set_new(js, "dp", json_integer(dp));
            break;
    }
    json_object_set_new(js, "proto", json_string(proto));
    switch (p->proto) {
        case IPPROTO_ICMP:
            if (p->icmpv4h) {
                json_object_set_new(js, "icmp_type",
                                    json_integer(p->icmpv4h->type));
                json_object_set_new(js, "icmp_code",
                                    json_integer(p->icmpv4h->code));
            }
            break;
        case IPPROTO_ICMPV6:
            if (p->icmpv6h) {
                json_object_set_new(js, "icmp_type",
                                    json_integer(p->icmpv6h->type));
                json_object_set_new(js, "icmp_code",
                                    json_integer(p->icmpv6h->code));
            }
            break;
    }

    return js;
}

TmEcode OutputJSON(json_t *js, void *data, uint64_t *count)
{
    AlertJsonThread *aft = (AlertJsonThread *)data;
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
    char *js_s = json_dumps(js, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
    if (unlikely(js_s == NULL))
        return TM_ECODE_OK;

    SCMutexLock(&aft->file_ctx->fp_mutex);
    if (json_out == ALERT_FILE) {
        MemBufferWriteString(buffer, "%s\n", js_s);
        (void)MemBufferPrintToFPAsString(buffer, aft->file_ctx->fp);
        fflush(aft->file_ctx->fp);
    } else {
        syslog(alert_syslog_level, "%s", js_s);
    }
    *count += 1;
    SCMutexUnlock(&aft->file_ctx->fp_mutex);
    return TM_ECODE_OK;
}

TmEcode AlertJsonIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertJsonThread *aft = (AlertJsonThread *)data;
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
    int i;
    char *action = "Pass";

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    MemBufferReset(buffer);

    json_t *js = CreateJSONHeader(p, 0);
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        if ((pa->action & ACTION_DROP) && IS_ENGINE_MODE_IPS(engine_mode)) {
            action = "Drop";
        } else if (pa->action & ACTION_DROP) {
            action = "wDrop";
        }

        json_t *ajs = json_object();
        if (ajs == NULL) {
            json_decref(js);
            return TM_ECODE_OK;
        }

        json_object_set_new(ajs, "action", json_string(action));
        json_object_set_new(ajs, "gid", json_integer(pa->s->gid));
        json_object_set_new(ajs, "id", json_integer(pa->s->id));
        json_object_set_new(ajs, "rev", json_integer(pa->s->rev));
        json_object_set_new(ajs, "msg",
                            json_string((pa->s->msg) ? pa->s->msg : ""));
        json_object_set_new(ajs, "class",
                            json_string((pa->s->class_msg) ? pa->s->class_msg : ""));
        json_object_set_new(ajs, "pri", json_integer(pa->s->prio));
   
        /* alert */ 
        json_object_set_new(js, "alert", ajs);

        OutputJSON(js, aft, &aft->file_ctx->alerts);
        json_object_del(js, "alert");
    }
    json_object_clear(js);
    json_decref(js);

    return TM_ECODE_OK;
}

TmEcode AlertJsonIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertJsonThread *aft = (AlertJsonThread *)data;
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
    int i;
    char *action = "Pass";

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    MemBufferReset(buffer);

    json_t *js = CreateJSONHeader(p, 0);
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        if ((pa->action & ACTION_DROP) && IS_ENGINE_MODE_IPS(engine_mode)) {
            action = "Drop";
        } else if (pa->action & ACTION_DROP) {
            action = "wDrop";
        }

        json_t *ajs = json_object();
        if (ajs == NULL) {
            json_decref(js);
            return TM_ECODE_OK;
        }

        json_object_set_new(ajs, "action", json_string(action));
        json_object_set_new(ajs, "gid", json_integer(pa->s->gid));
        json_object_set_new(ajs, "id", json_integer(pa->s->id));
        json_object_set_new(ajs, "rev", json_integer(pa->s->rev));
        json_object_set_new(ajs, "msg",
                            json_string((pa->s->msg) ? pa->s->msg : ""));
        json_object_set_new(ajs, "class",
                            json_string((pa->s->class_msg) ? pa->s->class_msg : ""));
        json_object_set_new(ajs, "pri", json_integer(pa->s->prio));
   
        /* alert */ 
        json_object_set_new(js, "alert", ajs);

        OutputJSON(js, aft, &aft->file_ctx->alerts);
        json_object_del(js, "alert");
    }
    json_object_clear(js);
    json_decref(js);

    return TM_ECODE_OK;
}

TmEcode AlertJsonDecoderEvent(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertJsonThread *aft = (AlertJsonThread *)data;
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
    int i;
    char timebuf[64];
    char *action = "Pass";
    json_t *js;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    MemBufferReset(buffer);

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        if ((pa->action & ACTION_DROP) && IS_ENGINE_MODE_IPS(engine_mode)) {
            action = "Drop";
        } else if (pa->action & ACTION_DROP) {
            action = "wDrop";
        }

        char buf[(32 * 3) + 1];
        PrintRawLineHexBuf(buf, sizeof(buf), GET_PKT_DATA(p), GET_PKT_LEN(p) < 32 ? GET_PKT_LEN(p) : 32);

        js = json_object();
        if (js == NULL)
            return TM_ECODE_OK;

        json_t *ajs = json_object();
        if (ajs == NULL) {
            json_decref(js);
            return TM_ECODE_OK;
        }

        /* time & tx */
        json_object_set_new(js, "time", json_string(timebuf));

        /* tuple */
        //json_object_set_new(js, "srcip", json_string(srcip));
        //json_object_set_new(js, "sp", json_integer(p->sp));
        //json_object_set_new(js, "dstip", json_string(dstip));
        //json_object_set_new(js, "dp", json_integer(p->dp));
        //json_object_set_new(js, "proto", json_integer(proto));

        json_object_set_new(ajs, "action", json_string(action));
        json_object_set_new(ajs, "gid", json_integer(pa->s->gid));
        json_object_set_new(ajs, "id", json_integer(pa->s->id));
        json_object_set_new(ajs, "rev", json_integer(pa->s->rev));
        json_object_set_new(ajs, "msg",
                            json_string((pa->s->msg) ? pa->s->msg : ""));
        json_object_set_new(ajs, "class",
                            json_string((pa->s->class_msg) ? pa->s->class_msg : ""));
        json_object_set_new(ajs, "pri", json_integer(pa->s->prio));
   
        /* alert */ 
        json_object_set_new(js, "alert", ajs);
        OutputJSON(js, aft, &aft->file_ctx->alerts);
        json_object_clear(js);
        json_decref(js);
    }

    return TM_ECODE_OK;
}

TmEcode AlertJson (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    if (outputFlags & OUTPUT_ALERTS) {

        if (PKT_IS_IPV4(p)) {
            AlertJsonIPv4(tv, p, data, pq, postpq);
        } else if (PKT_IS_IPV6(p)) {
            AlertJsonIPv6(tv, p, data, pq, postpq);
        } else if (p->events.cnt > 0) {
            AlertJsonDecoderEvent(tv, p, data, pq, postpq);
        }
    }

    if (outputFlags & OUTPUT_DNS) {
        if (OutputDnsNeedsLog(p)) {
            OutputDnsLog(tv, p, data, pq, postpq);
        }
    }

    if (outputFlags & OUTPUT_HTTP) {
        OutputHttpLog(tv, p, data, pq, postpq);
    }

    if (outputFlags & OUTPUT_TLS) {
        OutputTlsLog(tv, p, data, pq, postpq);
    }

    return TM_ECODE_OK;
}

TmEcode AlertJsonThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertJsonThread *aft = SCMalloc(sizeof(AlertJsonThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(AlertJsonThread));
    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for AlertJson.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /** Use the Ouptut Context (file pointer and mutex) */
    OutputJsonCtx *json_ctx = ((OutputCtx *)initdata)->data;
    if (json_ctx != NULL) {
        aft->file_ctx = json_ctx->file_ctx;
        aft->http_ctx = json_ctx->http_ctx;
        aft->tls_ctx = json_ctx->tls_ctx;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode AlertJsonThreadDeinit(ThreadVars *t, void *data)
{
    AlertJsonThread *aft = (AlertJsonThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    SCFree(aft);
    return TM_ECODE_OK;
}

void AlertJsonExitPrintStats(ThreadVars *tv, void *data) {
    AlertJsonThread *aft = (AlertJsonThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("JSON output wrote %" PRIu64 " alerts", aft->file_ctx->alerts);

}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
OutputCtx *AlertJsonInitCtx(ConfNode *conf)
{
    OutputJsonCtx *json_ctx = SCCalloc(1, sizeof(OutputJsonCtx));;
    if (unlikely(json_ctx == NULL)) {
        SCLogDebug("AlertJsonInitCtx: Could not create new LogFileCtx");
        return NULL;
    }

    json_ctx->file_ctx = LogFileNewCtx();
    if (unlikely(json_ctx->file_ctx == NULL)) {
        SCLogDebug("AlertJsonInitCtx: Could not create new LogFileCtx");
        SCFree(json_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;

    output_ctx->data = json_ctx;
    output_ctx->DeInit = AlertJsonDeInitCtx;

    if (conf) {
        const char *output_s = ConfNodeLookupChildValue(conf, "type");
        if (output_s != NULL) {
            if (strcmp(output_s, "file") == 0) {
                json_out = ALERT_FILE;
            } else if (strcmp(output_s, "syslog") == 0) {
                json_out = ALERT_SYSLOG;
            } else if (strcmp(output_s, "unix_dgram") == 0) {
                json_out = ALERT_UNIX_DGRAM;
            } else if (strcmp(output_s, "unix_stream") == 0) {
                json_out = ALERT_UNIX_STREAM;
            } else {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                           "Invalid JSON output option: %s", output_s);
                exit(EXIT_FAILURE);
            }
        }

        if (json_out == ALERT_FILE) {

            if (SCConfLogOpenGeneric(conf, json_ctx->file_ctx, DEFAULT_LOG_FILENAME) < 0) {
                LogFileFreeCtx(json_ctx->file_ctx);
                return NULL;
            }

            const char *format_s = ConfNodeLookupChildValue(conf, "format");
            if (format_s != NULL) {
                if (strcmp(format_s, "indent") == 0) {
                    format = INDENT;
                } else if (strcmp(format_s, "compact") == 0) {
                    format = COMPACT;
                } else {
                    SCLogError(SC_ERR_INVALID_ARGUMENT,
                               "Invalid JSON format option: %s", format_s);
                    exit(EXIT_FAILURE);
                }
            }
        } else if (json_out == ALERT_SYSLOG) {
            const char *facility_s = ConfNodeLookupChildValue(conf, "facility");
            if (facility_s == NULL) {
                facility_s = DEFAULT_ALERT_SYSLOG_FACILITY_STR;
            }

            int facility = SCMapEnumNameToValue(facility_s, SCSyslogGetFacilityMap());
            if (facility == -1) {
                SCLogWarning(SC_ERR_INVALID_ARGUMENT, "Invalid syslog facility: \"%s\","
                        " now using \"%s\" as syslog facility", facility_s,
                        DEFAULT_ALERT_SYSLOG_FACILITY_STR);
                facility = DEFAULT_ALERT_SYSLOG_FACILITY;
            }

            const char *level_s = ConfNodeLookupChildValue(conf, "level");
            if (level_s != NULL) {
                int level = SCMapEnumNameToValue(level_s, SCSyslogGetLogLevelMap());
                if (level != -1) {
                    alert_syslog_level = level;
                }
            }

            const char *ident = ConfNodeLookupChildValue(conf, "identity");
            /* if null we just pass that to openlog, which will then
             * figure it out by itself. */

            openlog(ident, LOG_PID|LOG_NDELAY, facility);

        }

        const char *sensor_id_s = ConfNodeLookupChildValue(conf, "sensor-id");
        if (sensor_id_s != NULL) {
            if (ByteExtractStringUint64((uint64_t *)&sensor_id, 10, 0, sensor_id_s) == -1) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                           "Failed to initialize JSON output, "
                           "invalid sensor-is: %s", sensor_id_s);
                exit(EXIT_FAILURE);
            }
        }

        ConfNode *outputs, *output;
        outputs = ConfNodeLookupChild(conf, "types");
        if (outputs) {
            /*
             * TODO: make this more general with some sort of 
             * registration capability
             */
            TAILQ_FOREACH(output, &outputs->head, next) {
                if (strcmp(output->val, "alert") == 0) {
                    SCLogDebug("Enabling alert output");
                    outputFlags |= OUTPUT_ALERTS;
                    continue;
                }
                if (strcmp(output->val, "dns") == 0) {
                    SCLogDebug("Enabling DNS output");
                    outputFlags |= OUTPUT_DNS;
                    continue;
                }
                if (strcmp(output->val, "http") == 0) {
                    SCLogDebug("Enabling HTTP output");
                    /* Yuck.  there has to be a better way */
                    ConfNode *child = ConfNodeLookupChild(output, "http"); 
                    if (child) {
                        json_ctx->http_ctx = OutputHttpLogInit(child);
                        if (json_ctx->http_ctx != NULL)
                            outputFlags |= OUTPUT_HTTP;
                    } else {
                        outputFlags |= OUTPUT_HTTP;
                    }
                    continue;
                }
                if (strcmp(output->val, "tls") == 0) {
                    SCLogDebug("Enabling TLS output");
                    ConfNode *child = ConfNodeLookupChild(output, "tls"); 
#if 1
                    json_ctx->tls_ctx = OutputTlsLogInit(child);
                    outputFlags |= OUTPUT_TLS;
#else
                    if (child) {
                        json_ctx->tls_ctx = OutputTlsLogInit(child);
                        if (json_ctx->tls_ctx != NULL)
                            outputFlags |= OUTPUT_TLS;
                    } else {
                        outputFlags |= OUTPUT_TLS;
                    }
#endif
                    continue;
                }
            }
        }
    }

    return output_ctx;
}

static void AlertJsonDeInitCtx(OutputCtx *output_ctx)
{
    OutputJsonCtx *json_ctx = (OutputJsonCtx *)output_ctx->data;
    LogFileCtx *logfile_ctx = json_ctx->file_ctx;
    LogFileFreeCtx(logfile_ctx);
    SCFree(output_ctx);
}

/*------------------------------Unittests-------------------------------------*/

#ifdef UNITTESTS

int AlertBroccoliTest01()
{
    int result = 0;
    uint8_t *buf = (uint8_t *) "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n";

    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return result;
    }

    de_ctx->flags |= DE_QUIET;

    SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx);
    SCClassConfDeleteDummyClassificationConfigFD();

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
            "(msg:\"FastLog test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");
    result = (de_ctx->sig_list != NULL);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1)
        result = (strcmp(p->alerts.alerts[0].s->class_msg, "Unknown are we") == 0);
    else
        result = 0;

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadRC();
    if (SCCudaHlPushCudaContextFromModule("SC_RULES_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    return result;
}

int AlertBroccoliTest02()
{
    int result = 0;
    uint8_t *buf = (uint8_t *) "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        return result;
    }

    de_ctx->flags |= DE_QUIET;

    SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx);
    SCClassConfDeleteDummyClassificationConfigFD();

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
            "(msg:\"FastLog test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");
    result = (de_ctx->sig_list != NULL);
    if (result == 0)
        printf("sig parse failed: ");

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1) {
        result = (strcmp(p->alerts.alerts[0].s->class_msg, "Unknown Traffic") != 0);
        if (result == 0)
            printf("p->alerts.alerts[0].class_msg %s: ", p->alerts.alerts[0].s->class_msg);

        result = (strcmp(p->alerts.alerts[0].s->class_msg,
                    "Unknown are we") == 0);
        if (result == 0)
            printf("p->alerts.alerts[0].class_msg %s: ", p->alerts.alerts[0].s->class_msg);
    } else {
        result = 0;
    }

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadRC();
    if (SCCudaHlPushCudaContextFromModule("SC_RULES_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for AlertFastLog API.
 */
void AlertJsonRegisterTests(void)
{

#ifdef UNITTESTS

#ifdef __SC_CUDA_SUPPORT__
    UtRegisterTest("AlertFastLogCudaContextInit",
            SCCudaHlTestEnvCudaContextInit, 1);
#endif

    UtRegisterTest("AlertBroccoliLogTest01", AlertBroccoliLogTest01, 1);
    UtRegisterTest("AlertBroccoliLogTest02", AlertBroccoliLogTest02, 1);

#ifdef __SC_CUDA_SUPPORT__
    UtRegisterTest("AlertFastLogCudaContextDeInit",
            SCCudaHlTestEnvCudaContextDeInit, 1);
#endif

#endif /* UNITTESTS */

}
#endif
