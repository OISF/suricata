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
#include "alert-json.h"

#include "util-byte.h"
#include "util-mpm-b2g-cuda.h"
#include "util-cuda-handlers.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-logopenfile.h"

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
}

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

#define DEFAULT_LOG_FILENAME "json.log"
#define DEFAULT_ALERT_SYSLOG_FACILITY_STR       "local0"
#define DEFAULT_ALERT_SYSLOG_FACILITY           LOG_LOCAL0
#define DEFAULT_ALERT_SYSLOG_LEVEL              LOG_INFO
#define MODULE_NAME "AlertJSON"

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

    OutputRegisterModule(MODULE_NAME, "json", AlertJsonInitCtx);
}

/* Default Sensor ID value */
static uint64_t sensor_id = 0;

enum json_output { ALERT_FILE, ALERT_SYSLOG };
static enum json_output json_out = ALERT_FILE;

enum json_format { COMPACT, INDENT };
static enum json_format format = COMPACT;

typedef struct AlertJsonThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
} AlertJsonThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm *)SCLocalTime(time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
            t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
            t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}

TmEcode AlertJsonIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertJsonThread *aft = (AlertJsonThread *)data;
    int i;
    char timebuf[64];
    char *action = "Pass";

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[16], dstip[16];
    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        json_t *js;
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        if ((pa->action & ACTION_DROP) && IS_ENGINE_MODE_IPS(engine_mode)) {
            action = "Drop";
        } else if (pa->action & ACTION_DROP) {
            action = "wDrop";
        }

        char proto[16] = "";
        if (SCProtoNameValid(IPV4_GET_IPPROTO(p)) == TRUE) {
            strlcpy(proto, known_proto[IPV4_GET_IPPROTO(p)], sizeof(proto));
        } else {
            snprintf(proto, sizeof(proto), "PROTO:%03" PRIu32, IPV4_GET_IPPROTO(p));
        }
        json_error_t error;
        js = json_pack_ex(
                       &error, 0,
                       "{"
                       "ss"
                       "ss"
                       "si"
                       "si"
                       "si"
                       "ss"
                       "ss"
                       "si"
                       "ss"
                       "ss"
                       "si"
                       "ss"
                       "si}",
                       "time", timebuf,
                       "action", action,
                       "gid", pa->s->gid,
                       "id", pa->s->id,
                       "rev", pa->s->rev,
                       "msg", (pa->s->msg) ? pa->s->msg : "",
                       "class", (pa->s->class_msg) ? pa->s->class_msg : "",
                       "pri", pa->s->prio,
                       "proto", proto,
                       "srcip", srcip,
                       "sp", p->sp,
                       "dstip", dstip,
                       "dp", p->dp
                      );

        if (js == NULL) {
            SCLogInfo("json_pack error %s", error.text);
            return TM_ECODE_OK;
        }

        SCMutexLock(&aft->file_ctx->fp_mutex);
        if (json_out == ALERT_FILE) {
            json_dumpf(js, aft->file_ctx->fp,
                       ((format == INDENT) ? JSON_INDENT(2) : 0) |
                       JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
            if (format == INDENT) {
                fputs("\n", aft->file_ctx->fp);
            }
        } else {
            char *js_s;
            js_s = json_dumps(js, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
            if (js_s) {
                syslog(alert_syslog_level, "%s", js_s);
                free(js_s);
            }
        }
        aft->file_ctx->alerts++;
        SCMutexUnlock(&aft->file_ctx->fp_mutex);
        free(js);
    }

    return TM_ECODE_OK;
}

TmEcode AlertJsonIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertJsonThread *aft = (AlertJsonThread *)data;
    int i;
    char timebuf[64];
    char *action = "Pass";

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[46], dstip[46];
    PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
    PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        json_t *js;
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        if ((pa->action & ACTION_DROP) && IS_ENGINE_MODE_IPS(engine_mode)) {
            action = "Drop";
        } else if (pa->action & ACTION_DROP) {
            action = "wDrop";
        }

        char proto[16] = "";
        if (SCProtoNameValid(IP_GET_IPPROTO(p)) == TRUE) {
            strlcpy(proto, known_proto[IP_GET_IPPROTO(p)], sizeof(proto));
        } else {
            snprintf(proto, sizeof(proto), "PROTO:%03" PRIu32, IP_GET_IPPROTO(p));
        }
        json_error_t error;
        js = json_pack_ex(
                       &error, 0,
                       "{"
                       "ss"
                       "ss"
                       "si"
                       "si"
                       "si"
                       "ss"
                       "ss"
                       "si"
                       "ss"
                       "ss"
                       "si"
                       "ss"
                       "si}",
                       "time", timebuf,
                       "action", action,
                       "gid", pa->s->gid,
                       "id", pa->s->id,
                       "rev", pa->s->rev,
                       "msg", (pa->s->msg) ? pa->s->msg : "",
                       "class", (pa->s->class_msg) ? pa->s->class_msg : "",
                       "pri", pa->s->prio,
                       "proto", proto,
                       "srcip", srcip,
                       "sp", p->sp,
                       "dstip", dstip,
                       "dp", p->dp
                      );

        if (js == NULL) {
            SCLogInfo("json_pack error %s", error.text);
            return TM_ECODE_OK;
        }

        SCMutexLock(&aft->file_ctx->fp_mutex);
        if (json_out == ALERT_FILE) {
            json_dumpf(js, aft->file_ctx->fp,
                       ((format == INDENT) ? JSON_INDENT(2) : 0) |
                       JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
            if (format == INDENT) {
                fputs("\n", aft->file_ctx->fp);
            }
        } else {
            char *js_s;
            js_s = json_dumps(js, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
            if (js_s) {
                syslog(alert_syslog_level, "%s", js_s);
                free(js_s);
            }
        }
        aft->file_ctx->alerts++;
        SCMutexUnlock(&aft->file_ctx->fp_mutex);
        free(js);
    }

    return TM_ECODE_OK;
}

TmEcode AlertJsonDecoderEvent(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    AlertJsonThread *aft = (AlertJsonThread *)data;
    int i;
    char timebuf[64];
    char *action = "Pass";

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        json_t *js;
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

        json_error_t error;
        js = json_pack_ex(
                       &error, 0,
                       "{"
                       "ss"
                       "ss"
                       "si"
                       "si"
                       "si"
                       "ss"
                       "ss"
                       "si"
                       "ss}",
                       "time", timebuf,
                       "action", action,
                       "gid", pa->s->gid,
                       "id", pa->s->id,
                       "rev", pa->s->rev,
                       "msg", (pa->s->msg) ? pa->s->msg : "",
                       "class", (pa->s->class_msg) ? pa->s->class_msg : "",
                       "pri", pa->s->prio,
                       "pkt", buf
                      );

        if (js == NULL) {
            SCLogInfo("json_pack error %s", error.text);
            return TM_ECODE_OK;
        }

        SCMutexLock(&aft->file_ctx->fp_mutex);
        if (json_out == ALERT_FILE) {
            json_dumpf(js, aft->file_ctx->fp,
                       ((format == INDENT) ? JSON_INDENT(2) : 0) |
                       JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
            if (format == INDENT) {
                fputs("\n", aft->file_ctx->fp);
            }
        } else {
            char *js_s;
            js_s = json_dumps(js, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
            if (js_s) {
                syslog(alert_syslog_level, "%s", js_s);
                free(js_s);
            }
        }
        aft->file_ctx->alerts++;
        SCMutexUnlock(&aft->file_ctx->fp_mutex);
        free(js);
    }

    return TM_ECODE_OK;
}

TmEcode AlertJson (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    if (PKT_IS_IPV4(p)) {
        return AlertJsonIPv4(tv, p, data, pq, postpq);
    } else if (PKT_IS_IPV6(p)) {
        return AlertJsonIPv6(tv, p, data, pq, postpq);
    } else if (p->events.cnt > 0) {
        return AlertJsonDecoderEvent(tv, p, data, pq, postpq);
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
    /** Use the Ouptut Context (file pointer and mutex) */
    //aft->ctx = ((OutputCtx *)initdata)->data;
    aft->file_ctx = ((OutputCtx *)initdata)->data;

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
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("AlertJsonInitCtx: Could not create nnew LogFileCtx");
        return NULL;
    }


    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;
    output_ctx->data = logfile_ctx;
    output_ctx->DeInit = AlertJsonDeInitCtx;

    if (conf) {
        const char *output_s = ConfNodeLookupChildValue(conf, "output");
        if (output_s != NULL) {
            if (strcmp(output_s, "file") == 0) {
                json_out = ALERT_FILE;
            } else if (strcmp(output_s, "syslog") == 0) {
                json_out = ALERT_SYSLOG;
            } else {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                           "Invalid JSON output option: %s", output_s);
                exit(EXIT_FAILURE);
            }
        }

        if (json_out == ALERT_FILE) {

            if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME) < 0) {
                LogFileFreeCtx(logfile_ctx);
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
        } else {
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
            if (ByteExtractStringUint64(&sensor_id, 10, 0, sensor_id_s) == -1) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                           "Failed to initialize broccoli output, "
                           "invalid sensor-is: %s", sensor_id_s);
                exit(EXIT_FAILURE);
            }
            sensor_id = htonl(sensor_id);
        }
    }

    return output_ctx;
}

static void AlertJsonDeInitCtx(OutputCtx *output_ctx)
{
    LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
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
