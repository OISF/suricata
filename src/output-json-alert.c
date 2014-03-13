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

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"
#include "app-layer-parser.h"
#include "util-classification-config.h"
#include "util-syslog.h"

#include "output.h"
#include "output-json.h"

#include "util-byte.h"
#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-buffer.h"
#include "util-logopenfile.h"

#define MODULE_NAME "JsonAlertLog"

#ifdef HAVE_LIBJANSSON

extern int engine_mode;

typedef struct JsonAlertLogThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
    MemBuffer *buffer;
} JsonAlertLogThread;

/** Handle the case where no JSON support is compiled in.
 *
 */
static int AlertJson(ThreadVars *tv, JsonAlertLogThread *aft, const Packet *p)
{
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
    int i;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    MemBufferReset(buffer);

    json_t *js = CreateJSONHeader((Packet *)p, 0, "alert");
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        char *action = "allowed";
        if (pa->action & (ACTION_REJECT|ACTION_REJECT_DST|ACTION_REJECT_BOTH)) {
            action = "blocked";
        } else if ((pa->action & ACTION_DROP) && IS_ENGINE_MODE_IPS(engine_mode)) {
            action = "blocked";
        }

        json_t *ajs = json_object();
        if (ajs == NULL) {
            json_decref(js);
            return TM_ECODE_OK;
        }

        json_object_set_new(ajs, "action", json_string(action));
        json_object_set_new(ajs, "gid", json_integer(pa->s->gid));
        json_object_set_new(ajs, "signature_id", json_integer(pa->s->id));
        json_object_set_new(ajs, "rev", json_integer(pa->s->rev));
        json_object_set_new(ajs, "signature",
                            json_string((pa->s->msg) ? pa->s->msg : ""));
        json_object_set_new(ajs, "category",
                            json_string((pa->s->class_msg) ? pa->s->class_msg : ""));
        json_object_set_new(ajs, "severity", json_integer(pa->s->prio));

        /* alert */
        json_object_set_new(js, "alert", ajs);

        OutputJSONBuffer(js, aft->file_ctx, aft->buffer);
        json_object_del(js, "alert");
    }
    json_object_clear(js);
    json_decref(js);

    return TM_ECODE_OK;
}

static int AlertJsonDecoderEvent(ThreadVars *tv, JsonAlertLogThread *aft, const Packet *p)
{
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
    int i;
    char timebuf[64];
    json_t *js;

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    MemBufferReset(buffer);

    CreateIsoTimeString(&p->ts, timebuf, sizeof(timebuf));

    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        char *action = "allowed";
        if (pa->action & (ACTION_REJECT|ACTION_REJECT_DST|ACTION_REJECT_BOTH)) {
            action = "blocked";
        } else if ((pa->action & ACTION_DROP) && IS_ENGINE_MODE_IPS(engine_mode)) {
            action = "blocked";
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

        /* alert */
        json_object_set_new(js, "alert", ajs);
        OutputJSONBuffer(js, aft->file_ctx, buffer);
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
    return (p->alerts.cnt ? TRUE : FALSE);
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonAlertLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    JsonAlertLogThread *aft = SCMalloc(sizeof(JsonAlertLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonAlertLogThread));
    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for AlertFastLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /** Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonAlertLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonAlertLogThread *aft = (JsonAlertLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);

    /* clear memory */
    memset(aft, 0, sizeof(JsonAlertLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void JsonAlertLogDeInitCtx(OutputCtx *output_ctx)
{
    LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
    LogFileFreeCtx(logfile_ctx);
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "alert.json"
/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
static OutputCtx *JsonAlertLogInitCtx(ConfNode *conf)
{
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("AlertFastLogInitCtx2: Could not create new LogFileCtx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;
    output_ctx->data = logfile_ctx;
    output_ctx->DeInit = JsonAlertLogDeInitCtx;

    return output_ctx;
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
static OutputCtx *JsonAlertLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;

    output_ctx->data = ajt->file_ctx;
    output_ctx->DeInit = JsonAlertLogDeInitCtx;

    return output_ctx;
}

void TmModuleJsonAlertLogRegister (void) {
    tmm_modules[TMM_JSONALERTLOG].name = MODULE_NAME;
    tmm_modules[TMM_JSONALERTLOG].ThreadInit = JsonAlertLogThreadInit;
    tmm_modules[TMM_JSONALERTLOG].ThreadDeinit = JsonAlertLogThreadDeinit;
    tmm_modules[TMM_JSONALERTLOG].cap_flags = 0;
    tmm_modules[TMM_JSONALERTLOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterPacketModule(MODULE_NAME, "alert-json-log",
            JsonAlertLogInitCtx, JsonAlertLogger, JsonAlertLogCondition);
    OutputRegisterPacketSubModule("eve-log", MODULE_NAME, "eve-log.alert",
            JsonAlertLogInitCtxSub, JsonAlertLogger, JsonAlertLogCondition);
}

#else

static TmEcode OutputJsonThreadInit(ThreadVars *t, void *initdata, void **data)
{
    SCLogInfo("Can't init JSON output - JSON support was disabled during build.");
    return TM_ECODE_FAILED;
}

void TmModuleJsonAlertLogRegister (void)
{
    tmm_modules[TMM_JSONALERTLOG].name = MODULE_NAME;
    tmm_modules[TMM_JSONALERTLOG].ThreadInit = OutputJsonThreadInit;
}

#endif

