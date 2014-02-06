/* Copyright (C) 2011-2014 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * Logs alerts in a line based text format suitable for interaction
 * with wireshark or another pcap file analysis tools.
 *
 * The format of the logging is:
 *  Packet number:GID of matching signature:SID of signature:REV of signature:Flow:To Server:To Client:0:0:Signature Message
 * The two zeros are reserved for upcoming usage (probably byte start
 * and byte end of payload)
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

#include "output.h"
#include "alert-pcapinfo.h"

#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-logopenfile.h"

#define DEFAULT_LOG_FILENAME "alert-pcapinfo.log"
/* We need a new file for each pcap */
#define DEFAULT_PCAPINFO_MODE_APPEND "no"

#define MODULE_NAME "AlertPcapInfo"

typedef struct AlertPcapInfoThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
} AlertPcapInfoThread;

static TmEcode AlertPcapInfoThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertPcapInfoThread *aft = SCMalloc(sizeof(AlertPcapInfoThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(AlertPcapInfoThread));
    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for AlertPcapInfo.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode AlertPcapInfoThreadDeinit(ThreadVars *t, void *data)
{
    AlertPcapInfoThread *aft = (AlertPcapInfoThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(AlertPcapInfoThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void AlertPcapInfoExitPrintStats(ThreadVars *tv, void *data) {
    AlertPcapInfoThread *aft = (AlertPcapInfoThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) Alerts %" PRIu64 "", tv->name, aft->file_ctx->alerts);
}

static void AlertPcapInfoDeInitCtx(OutputCtx *output_ctx)
{
    LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
    LogFileFreeCtx(logfile_ctx);
    SCFree(output_ctx);
}

/** \brief Read the config set the file pointer, open the file
 *  \param file_ctx pointer to a created LogFileCtx using LogFileNewCtx()
 *  \param filename name of log file
 *  \param mode append mode (bool)
 *  \return -1 if failure, 0 if succesful
 * */
static int AlertPcapInfoOpenFileCtx(LogFileCtx *file_ctx, const char *filename,
                                    const char *mode)
{
    char log_path[PATH_MAX];
    char *log_dir;

    log_dir = ConfigGetLogDirectory();

    snprintf(log_path, PATH_MAX, "%s/%s", log_dir, filename);

    if (ConfValIsTrue(mode)) {
        file_ctx->fp = fopen(log_path, "a");
    } else {
        file_ctx->fp = fopen(log_path, "w");
    }

    if (file_ctx->fp == NULL) {
        SCLogError(SC_ERR_FOPEN, "failed to open %s: %s", log_path,
                strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
static OutputCtx *AlertPcapInfoInitCtx(ConfNode *conf)
{
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("AlertPcapInfoInitCtx2: Could not create new LogFileCtx");
        return NULL;
    }

    const char *filename = ConfNodeLookupChildValue(conf, "filename");
    if (filename == NULL)
        filename = DEFAULT_LOG_FILENAME;

    const char *mode = ConfNodeLookupChildValue(conf, "append");
    if (mode == NULL)
        mode = DEFAULT_PCAPINFO_MODE_APPEND;

    if (AlertPcapInfoOpenFileCtx(logfile_ctx, filename, mode) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;
    output_ctx->data = logfile_ctx;
    output_ctx->DeInit = AlertPcapInfoDeInitCtx;

    SCLogInfo("Fast log output initialized, filename: %s", filename);

    return output_ctx;
}

static int AlertPcapInfoCondition(ThreadVars *tv, const Packet *p) {
    return ((p->pcap_cnt != 0 && p->alerts.cnt > 0) ? TRUE : FALSE);
}

static int AlertPcapInfoLogger(ThreadVars *tv, void *thread_data, const Packet *p) {
    AlertPcapInfoThread *aft = (AlertPcapInfoThread *)thread_data;
    int i;

    /* logging is useless if we don't have pcap number */
    if ((p->pcap_cnt != 0) && (p->alerts.cnt > 0)) {
        SCMutexLock(&aft->file_ctx->fp_mutex);
        /* only count logged alert */
        aft->file_ctx->alerts += p->alerts.cnt;
        for (i = 0; i < p->alerts.cnt; i++) {
            const PacketAlert *pa = &p->alerts.alerts[i];

            fprintf(aft->file_ctx->fp, "%" PRIu64 ":%" PRIu32 ":%" PRIu32 ":%d:%d:%d:%d:0:0:%s\n",
                    p->pcap_cnt, pa->s->gid, pa->s->id, pa->s->rev,
                    pa->flags & (PACKET_ALERT_FLAG_STATE_MATCH|PACKET_ALERT_FLAG_STREAM_MATCH) ? 1 : 0,
                    p->flowflags & FLOW_PKT_TOSERVER ? 1 : 0,
                    p->flowflags & FLOW_PKT_TOCLIENT ? 1 : 0,
                    pa->s->msg);
        }
        SCMutexUnlock(&aft->file_ctx->fp_mutex);
    }

    return 0;
}

void TmModuleAlertPcapInfoRegister (void) {
    tmm_modules[TMM_ALERTPCAPINFO].name = MODULE_NAME;
    tmm_modules[TMM_ALERTPCAPINFO].ThreadInit = AlertPcapInfoThreadInit;
    tmm_modules[TMM_ALERTPCAPINFO].Func = NULL;
    tmm_modules[TMM_ALERTPCAPINFO].ThreadExitPrintStats = AlertPcapInfoExitPrintStats;
    tmm_modules[TMM_ALERTPCAPINFO].ThreadDeinit = AlertPcapInfoThreadDeinit;
    tmm_modules[TMM_ALERTPCAPINFO].RegisterTests = NULL;
    tmm_modules[TMM_ALERTPCAPINFO].cap_flags = 0;
    tmm_modules[TMM_ALERTPCAPINFO].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterPacketModule(MODULE_NAME, "pcap-info",
        AlertPcapInfoInitCtx, AlertPcapInfoLogger, AlertPcapInfoCondition);
}
