/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * \todo figure out a way to (thread) safely print detection engine info
 * \todo maybe by having a log queue in the packet
 * \todo maybe by accessing it just and hoping threading doesn't hurt
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-modules.h"

#include "util-print.h"

#include "pkt-var.h"

#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "alert-debuglog.h"
#include "util-privs.h"

#define DEFAULT_LOG_FILENAME "alert-debug.log"

#define MODULE_NAME "AlertDebugLog"

TmEcode AlertDebugLog (ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode AlertDebugLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode AlertDebugLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *);
TmEcode AlertDebugLogThreadInit(ThreadVars *, void*, void **);
TmEcode AlertDebugLogThreadDeinit(ThreadVars *, void *);
void AlertDebugLogExitPrintStats(ThreadVars *, void *);
int AlertDebugLogOpenFileCtx(LogFileCtx* , const char *);

void TmModuleAlertDebugLogRegister (void) {
    tmm_modules[TMM_ALERTDEBUGLOG].name = MODULE_NAME;
    tmm_modules[TMM_ALERTDEBUGLOG].ThreadInit = AlertDebugLogThreadInit;
    tmm_modules[TMM_ALERTDEBUGLOG].Func = AlertDebugLog;
    tmm_modules[TMM_ALERTDEBUGLOG].ThreadExitPrintStats = AlertDebugLogExitPrintStats;
    tmm_modules[TMM_ALERTDEBUGLOG].ThreadDeinit = AlertDebugLogThreadDeinit;
    tmm_modules[TMM_ALERTDEBUGLOG].RegisterTests = NULL;
    tmm_modules[TMM_ALERTDEBUGLOG].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "alert-debug", AlertDebugLogInitCtx);
}

typedef struct AlertDebugLogThread_ {
    LogFileCtx *file_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
} AlertDebugLogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size) {
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = gmtime_r(&time, &local_tm);
    uint32_t sec = ts->tv_sec % 86400;

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year - 100,
        sec / 3600, (sec % 3600) / 60, sec % 60,
        (uint32_t) ts->tv_usec);
}

TmEcode AlertDebugLogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    AlertDebugLogThread *aft = (AlertDebugLogThread *)data;
    int i;
    char timebuf[64];

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    SCMutexLock(&aft->file_ctx->fp_mutex);

    fprintf(aft->file_ctx->fp, "+================\n");
    fprintf(aft->file_ctx->fp, "TIME:              %s\n", timebuf);
    if (p->pcap_cnt > 0) {
        fprintf(aft->file_ctx->fp, "PCAP PKT NUM:      %"PRIu64"\n", p->pcap_cnt);
    }
    fprintf(aft->file_ctx->fp, "ALERT CNT:         %" PRIu32 "\n", p->alerts.cnt);

    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];

        fprintf(aft->file_ctx->fp, "ALERT MSG [%02d]:    %s\n", i, pa->msg);
        fprintf(aft->file_ctx->fp, "ALERT GID [%02d]:    %" PRIu32 "\n", i, pa->gid);
        fprintf(aft->file_ctx->fp, "ALERT SID [%02d]:    %" PRIu32 "\n", i, pa->sid);
        fprintf(aft->file_ctx->fp, "ALERT REV [%02d]:    %" PRIu32 "\n", i, pa->rev);
        fprintf(aft->file_ctx->fp, "ALERT CLASS [%02d]:  %s\n", i, pa->class_msg);
        fprintf(aft->file_ctx->fp, "ALERT PRIO [%02d]:   %" PRIu32 "\n", i, pa->prio);
    }

    char srcip[16], dstip[16];
    inet_ntop(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
    inet_ntop(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));

    fprintf(aft->file_ctx->fp, "SRC IP:            %s\n", srcip);
    fprintf(aft->file_ctx->fp, "DST IP:            %s\n", dstip);
    fprintf(aft->file_ctx->fp, "PROTO:             %" PRIu32 "\n", IPV4_GET_IPPROTO(p));
    if (PKT_IS_TCP(p) || PKT_IS_UDP(p)) {
        fprintf(aft->file_ctx->fp, "SRC PORT:          %" PRIu32 "\n", p->sp);
        fprintf(aft->file_ctx->fp, "DST PORT:          %" PRIu32 "\n", p->dp);
        if (PKT_IS_TCP(p)) {
            fprintf(aft->file_ctx->fp, "TCP SEQ:           %"PRIu32"\n", TCP_GET_SEQ(p));
            fprintf(aft->file_ctx->fp, "TCP ACK:           %"PRIu32"\n", TCP_GET_ACK(p));
        }
    }

    /* flow stuff */
    fprintf(aft->file_ctx->fp, "FLOW:              to_server: %s, to_client %s\n",
        p->flowflags & FLOW_PKT_TOSERVER ? "TRUE" : "FALSE",
        p->flowflags & FLOW_PKT_TOCLIENT ? "TRUE" : "FALSE");

    PktVar *pv = PktVarGet(p,"http_host");
    if (pv) {
        fprintf(aft->file_ctx->fp, "PKTVAR:            %s\n", pv->name);
        PrintRawDataFp(aft->file_ctx->fp, pv->value, pv->value_len);
    }

    pv = PktVarGet(p,"http_ua");
    if (pv) {
        fprintf(aft->file_ctx->fp, "PKTVAR:            %s\n", pv->name);
        PrintRawDataFp(aft->file_ctx->fp, pv->value, pv->value_len);
    }

/* any stuff */
/* Sig details? */
/* pkt vars */
/* flowvars */

    aft->file_ctx->alerts += p->alerts.cnt;

    fprintf(aft->file_ctx->fp, "PACKET LEN:        %" PRIu32 "\n", p->pktlen);
    fprintf(aft->file_ctx->fp, "PACKET:\n");
    PrintRawDataFp(aft->file_ctx->fp, p->pkt, p->pktlen);

    fflush(aft->file_ctx->fp);
    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    return TM_ECODE_OK;
}

TmEcode AlertDebugLogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    AlertDebugLogThread *aft = (AlertDebugLogThread *)data;
    int i;
    char timebuf[64];

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    aft->file_ctx->alerts += p->alerts.cnt;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    SCMutexLock(&aft->file_ctx->fp_mutex);
    for (i = 0; i < p->alerts.cnt; i++) {
        PacketAlert *pa = &p->alerts.alerts[i];
        char srcip[46], dstip[46];

        inet_ntop(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        inet_ntop(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));

        fprintf(aft->file_ctx->fp, "%s  [**] [%" PRIu32 ":%" PRIu32 ":%" PRIu32 "] %s [**] [Classification: fixme] [Priority: %" PRIu32 "] {%" PRIu32 "} %s:%" PRIu32 " -> %s:%" PRIu32 "\n",
            timebuf, pa->gid, pa->sid, pa->rev, pa->msg, pa->prio, IPV6_GET_L4PROTO(p), srcip, p->sp, dstip, p->dp);
    }
    fflush(aft->file_ctx->fp);
    SCMutexUnlock(&aft->file_ctx->fp_mutex);

    return TM_ECODE_OK;
}

TmEcode AlertDebugLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    if (PKT_IS_IPV4(p)) {
        return AlertDebugLogIPv4(tv, p, data, pq);
    } else if (PKT_IS_IPV6(p)) {
        return AlertDebugLogIPv6(tv, p, data, pq);
    }

    return TM_ECODE_OK;
}

TmEcode AlertDebugLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    AlertDebugLogThread *aft = SCMalloc(sizeof(AlertDebugLogThread));
    if (aft == NULL)
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(AlertDebugLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for DebugLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode AlertDebugLogThreadDeinit(ThreadVars *t, void *data)
{
    AlertDebugLogThread *aft = (AlertDebugLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(AlertDebugLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void AlertDebugLogExitPrintStats(ThreadVars *tv, void *data) {
    AlertDebugLogThread *aft = (AlertDebugLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) Alerts %" PRIu64 "", tv->name, aft->file_ctx->alerts);
}


/** \brief Create a new LogFileCtx for alert debug logging.
 *  \param ConfNode containing configuration for this logger.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *AlertDebugLogInitCtx(ConfNode *conf)
{
    int ret=0;
    LogFileCtx* file_ctx=LogFileNewCtx();

    if(file_ctx == NULL)
    {
        SCLogDebug("AlertDebugLogInitCtx: Couldn't create new file_ctx");
        return NULL;
    }

    const char *filename = ConfNodeLookupChildValue(conf, "filename");
    if (filename == NULL)
        filename = DEFAULT_LOG_FILENAME;

    /** fill the new LogFileCtx with the specific AlertDebugLog configuration */
    ret=AlertDebugLogOpenFileCtx(file_ctx, filename);

    if(ret < 0)
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (output_ctx == NULL)
        return NULL;
    output_ctx->data = file_ctx;

    return output_ctx;
}

/** \brief Read the config set the file pointer, open the file
 *  \param file_ctx pointer to a created LogFileCtx using LogFileNewCtx()
 *  \param filename name of log file
 *  \return -1 if failure, 0 if succesful
 * */
int AlertDebugLogOpenFileCtx(LogFileCtx *file_ctx, const char *filename)
{
    int ret=0;

    char log_path[PATH_MAX], *log_dir;
    if (ConfGet("default-log-dir", &log_dir) != 1)
        log_dir = DEFAULT_LOG_DIR;
    snprintf(log_path, PATH_MAX, "%s/%s", log_dir, DEFAULT_LOG_FILENAME);
    file_ctx->fp = fopen(log_path, "w");
    if (file_ctx->fp == NULL) {
        SCLogError(SC_ERR_FOPEN, "ERROR: failed to open %s: %s", log_path,
            strerror(errno));
        return -1;
    }

    return ret;
}


