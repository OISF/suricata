/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Logs alerts in a line based text format in to syslog.
 *
 */

#include "suricata-common.h"
#include "debug.h"
#include "flow.h"
#include "conf.h"

#include "threads.h"
#include "tm-threads.h"
#include "threadvars.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"

#include "output.h"
#include "alert-syslog.h"

#include "util-classification-config.h"
#include "util-debug.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-syslog.h"
#include "util-optimize.h"
#include "util-logopenfile.h"

#ifndef OS_WIN32

#define DEFAULT_ALERT_SYSLOG_FACILITY_STR       "local0"
#define DEFAULT_ALERT_SYSLOG_FACILITY           LOG_LOCAL0
#define DEFAULT_ALERT_SYSLOG_LEVEL              LOG_ERR
#define MODULE_NAME                             "AlertSyslog"

static int alert_syslog_level = DEFAULT_ALERT_SYSLOG_LEVEL;

typedef struct AlertSyslogThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
} AlertSyslogThread;

/**
 * \brief Function to clear the memory of the output context and closes the
 *        syslog interface
 *
 * \param output_ctx pointer to the output context to be cleared
 */
static void AlertSyslogDeInitCtx(OutputCtx *output_ctx)
{
    if (output_ctx != NULL) {
        LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
        if (logfile_ctx != NULL) {
            LogFileFreeCtx(logfile_ctx);
        }
        SCFree(output_ctx);
    }
    closelog();
}

/**
 * \brief Create a new LogFileCtx for "syslog" output style.
 *
 * \param conf The configuration node for this output.
 * \return A OutputCtx pointer on success, NULL on failure.
 */
OutputCtx *AlertSyslogInitCtx(ConfNode *conf)
{
    const char *facility_s = ConfNodeLookupChildValue(conf, "facility");
    if (facility_s == NULL) {
        facility_s = DEFAULT_ALERT_SYSLOG_FACILITY_STR;
    }

    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("AlertSyslogInitCtx: Could not create new LogFileCtx");
        return NULL;
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

    OutputCtx *output_ctx = SCMalloc(sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCLogDebug("AlertSyslogInitCtx: Could not create new OutputCtx");
        return NULL;
    }
    memset(output_ctx, 0x00, sizeof(OutputCtx));

    output_ctx->data = logfile_ctx;
    output_ctx->DeInit = AlertSyslogDeInitCtx;

    SCLogInfo("Syslog output initialized");

    return output_ctx;
}

/**
 * \brief Function to initialize the AlertSystlogThread and sets the output
 *        context pointer
 *
 * \param tv            Pointer to the threadvars
 * \param initdata      Pointer to the output context
 * \param data          pointer to pointer to point to the AlertSyslogThread
 */
static TmEcode AlertSyslogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    if(initdata == NULL) {
        SCLogDebug("Error getting context for AlertSyslog. \"initdata\" "
                "argument NULL");
        return TM_ECODE_FAILED;
    }

    AlertSyslogThread *ast = SCMalloc(sizeof(AlertSyslogThread));
    if (unlikely(ast == NULL))
        return TM_ECODE_FAILED;

    memset(ast, 0, sizeof(AlertSyslogThread));

    /** Use the Ouptut Context (file pointer and mutex) */
    ast->file_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)ast;
    return TM_ECODE_OK;
}

/**
 * \brief Function to deinitialize the AlertSystlogThread
 *
 * \param tv            Pointer to the threadvars
 * \param data          pointer to the AlertSyslogThread to be cleared
 */
static TmEcode AlertSyslogThreadDeinit(ThreadVars *t, void *data)
{
    AlertSyslogThread *ast = (AlertSyslogThread *)data;
    if (ast == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(ast, 0, sizeof(AlertSyslogThread));

    SCFree(ast);
    return TM_ECODE_OK;
}

/**
 * \brief   Function which is called to print the IPv4 alerts to the syslog
 *
 * \param tv    Pointer to the threadvars
 * \param p     Pointer to the packet
 * \param data  pointer to the AlertSyslogThread
 *
 * \return On succes return TM_ECODE_OK
 */
static TmEcode AlertSyslogIPv4(ThreadVars *tv, const Packet *p, void *data)
{
    AlertSyslogThread *ast = (AlertSyslogThread *)data;
    int i;
    char *action = "";

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    SCMutexLock(&ast->file_ctx->fp_mutex);

    ast->file_ctx->alerts += p->alerts.cnt;

    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        char srcip[16], dstip[16];

        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));

        if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
            action = "[Drop] ";
        } else if (pa->action & ACTION_DROP) {
            action = "[wDrop] ";
        }

        if (SCProtoNameValid(IPV4_GET_IPPROTO(p)) == TRUE) {
            syslog(alert_syslog_level, "%s[%" PRIu32 ":%" PRIu32 ":%"
                    PRIu32 "] %s [Classification: %s] [Priority: %"PRIu32"]"
                    " {%s} %s:%" PRIu32 " -> %s:%" PRIu32 "", action, pa->s->gid,
                    pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio,
                    known_proto[IPV4_GET_IPPROTO(p)], srcip, p->sp, dstip, p->dp);
        } else {
            syslog(alert_syslog_level, "%s[%" PRIu32 ":%" PRIu32 ":%"
                    PRIu32 "] %s [Classification: %s] [Priority: %"PRIu32"]"
                    " {PROTO:%03" PRIu32 "} %s:%" PRIu32 " -> %s:%" PRIu32 "",
                    action, pa->s->gid, pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg,
                    pa->s->prio, IPV4_GET_IPPROTO(p), srcip, p->sp, dstip, p->dp);
        }
    }
    SCMutexUnlock(&ast->file_ctx->fp_mutex);

    return TM_ECODE_OK;
}

/**
 * \brief   Function which is called to print the IPv6 alerts to the syslog
 *
 * \param tv    Pointer to the threadvars
 * \param p     Pointer to the packet
 * \param data  pointer to the AlertSyslogThread
 *
 * \return On succes return TM_ECODE_OK
 */
static TmEcode AlertSyslogIPv6(ThreadVars *tv, const Packet *p, void *data)
{
    AlertSyslogThread *ast = (AlertSyslogThread *)data;
    int i;
    char *action = "";

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    SCMutexLock(&ast->file_ctx->fp_mutex);

    ast->file_ctx->alerts += p->alerts.cnt;

    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        char srcip[46], dstip[46];

        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));

        if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
            action = "[Drop] ";
        } else if (pa->action & ACTION_DROP) {
            action = "[wDrop] ";
        }

        if (SCProtoNameValid(IPV6_GET_L4PROTO(p)) == TRUE) {
            syslog(alert_syslog_level, "%s[%" PRIu32 ":%" PRIu32 ":%"
                    "" PRIu32 "] %s [Classification: %s] [Priority: %"
                    "" PRIu32 "] {%s} %s:%" PRIu32 " -> %s:%" PRIu32 "",
                    action, pa->s->gid, pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg,
                    pa->s->prio, known_proto[IPV6_GET_L4PROTO(p)], srcip, p->sp,
                    dstip, p->dp);

        } else {
            syslog(alert_syslog_level, "%s[%" PRIu32 ":%" PRIu32 ":%"
                    "" PRIu32 "] %s [Classification: %s] [Priority: %"
                    "" PRIu32 "] {PROTO:%03" PRIu32 "} %s:%" PRIu32 " -> %s:%" PRIu32 "",
                    action, pa->s->gid, pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg,
                    pa->s->prio, IPV6_GET_L4PROTO(p), srcip, p->sp, dstip, p->dp);
        }

    }
    SCMutexUnlock(&ast->file_ctx->fp_mutex);

    return TM_ECODE_OK;
}

/**
 * \brief   Function which is called to print the decode alerts to the syslog
 *
 * \param tv    Pointer to the threadvars
 * \param p     Pointer to the packet
 * \param data  pointer to the AlertSyslogThread
 * \param pq    pointer the to packet queue
 * \param postpq pointer to the post processed packet queue
 *
 * \return On succes return TM_ECODE_OK
 */
static TmEcode AlertSyslogDecoderEvent(ThreadVars *tv, const Packet *p, void *data)
{
    AlertSyslogThread *ast = (AlertSyslogThread *)data;
    int i;
    char *action = "";

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    SCMutexLock(&ast->file_ctx->fp_mutex);

    ast->file_ctx->alerts += p->alerts.cnt;
    char temp_buf_hdr[512];
    char temp_buf_pkt[65] = "";
    char temp_buf_tail[32];
    char alert[2048] = "";

    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
            action = "[Drop] ";
        } else if (pa->action & ACTION_DROP) {
            action = "[wDrop] ";
        }

        snprintf(temp_buf_hdr, sizeof(temp_buf_hdr), "%s[%" PRIu32 ":%" PRIu32
                ":%" PRIu32 "] %s [Classification: %s] [Priority: %" PRIu32
                "] [**] [Raw pkt: ", action, pa->s->gid, pa->s->id, pa->s->rev, pa->s->msg,
                pa->s->class_msg, pa->s->prio);
        strlcpy(alert, temp_buf_hdr, sizeof(alert));

        PrintRawLineHexBuf(temp_buf_pkt, sizeof(temp_buf_pkt), GET_PKT_DATA(p), GET_PKT_LEN(p) < 32 ? GET_PKT_LEN(p) : 32);
        strlcat(alert, temp_buf_pkt, sizeof(alert));

        if (p->pcap_cnt != 0) {
            snprintf(temp_buf_tail, sizeof(temp_buf_tail), "] [pcap file packet: %"PRIu64"]",
                    p->pcap_cnt);
        } else {
            temp_buf_tail[0] = ']';
            temp_buf_tail[1] = '\0';
        }
        strlcat(alert, temp_buf_tail, sizeof(alert));

        syslog(alert_syslog_level, "%s", alert);
    }
    SCMutexUnlock(&ast->file_ctx->fp_mutex);

    return TM_ECODE_OK;
}

/**
 * \brief   Function to print the total alert while closing the engine
 *
 * \param tv    Pointer to the output threadvars
 * \param data  Pointer to the AlertSyslogThread data
 */
static void AlertSyslogExitPrintStats(ThreadVars *tv, void *data)
{
    AlertSyslogThread *ast = (AlertSyslogThread *)data;
    if (ast == NULL) {
        return;
    }

    SCLogInfo("(%s) Alerts %" PRIu64 "", tv->name, ast->file_ctx->alerts);
}

static int AlertSyslogCondition(ThreadVars *tv, const Packet *p)
{
    return (p->alerts.cnt > 0 ? TRUE : FALSE);
}

static int AlertSyslogLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    if (PKT_IS_IPV4(p)) {
        return AlertSyslogIPv4(tv, p, thread_data);
    } else if (PKT_IS_IPV6(p)) {
        return AlertSyslogIPv6(tv, p, thread_data);
    } else if (p->events.cnt > 0) {
        return AlertSyslogDecoderEvent(tv, p, thread_data);
    }

    return TM_ECODE_OK;
}

#endif /* !OS_WIN32 */

/** \brief   Function to register the AlertSyslog module */
void TmModuleAlertSyslogRegister (void)
{
#ifndef OS_WIN32
    tmm_modules[TMM_ALERTSYSLOG].name = MODULE_NAME;
    tmm_modules[TMM_ALERTSYSLOG].ThreadInit = AlertSyslogThreadInit;
    tmm_modules[TMM_ALERTSYSLOG].Func = NULL;
    tmm_modules[TMM_ALERTSYSLOG].ThreadExitPrintStats = AlertSyslogExitPrintStats;
    tmm_modules[TMM_ALERTSYSLOG].ThreadDeinit = AlertSyslogThreadDeinit;
    tmm_modules[TMM_ALERTSYSLOG].RegisterTests = NULL;
    tmm_modules[TMM_ALERTSYSLOG].cap_flags = 0;
    tmm_modules[TMM_ALERTSYSLOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterPacketModule(MODULE_NAME, "syslog",
        AlertSyslogInitCtx, AlertSyslogLogger, AlertSyslogCondition);

#endif /* !OS_WIN32 */
}
