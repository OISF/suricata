/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * Logs alerts in a line based text format into syslog.
 *
 */

#include "suricata-common.h"
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
#include "action-globals.h"

#ifndef OS_WIN32

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
static OutputInitResult AlertSyslogInitCtx(ConfNode *conf)
{
    SCLogWarning("The syslog output has been deprecated and will be removed in Suricata 9.0.");

    OutputInitResult result = { NULL, false };
    const char *facility_s = ConfNodeLookupChildValue(conf, "facility");
    if (facility_s == NULL) {
        facility_s = DEFAULT_ALERT_SYSLOG_FACILITY_STR;
    }

    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("AlertSyslogInitCtx: Could not create new LogFileCtx");
        return result;
    }

    int facility = SCMapEnumNameToValue(facility_s, SCSyslogGetFacilityMap());
    if (facility == -1) {
        SCLogWarning("Invalid syslog facility: \"%s\","
                     " now using \"%s\" as syslog facility",
                facility_s, DEFAULT_ALERT_SYSLOG_FACILITY_STR);
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

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCLogDebug("could not create new OutputCtx");
        LogFileFreeCtx(logfile_ctx);
        return result;
    }

    output_ctx->data = logfile_ctx;
    output_ctx->DeInit = AlertSyslogDeInitCtx;

    SCLogInfo("Syslog output initialized");

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/**
 * \brief Function to initialize the AlertSyslogThread and sets the output
 *        context pointer
 *
 * \param tv            Pointer to the threadvars
 * \param initdata      Pointer to the output context
 * \param data          pointer to pointer to point to the AlertSyslogThread
 */
static TmEcode AlertSyslogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    if(initdata == NULL) {
        SCLogDebug("Error getting context for AlertSyslog. \"initdata\" "
                "argument NULL");
        return TM_ECODE_FAILED;
    }

    AlertSyslogThread *ast = SCCalloc(1, sizeof(AlertSyslogThread));
    if (unlikely(ast == NULL))
        return TM_ECODE_FAILED;

    /** Use the Output Context (file pointer and mutex) */
    ast->file_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)ast;
    return TM_ECODE_OK;
}

/**
 * \brief Function to deinitialize the AlertSyslogThread
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
    const char *action = "";

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    char proto[16] = "";
    const char *protoptr;
    const IPV4Hdr *ipv4h = PacketGetIPv4(p);
    const uint8_t ipproto = IPV4_GET_RAW_IPPROTO(ipv4h);
    if (SCProtoNameValid(ipproto)) {
        protoptr = known_proto[ipproto];
    } else {
        snprintf(proto, sizeof(proto), "PROTO:%03" PRIu8, ipproto);
        protoptr = proto;
    }

    char srcip[16], dstip[16];
    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));

    for (int i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
            action = "[Drop] ";
        } else if (pa->action & ACTION_DROP) {
            action = "[wDrop] ";
        }

        /* Not sure if this mutex is needed around calls to syslog. */
        SCMutexLock(&ast->file_ctx->fp_mutex);
        syslog(alert_syslog_level, "%s[%" PRIu32 ":%" PRIu32 ":%"
                PRIu32 "] %s [Classification: %s] [Priority: %"PRIu32"]"
                " {%s} %s:%" PRIu32 " -> %s:%" PRIu32 "", action, pa->s->gid,
                pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio,
                protoptr,  srcip, p->sp, dstip, p->dp);
        SCMutexUnlock(&ast->file_ctx->fp_mutex);
    }

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
    const char *action = "";

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    char proto[16] = "";
    const char *protoptr;
    const uint8_t ipproto = IPV6_GET_L4PROTO(p);
    if (SCProtoNameValid(ipproto)) {
        protoptr = known_proto[ipproto];
    } else {
        snprintf(proto, sizeof(proto), "PROTO:03%" PRIu8, ipproto);
        protoptr = proto;
    }

    char srcip[46], dstip[46];
    PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
    PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));

    for (int i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
            action = "[Drop] ";
        } else if (pa->action & ACTION_DROP) {
            action = "[wDrop] ";
        }

        SCMutexLock(&ast->file_ctx->fp_mutex);
        syslog(alert_syslog_level, "%s[%" PRIu32 ":%" PRIu32 ":%"
                "" PRIu32 "] %s [Classification: %s] [Priority: %"
                "" PRIu32 "] {%s} %s:%" PRIu32 " -> %s:%" PRIu32 "",
                action, pa->s->gid, pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg,
                pa->s->prio, protoptr, srcip, p->sp,
                dstip, p->dp);
        SCMutexUnlock(&ast->file_ctx->fp_mutex);
    }

    return TM_ECODE_OK;
}

/**
 * \brief   Function which is called to print the decode alerts to the syslog
 *
 * \param tv    Pointer to the threadvars
 * \param p     Pointer to the packet
 * \param data  pointer to the AlertSyslogThread
 *
 * \return On succes return TM_ECODE_OK
 */
static TmEcode AlertSyslogDecoderEvent(ThreadVars *tv, const Packet *p, void *data)
{
    AlertSyslogThread *ast = (AlertSyslogThread *)data;
    const char *action = "";

    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    char temp_buf_hdr[512];
    char temp_buf_pkt[65] = "";
    char temp_buf_tail[64];
    char alert[2048] = "";

    for (int i = 0; i < p->alerts.cnt; i++) {
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

        SCMutexLock(&ast->file_ctx->fp_mutex);
        syslog(alert_syslog_level, "%s", alert);
        SCMutexUnlock(&ast->file_ctx->fp_mutex);
    }

    return TM_ECODE_OK;
}

static bool AlertSyslogCondition(ThreadVars *tv, void *thread_data, const Packet *p)
{
    return (p->alerts.cnt > 0);
}

static int AlertSyslogLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    if (PacketIsIPv4(p)) {
        return AlertSyslogIPv4(tv, p, thread_data);
    } else if (PacketIsIPv6(p)) {
        return AlertSyslogIPv6(tv, p, thread_data);
    } else if (p->events.cnt > 0) {
        return AlertSyslogDecoderEvent(tv, p, thread_data);
    }

    return TM_ECODE_OK;
}

#endif /* !OS_WIN32 */

/** \brief   Function to register the AlertSyslog module */
void AlertSyslogRegister (void)
{
#ifndef OS_WIN32
    OutputPacketLoggerFunctions output_logger_functions = {
        .LogFunc = AlertSyslogLogger,
        .FlushFunc = NULL,
        .ConditionFunc = AlertSyslogCondition,
        .ThreadInitFunc = AlertSyslogThreadInit,
        .ThreadDeinitFunc = AlertSyslogThreadDeinit,
        .ThreadExitPrintStatsFunc = NULL,
    };
    OutputRegisterPacketModule(LOGGER_ALERT_SYSLOG, MODULE_NAME, "syslog", AlertSyslogInitCtx,
            &output_logger_functions);
#endif /* !OS_WIN32 */
}
