/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * Logs alerts in a line based text format compatible to Snort's
 * alert_fast format.
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

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-reference.h"
#include "util-classification-config.h"

#include "output.h"
#include "alert-fastlog.h"

#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-logopenfile.h"
#include "util-time.h"

#include <mysql.h>

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

#define DEFAULT_LOG_FILENAME "fast.log"

#define MODULE_NAME "AlertFastLog"

/* The largest that size allowed for one alert string. */
#define MAX_FASTLOG_ALERT_SIZE 2048
/* The largest alert buffer that will be written at one time, possibly
 * holding multiple alerts. */
#define MAX_FASTLOG_BUFFER_SIZE (2 * MAX_FASTLOG_ALERT_SIZE)

TmEcode AlertFastLogThreadInit(ThreadVars *, const void *, void **);
TmEcode AlertFastLogThreadDeinit(ThreadVars *, void *);
void AlertFastLogRegisterTests(void);
static void AlertFastLogDeInitCtx(OutputCtx *);

int AlertFastLogCondition(ThreadVars *tv, const Packet *p);
int AlertFastLogger(ThreadVars *tv, void *data, const Packet *p);

const char * sig_file = "/etc/suricata/my.cnf";
int conf_file_exists;

void AlertFastLogRegister(void)
{
    OutputRegisterPacketModule(LOGGER_ALERT_FAST, MODULE_NAME, "fast",
        AlertFastLogInitCtx, AlertFastLogger, AlertFastLogCondition,
        AlertFastLogThreadInit, AlertFastLogThreadDeinit, NULL);
    AlertFastLogRegisterTests();
}

typedef struct AlertFastLogThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
} AlertFastLogThread;

int AlertFastLogCondition(ThreadVars *tv, const Packet *p)
{
    return (p->alerts.cnt ? TRUE : FALSE);
}

static inline void AlertFastLogOutputAlert(AlertFastLogThread *aft, char *buffer,
                                           int alert_size)
{
    /* Output the alert string and count alerts. Only need to lock here. */
    aft->file_ctx->Write(buffer, alert_size, aft->file_ctx);
}


int AlertFastLogger(ThreadVars *tv, void *data, const Packet *p)
{
  /*
    Create SQL connection to insert fast log data.
   */

    MYSQL *con;
    if(conf_file_exists == 0){
        con = mysql_init(NULL);
        const char * sig_file = "/etc/suricata/my.cnf";
        if(con == NULL){
          mysql_error(con);
          SCLogError(SC_ERR_OPENING_RULE_FILE, "No connection error.");
        }
        mysql_options(con, MYSQL_READ_DEFAULT_FILE, sig_file);
        if (mysql_real_connect(con, NULL, NULL, NULL, NULL, 0, NULL, 0) == NULL)
        {
            mysql_error(con);
            SCLogError(SC_ERR_OPENING_RULE_FILE, "Opening mysql database.");
        }
        if(con == NULL){
          mysql_error(con);
        }
        if (mysql_query(con, "SHOW TABLES LIKE 'fastlog'"))
        {
          mysql_error(con);
          SCLogError(SC_ERR_DATABASE, "No table called fastlog.");
        }
        else{
            MYSQL_RES *result = mysql_store_result(con);
            int exists_or_not = mysql_num_rows(result);
            if(exists_or_not == 0){
                if (mysql_query(con, "CREATE TABLE `fastlog` ( `id` int NOT NULL AUTO_INCREMENT, `timebuf` varchar(200) DEFAULT NULL, `action` varchar(100) DEFAULT NULL, `sid` varchar(100) DEFAULT NULL, `rev` varchar(100) DEFAULT NULL,  `msg` varchar(500) DEFAULT NULL, `class_msg` varchar(500) DEFAULT NULL, `priority` varchar(100) DEFAULT NULL, `protocol` varchar(200) DEFAULT NULL, `srcip` varchar(100) DEFAULT NULL, `srcport` varchar(100) DEFAULT NULL, `dstip` varchar(100) DEFAULT NULL, `dstport` varchar(100) DEFAULT NULL, PRIMARY KEY (`id`) )"))
                {
                    mysql_error(con);
                    SCLogError(SC_ERR_OPENING_RULE_FILE, "Could not create table fastlog");
                }
                else{
                    SCLogError(SC_ERR_DATABASE, "Created table fastlog.");
                }
            }
        }
    }
    /*
        SQL part end.
    */
    AlertFastLogThread *aft = (AlertFastLogThread *)data;
    int i;
    char timebuf[64];
    int decoder_event = 0;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[46], dstip[46];
    if (PKT_IS_IPV4(p)) {
        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
    } else if (PKT_IS_IPV6(p)) {
        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
    } else {
        decoder_event = 1;
    }

    /* Buffer to store the generated alert strings. The buffer is
     * filled with alert strings until it doesn't have room to store
     * another full alert, only then is the buffer written.  This is
     * more efficient for multiple alerts and only slightly slower for
     * single alerts.
     */

    char alert_buffer[MAX_FASTLOG_BUFFER_SIZE];

    //Add alert buffer for mysql query.
    char alert_buffer_mysql[MAX_FASTLOG_BUFFER_SIZE];

    char buf[MAX_FASTLOG_ALERT_SIZE];

    char proto[16] = "";
    char *protoptr;
    if (SCProtoNameValid(IP_GET_IPPROTO(p))) {
        protoptr = known_proto[IP_GET_IPPROTO(p)];
    } else {
        snprintf(proto, sizeof(proto), "PROTO:%03" PRIu32, IP_GET_IPPROTO(p));
        protoptr = proto;
    }
    uint16_t src_port_or_icmp = p->sp;
    uint16_t dst_port_or_icmp = p->dp;
    if (IP_GET_IPPROTO(p) == IPPROTO_ICMP || IP_GET_IPPROTO(p) == IPPROTO_ICMPV6) {
        src_port_or_icmp = p->icmp_s.type;
        dst_port_or_icmp = p->icmp_s.code;
    }
    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        const char *action = "";
        if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
            action = "[Drop] ";
        } else if (pa->action & ACTION_DROP) {
            action = "[wDrop] ";
        }
	else{
	  action = "[alert]";
	}

        /* Create the alert string without locking. */
        int size = 0;
	int length = 0;

        if (likely(decoder_event == 0)) {
            PrintBufferData(alert_buffer, &size, MAX_FASTLOG_ALERT_SIZE,
                            "%s  %s[**] [%" PRIu32 ":%" PRIu32 ":%"
                            PRIu32 "] %s [**] [Classification: %s] [Priority: %"PRIu32"]"
                            " {%s} %s:%" PRIu32 " -> %s:%" PRIu32 "\n", timebuf, action,
                            pa->s->gid, pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio,
                            protoptr, srcip, src_port_or_icmp, dstip, dst_port_or_icmp);

	    // Copy to the formatted mysql string to insert into the database
            if(conf_file_exists == 0){
                PrintBufferData(alert_buffer_mysql, &length, MAX_FASTLOG_ALERT_SIZE, "insert into fastlog  (timebuf, action, sid, rev, msg, class_msg, priority, protocol, srcip, srcport, dstip, dstport) values('%s', '%s', '%" PRIu32 "', '%" PRIu32 "', '%s', '%s', '%" PRIu32 "', '%s', '%s', '%" PRIu32 "', '%s', '%" PRIu32 "')",  timebuf, action, pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio, protoptr, srcip, src_port_or_icmp, dstip, dst_port_or_icmp);

                // copy only the data to buf and run the query on database
                //memcpy(buf, alert_buffer_mysql, length);

                // Log error with insert, & what it was
                if(mysql_real_query(con, alert_buffer_mysql, length + 1)){
                  SCLogError(SC_ERR_DATABASE, "Could not complete db query insert for fastlog :  %s", buf);
                };
            }
        }
         else {
            PrintBufferData(alert_buffer, &size, MAX_FASTLOG_ALERT_SIZE,
                            "%s  %s[**] [%" PRIu32 ":%" PRIu32
                            ":%" PRIu32 "] %s [**] [Classification: %s] [Priority: "
                            "%" PRIu32 "] [**] [Raw pkt: ", timebuf, action, pa->s->gid,
                            pa->s->id, pa->s->rev, pa->s->msg, pa->s->class_msg, pa->s->prio);
            PrintBufferRawLineHex(alert_buffer, &size, MAX_FASTLOG_ALERT_SIZE,
                                  GET_PKT_DATA(p), GET_PKT_LEN(p) < 32 ? GET_PKT_LEN(p) : 32);
            if (p->pcap_cnt != 0) {
                PrintBufferData(alert_buffer, &size, MAX_FASTLOG_ALERT_SIZE,
                                "] [pcap file packet: %"PRIu64"]\n", p->pcap_cnt);
            } else {
                PrintBufferData(alert_buffer, &size, MAX_FASTLOG_ALERT_SIZE, "]\n");
            }
        }

        /* Write the alert to output file */

        AlertFastLogOutputAlert(aft, alert_buffer, size);
    }

    if(conf_file_exists == 0){
        // Close the sql connection
        mysql_close(con);
    }

    return TM_ECODE_OK;
}

TmEcode AlertFastLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    AlertFastLogThread *aft = SCMalloc(sizeof(AlertFastLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(AlertFastLogThread));
    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for AlertFastLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }
    /** Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode AlertFastLogThreadDeinit(ThreadVars *t, void *data)
{
    AlertFastLogThread *aft = (AlertFastLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(AlertFastLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

/**
 * \brief Create a new LogFileCtx for "fast" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
OutputInitResult AlertFastLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("AlertFastLogInitCtx2: Could not create new LogFileCtx");
        return result;
    }

    if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return result;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(logfile_ctx);
        return result;
    }

    output_ctx->data = logfile_ctx;
    output_ctx->DeInit = AlertFastLogDeInitCtx;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static void AlertFastLogDeInitCtx(OutputCtx *output_ctx)
{
    LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
    LogFileFreeCtx(logfile_ctx);
    SCFree(output_ctx);
}

/*
Check fastlog db connection using the parameters of the default sql file in the suricata.yaml.
*/

int CheckMySqlConfExists(void){
int r = 0;
const char * pattern = "/etc/suricata/my.cnf";
#ifdef HAVE_GLOB_H
    glob_t files;
    r = glob(pattern, 0, NULL, &files);
    if (r == GLOB_NOMATCH) {
        SCLogWarning(SC_WARN_DATABASE, "To use database, include configuration options in the file: %s", pattern);
        return -1;
    } else if (r != 0) {
        SCLogError(SC_ERR_OPENING_RULE_FILE, "error expanding template %s: %s", pattern, strerror(errno));
        return -1;
    }
    for (size_t i = 0; i < (size_t)files.gl_pathc; i++) {
        char *fname = files.gl_pathv[i];
        if (strcmp("/dev/null", fname) == 0)
            continue;
#else
        char *fname = pattern;
        if (strcmp("/dev/null", fname) == 0)
            return 1;
#endif
        if (strcmp("/etc/suricata/my.cnf", fname) == 0){
            SCLogWarning(SC_WARN_DATABASE, "Found valid database configuration file. : %s", fname);
            return 0;
        }
#ifdef HAVE_GLOB_H
    }
    globfree(&files);
#endif
return 1; // added
}


/*------------------------------Unittests-------------------------------------*/

#ifdef UNITTESTS

static int AlertFastLogTest01(void)
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

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
            "(msg:\"FastLog test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1) {
        result = (strcmp(p->alerts.alerts[0].s->class_msg, "Unknown are we") == 0);
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    return result;
}

static int AlertFastLogTest02(void)
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

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
            "(msg:\"FastLog test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1) {
        result = (strcmp(p->alerts.alerts[0].s->class_msg,
                    "Unknown are we") == 0);
        if (result == 0)
            printf("p->alerts.alerts[0].class_msg %s: ", p->alerts.alerts[0].s->class_msg);
    }

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
void AlertFastLogRegisterTests(void)
{

#ifdef UNITTESTS

    UtRegisterTest("AlertFastLogTest01", AlertFastLogTest01);
    UtRegisterTest("AlertFastLogTest02", AlertFastLogTest02);

#endif /* UNITTESTS */

}
