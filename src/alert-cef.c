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
 * \author Giacomo Milani <giacomo83m@gmail.com>
 *
 * Logs alerts in Common Event Format - CEF
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

#include "output.h"
#include "alert-cef.h"

#include "util-privs.h"
#include "util-print.h"
#include "util-proto-name.h"
#include "util-optimize.h"
#include "util-logopenfile.h"
#include "util-time.h"

#include "app-layer-htp.h"
#include "app-layer.h"
#include "app-layer-parser.h"

#define DEFAULT_LOG_FILENAME "cef.log"

#define MODULE_NAME "AlertCEFLog"

/* The largest that size allowed for one alert string. */
#define MAX_CEFLOG_ALERT_SIZE 2048
/* The largest alert buffer that will be written at one time, possibly
 * holding multiple alerts. */
#define MAX_CEFLOG_BUFFER_SIZE (2 * MAX_CEFLOG_ALERT_SIZE)

TmEcode AlertCefLogThreadInit(ThreadVars *, void *, void **);
TmEcode AlertCefLogThreadDeinit(ThreadVars *, void *);
void AlertCefLogExitPrintStats(ThreadVars *, void *);
void AlertCefLogRegisterTests(void);
static void AlertCefLogDeInitCtx(OutputCtx *);

void CreateCefRecepitTime(const struct timeval *ts,char *str,size_t sz);
int AlertCefLogCondition(ThreadVars *tv, const Packet *p);
int AlertCefLogger(ThreadVars *tv, void *data, const Packet *p);

void TmModuleAlertCefLogRegister (void) {
    tmm_modules[TMM_ALERTCEFLOG].name = MODULE_NAME;
    tmm_modules[TMM_ALERTCEFLOG].ThreadInit = AlertCefLogThreadInit;
    tmm_modules[TMM_ALERTCEFLOG].ThreadExitPrintStats = AlertCefLogExitPrintStats;
    tmm_modules[TMM_ALERTCEFLOG].ThreadDeinit = AlertCefLogThreadDeinit;
    tmm_modules[TMM_ALERTCEFLOG].RegisterTests = AlertCefLogRegisterTests;
    tmm_modules[TMM_ALERTCEFLOG].cap_flags = 0;
    tmm_modules[TMM_ALERTCEFLOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterPacketModule(MODULE_NAME, "cef",
            AlertCefLogInitCtx, AlertCefLogger, AlertCefLogCondition);
}

typedef struct AlertCefLogThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx* file_ctx;
    const char *device_name;
    int http_extensions;
    int short_labels;
} AlertCefLogThread;

int AlertCefLogCondition(ThreadVars *tv, const Packet *p) {
    return (p->alerts.cnt ? TRUE : FALSE);
}

/* TODO: should be moved to util-time.c */
void CreateCefRecepitTime (const struct timeval *ts, char *str,size_t size) {
    snprintf(str,size,"%lu%04lu",ts->tv_sec,(ts->tv_usec/1000));
}

static inline void AlertCefLogOutputAlert(AlertCefLogThread *aft, char *buffer,
                                           int alert_size)
{
    SCMutex *file_lock = &aft->file_ctx->fp_mutex;
    /* Output the alert string and count alerts. Only need to lock here. */
    SCMutexLock(file_lock);
    aft->file_ctx->alerts++;
    aft->file_ctx->Write(buffer, alert_size, aft->file_ctx);
    SCMutexUnlock(file_lock);
}

static inline void AlertCefLoggerHttp(const Packet *p, char *alert_buffer, int *psize) 
{
    /* Print HTTP Fields using CEF Dictionary Extension */
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if ( htp_state ) {
        uint64_t tx_id = AppLayerParserGetTransactionLogId(p->flow->alparser);
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, tx_id);
        if (tx) {
            char *method = NULL;
            if ( (method = bstr_util_strdup_to_c(tx->request_method)) ) {
                PrintBufferData(alert_buffer,psize,MAX_CEFLOG_ALERT_SIZE,
                                " requestMethod=%s",method);
                SCFree ( method );
            }
            char *uri = NULL;
            if ( (uri = bstr_util_strdup_to_c(tx->request_uri)) ) {
                PrintBufferData(alert_buffer,psize,MAX_CEFLOG_ALERT_SIZE,
                                " request=%s",uri);
                SCFree (uri);
            }
            char *host = NULL;
            if ( (host = bstr_util_strdup_to_c(tx->request_hostname)) ) {
                PrintBufferData(alert_buffer,psize,MAX_CEFLOG_ALERT_SIZE,
                                " dhost=%s",host);
                SCFree (host);
            }

            htp_header_t *agent_h;
            if ( (agent_h = htp_table_get_c(tx->request_headers,"user-agent")) ) {
                char *agent = bstr_util_strdup_to_c(agent_h->value);
                if ( agent ) {
                    PrintBufferData(alert_buffer,psize,MAX_CEFLOG_ALERT_SIZE,
                                    " requestClientApplication=%s",agent);
                    SCFree (agent);
                }
            }
            
            /* CEF is missing a key for referer header, but provide way to add custom key
             * and relative label: csX= csXLabel where cs means Costum String */
            const char *header_tx_v[] = {"referer","x-forwarded-for","via"};
            unsigned int header_tx_v_sz = 3; 

            for ( unsigned int i = 0; i < header_tx_v_sz; i++ ) {
                htp_header_t *ptr_h;
                if ( (ptr_h = htp_table_get_c(tx->request_headers,header_tx_v[i])) ) {
                    char *ptr = bstr_util_strdup_to_c(ptr_h->value);
                    if ( ptr ) {
                        PrintBufferData(alert_buffer,psize,MAX_CEFLOG_ALERT_SIZE,
                                        " cs%d=%s cs%dLabel=%s",i,ptr,i,header_tx_v[i]);
                        SCFree (ptr);
                    }
                }
            }

            /* Process Http Responses */
            char *status;
            if ( (status = bstr_util_strdup_to_c(tx->response_status)) ) {
                PrintBufferData(alert_buffer,psize,MAX_CEFLOG_ALERT_SIZE,
                        " cs%d=%s cs%dLabel=%s",header_tx_v_sz,status,header_tx_v_sz,"status");
                SCFree (status);
            }

            const char *header_rx_v[] = {"content-length","content-type","server","transfer-encoding","location"};
            unsigned int header_rx_v_sz = 5;
            for ( unsigned int i = 0; i < header_rx_v_sz; i++ ) {
                htp_header_t *ptr_h;
                if ( (ptr_h = htp_table_get_c(tx->response_headers,header_rx_v[i])) ) {
                    char *ptr = bstr_util_strdup_to_c(ptr_h->value);
                    if ( ptr ) {
                        PrintBufferData(alert_buffer,psize,MAX_CEFLOG_ALERT_SIZE,
                                        " cs%d=%s cs%dLabel=%s",i+1+header_tx_v_sz,ptr,i+1+header_tx_v_sz,header_rx_v[i]);
                        SCFree (ptr);
                    }
                }
            }
                
        }
    } 
}

static inline void AlertCefLoggerHttpShort(const Packet *p, char *alert_buffer, int *psize) 
{
    /* Print HTTP Fields using CEF Dictionary Extension */
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if ( htp_state ) {
        uint64_t tx_id = AppLayerParserGetTransactionLogId(p->flow->alparser);
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, tx_id);
        if (tx) {
            char *method = NULL;
            if ( (method = bstr_util_strdup_to_c(tx->request_method)) ) {
                PrintBufferData(alert_buffer,psize,MAX_CEFLOG_ALERT_SIZE,
                                " method=%s",method);
                SCFree ( method );
            }
            char *uri = NULL;
            if ( (uri = bstr_util_strdup_to_c(tx->request_uri)) ) {
                PrintBufferData(alert_buffer,psize,MAX_CEFLOG_ALERT_SIZE,
                                " request=%s",uri);
                SCFree (uri);
            }
            char *host = NULL;
            if ( (host = bstr_util_strdup_to_c(tx->request_hostname)) ) {
                PrintBufferData(alert_buffer,psize,MAX_CEFLOG_ALERT_SIZE,
                                " host=%s",host);
                SCFree (host);
            }

            htp_header_t *agent_h;
            if ( (agent_h = htp_table_get_c(tx->request_headers,"user-agent")) ) {
                char *agent = bstr_util_strdup_to_c(agent_h->value);
                if ( agent ) {
                    PrintBufferData(alert_buffer,psize,MAX_CEFLOG_ALERT_SIZE,
                                    " agent=%s",agent);
                    SCFree (agent);
                }
            }
            
            /* CEF is missing a key for referer header, but provide way to add custom key
             * and relative label: csX= csXLabel where cs means Costum String */
            const char *header_tx_v[] = {"referer","x-forwarded-for","via"};
            const char *header_tx_k[] = {"referer","forwardedFor","via"};
            unsigned int header_tx_v_sz = 3; 

            for ( unsigned int i = 0; i < header_tx_v_sz; i++ ) {
                htp_header_t *ptr_h;
                if ( (ptr_h = htp_table_get_c(tx->request_headers,header_tx_v[i])) ) {
                    char *ptr = bstr_util_strdup_to_c(ptr_h->value);
                    if ( ptr ) {
                        PrintBufferData(alert_buffer,psize,MAX_CEFLOG_ALERT_SIZE,
                                        " %s=%s",header_tx_k[i],ptr);
                        SCFree (ptr);
                    }
                }
            }

            /* Process Http Responses */
            char *status;
            if ( (status = bstr_util_strdup_to_c(tx->response_status)) ) {
                PrintBufferData(alert_buffer,psize,MAX_CEFLOG_ALERT_SIZE,
                        " status=%s",status);
                SCFree (status);
            }

            const char *header_rx_v[] = {"content-length","content-type","server","transfer-encoding","location"};
            const char *header_rx_k[] = {"contentLen","contentType","server","encoding","location"};
            unsigned int header_rx_v_sz = 5;
            for ( unsigned int i = 0; i < header_rx_v_sz; i++ ) {
                htp_header_t *ptr_h;
                if ( (ptr_h = htp_table_get_c(tx->response_headers,header_rx_v[i])) ) {
                    char *ptr = bstr_util_strdup_to_c(ptr_h->value);
                    if ( ptr ) {
                        PrintBufferData(alert_buffer,psize,MAX_CEFLOG_ALERT_SIZE,
                                        " %s=%s",header_rx_k[i],ptr);
                        SCFree (ptr);
                    }
                }
            }
                
        }
    } 
}



int AlertCefLogger(ThreadVars *tv, void *data, const Packet *p)
{
    AlertCefLogThread *aft = (AlertCefLogThread *)data;
    int raw_print = 0;
    int i = 0;

    /* Prepare Arguments */
    /* CEF Key: rt ( receiptTime ) */
    
    char rt[64];
    CreateCefRecepitTime(&p->ts, rt, sizeof(rt));
    
    /* CEF Keys: src,dst */
    char src[46], dst[46];
    if (PKT_IS_IPV4(p)) {
        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), src, sizeof(src));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dst, sizeof(dst));
    } else if (PKT_IS_IPV6(p)) {
        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), src, sizeof(src));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dst, sizeof(dst));
    } else {
        raw_print = 1;
    }

    /* Prepare Buffer for Log String */
    char alert_buffer[MAX_CEFLOG_BUFFER_SIZE];

    for (i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }
    
        /* CEF Key: act ( Action ) */
        char *act;
        if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
            act = "drop";
        } else if (pa->action & ACTION_DROP) {
            act = "wdrop";
        } else {
            act = "alert";
        }                                                                                                                          
        /* CEF Keys: proto ( Network Protocol ) */
        char proto[16] = "";
        if (SCProtoNameValid(IP_GET_IPPROTO(p)) == TRUE) {
            strlcpy(proto, known_proto[IP_GET_IPPROTO(p)], sizeof(proto));
        } else {
            snprintf(proto, sizeof(proto), "%03" PRIu32, IP_GET_IPPROTO(p));
        }
    
        /* Prepare Log String */
        int size = 0;
        if ( unlikely(raw_print == 1) ) { /* Print Raw Packet */
            PrintBufferData (alert_buffer, &size, MAX_CEFLOG_ALERT_SIZE, 
                            "CEF:0|IOSF|%s|%s|%"PRIu32":%"PRIu32":%"PRIu32"|"
                            "%s|%"PRIu32"|rt=%s act=%s proto=%s cat=%s "
                            "cs1=",
                            aft->device_name,PROG_VER,pa->s->gid,pa->s->id,pa->s->rev,
                            pa->s->msg,pa->s->prio,rt, act, proto, pa->s->class_msg
                    );

            PrintBufferRawLineHex(alert_buffer, &size, MAX_CEFLOG_ALERT_SIZE,
                                  GET_PKT_DATA(p), GET_PKT_LEN(p) < 32 ? GET_PKT_LEN(p) : 32);

            PrintBufferData(alert_buffer, &size, MAX_CEFLOG_ALERT_SIZE,
                            " cs1Label=RawPkt");

            if (p->pcap_cnt != 0) {
                PrintBufferData(alert_buffer, &size, MAX_CEFLOG_ALERT_SIZE, 
                                " cs2=%"PRIu64" cs2Label=PcapPacket", p->pcap_cnt);
            }
        }
        else { /* Standard Print */
            PrintBufferData (alert_buffer,&size,MAX_CEFLOG_ALERT_SIZE,
                    "CEF:0|OISF|%s|%s|%"PRIu32":%"PRIu32":%"PRIu32"|"
                    "%s|%"PRIu32"|rt=%s act=%s proto=%s src=%s spt=%"PRIu32""
                    " dst=%s dpt=%"PRIu32" msg=%s",
                    aft->device_name,PROG_VER,pa->s->gid,pa->s->id,pa->s->rev,
                    pa->s->class_msg,pa->s->prio,rt,act,proto,src,p->sp,
                    dst,p->dp,pa->s->msg
                );
    
            if ( likely(raw_print == 0 && p->flow) ) {
                /* Print CEF Key: Service ( Service Protocol )*/
                if (p->flow->flags & STREAM_TOSERVER && p->flow->alproto_ts ) {
                    PrintBufferData(alert_buffer,&size,MAX_CEFLOG_ALERT_SIZE,
                            " service=%s",AppProtoToString(p->flow->alproto_ts ));
                } else if( p->flow->alproto_tc ) {
                    PrintBufferData(alert_buffer,&size,MAX_CEFLOG_ALERT_SIZE,
                            " service=%s",AppProtoToString(p->flow->alproto_tc ));
                }         
            }
    
            if (likely(aft->http_extensions)) {
                if (p->flow->alproto_ts == ALPROTO_HTTP || p->flow->alproto_tc == ALPROTO_HTTP) {
                    if ( likely(aft->short_labels ))
                        AlertCefLoggerHttpShort(p,alert_buffer,&size);
                    else
                        AlertCefLoggerHttp(p,alert_buffer,&size);
                }
            } 

        } /* end Standard Print */

        /* Write the alert to output file */
        PrintBufferData(alert_buffer,&size,MAX_CEFLOG_ALERT_SIZE,"\n");
        AlertCefLogOutputAlert(aft, alert_buffer, size);
    } 

    return TM_ECODE_OK;
}

TmEcode AlertCefLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for AlertCefLog.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    *data =  ((OutputCtx *)initdata)->data;  
    return TM_ECODE_OK;
}

TmEcode AlertCefLogThreadDeinit(ThreadVars *t, void *data)
{
    return TM_ECODE_OK;
}

void AlertCefLogExitPrintStats(ThreadVars *tv, void *data)
{
    AlertCefLogThread *aft = (AlertCefLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("Cef log output wrote %" PRIu64 " alerts", aft->file_ctx->alerts);
}

/**
 * \brief Create a new LogFileCtx for "cef" output style.
 * \param conf The configuration node for this output.
 * \return A LogFileCtx pointer on success, NULL on failure.
 */
OutputCtx *AlertCefLogInitCtx(ConfNode *conf)
{
    LogFileCtx *logfile_ctx = LogFileNewCtx();
    if (logfile_ctx == NULL) {
        SCLogDebug("AlertCefLogInitCtx2: Could not create new LogFileCtx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, logfile_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(logfile_ctx);
        return NULL;
    }

    AlertCefLogThread *aft = SCMalloc(sizeof(AlertCefLogThread));                                                                                                                                
    if (unlikely(aft == NULL))
        return NULL;
    memset(aft, 0, sizeof(AlertCefLogThread));

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;

    aft->file_ctx = logfile_ctx;
    aft->device_name = ConfNodeLookupChildValue(conf,"devicename");
    if ( ConfNodeChildValueIsTrue(conf,"httpextension") )
        aft->http_extensions = 1;
    else
        aft->http_extensions = 0;
    if ( ConfNodeChildValueIsTrue(conf,"shortlabels") )
        aft->short_labels = 1;
    else
        aft->short_labels = 0;

    output_ctx->data = aft;
    output_ctx->DeInit = AlertCefLogDeInitCtx;

    return output_ctx;
}

static void AlertCefLogDeInitCtx(OutputCtx *output_ctx)
{
    AlertCefLogThread *aft = (AlertCefLogThread *)output_ctx->data;

    LogFileCtx *logfile_ctx = (LogFileCtx *)aft->file_ctx;
    LogFileFreeCtx(logfile_ctx);

    if (aft != NULL) {
        /* clear memory */
        memset(aft, 0, sizeof(AlertCefLogThread));
        SCFree(aft);
    }

    SCFree(output_ctx);
}

/*------------------------------Unittests-------------------------------------*/

#ifdef UNITTESTS

static int AlertCefLogTest01()
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
            "(msg:\"CefLog test\"; content:\"GET\"; "
            "Classtype:unknown; sid:1;)");
    result = (de_ctx->sig_list != NULL);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt == 1)
        result = (strcmp(p->alerts.alerts[0].s->class_msg, "Unknown are we") == 0);
    else
        result = 0;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    return result;
}

static int AlertCefLogTest02()
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
            "(msg:\"CefLog test\"; content:\"GET\"; "
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

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for AlertCefLog API.
 */
void AlertCefLogRegisterTests(void)
{

#ifdef UNITTESTS

    UtRegisterTest("AlertCefLogTest01", AlertCefLogTest01, 1);
    UtRegisterTest("AlertCefLogTest02", AlertCefLogTest02, 1);

#endif /* UNITTESTS */

}
