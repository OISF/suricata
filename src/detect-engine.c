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
 */

#include "suricata-common.h"
#include "suricata.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "flow-private.h"
#include "flow-util.h"
#include "flow-worker.h"
#include "conf.h"
#include "conf-yaml-loader.h"

#include "app-layer-htp.h"

#include "detect-parse.h"
#include "detect-engine-sigorder.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-hcbd.h"
#include "detect-engine-iponly.h"
#include "detect-engine-tag.h"

#include "detect-engine-uri.h"
#include "detect-engine-hsbd.h"
#include "detect-engine-hhd.h"
#include "detect-engine-hrhd.h"
#include "detect-engine-hmd.h"
#include "detect-engine-hcd.h"
#include "detect-engine-hrud.h"
#include "detect-engine-hrl.h"
#include "detect-engine-hsmd.h"
#include "detect-engine-hscd.h"
#include "detect-engine-hua.h"
#include "detect-engine-hhhd.h"
#include "detect-engine-hrhhd.h"
#include "detect-engine-file.h"
#include "detect-engine-dns.h"
#include "detect-engine-tls.h"
#include "detect-engine-modbus.h"
#include "detect-engine-filedata-smtp.h"
#include "detect-engine-template.h"

#include "detect-engine.h"
#include "detect-engine-state.h"

#include "detect-byte-extract.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-engine-threshold.h"

#include "detect-engine-loader.h"

#include "util-classification-config.h"
#include "util-reference-config.h"
#include "util-threshold-config.h"
#include "util-error.h"
#include "util-hash.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-action.h"
#include "util-magic.h"
#include "util-signal.h"
#include "util-spm.h"

#include "util-var-name.h"

#include "tm-threads.h"
#include "runmodes.h"

#ifdef PROFILING
#include "util-profiling.h"
#endif

#include "reputation.h"

#define DETECT_ENGINE_DEFAULT_INSPECTION_RECURSION_LIMIT 3000

static uint32_t detect_engine_ctx_id = 1;

static DetectEngineThreadCtx *DetectEngineThreadCtxInitForReload(
        ThreadVars *tv, DetectEngineCtx *new_de_ctx, int mt);

static int DetectEngineCtxLoadConf(DetectEngineCtx *);

static DetectEngineMasterCtx g_master_de_ctx = { SCMUTEX_INITIALIZER, 0, NULL, NULL, TENANT_SELECTOR_UNKNOWN, NULL,};

static uint32_t TenantIdHash(HashTable *h, void *data, uint16_t data_len);
static char TenantIdCompare(void *d1, uint16_t d1_len, void *d2, uint16_t d2_len);
static void TenantIdFree(void *d);
static uint32_t DetectEngineTentantGetIdFromVlanId(const void *ctx, const Packet *p);
static uint32_t DetectEngineTentantGetIdFromPcap(const void *ctx, const Packet *p);

/* 2 - for each direction */
DetectEngineAppInspectionEngine *app_inspection_engine[FLOW_PROTO_DEFAULT][ALPROTO_MAX][2];

#if 0

static void DetectEnginePrintAppInspectionEngines(DetectEngineAppInspectionEngine *list[][ALPROTO_MAX][2])
{
    printf("\n");

    AppProto alproto = ALPROTO_UNKNOWN + 1;
    for ( ; alproto < ALPROTO_MAX; alproto++) {
        printf("alproto - %d\n", alproto);
        int dir = 0;
        for ( ; dir < 2; dir++) {
            printf("  direction - %d\n", dir);
            DetectEngineAppInspectionEngine *engine = list[alproto][dir];
            while (engine != NULL) {
                printf("    engine->alproto - %"PRIu16"\n", engine->alproto);
                printf("    engine->dir - %"PRIu16"\n", engine->dir);
                printf("    engine->sm_list - %d\n", engine->sm_list);
                printf("    engine->inspect_flags - %"PRIu32"\n", engine->inspect_flags);
                printf("    engine->match_flags - %"PRIu32"\n", engine->match_flags);
                printf("\n");

                engine = engine->next;
            }
        } /* for ( ; dir < 2; dir++) */
    } /* for ( ; alproto < ALPROTO_MAX; alproto++) */

    return;
}

#endif

void DetectEngineRegisterAppInspectionEngines(void)
{
    struct tmp_t {
        uint8_t ipproto;
        AppProto alproto;
        int32_t sm_list;
        uint32_t inspect_flags;
        uint16_t dir;
        int (*Callback)(ThreadVars *tv,
                        DetectEngineCtx *de_ctx,
                        DetectEngineThreadCtx *det_ctx,
                        Signature *sig, Flow *f,
                        uint8_t flags, void *alstate,
                        void *tx, uint64_t tx_id);

    };

    struct tmp_t data_toserver[] = {
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_UMATCH,
          DE_STATE_FLAG_URI_INSPECT,
          0,
          DetectEngineInspectPacketUris },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HRLMATCH,
          DE_STATE_FLAG_HRL_INSPECT,
          0,
          DetectEngineInspectHttpRequestLine },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HCBDMATCH,
          DE_STATE_FLAG_HCBD_INSPECT,
          0,
          DetectEngineInspectHttpClientBody },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HHDMATCH,
          DE_STATE_FLAG_HHD_INSPECT,
          0,
          DetectEngineInspectHttpHeader },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HRHDMATCH,
          DE_STATE_FLAG_HRHD_INSPECT,
          0,
          DetectEngineInspectHttpRawHeader },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HMDMATCH,
          DE_STATE_FLAG_HMD_INSPECT,
          0,
          DetectEngineInspectHttpMethod },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HCDMATCH,
          DE_STATE_FLAG_HCD_INSPECT,
          0,
          DetectEngineInspectHttpCookie },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HRUDMATCH,
          DE_STATE_FLAG_HRUD_INSPECT,
          0,
          DetectEngineInspectHttpRawUri },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_FILEMATCH,
          DE_STATE_FLAG_FILE_TS_INSPECT,
          0,
          DetectFileInspectHttp },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HUADMATCH,
          DE_STATE_FLAG_HUAD_INSPECT,
          0,
          DetectEngineInspectHttpUA },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HHHDMATCH,
          DE_STATE_FLAG_HHHD_INSPECT,
          0,
          DetectEngineInspectHttpHH },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HRHHDMATCH,
          DE_STATE_FLAG_HRHHD_INSPECT,
          0,
          DetectEngineInspectHttpHRH },
        /* DNS */
        { IPPROTO_TCP,
          ALPROTO_DNS,
          DETECT_SM_LIST_DNSQUERYNAME_MATCH,
          DE_STATE_FLAG_DNSQUERYNAME_INSPECT,
          0,
          DetectEngineInspectDnsQueryName },
        /* specifically for UDP, register again
         * allows us to use the alproto w/o translation
         * in the detection engine */
        { IPPROTO_UDP,
          ALPROTO_DNS,
          DETECT_SM_LIST_DNSQUERYNAME_MATCH,
          DE_STATE_FLAG_DNSQUERYNAME_INSPECT,
          0,
          DetectEngineInspectDnsQueryName },
        { IPPROTO_TCP,
          ALPROTO_DNS,
          DETECT_SM_LIST_DNSREQUEST_MATCH,
          DE_STATE_FLAG_DNSREQUEST_INSPECT,
          0,
          DetectEngineInspectDnsRequest },
        /* specifically for UDP, register again
         * allows us to use the alproto w/o translation
         * in the detection engine */
        { IPPROTO_UDP,
          ALPROTO_DNS,
          DETECT_SM_LIST_DNSREQUEST_MATCH,
          DE_STATE_FLAG_DNSREQUEST_INSPECT,
          0,
          DetectEngineInspectDnsRequest },
        /* TLS */
        { IPPROTO_TCP,
          ALPROTO_TLS,
          DETECT_SM_LIST_TLSSNI_MATCH,
          DE_STATE_FLAG_TLSSNI_INSPECT,
          0,
          DetectEngineInspectTlsSni },
        /* SMTP */
        { IPPROTO_TCP,
          ALPROTO_SMTP,
          DETECT_SM_LIST_FILEMATCH,
          DE_STATE_FLAG_FILE_TS_INSPECT,
          0,
          DetectFileInspectSmtp },
        /* Modbus */
        { IPPROTO_TCP,
          ALPROTO_MODBUS,
          DETECT_SM_LIST_MODBUS_MATCH,
          DE_STATE_FLAG_MODBUS_INSPECT,
          0,
          DetectEngineInspectModbus },
        /* file_data smtp */
        { IPPROTO_TCP,
          ALPROTO_SMTP,
          DETECT_SM_LIST_FILEDATA,
          DE_STATE_FLAG_FD_SMTP_INSPECT,
          0,
          DetectEngineInspectSMTPFiledata },
        /* Template. */
        { IPPROTO_TCP,
          ALPROTO_TEMPLATE,
          DETECT_SM_LIST_TEMPLATE_BUFFER_MATCH,
          DE_STATE_FLAG_TEMPLATE_BUFFER_INSPECT,
          0,
          DetectEngineInspectTemplateBuffer },
    };

    struct tmp_t data_toclient[] = {
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_FILEDATA,
          DE_STATE_FLAG_HSBD_INSPECT,
          1,
          DetectEngineInspectHttpServerBody },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HHDMATCH,
          DE_STATE_FLAG_HHD_INSPECT,
          1,
          DetectEngineInspectHttpHeader },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HRHDMATCH,
          DE_STATE_FLAG_HRHD_INSPECT,
          1,
          DetectEngineInspectHttpRawHeader },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HCDMATCH,
          DE_STATE_FLAG_HCD_INSPECT,
          1,
          DetectEngineInspectHttpCookie },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_FILEMATCH,
          DE_STATE_FLAG_FILE_TC_INSPECT,
          1,
          DetectFileInspectHttp },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HSMDMATCH,
          DE_STATE_FLAG_HSMD_INSPECT,
          1,
          DetectEngineInspectHttpStatMsg },
        { IPPROTO_TCP,
          ALPROTO_HTTP,
          DETECT_SM_LIST_HSCDMATCH,
          DE_STATE_FLAG_HSCD_INSPECT,
          1,
          DetectEngineInspectHttpStatCode },
        /* Modbus */
        { IPPROTO_TCP,
          ALPROTO_MODBUS,
          DETECT_SM_LIST_MODBUS_MATCH,
          DE_STATE_FLAG_MODBUS_INSPECT,
          0,
          DetectEngineInspectModbus },
        { IPPROTO_TCP,
          ALPROTO_DNS,
          DETECT_SM_LIST_DNSRESPONSE_MATCH,
          DE_STATE_FLAG_DNSRESPONSE_INSPECT,
          1,
          DetectEngineInspectDnsResponse },
        /* specifically for UDP, register again
         * allows us to use the alproto w/o translation
         * in the detection engine */
        { IPPROTO_UDP,
          ALPROTO_DNS,
          DETECT_SM_LIST_DNSRESPONSE_MATCH,
          DE_STATE_FLAG_DNSRESPONSE_INSPECT,
          1,
          DetectEngineInspectDnsResponse },
        /* Template. */
        { IPPROTO_TCP,
          ALPROTO_TEMPLATE,
          DETECT_SM_LIST_TEMPLATE_BUFFER_MATCH,
          DE_STATE_FLAG_TEMPLATE_BUFFER_INSPECT,
          1,
          DetectEngineInspectTemplateBuffer },
    };

    size_t i;
    for (i = 0 ; i < sizeof(data_toserver) / sizeof(struct tmp_t); i++) {
        DetectEngineRegisterAppInspectionEngine(data_toserver[i].ipproto,
                                                data_toserver[i].alproto,
                                                data_toserver[i].dir,
                                                data_toserver[i].sm_list,
                                                data_toserver[i].inspect_flags,
                                                data_toserver[i].Callback,
                                                app_inspection_engine);
    }

    for (i = 0 ; i < sizeof(data_toclient) / sizeof(struct tmp_t); i++) {
        DetectEngineRegisterAppInspectionEngine(data_toclient[i].ipproto,
                                                data_toclient[i].alproto,
                                                data_toclient[i].dir,
                                                data_toclient[i].sm_list,
                                                data_toclient[i].inspect_flags,
                                                data_toclient[i].Callback,
                                                app_inspection_engine);
    }

#if 0
    DetectEnginePrintAppInspectionEngines(app_inspection_engine);
#endif

    return;
}

static void AppendAppInspectionEngine(DetectEngineAppInspectionEngine *engine,
                                      DetectEngineAppInspectionEngine *list[][ALPROTO_MAX][2])
{
    /* append to the list */
    DetectEngineAppInspectionEngine *tmp = list[FlowGetProtoMapping(engine->ipproto)][engine->alproto][engine->dir];
    DetectEngineAppInspectionEngine *insert = NULL;
    while (tmp != NULL) {
        if (tmp->dir == engine->dir &&
            (tmp->sm_list == engine->sm_list ||
             tmp->inspect_flags == engine->inspect_flags
            )) {
            SCLogError(SC_ERR_DETECT_PREPARE, "App Inspection Engine already "
                       "registered for this direction(%"PRIu16") ||"
                       "sm_list(%d) || "
                       "[inspect(%"PRIu32")]_flags",
                       tmp->dir, tmp->sm_list, tmp->inspect_flags);
            exit(EXIT_FAILURE);
        }
        insert = tmp;
        tmp = tmp->next;
    }
    if (insert == NULL)
        list[FlowGetProtoMapping(engine->ipproto)][engine->alproto][engine->dir] = engine;
    else
        insert->next = engine;

    return;
}

void DetectEngineRegisterAppInspectionEngine(uint8_t ipproto,
                                             AppProto alproto,
                                             uint16_t dir,
                                             int32_t sm_list,
                                             uint32_t inspect_flags,
                                             int (*Callback)(ThreadVars *tv,
                                                             DetectEngineCtx *de_ctx,
                                                             DetectEngineThreadCtx *det_ctx,
                                                             Signature *sig, Flow *f,
                                                             uint8_t flags, void *alstate,
                                                             void *tx, uint64_t tx_id),
                                             DetectEngineAppInspectionEngine *list[][ALPROTO_MAX][2])
{
    if ((list == NULL) ||
        (alproto <= ALPROTO_UNKNOWN || alproto >= ALPROTO_FAILED) ||
        (dir > 1) ||
        (sm_list < DETECT_SM_LIST_MATCH || sm_list >= DETECT_SM_LIST_MAX) ||
        (Callback == NULL))
    {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid arguments");
        exit(EXIT_FAILURE);
    }

    DetectEngineAppInspectionEngine *tmp = list[FlowGetProtoMapping(ipproto)][alproto][dir];
    while (tmp != NULL) {
        if (tmp->sm_list == sm_list && tmp->Callback == Callback) {
            return;
        }
        tmp = tmp->next;
    }

    DetectEngineAppInspectionEngine *new_engine = SCMalloc(sizeof(DetectEngineAppInspectionEngine));
    if (unlikely(new_engine == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(new_engine, 0, sizeof(*new_engine));
    new_engine->ipproto = ipproto;
    new_engine->alproto = alproto;
    new_engine->dir = dir;
    new_engine->sm_list = sm_list;
    new_engine->inspect_flags = inspect_flags;
    new_engine->Callback = Callback;

    AppendAppInspectionEngine(new_engine, list);

    return;
}

/* code to control the main thread to do a reload */

enum DetectEngineSyncState {
    IDLE,   /**< ready to start a reload */
    RELOAD, /**< command main thread to do the reload */
    DONE,   /**< main thread telling us reload is done */
};


typedef struct DetectEngineSyncer_ {
    SCMutex m;
    enum DetectEngineSyncState state;
} DetectEngineSyncer;

static DetectEngineSyncer detect_sync = { SCMUTEX_INITIALIZER, IDLE };

/* tell main to start reloading */
int DetectEngineReloadStart(void)
{
    int r = 0;
    SCMutexLock(&detect_sync.m);
    if (detect_sync.state == IDLE) {
        detect_sync.state = RELOAD;
    } else {
        r = -1;
    }
    SCMutexUnlock(&detect_sync.m);
    return r;
}

/* main thread checks this to see if it should start */
int DetectEngineReloadIsStart(void)
{
    int r = 0;
    SCMutexLock(&detect_sync.m);
    if (detect_sync.state == RELOAD) {
        r = 1;
    }
    SCMutexUnlock(&detect_sync.m);
    return r;
}

/* main thread sets done when it's done */
void DetectEngineReloadSetDone(void)
{
    SCMutexLock(&detect_sync.m);
    detect_sync.state = DONE;
    SCMutexUnlock(&detect_sync.m);
}

/* caller loops this until it returns 1 */
int DetectEngineReloadIsDone(void)
{
    int r = 0;
    SCMutexLock(&detect_sync.m);
    if (detect_sync.state == DONE) {
        r = 1;
        detect_sync.state = IDLE;
    }
    SCMutexUnlock(&detect_sync.m);
    return r;
}

/* nudge capture loops to wake up */
static void BreakCapture(void)
{
    SCMutexLock(&tv_root_lock);
    ThreadVars *tv = tv_root[TVT_PPT];
    while (tv) {
        /* find the correct slot */
        TmSlot *slots = tv->tm_slots;
        while (slots != NULL) {
            if (suricata_ctl_flags != 0) {
                SCMutexUnlock(&tv_root_lock);
                return;
            }

            TmModule *tm = TmModuleGetById(slots->tm_id);
            if (!(tm->flags & TM_FLAG_RECEIVE_TM)) {
                slots = slots->slot_next;
                continue;
            }

            /* signal capture method that we need a packet. */
            TmThreadsSetFlag(tv, THV_CAPTURE_INJECT_PKT);
            /* if the method supports it, BreakLoop. Otherwise we rely on
             * the capture method's recv timeout */
            if (tm->PktAcqLoop && tm->PktAcqBreakLoop) {
                tm->PktAcqBreakLoop(tv, SC_ATOMIC_GET(slots->slot_data));
            }

            break;
        }
        tv = tv->next;
    }
    SCMutexUnlock(&tv_root_lock);
}

/** \internal
 *  \brief inject a pseudo packet into each detect thread that doesn't use the
 *         new det_ctx yet
 */
static void InjectPackets(ThreadVars **detect_tvs,
                          DetectEngineThreadCtx **new_det_ctx,
                          int no_of_detect_tvs)
{
    int i;
    /* inject a fake packet if the detect thread isn't using the new ctx yet,
     * this speeds up the process */
    for (i = 0; i < no_of_detect_tvs; i++) {
        if (SC_ATOMIC_GET(new_det_ctx[i]->so_far_used_by_detect) != 1) {
            if (detect_tvs[i]->inq != NULL) {
                Packet *p = PacketGetFromAlloc();
                if (p != NULL) {
                    p->flags |= PKT_PSEUDO_STREAM_END;
                    PacketQueue *q = &trans_q[detect_tvs[i]->inq->id];
                    SCMutexLock(&q->mutex_q);
                    PacketEnqueue(q, p);
                    SCCondSignal(&q->cond_q);
                    SCMutexUnlock(&q->mutex_q);
                }
            }
        }
    }
}

/** \internal
 *  \brief Update detect threads with new detect engine
 *
 *  Atomically update each detect thread with a new thread context
 *  that is associated to the new detection engine(s).
 *
 *  If called in unix socket mode, it's possible that we don't have
 *  detect threads yet.
 *
 *  \retval -1 error
 *  \retval 0 no detection threads
 *  \retval 1 successful reload
 */
static int DetectEngineReloadThreads(DetectEngineCtx *new_de_ctx)
{
    SCEnter();
    int i = 0;
    int no_of_detect_tvs = 0;
    ThreadVars *tv = NULL;

    /* count detect threads in use */
    SCMutexLock(&tv_root_lock);
    tv = tv_root[TVT_PPT];
    while (tv) {
        /* obtain the slots for this TV */
        TmSlot *slots = tv->tm_slots;
        while (slots != NULL) {
            TmModule *tm = TmModuleGetById(slots->tm_id);

            if (suricata_ctl_flags != 0) {
                SCLogInfo("rule reload interupted by engine shutdown");
                SCMutexUnlock(&tv_root_lock);
                return -1;
            }

            if (!(tm->flags & TM_FLAG_DETECT_TM)) {
                slots = slots->slot_next;
                continue;
            }
            no_of_detect_tvs++;
            break;
        }

        tv = tv->next;
    }
    SCMutexUnlock(&tv_root_lock);

    /* can be zero in unix socket mode */
    if (no_of_detect_tvs == 0) {
        return 0;
    }

    /* prepare swap structures */
    DetectEngineThreadCtx *old_det_ctx[no_of_detect_tvs];
    DetectEngineThreadCtx *new_det_ctx[no_of_detect_tvs];
    ThreadVars *detect_tvs[no_of_detect_tvs];
    memset(old_det_ctx, 0x00, (no_of_detect_tvs * sizeof(DetectEngineThreadCtx *)));
    memset(new_det_ctx, 0x00, (no_of_detect_tvs * sizeof(DetectEngineThreadCtx *)));
    memset(detect_tvs, 0x00, (no_of_detect_tvs * sizeof(ThreadVars *)));

    /* start the process of swapping detect threads ctxs */

    /* get reference to tv's and setup new_det_ctx array */
    SCMutexLock(&tv_root_lock);
    tv = tv_root[TVT_PPT];
    while (tv) {
        /* obtain the slots for this TV */
        TmSlot *slots = tv->tm_slots;
        while (slots != NULL) {
            TmModule *tm = TmModuleGetById(slots->tm_id);

            if (suricata_ctl_flags != 0) {
                SCMutexUnlock(&tv_root_lock);
                goto error;
            }

            if (!(tm->flags & TM_FLAG_DETECT_TM)) {
                slots = slots->slot_next;
                continue;
            }

            old_det_ctx[i] = FlowWorkerGetDetectCtxPtr(SC_ATOMIC_GET(slots->slot_data));
            detect_tvs[i] = tv;

            new_det_ctx[i] = DetectEngineThreadCtxInitForReload(tv, new_de_ctx, 1);
            if (new_det_ctx[i] == NULL) {
                SCLogError(SC_ERR_LIVE_RULE_SWAP, "Detect engine thread init "
                           "failure in live rule swap.  Let's get out of here");
                SCMutexUnlock(&tv_root_lock);
                goto error;
            }
            SCLogDebug("live rule swap created new det_ctx - %p and de_ctx "
                       "- %p\n", new_det_ctx[i], new_de_ctx);
            i++;
            break;
        }

        tv = tv->next;
    }
    BUG_ON(i != no_of_detect_tvs);

    /* atomicly replace the det_ctx data */
    i = 0;
    tv = tv_root[TVT_PPT];
    while (tv) {
        /* find the correct slot */
        TmSlot *slots = tv->tm_slots;
        while (slots != NULL) {
            if (suricata_ctl_flags != 0) {
                return -1;
            }

            TmModule *tm = TmModuleGetById(slots->tm_id);
            if (!(tm->flags & TM_FLAG_DETECT_TM)) {
                slots = slots->slot_next;
                continue;
            }
            SCLogDebug("swapping new det_ctx - %p with older one - %p",
                       new_det_ctx[i], SC_ATOMIC_GET(slots->slot_data));
            FlowWorkerReplaceDetectCtx(SC_ATOMIC_GET(slots->slot_data), new_det_ctx[i++]);
            break;
        }
        tv = tv->next;
    }
    SCMutexUnlock(&tv_root_lock);

    /* threads now all have new data, however they may not have started using
     * it and may still use the old data */

    SCLogDebug("Live rule swap has swapped %d old det_ctx's with new ones, "
               "along with the new de_ctx", no_of_detect_tvs);

    InjectPackets(detect_tvs, new_det_ctx, no_of_detect_tvs);

    for (i = 0; i < no_of_detect_tvs; i++) {
        int break_out = 0;
        usleep(1000);
        while (SC_ATOMIC_GET(new_det_ctx[i]->so_far_used_by_detect) != 1) {
            if (suricata_ctl_flags != 0) {
                break_out = 1;
                break;
            }

            BreakCapture();
            usleep(1000);
        }
        if (break_out)
            break;
        SCLogDebug("new_det_ctx - %p used by detect engine", new_det_ctx[i]);
    }

    /* this is to make sure that if someone initiated shutdown during a live
     * rule swap, the live rule swap won't clean up the old det_ctx and
     * de_ctx, till all detect threads have stopped working and sitting
     * silently after setting RUNNING_DONE flag and while waiting for
     * THV_DEINIT flag */
    if (i != no_of_detect_tvs) { // not all threads we swapped
        ThreadVars *tv = tv_root[TVT_PPT];
        while (tv) {
            /* obtain the slots for this TV */
            TmSlot *slots = tv->tm_slots;
            while (slots != NULL) {
                TmModule *tm = TmModuleGetById(slots->tm_id);
                if (!(tm->flags & TM_FLAG_DETECT_TM)) {
                    slots = slots->slot_next;
                    continue;
                }

                while (!TmThreadsCheckFlag(tv, THV_RUNNING_DONE)) {
                    usleep(100);
                }

                slots = slots->slot_next;
            }

            tv = tv->next;
        }
    }

    /* free all the ctxs */
    for (i = 0; i < no_of_detect_tvs; i++) {
        SCLogDebug("Freeing old_det_ctx - %p used by detect",
                   old_det_ctx[i]);
        DetectEngineThreadCtxDeinit(NULL, old_det_ctx[i]);
    }

    SRepReloadComplete();

    return 1;

 error:
    for (i = 0; i < no_of_detect_tvs; i++) {
        if (new_det_ctx[i] != NULL)
            DetectEngineThreadCtxDeinit(NULL, new_det_ctx[i]);
    }
    return -1;
}

static DetectEngineCtx *DetectEngineCtxInitReal(int minimal, const char *prefix)
{
    DetectEngineCtx *de_ctx;

    de_ctx = SCMalloc(sizeof(DetectEngineCtx));
    if (unlikely(de_ctx == NULL))
        goto error;

    memset(de_ctx,0,sizeof(DetectEngineCtx));

    if (minimal) {
        de_ctx->minimal = 1;
        de_ctx->id = detect_engine_ctx_id++;
        return de_ctx;
    }

    if (prefix != NULL) {
        strlcpy(de_ctx->config_prefix, prefix, sizeof(de_ctx->config_prefix));
    }

    if (ConfGetBool("engine.init-failure-fatal", (int *)&(de_ctx->failure_fatal)) != 1) {
        SCLogDebug("ConfGetBool could not load the value.");
    }

    de_ctx->mpm_matcher = PatternMatchDefaultMatcher();
    de_ctx->spm_matcher = SinglePatternMatchDefaultMatcher();
    SCLogConfig("pattern matchers: MPM: %s, SPM: %s",
        mpm_table[de_ctx->mpm_matcher].name,
        spm_table[de_ctx->spm_matcher].name);

    de_ctx->spm_global_thread_ctx = SpmInitGlobalThreadCtx(de_ctx->spm_matcher);
    if (de_ctx->spm_global_thread_ctx == NULL) {
        SCLogDebug("Unable to alloc SpmGlobalThreadCtx.");
        goto error;
    }

    DetectEngineCtxLoadConf(de_ctx);

    SigGroupHeadHashInit(de_ctx);
    MpmStoreInit(de_ctx);
    ThresholdHashInit(de_ctx);
    VariableNameInitHash(de_ctx);
    DetectParseDupSigHashInit(de_ctx);

    /* init iprep... ignore errors for now */
    (void)SRepInit(de_ctx);

#ifdef PROFILING
    SCProfilingKeywordInitCounters(de_ctx);
    de_ctx->profile_match_logging_threshold = UINT_MAX; // disabled

    intmax_t v = 0;
    if (ConfGetInt("detect.profiling.inspect-logging-threshold", &v) == 1)
        de_ctx->profile_match_logging_threshold = (uint32_t)v;
#endif

    SCClassConfLoadClassficationConfigFile(de_ctx, NULL);
    SCRConfLoadReferenceConfigFile(de_ctx, NULL);

    if (ActionInitConfig() < 0) {
        goto error;
    }

    de_ctx->id = detect_engine_ctx_id++;
    return de_ctx;
error:
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }
    return NULL;

}

DetectEngineCtx *DetectEngineCtxInitMinimal(void)
{
    return DetectEngineCtxInitReal(1, NULL);
}

DetectEngineCtx *DetectEngineCtxInit(void)
{
    return DetectEngineCtxInitReal(0, NULL);
}

DetectEngineCtx *DetectEngineCtxInitWithPrefix(const char *prefix)
{
    if (prefix == NULL || strlen(prefix) == 0)
        return DetectEngineCtxInit();
    else
        return DetectEngineCtxInitReal(0, prefix);
}

static void DetectEngineCtxFreeThreadKeywordData(DetectEngineCtx *de_ctx)
{
    DetectEngineThreadKeywordCtxItem *item = de_ctx->keyword_list;
    while (item) {
        DetectEngineThreadKeywordCtxItem *next = item->next;
        SCFree(item);
        item = next;
    }
    de_ctx->keyword_list = NULL;
}

/**
 * \brief Free a DetectEngineCtx::
 *
 * \param de_ctx DetectEngineCtx:: to be freed
 */
void DetectEngineCtxFree(DetectEngineCtx *de_ctx)
{

    if (de_ctx == NULL)
        return;

#ifdef PROFILING
    if (de_ctx->profile_ctx != NULL) {
        SCProfilingRuleDestroyCtx(de_ctx->profile_ctx);
        de_ctx->profile_ctx = NULL;
    }
    if (de_ctx->profile_keyword_ctx != NULL) {
        SCProfilingKeywordDestroyCtx(de_ctx);//->profile_keyword_ctx);
//        de_ctx->profile_keyword_ctx = NULL;
    }
    if (de_ctx->profile_sgh_ctx != NULL) {
        SCProfilingSghDestroyCtx(de_ctx);
    }
#endif

    /* Normally the hashes are freed elsewhere, but
     * to be sure look at them again here.
     */
    SigGroupHeadHashFree(de_ctx);
    MpmStoreFree(de_ctx);
    DetectParseDupSigHashFree(de_ctx);
    SCSigSignatureOrderingModuleCleanup(de_ctx);
    ThresholdContextDestroy(de_ctx);
    SigCleanSignatures(de_ctx);

    VariableNameFreeHash(de_ctx);
    if (de_ctx->sig_array)
        SCFree(de_ctx->sig_array);

    SCClassConfDeInitContext(de_ctx);
    SCRConfDeInitContext(de_ctx);

    SigGroupCleanup(de_ctx);

    SpmDestroyGlobalThreadCtx(de_ctx->spm_global_thread_ctx);

    MpmFactoryDeRegisterAllMpmCtxProfiles(de_ctx);

    DetectEngineCtxFreeThreadKeywordData(de_ctx);
    SRepDestroy(de_ctx);

    /* if we have a config prefix, remove the config from the tree */
    if (strlen(de_ctx->config_prefix) > 0) {
        /* remove config */
        ConfNode *node = ConfGetNode(de_ctx->config_prefix);
        if (node != NULL) {
            ConfNodeRemove(node); /* frees node */
        }
#if 0
        ConfDump();
#endif
    }

    DetectPortCleanupList(de_ctx->tcp_whitelist);
    DetectPortCleanupList(de_ctx->udp_whitelist);

    SCFree(de_ctx);
    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();
}

/** \brief  Function that load DetectEngineCtx config for grouping sigs
 *          used by the engine
 *  \retval 0 if no config provided, 1 if config was provided
 *          and loaded successfuly
 */
static int DetectEngineCtxLoadConf(DetectEngineCtx *de_ctx)
{
    uint8_t profile = ENGINE_PROFILE_UNKNOWN;
    char *max_uniq_toclient_groups_str = NULL;
    char *max_uniq_toserver_groups_str = NULL;
    char *sgh_mpm_context = NULL;
    char *de_ctx_profile = NULL;

    (void)ConfGet("detect.profile", &de_ctx_profile);
    (void)ConfGet("detect.sgh-mpm-context", &sgh_mpm_context);

    ConfNode *de_ctx_custom = ConfGetNode("detect-engine");
    ConfNode *opt = NULL;

    if (de_ctx_custom != NULL) {
        TAILQ_FOREACH(opt, &de_ctx_custom->head, next) {
            if (de_ctx_profile == NULL) {
                if (strcmp(opt->val, "profile") == 0) {
                    de_ctx_profile = opt->head.tqh_first->val;
                }
            }

            if (sgh_mpm_context == NULL) {
                if (strcmp(opt->val, "sgh-mpm-context") == 0) {
                    sgh_mpm_context = opt->head.tqh_first->val;
                }
            }
        }
    }

    if (de_ctx_profile != NULL) {
        if (strcmp(de_ctx_profile, "low") == 0) {
            profile = ENGINE_PROFILE_LOW;
        } else if (strcmp(de_ctx_profile, "medium") == 0) {
            profile = ENGINE_PROFILE_MEDIUM;
        } else if (strcmp(de_ctx_profile, "high") == 0) {
            profile = ENGINE_PROFILE_HIGH;
        } else if (strcmp(de_ctx_profile, "custom") == 0) {
            profile = ENGINE_PROFILE_CUSTOM;
        }

        SCLogDebug("Profile for detection engine groups is \"%s\"", de_ctx_profile);
    } else {
        SCLogDebug("Profile for detection engine groups not provided "
                   "at suricata.yaml. Using default (\"medium\").");
    }

    /* detect-engine.sgh-mpm-context option parsing */
    if (sgh_mpm_context == NULL || strcmp(sgh_mpm_context, "auto") == 0) {
        /* for now, since we still haven't implemented any intelligence into
         * understanding the patterns and distributing mpm_ctx across sgh */
        if (de_ctx->mpm_matcher == MPM_AC || de_ctx->mpm_matcher == MPM_AC_TILE ||
#ifdef BUILD_HYPERSCAN
            de_ctx->mpm_matcher == MPM_HS ||
#endif
#ifdef __SC_CUDA_SUPPORT__
            de_ctx->mpm_matcher == MPM_AC_BS || de_ctx->mpm_matcher == MPM_AC_CUDA) {
#else
            de_ctx->mpm_matcher == MPM_AC_BS) {
#endif
            de_ctx->sgh_mpm_context = ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE;
        } else {
            de_ctx->sgh_mpm_context = ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL;
        }
    } else {
        if (strcmp(sgh_mpm_context, "single") == 0) {
            de_ctx->sgh_mpm_context = ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE;
        } else if (strcmp(sgh_mpm_context, "full") == 0) {
#ifdef __SC_CUDA_SUPPORT__
            if (de_ctx->mpm_matcher == MPM_AC_CUDA) {
                SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "You can't use "
                           "the cuda version of our mpm ac, i.e. \"ac-cuda\" "
                           "along with \"full\" \"sgh-mpm-context\".  "
                           "Allowed values are \"single\" and \"auto\".");
                exit(EXIT_FAILURE);
            }
#endif
            de_ctx->sgh_mpm_context = ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL;
        } else {
           SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "You have supplied an "
                      "invalid conf value for detect-engine.sgh-mpm-context-"
                      "%s", sgh_mpm_context);
           exit(EXIT_FAILURE);
        }
    }

    if (run_mode == RUNMODE_UNITTEST) {
        de_ctx->sgh_mpm_context = ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL;
    }

    /* parse profile custom-values */
    opt = NULL;
    switch (profile) {
        case ENGINE_PROFILE_LOW:
            de_ctx->max_uniq_toclient_groups = 15;
            de_ctx->max_uniq_toserver_groups = 25;
            break;

        case ENGINE_PROFILE_HIGH:
            de_ctx->max_uniq_toclient_groups = 75;
            de_ctx->max_uniq_toserver_groups = 75;
            break;

        case ENGINE_PROFILE_CUSTOM:
            (void)ConfGet("detect.custom-values.toclient-groups",
                    &max_uniq_toclient_groups_str);
            (void)ConfGet("detect.custom-values.toserver-groups",
                    &max_uniq_toserver_groups_str);

            if (de_ctx_custom != NULL) {
                TAILQ_FOREACH(opt, &de_ctx_custom->head, next) {
                    if (strcmp(opt->val, "custom-values") == 0) {
                        if (max_uniq_toclient_groups_str == NULL) {
                            max_uniq_toclient_groups_str = (char *)ConfNodeLookupChildValue
                                (opt->head.tqh_first, "toclient-sp-groups");
                        }
                        if (max_uniq_toclient_groups_str == NULL) {
                            max_uniq_toclient_groups_str = (char *)ConfNodeLookupChildValue
                                (opt->head.tqh_first, "toclient-groups");
                        }
                        if (max_uniq_toserver_groups_str == NULL) {
                            max_uniq_toserver_groups_str = (char *)ConfNodeLookupChildValue
                                (opt->head.tqh_first, "toserver-dp-groups");
                        }
                        if (max_uniq_toserver_groups_str == NULL) {
                            max_uniq_toserver_groups_str = (char *)ConfNodeLookupChildValue
                                (opt->head.tqh_first, "toserver-groups");
                        }
                    }
                }
            }
            if (max_uniq_toclient_groups_str != NULL) {
                if (ByteExtractStringUint16(&de_ctx->max_uniq_toclient_groups, 10,
                    strlen(max_uniq_toclient_groups_str),
                    (const char *)max_uniq_toclient_groups_str) <= 0)
                {
                    de_ctx->max_uniq_toclient_groups = 20;

                    SCLogWarning(SC_ERR_SIZE_PARSE, "parsing '%s' for "
                            "toclient-groups failed, using %u",
                            max_uniq_toclient_groups_str,
                            de_ctx->max_uniq_toclient_groups);
                }
            } else {
                de_ctx->max_uniq_toclient_groups = 20;
            }
            SCLogConfig("toclient-groups %u", de_ctx->max_uniq_toclient_groups);

            if (max_uniq_toserver_groups_str != NULL) {
                if (ByteExtractStringUint16(&de_ctx->max_uniq_toserver_groups, 10,
                    strlen(max_uniq_toserver_groups_str),
                    (const char *)max_uniq_toserver_groups_str) <= 0)
                {
                    de_ctx->max_uniq_toserver_groups = 40;

                    SCLogWarning(SC_ERR_SIZE_PARSE, "parsing '%s' for "
                            "toserver-groups failed, using %u",
                            max_uniq_toserver_groups_str,
                            de_ctx->max_uniq_toserver_groups);
                }
            } else {
                de_ctx->max_uniq_toserver_groups = 40;
            }
            SCLogConfig("toserver-groups %u", de_ctx->max_uniq_toserver_groups);
            break;

        /* Default (or no config provided) is profile medium */
        case ENGINE_PROFILE_MEDIUM:
        case ENGINE_PROFILE_UNKNOWN:
        default:
            de_ctx->max_uniq_toclient_groups = 20;
            de_ctx->max_uniq_toserver_groups = 40;
            break;
    }

    if (profile == ENGINE_PROFILE_UNKNOWN) {
        goto error;
    }

    intmax_t value = 0;
    if (ConfGetInt("detect.inspection-recursion-limit", &value) == 1)
    {
        if (value >= 0 && value <= INT_MAX) {
            de_ctx->inspection_recursion_limit = (int)value;
        }

    /* fall back to old config parsing */
    } else {
        ConfNode *insp_recursion_limit_node = NULL;
        char *insp_recursion_limit = NULL;

        if (de_ctx_custom != NULL) {
            opt = NULL;
            TAILQ_FOREACH(opt, &de_ctx_custom->head, next) {
                if (strcmp(opt->val, "inspection-recursion-limit") != 0)
                    continue;

                insp_recursion_limit_node = ConfNodeLookupChild(opt, opt->val);
                if (insp_recursion_limit_node == NULL) {
                    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Error retrieving conf "
                            "entry for detect-engine:inspection-recursion-limit");
                    break;
                }
                insp_recursion_limit = insp_recursion_limit_node->val;
                SCLogDebug("Found detect-engine.inspection-recursion-limit - %s:%s",
                        insp_recursion_limit_node->name, insp_recursion_limit_node->val);
                break;
            }

            if (insp_recursion_limit != NULL) {
                de_ctx->inspection_recursion_limit = atoi(insp_recursion_limit);
            } else {
                de_ctx->inspection_recursion_limit =
                    DETECT_ENGINE_DEFAULT_INSPECTION_RECURSION_LIMIT;
            }
        }
    }

    if (de_ctx->inspection_recursion_limit == 0)
        de_ctx->inspection_recursion_limit = -1;

    SCLogDebug("de_ctx->inspection_recursion_limit: %d",
               de_ctx->inspection_recursion_limit);

    /* parse port grouping whitelisting settings */

    char *ports = NULL;
    (void)ConfGet("detect.grouping.tcp-whitelist", &ports);
    if (ports) {
        SCLogConfig("grouping: tcp-whitelist %s", ports);
    } else {
        ports = "53, 80, 139, 443, 445, 1433, 3306, 3389, 6666, 6667, 8080";
        SCLogConfig("grouping: tcp-whitelist (default) %s", ports);

    }
    if (DetectPortParse(de_ctx, &de_ctx->tcp_whitelist, ports) != 0) {
        SCLogWarning(SC_ERR_INVALID_YAML_CONF_ENTRY, "'%s' is not a valid value "
                "for detect.grouping.tcp-whitelist", ports);
    }
    DetectPort *x = de_ctx->tcp_whitelist;
    for ( ; x != NULL;  x = x->next) {
        if (x->port != x->port2) {
            SCLogWarning(SC_ERR_INVALID_YAML_CONF_ENTRY, "'%s' is not a valid value "
                "for detect.grouping.tcp-whitelist: only single ports allowed", ports);
            DetectPortCleanupList(de_ctx->tcp_whitelist);
            de_ctx->tcp_whitelist = NULL;
            break;
        }
    }

    ports = NULL;
    (void)ConfGet("detect.grouping.udp-whitelist", &ports);
    if (ports) {
        SCLogConfig("grouping: udp-whitelist %s", ports);
    } else {
        ports = "53, 135, 5060";
        SCLogConfig("grouping: udp-whitelist (default) %s", ports);

    }
    if (DetectPortParse(de_ctx, &de_ctx->udp_whitelist, ports) != 0) {
        SCLogWarning(SC_ERR_INVALID_YAML_CONF_ENTRY, "'%s' is not a valid value "
                "forr detect.grouping.udp-whitelist", ports);
    }
    for (x = de_ctx->udp_whitelist; x != NULL;  x = x->next) {
        if (x->port != x->port2) {
            SCLogWarning(SC_ERR_INVALID_YAML_CONF_ENTRY, "'%s' is not a valid value "
                "for detect.grouping.udp-whitelist: only single ports allowed", ports);
            DetectPortCleanupList(de_ctx->udp_whitelist);
            de_ctx->udp_whitelist = NULL;
            break;
        }
    }

    return 0;
error:
    return -1;
}

/*
 * getting & (re)setting the internal sig i
 */

//inline uint32_t DetectEngineGetMaxSigId(DetectEngineCtx *de_ctx)
//{
//    return de_ctx->signum;
//}

void DetectEngineResetMaxSigId(DetectEngineCtx *de_ctx)
{
    de_ctx->signum = 0;
}

static int DetectEngineThreadCtxInitKeywords(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx)
{
    if (de_ctx->keyword_id > 0) {
        det_ctx->keyword_ctxs_array = SCMalloc(de_ctx->keyword_id * sizeof(void *));
        if (det_ctx->keyword_ctxs_array == NULL) {
            SCLogError(SC_ERR_DETECT_PREPARE, "setting up thread local detect ctx");
            return TM_ECODE_FAILED;
        }

        memset(det_ctx->keyword_ctxs_array, 0x00, de_ctx->keyword_id * sizeof(void *));

        det_ctx->keyword_ctxs_size = de_ctx->keyword_id;

        DetectEngineThreadKeywordCtxItem *item = de_ctx->keyword_list;
        while (item) {
            det_ctx->keyword_ctxs_array[item->id] = item->InitFunc(item->data);
            if (det_ctx->keyword_ctxs_array[item->id] == NULL) {
                SCLogError(SC_ERR_DETECT_PREPARE, "setting up thread local detect ctx "
                        "for keyword \"%s\" failed", item->name);
                return TM_ECODE_FAILED;
            }
            item = item->next;
        }
    }
    return TM_ECODE_OK;
}

static void DetectEngineThreadCtxDeinitKeywords(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx)
{
    if (de_ctx->keyword_id > 0) {
        DetectEngineThreadKeywordCtxItem *item = de_ctx->keyword_list;
        while (item) {
            if (det_ctx->keyword_ctxs_array[item->id] != NULL)
                item->FreeFunc(det_ctx->keyword_ctxs_array[item->id]);

            item = item->next;
        }
        det_ctx->keyword_ctxs_size = 0;
        SCFree(det_ctx->keyword_ctxs_array);
        det_ctx->keyword_ctxs_array = NULL;
    }
}

/** NOTE: master MUST be locked before calling this */
static TmEcode DetectEngineThreadCtxInitForMT(ThreadVars *tv, DetectEngineThreadCtx *det_ctx)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    DetectEngineTenantMapping *map_array = NULL;
    uint32_t map_array_size = 0;
    uint32_t map_cnt = 0;
    int max_tenant_id = 0;
    DetectEngineCtx *list = master->list;
    HashTable *mt_det_ctxs_hash = NULL;

    if (master->tenant_selector == TENANT_SELECTOR_UNKNOWN) {
        SCLogError(SC_ERR_MT_NO_SELECTOR, "no tenant selector set: "
                                          "set using multi-detect.selector");
        return TM_ECODE_FAILED;
    }

    uint32_t tcnt = 0;
    while (list) {
        if (list->tenant_id > max_tenant_id)
            max_tenant_id = list->tenant_id;

        list = list->next;
        tcnt++;
    }

    mt_det_ctxs_hash = HashTableInit(tcnt * 2, TenantIdHash, TenantIdCompare, TenantIdFree);
    if (mt_det_ctxs_hash == NULL) {
        goto error;
    }

    if (max_tenant_id == 0) {
        SCLogInfo("no tenants left, or none registered yet");
    } else {
        max_tenant_id++;

        DetectEngineTenantMapping *map = master->tenant_mapping_list;
        while (map) {
            map_cnt++;
            map = map->next;
        }

        if (map_cnt > 0) {
            map_array_size = map_cnt + 1;

            map_array = SCCalloc(map_array_size, sizeof(*map_array));
            if (map_array == NULL)
                goto error;

            /* fill the array */
            map_cnt = 0;
            map = master->tenant_mapping_list;
            while (map) {
                if (map_cnt >= map_array_size) {
                    goto error;
                }
                map_array[map_cnt].traffic_id = map->traffic_id;
                map_array[map_cnt].tenant_id = map->tenant_id;
                map_cnt++;
                map = map->next;
            }

        }

        /* set up hash for tenant lookup */
        list = master->list;
        while (list) {
            SCLogInfo("tenant-id %u", list->tenant_id);
            if (list->tenant_id != 0) {
                DetectEngineThreadCtx *mt_det_ctx = DetectEngineThreadCtxInitForReload(tv, list, 0);
                if (mt_det_ctx == NULL)
                    goto error;
                if (HashTableAdd(mt_det_ctxs_hash, mt_det_ctx, 0) != 0) {
                    goto error;
                }
            }
            list = list->next;
        }
    }

    det_ctx->mt_det_ctxs_hash = mt_det_ctxs_hash;
    mt_det_ctxs_hash = NULL;

    det_ctx->mt_det_ctxs_cnt = max_tenant_id;

    det_ctx->tenant_array = map_array;
    det_ctx->tenant_array_size = map_array_size;

    switch (master->tenant_selector) {
        case TENANT_SELECTOR_UNKNOWN:
            SCLogDebug("TENANT_SELECTOR_UNKNOWN");
            break;
        case TENANT_SELECTOR_VLAN:
            det_ctx->TenantGetId = DetectEngineTentantGetIdFromVlanId;
            SCLogDebug("TENANT_SELECTOR_VLAN");
            break;
        case TENANT_SELECTOR_DIRECT:
            det_ctx->TenantGetId = DetectEngineTentantGetIdFromPcap;
            SCLogDebug("TENANT_SELECTOR_DIRECT");
            break;
    }

    return TM_ECODE_OK;
error:
    if (map_array != NULL)
        SCFree(map_array);
    if (mt_det_ctxs_hash != NULL)
        HashTableFree(mt_det_ctxs_hash);

    return TM_ECODE_FAILED;
}

/** \internal
 *  \brief Helper for DetectThread setup functions
 */
static TmEcode ThreadCtxDoInit (DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx)
{
    PatternMatchThreadPrepare(&det_ctx->mtc, de_ctx->mpm_matcher);
    PatternMatchThreadPrepare(&det_ctx->mtcs, de_ctx->mpm_matcher);
    PatternMatchThreadPrepare(&det_ctx->mtcu, de_ctx->mpm_matcher);

    PmqSetup(&det_ctx->pmq);

    det_ctx->spm_thread_ctx = SpmMakeThreadCtx(de_ctx->spm_global_thread_ctx);
    if (det_ctx->spm_thread_ctx == NULL) {
        return TM_ECODE_FAILED;
    }

    /* sized to the max of our sgh settings. A max setting of 0 implies that all
     * sgh's have: sgh->non_mpm_store_cnt == 0 */
    if (de_ctx->non_mpm_store_cnt_max > 0) {
        det_ctx->non_mpm_id_array =  SCCalloc(de_ctx->non_mpm_store_cnt_max, sizeof(SigIntId));
        BUG_ON(det_ctx->non_mpm_id_array == NULL);
    }

    /* IP-ONLY */
    DetectEngineIPOnlyThreadInit(de_ctx,&det_ctx->io_ctx);

    /* DeState */
    if (de_ctx->sig_array_len > 0) {
        det_ctx->de_state_sig_array_len = de_ctx->sig_array_len;
        det_ctx->de_state_sig_array = SCMalloc(det_ctx->de_state_sig_array_len * sizeof(uint8_t));
        if (det_ctx->de_state_sig_array == NULL) {
            return TM_ECODE_FAILED;
        }
        memset(det_ctx->de_state_sig_array, 0,
               det_ctx->de_state_sig_array_len * sizeof(uint8_t));

        det_ctx->match_array_len = de_ctx->sig_array_len;
        det_ctx->match_array = SCMalloc(det_ctx->match_array_len * sizeof(Signature *));
        if (det_ctx->match_array == NULL) {
            return TM_ECODE_FAILED;
        }
        memset(det_ctx->match_array, 0,
               det_ctx->match_array_len * sizeof(Signature *));
    }

    /* byte_extract storage */
    det_ctx->bj_values = SCMalloc(sizeof(*det_ctx->bj_values) *
                                  (de_ctx->byte_extract_max_local_id + 1));
    if (det_ctx->bj_values == NULL) {
        return TM_ECODE_FAILED;
    }

    /* Allocate space for base64 decoded data. */
    if (de_ctx->base64_decode_max_len) {
        det_ctx->base64_decoded = SCMalloc(de_ctx->base64_decode_max_len);
        if (det_ctx->base64_decoded == NULL) {
            return TM_ECODE_FAILED;
        }
        det_ctx->base64_decoded_len_max = de_ctx->base64_decode_max_len;
        det_ctx->base64_decoded_len = 0;
    }

    DetectEngineThreadCtxInitKeywords(de_ctx, det_ctx);
#ifdef PROFILING
    SCProfilingRuleThreadSetup(de_ctx->profile_ctx, det_ctx);
    SCProfilingKeywordThreadSetup(de_ctx->profile_keyword_ctx, det_ctx);
    SCProfilingSghThreadSetup(de_ctx->profile_sgh_ctx, det_ctx);
#endif
    SC_ATOMIC_INIT(det_ctx->so_far_used_by_detect);

    return TM_ECODE_OK;
}

/** \brief initialize thread specific detection engine context
 *
 *  \note there is a special case when using delayed detect. In this case the
 *        function is called twice per thread. The first time the rules are not
 *        yet loaded. de_ctx->delayed_detect_initialized will be 0. The 2nd
 *        time they will be loaded. de_ctx->delayed_detect_initialized will be 1.
 *        This is needed to do the per thread counter registration before the
 *        packet runtime starts. In delayed detect mode, the first call will
 *        return a NULL ptr through the data ptr.
 *
 *  \param tv ThreadVars for this thread
 *  \param initdata pointer to de_ctx
 *  \param data[out] pointer to store our thread detection ctx
 *
 *  \retval TM_ECODE_OK if all went well
 *  \retval TM_ECODE_FAILED on serious erro
 */
TmEcode DetectEngineThreadCtxInit(ThreadVars *tv, void *initdata, void **data)
{
    /* first register the counter. In delayed detect mode we exit right after if the
     * rules haven't been loaded yet. */
    uint16_t counter_alerts = StatsRegisterCounter("detect.alert", tv);
#ifdef PROFILING
    uint16_t counter_mpm_list = StatsRegisterAvgCounter("detect.mpm_list", tv);
    uint16_t counter_nonmpm_list = StatsRegisterAvgCounter("detect.nonmpm_list", tv);
    uint16_t counter_fnonmpm_list = StatsRegisterAvgCounter("detect.fnonmpm_list", tv);
    uint16_t counter_match_list = StatsRegisterAvgCounter("detect.match_list", tv);
#endif
    DetectEngineThreadCtx *det_ctx = SCMalloc(sizeof(DetectEngineThreadCtx));
    if (unlikely(det_ctx == NULL))
        return TM_ECODE_FAILED;
    memset(det_ctx, 0, sizeof(DetectEngineThreadCtx));

    det_ctx->tv = tv;
    det_ctx->de_ctx = DetectEngineGetCurrent();
    if (det_ctx->de_ctx == NULL) {
#ifdef UNITTESTS
        if (RunmodeIsUnittests()) {
            det_ctx->de_ctx = (DetectEngineCtx *)initdata;
        } else {
            DetectEngineThreadCtxDeinit(tv, det_ctx);
            return TM_ECODE_FAILED;
        }
#else
        DetectEngineThreadCtxDeinit(tv, det_ctx);
        return TM_ECODE_FAILED;
#endif
    }

    if (det_ctx->de_ctx->minimal == 0) {
        if (ThreadCtxDoInit(det_ctx->de_ctx, det_ctx) != TM_ECODE_OK) {
            DetectEngineThreadCtxDeinit(tv, det_ctx);
            return TM_ECODE_FAILED;
        }
    }

    /** alert counter setup */
    det_ctx->counter_alerts = counter_alerts;
#ifdef PROFILING
    det_ctx->counter_mpm_list = counter_mpm_list;
    det_ctx->counter_nonmpm_list = counter_nonmpm_list;
    det_ctx->counter_fnonmpm_list = counter_fnonmpm_list;
    det_ctx->counter_match_list = counter_match_list;
#endif

    /* pass thread data back to caller */
    *data = (void *)det_ctx;

    if (DetectEngineMultiTenantEnabled()) {
        if (DetectEngineThreadCtxInitForMT(tv, det_ctx) != TM_ECODE_OK)
            return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}

/**
 * \internal
 * \brief initialize a det_ctx for reload cases
 * \param new_de_ctx the new detection engine
 * \param mt flag to indicate if MT should be set up for this det_ctx
 *           this should only be done for the 'root' det_ctx
 *
 * \retval det_ctx detection engine thread ctx or NULL in case of error
 */
static DetectEngineThreadCtx *DetectEngineThreadCtxInitForReload(
        ThreadVars *tv, DetectEngineCtx *new_de_ctx, int mt)
{
    DetectEngineThreadCtx *det_ctx = SCMalloc(sizeof(DetectEngineThreadCtx));
    if (unlikely(det_ctx == NULL))
        return NULL;
    memset(det_ctx, 0, sizeof(DetectEngineThreadCtx));

    det_ctx->tenant_id = new_de_ctx->tenant_id;
    det_ctx->tv = tv;
    det_ctx->de_ctx = DetectEngineReference(new_de_ctx);
    if (det_ctx->de_ctx == NULL) {
        SCFree(det_ctx);
        return NULL;
    }

    /* most of the init happens here */
    if (ThreadCtxDoInit(det_ctx->de_ctx, det_ctx) != TM_ECODE_OK) {
        DetectEngineDeReference(&det_ctx->de_ctx);
        SCFree(det_ctx);
        return NULL;
    }

    /** alert counter setup */
    det_ctx->counter_alerts = StatsRegisterCounter("detect.alert", tv);
#ifdef PROFILING
    uint16_t counter_mpm_list = StatsRegisterAvgCounter("detect.mpm_list", tv);
    uint16_t counter_nonmpm_list = StatsRegisterAvgCounter("detect.nonmpm_list", tv);
    uint16_t counter_fnonmpm_list = StatsRegisterAvgCounter("detect.fnonmpm_list", tv);
    uint16_t counter_match_list = StatsRegisterAvgCounter("detect.match_list", tv);
    det_ctx->counter_mpm_list = counter_mpm_list;
    det_ctx->counter_nonmpm_list = counter_nonmpm_list;
    det_ctx->counter_fnonmpm_list = counter_fnonmpm_list;
    det_ctx->counter_match_list = counter_match_list;
#endif

    if (mt && DetectEngineMultiTenantEnabled()) {
        if (DetectEngineThreadCtxInitForMT(tv, det_ctx) != TM_ECODE_OK) {
            DetectEngineDeReference(&det_ctx->de_ctx);
            SCFree(det_ctx);
            return NULL;
        }
    }

    return det_ctx;
}

void DetectEngineThreadCtxFree(DetectEngineThreadCtx *det_ctx)
{
    int i;

    if (det_ctx->tenant_array != NULL) {
        SCFree(det_ctx->tenant_array);
        det_ctx->tenant_array = NULL;
    }

#ifdef PROFILING
    SCProfilingRuleThreadCleanup(det_ctx);
    SCProfilingKeywordThreadCleanup(det_ctx);
    SCProfilingSghThreadCleanup(det_ctx);
#endif

    DetectEngineIPOnlyThreadDeinit(&det_ctx->io_ctx);

    /** \todo get rid of this static */
    if (det_ctx->de_ctx != NULL) {
        PatternMatchThreadDestroy(&det_ctx->mtc, det_ctx->de_ctx->mpm_matcher);
        PatternMatchThreadDestroy(&det_ctx->mtcs, det_ctx->de_ctx->mpm_matcher);
        PatternMatchThreadDestroy(&det_ctx->mtcu, det_ctx->de_ctx->mpm_matcher);
    }

    PmqFree(&det_ctx->pmq);

    if (det_ctx->spm_thread_ctx != NULL) {
        SpmDestroyThreadCtx(det_ctx->spm_thread_ctx);
    }

    if (det_ctx->non_mpm_id_array != NULL)
        SCFree(det_ctx->non_mpm_id_array);

    if (det_ctx->de_state_sig_array != NULL)
        SCFree(det_ctx->de_state_sig_array);
    if (det_ctx->match_array != NULL)
        SCFree(det_ctx->match_array);

    if (det_ctx->bj_values != NULL)
        SCFree(det_ctx->bj_values);

    /* HHD temp storage */
    for (i = 0; i < det_ctx->hhd_buffers_size; i++) {
        if (det_ctx->hhd_buffers[i] != NULL)
            SCFree(det_ctx->hhd_buffers[i]);
    }
    if (det_ctx->hhd_buffers)
        SCFree(det_ctx->hhd_buffers);
    det_ctx->hhd_buffers = NULL;
    if (det_ctx->hhd_buffers_len)
        SCFree(det_ctx->hhd_buffers_len);
    det_ctx->hhd_buffers_len = NULL;

    /* HSBD */
    if (det_ctx->hsbd != NULL) {
        SCLogDebug("det_ctx hsbd %u", det_ctx->hsbd_buffers_size);
        SCFree(det_ctx->hsbd);
    }

    /* HSCB */
    if (det_ctx->hcbd != NULL) {
        SCLogDebug("det_ctx hcbd %u", det_ctx->hcbd_buffers_size);
        SCFree(det_ctx->hcbd);
    }

    /* SMTP */
    if (det_ctx->smtp != NULL) {
        SCLogDebug("det_ctx smtp %u", det_ctx->smtp_buffers_size);
        SCFree(det_ctx->smtp);
    }

    /* Decoded base64 data. */
    if (det_ctx->base64_decoded != NULL) {
        SCFree(det_ctx->base64_decoded);
    }

    if (det_ctx->de_ctx != NULL) {
        DetectEngineThreadCtxDeinitKeywords(det_ctx->de_ctx, det_ctx);
#ifdef UNITTESTS
        if (!RunmodeIsUnittests() || det_ctx->de_ctx->ref_cnt > 0)
            DetectEngineDeReference(&det_ctx->de_ctx);
#else
        DetectEngineDeReference(&det_ctx->de_ctx);
#endif
    }
    SCFree(det_ctx);
}

TmEcode DetectEngineThreadCtxDeinit(ThreadVars *tv, void *data)
{
    DetectEngineThreadCtx *det_ctx = (DetectEngineThreadCtx *)data;

    if (det_ctx == NULL) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "argument \"data\" NULL");
        return TM_ECODE_OK;
    }

    if (det_ctx->mt_det_ctxs_hash != NULL) {
        HashTableFree(det_ctx->mt_det_ctxs_hash);
        det_ctx->mt_det_ctxs_hash = NULL;
    }
    DetectEngineThreadCtxFree(det_ctx);

    return TM_ECODE_OK;
}

void DetectEngineThreadCtxInfo(ThreadVars *t, DetectEngineThreadCtx *det_ctx)
{
    /* XXX */
    PatternMatchThreadPrint(&det_ctx->mtc, det_ctx->de_ctx->mpm_matcher);
    PatternMatchThreadPrint(&det_ctx->mtcu, det_ctx->de_ctx->mpm_matcher);
}

/** \brief Register Thread keyword context Funcs
 *
 *  \param de_ctx detection engine to register in
 *  \param name keyword name for error printing
 *  \param InitFunc function ptr
 *  \param data keyword init data to pass to Func
 *  \param FreeFunc function ptr
 *  \param mode 0 normal (ctx per keyword instance) 1 shared (one ctx per det_ct)
 *
 *  \retval id for retrieval of ctx at runtime
 *  \retval -1 on error
 *
 *  \note make sure "data" remains valid and it free'd elsewhere. It's
 *        recommended to store it in the keywords global ctx so that
 *        it's freed when the de_ctx is freed.
 */
int DetectRegisterThreadCtxFuncs(DetectEngineCtx *de_ctx, const char *name, void *(*InitFunc)(void *), void *data, void (*FreeFunc)(void *), int mode)
{
    BUG_ON(de_ctx == NULL || InitFunc == NULL || FreeFunc == NULL || data == NULL);

    if (mode) {
        DetectEngineThreadKeywordCtxItem *item = de_ctx->keyword_list;
        while (item != NULL) {
            if (strcmp(name, item->name) == 0) {
                return item->id;
            }

            item = item->next;
        }
    }

    DetectEngineThreadKeywordCtxItem *item = SCMalloc(sizeof(DetectEngineThreadKeywordCtxItem));
    if (unlikely(item == NULL))
        return -1;
    memset(item, 0x00, sizeof(DetectEngineThreadKeywordCtxItem));

    item->InitFunc = InitFunc;
    item->FreeFunc = FreeFunc;
    item->data = data;
    item->name = name;

    item->next = de_ctx->keyword_list;
    de_ctx->keyword_list = item;
    item->id = de_ctx->keyword_id++;

    return item->id;
}

/** \brief Retrieve thread local keyword ctx by id
 *
 *  \param det_ctx detection engine thread ctx to retrieve the ctx from
 *  \param id id of the ctx returned by DetectRegisterThreadCtxInitFunc at
 *            keyword init.
 *
 *  \retval ctx or NULL on error
 */
void *DetectThreadCtxGetKeywordThreadCtx(DetectEngineThreadCtx *det_ctx, int id)
{
    if (id < 0 || id > det_ctx->keyword_ctxs_size || det_ctx->keyword_ctxs_array == NULL)
        return NULL;

    return det_ctx->keyword_ctxs_array[id];
}

/** \brief Check if detection is enabled
 *  \retval bool true or false */
int DetectEngineEnabled(void)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);

    if (master->list == NULL) {
        SCMutexUnlock(&master->lock);
        return 0;
    }

    SCMutexUnlock(&master->lock);
    return 1;
}

DetectEngineCtx *DetectEngineGetCurrent(void)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);

    if (master->list == NULL) {
        SCMutexUnlock(&master->lock);
        return NULL;
    }

    master->list->ref_cnt++;
    SCLogDebug("master->list %p ref_cnt %u", master->list, master->list->ref_cnt);
    SCMutexUnlock(&master->lock);
    return master->list;
}

DetectEngineCtx *DetectEngineReference(DetectEngineCtx *de_ctx)
{
    if (de_ctx == NULL)
        return NULL;
    de_ctx->ref_cnt++;
    return de_ctx;
}

/** TODO locking? Not needed if this is a one time setting at startup */
int DetectEngineMultiTenantEnabled(void)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    return (master->multi_tenant_enabled);
}

/** \internal
 *  \brief load a tenant from a yaml file
 *
 *  \param tenant_id the tenant id by which the config is known
 *  \param filename full path of a yaml file
 *  \param loader_id id of loader thread or -1
 *
 *  \retval 0 ok
 *  \retval -1 failed
 */
static int DetectEngineMultiTenantLoadTenant(uint32_t tenant_id, const char *filename, int loader_id)
{
    DetectEngineCtx *de_ctx = NULL;
    char prefix[64];

    snprintf(prefix, sizeof(prefix), "multi-detect.%d", tenant_id);

#ifdef OS_WIN32
    struct _stat st;
    if(_stat(filename, &st) != 0) {
#else
    struct stat st;
    if(stat(filename, &st) != 0) {
#endif /* OS_WIN32 */
        SCLogError(SC_ERR_FOPEN, "failed to stat file %s", filename);
        goto error;
    }

    de_ctx = DetectEngineGetByTenantId(tenant_id);
    if (de_ctx != NULL) {
        SCLogError(SC_ERR_MT_DUPLICATE_TENANT, "tenant %u already registered",
                tenant_id);
        DetectEngineDeReference(&de_ctx);
        goto error;
    }

    ConfNode *node = ConfGetNode(prefix);
    if (node == NULL) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "failed to properly setup yaml %s", filename);
        goto error;
    }

    de_ctx = DetectEngineCtxInitWithPrefix(prefix);
    if (de_ctx == NULL) {
        SCLogError(SC_ERR_INITIALIZATION, "initializing detection engine "
                "context failed.");
        goto error;
    }
    SCLogDebug("de_ctx %p with prefix %s", de_ctx, de_ctx->config_prefix);

    de_ctx->tenant_id = tenant_id;
    de_ctx->loader_id = loader_id;

    if (SigLoadSignatures(de_ctx, NULL, 0) < 0) {
        SCLogError(SC_ERR_NO_RULES_LOADED, "Loading signatures failed.");
        goto error;
    }

    DetectEngineAddToMaster(de_ctx);

    return 0;

error:
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }
    return -1;
}

static int DetectEngineMultiTenantReloadTenant(uint32_t tenant_id, const char *filename, int reload_cnt)
{
    DetectEngineCtx *old_de_ctx = DetectEngineGetByTenantId(tenant_id);
    if (old_de_ctx == NULL) {
        SCLogError(SC_ERR_INITIALIZATION, "tenant detect engine not found");
        return -1;
    }

    char prefix[64];
    snprintf(prefix, sizeof(prefix), "multi-detect.%d.reload.%d", tenant_id, reload_cnt);
    reload_cnt++;
    SCLogInfo("prefix %s", prefix);

    if (ConfYamlLoadFileWithPrefix(filename, prefix) != 0) {
        SCLogError(SC_ERR_INITIALIZATION,"failed to load yaml");
        goto error;
    }

    ConfNode *node = ConfGetNode(prefix);
    if (node == NULL) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "failed to properly setup yaml %s", filename);
        goto error;
    }

    DetectEngineCtx *new_de_ctx = DetectEngineCtxInitWithPrefix(prefix);
    if (new_de_ctx == NULL) {
        SCLogError(SC_ERR_INITIALIZATION, "initializing detection engine "
                "context failed.");
        goto error;
    }
    SCLogDebug("de_ctx %p with prefix %s", new_de_ctx, new_de_ctx->config_prefix);

    new_de_ctx->tenant_id = tenant_id;
    new_de_ctx->loader_id = old_de_ctx->loader_id;

    if (SigLoadSignatures(new_de_ctx, NULL, 0) < 0) {
        SCLogError(SC_ERR_NO_RULES_LOADED, "Loading signatures failed.");
        goto error;
    }

    DetectEngineAddToMaster(new_de_ctx);

    /* move to free list */
    DetectEngineMoveToFreeList(old_de_ctx);
    DetectEngineDeReference(&old_de_ctx);
    return 0;

error:
    DetectEngineDeReference(&old_de_ctx);
    return -1;
}


typedef struct TenantLoaderCtx_ {
    uint32_t tenant_id;
    int reload_cnt; /**< used by reload */
    const char *yaml;
} TenantLoaderCtx;

static int DetectLoaderFuncLoadTenant(void *vctx, int loader_id)
{
    TenantLoaderCtx *ctx = (TenantLoaderCtx *)vctx;

    SCLogDebug("loader %d", loader_id);
    if (DetectEngineMultiTenantLoadTenant(ctx->tenant_id, ctx->yaml, loader_id) != 0) {
        return -1;
    }
    return 0;
}

int DetectLoaderSetupLoadTenant(uint32_t tenant_id, const char *yaml)
{
    TenantLoaderCtx *t = SCCalloc(1, sizeof(*t));
    if (t == NULL)
        return -ENOMEM;

    t->tenant_id = tenant_id;
    t->yaml = yaml;

    return DetectLoaderQueueTask(-1, DetectLoaderFuncLoadTenant, t);
}

static int DetectLoaderFuncReloadTenant(void *vctx, int loader_id)
{
    TenantLoaderCtx *ctx = (TenantLoaderCtx *)vctx;

    SCLogDebug("loader_id %d", loader_id);

    if (DetectEngineMultiTenantReloadTenant(ctx->tenant_id, ctx->yaml, ctx->reload_cnt) != 0) {
        return -1;
    }
    return 0;
}

int DetectLoaderSetupReloadTenant(uint32_t tenant_id, const char *yaml, int reload_cnt)
{
    DetectEngineCtx *old_de_ctx = DetectEngineGetByTenantId(tenant_id);
    if (old_de_ctx == NULL)
        return -ENOENT;
    int loader_id = old_de_ctx->loader_id;
    DetectEngineDeReference(&old_de_ctx);

    TenantLoaderCtx *t = SCCalloc(1, sizeof(*t));
    if (t == NULL)
        return -ENOMEM;

    t->tenant_id = tenant_id;
    t->yaml = yaml;
    t->reload_cnt = reload_cnt;

    SCLogDebug("loader_id %d", loader_id);

    return DetectLoaderQueueTask(loader_id, DetectLoaderFuncReloadTenant, t);
}

/** \brief Load a tenant and wait for loading to complete
 */
int DetectEngineLoadTenantBlocking(uint32_t tenant_id, const char *yaml)
{
    int r = DetectLoaderSetupLoadTenant(tenant_id, yaml);
    if (r < 0)
        return r;

    if (DetectLoadersSync() != 0)
        return -1;

    return 0;
}

/** \brief Reload a tenant and wait for loading to complete
 */
int DetectEngineReloadTenantBlocking(uint32_t tenant_id, const char *yaml, int reload_cnt)
{
    int r = DetectLoaderSetupReloadTenant(tenant_id, yaml, reload_cnt);
    if (r < 0)
        return r;

    if (DetectLoadersSync() != 0)
        return -1;

    return 0;
}

/**
 *  \brief setup multi-detect / multi-tenancy
 *
 *  See if MT is enabled. If so, setup the selector, tenants and mappings.
 *  Tenants and mappings are optional, and can also dynamically be added
 *  and removed from the unix socket.
 */
int DetectEngineMultiTenantSetup(void)
{
    enum DetectEngineTenantSelectors tenant_selector = TENANT_SELECTOR_UNKNOWN;
    DetectEngineMasterCtx *master = &g_master_de_ctx;

    int unix_socket = 0;
    (void)ConfGetBool("unix-command.enabled", &unix_socket);

    int failure_fatal = 0;
    (void)ConfGetBool("engine.init-failure-fatal", &failure_fatal);

    int enabled = 0;
    (void)ConfGetBool("multi-detect.enabled", &enabled);
    if (enabled == 1) {
        DetectLoadersInit();
        TmModuleDetectLoaderRegister();
        DetectLoaderThreadSpawn();
        TmThreadContinueDetectLoaderThreads();

        SCMutexLock(&master->lock);
        master->multi_tenant_enabled = 1;

        char *handler = NULL;
        if (ConfGet("multi-detect.selector", &handler) == 1) {
            SCLogInfo("multi-tenant selector type %s", handler);

            if (strcmp(handler, "vlan") == 0) {
                tenant_selector = master->tenant_selector = TENANT_SELECTOR_VLAN;

                int vlanbool = 0;
                if ((ConfGetBool("vlan.use-for-tracking", &vlanbool)) == 1 && vlanbool == 0) {
                    SCLogError(SC_ERR_INVALID_VALUE, "vlan tracking is disabled, "
                            "can't use multi-detect selector 'vlan'");
                    SCMutexUnlock(&master->lock);
                    goto error;
                }

            } else if (strcmp(handler, "direct") == 0) {
                tenant_selector = master->tenant_selector = TENANT_SELECTOR_DIRECT;
            } else {
                SCLogError(SC_ERR_INVALID_VALUE, "unknown value %s "
                                                 "multi-detect.selector", handler);
                SCMutexUnlock(&master->lock);
                goto error;
            }
        }
        SCMutexUnlock(&master->lock);
        SCLogInfo("multi-detect is enabled (multi tenancy). Selector: %s", handler);

        /* traffic -- tenant mappings */
        ConfNode *mappings_root_node = ConfGetNode("multi-detect.mappings");
        ConfNode *mapping_node = NULL;

        int mapping_cnt = 0;
        if (mappings_root_node != NULL) {
            TAILQ_FOREACH(mapping_node, &mappings_root_node->head, next) {
                ConfNode *tenant_id_node = ConfNodeLookupChild(mapping_node, "tenant-id");
                if (tenant_id_node == NULL)
                    goto bad_mapping;
                ConfNode *vlan_id_node = ConfNodeLookupChild(mapping_node, "vlan-id");
                if (vlan_id_node == NULL)
                    goto bad_mapping;

                uint32_t tenant_id = 0;
                if (ByteExtractStringUint32(&tenant_id, 10, strlen(tenant_id_node->val),
                            tenant_id_node->val) == -1)
                {
                    SCLogError(SC_ERR_INVALID_ARGUMENT, "tenant-id  "
                            "of %s is invalid", tenant_id_node->val);
                    goto bad_mapping;
                }

                uint16_t vlan_id = 0;
                if (ByteExtractStringUint16(&vlan_id, 10, strlen(vlan_id_node->val),
                            vlan_id_node->val) == -1)
                {
                    SCLogError(SC_ERR_INVALID_ARGUMENT, "vlan-id  "
                            "of %s is invalid", vlan_id_node->val);
                    goto bad_mapping;
                }
                if (vlan_id == 0 || vlan_id >= 4095) {
                    SCLogError(SC_ERR_INVALID_ARGUMENT, "vlan-id  "
                            "of %s is invalid. Valid range 1-4094.", vlan_id_node->val);
                    goto bad_mapping;
                }

                if (DetectEngineTentantRegisterVlanId(tenant_id, (uint32_t)vlan_id) != 0) {
                    goto error;
                }
                SCLogInfo("vlan %u connected to tenant-id %u", vlan_id, tenant_id);
                mapping_cnt++;
                continue;

            bad_mapping:
                if (failure_fatal)
                    goto error;
            }
        }

        if (tenant_selector == TENANT_SELECTOR_VLAN && mapping_cnt == 0) {
            /* no mappings are valid when we're in unix socket mode,
             * they can be added on the fly. Otherwise warn/error
             * depending on failure_fatal */

            if (unix_socket) {
                SCLogNotice("no tenant traffic mappings defined, "
                        "tenants won't be used until mappings are added");
            } else {
                if (failure_fatal) {
                    SCLogError(SC_ERR_MT_NO_MAPPING, "no multi-detect mappings defined");
                    goto error;
                } else {
                    SCLogWarning(SC_ERR_MT_NO_MAPPING, "no multi-detect mappings defined");
                }
            }
        }

        /* tenants */
        ConfNode *tenants_root_node = ConfGetNode("multi-detect.tenants");
        ConfNode *tenant_node = NULL;

        if (tenants_root_node != NULL) {
            TAILQ_FOREACH(tenant_node, &tenants_root_node->head, next) {
                ConfNode *id_node = ConfNodeLookupChild(tenant_node, "id");
                if (id_node == NULL) {
                    goto bad_tenant;
                }
                ConfNode *yaml_node = ConfNodeLookupChild(tenant_node, "yaml");
                if (yaml_node == NULL) {
                    goto bad_tenant;
                }

                uint32_t tenant_id = 0;
                if (ByteExtractStringUint32(&tenant_id, 10, strlen(id_node->val),
                            id_node->val) == -1)
                {
                    SCLogError(SC_ERR_INVALID_ARGUMENT, "tenant_id  "
                            "of %s is invalid", id_node->val);
                    goto bad_tenant;
                }
                SCLogInfo("tenant id: %u, %s", tenant_id, yaml_node->val);

                /* setup the yaml in this loop so that it's not done by the loader
                 * threads. ConfYamlLoadFileWithPrefix is not thread safe. */
                char prefix[64];
                snprintf(prefix, sizeof(prefix), "multi-detect.%d", tenant_id);
                if (ConfYamlLoadFileWithPrefix(yaml_node->val, prefix) != 0) {
                    SCLogError(SC_ERR_CONF_YAML_ERROR, "failed to load yaml %s", yaml_node->val);
                    goto bad_tenant;
                }

                int r = DetectLoaderSetupLoadTenant(tenant_id, yaml_node->val);
                if (r < 0) {
                    /* error logged already */
                    goto bad_tenant;
                }
                continue;

            bad_tenant:
                if (failure_fatal)
                    goto error;
            }
        }

        /* wait for our loaders to complete their tasks */
        if (DetectLoadersSync() != 0) {
            goto error;
        }
    } else {
        SCLogDebug("multi-detect not enabled (multi tenancy)");
    }
    return 0;
error:
    return -1;
}

static uint32_t DetectEngineTentantGetIdFromVlanId(const void *ctx, const Packet *p)
{
    const DetectEngineThreadCtx *det_ctx = ctx;
    uint32_t x = 0;
    uint32_t vlan_id = 0;

    if (p->vlan_idx == 0)
        return 0;

    vlan_id = p->vlan_id[0];

    if (det_ctx == NULL || det_ctx->tenant_array == NULL || det_ctx->tenant_array_size == 0)
        return 0;

    /* not very efficient, but for now we're targeting only limited amounts.
     * Can use hash/tree approach later. */
    for (x = 0; x < det_ctx->tenant_array_size; x++) {
        if (det_ctx->tenant_array[x].traffic_id == vlan_id)
            return det_ctx->tenant_array[x].tenant_id;
    }

    return 0;
}

static int DetectEngineTentantRegisterSelector(enum DetectEngineTenantSelectors selector,
                                           uint32_t tenant_id, uint32_t traffic_id)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);

    if (!(master->tenant_selector == TENANT_SELECTOR_UNKNOWN || master->tenant_selector == selector)) {
        SCLogInfo("conflicting selector already set");
        SCMutexUnlock(&master->lock);
        return -1;
    }

    DetectEngineTenantMapping *m = master->tenant_mapping_list;
    while (m) {
        if (m->traffic_id == traffic_id) {
            SCLogInfo("traffic id already registered");
            SCMutexUnlock(&master->lock);
            return -1;
        }
        m = m->next;
    }

    DetectEngineTenantMapping *map = SCCalloc(1, sizeof(*map));
    if (map == NULL) {
        SCLogInfo("memory fail");
        SCMutexUnlock(&master->lock);
        return -1;
    }
    map->traffic_id = traffic_id;
    map->tenant_id = tenant_id;

    map->next = master->tenant_mapping_list;
    master->tenant_mapping_list = map;

    master->tenant_selector = selector;

    SCLogDebug("tenant handler %u %u %u registered", selector, tenant_id, traffic_id);
    SCMutexUnlock(&master->lock);
    return 0;
}

static int DetectEngineTentantUnregisterSelector(enum DetectEngineTenantSelectors selector,
                                           uint32_t tenant_id, uint32_t traffic_id)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);

    if (master->tenant_mapping_list == NULL) {
        SCMutexUnlock(&master->lock);
        return -1;
    }

    DetectEngineTenantMapping *prev = NULL;
    DetectEngineTenantMapping *map = master->tenant_mapping_list;
    while (map) {
        if (map->traffic_id == traffic_id &&
            map->tenant_id == tenant_id)
        {
            if (prev != NULL)
                prev->next = map->next;
            else
                master->tenant_mapping_list = map->next;

            map->next = NULL;
            SCFree(map);
            SCLogInfo("tenant handler %u %u %u unregistered", selector, tenant_id, traffic_id);
            SCMutexUnlock(&master->lock);
            return 0;
        }
        prev = map;
        map = map->next;
    }

    SCMutexUnlock(&master->lock);
    return -1;
}

int DetectEngineTentantRegisterVlanId(uint32_t tenant_id, uint16_t vlan_id)
{
    return DetectEngineTentantRegisterSelector(TENANT_SELECTOR_VLAN, tenant_id, (uint32_t)vlan_id);
}

int DetectEngineTentantUnregisterVlanId(uint32_t tenant_id, uint16_t vlan_id)
{
    return DetectEngineTentantUnregisterSelector(TENANT_SELECTOR_VLAN, tenant_id, (uint32_t)vlan_id);
}

int DetectEngineTentantRegisterPcapFile(uint32_t tenant_id)
{
    SCLogInfo("registering %u %d 0", TENANT_SELECTOR_DIRECT, tenant_id);
    return DetectEngineTentantRegisterSelector(TENANT_SELECTOR_DIRECT, tenant_id, 0);
}

int DetectEngineTentantUnregisterPcapFile(uint32_t tenant_id)
{
    SCLogInfo("unregistering %u %d 0", TENANT_SELECTOR_DIRECT, tenant_id);
    return DetectEngineTentantUnregisterSelector(TENANT_SELECTOR_DIRECT, tenant_id, 0);
}

static uint32_t DetectEngineTentantGetIdFromPcap(const void *ctx, const Packet *p)
{
    return p->pcap_v.tenant_id;
}

DetectEngineCtx *DetectEngineGetByTenantId(int tenant_id)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);

    if (master->list == NULL) {
        SCMutexUnlock(&master->lock);
        return NULL;
    }

    DetectEngineCtx *de_ctx = master->list;
    while (de_ctx) {
        if (de_ctx->tenant_id == tenant_id) {
            de_ctx->ref_cnt++;
            break;
        }

        de_ctx = de_ctx->next;
    }

    SCMutexUnlock(&master->lock);
    return de_ctx;
}

void DetectEngineDeReference(DetectEngineCtx **de_ctx)
{
    BUG_ON((*de_ctx)->ref_cnt == 0);
    (*de_ctx)->ref_cnt--;
    *de_ctx = NULL;
}

static int DetectEngineAddToList(DetectEngineCtx *instance)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;

    if (instance == NULL)
        return -1;

    if (master->list == NULL) {
        master->list = instance;
    } else {
        instance->next = master->list;
        master->list = instance;
    }

    return 0;
}

int DetectEngineAddToMaster(DetectEngineCtx *de_ctx)
{
    int r;

    if (de_ctx == NULL)
        return -1;

    SCLogDebug("adding de_ctx %p to master", de_ctx);

    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);
    r = DetectEngineAddToList(de_ctx);
    SCMutexUnlock(&master->lock);
    return r;
}

int DetectEngineMoveToFreeList(DetectEngineCtx *de_ctx)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;

    SCMutexLock(&master->lock);
    DetectEngineCtx *instance = master->list;
    if (instance == NULL) {
        SCMutexUnlock(&master->lock);
        return -1;
    }

    /* remove from active list */
    if (instance == de_ctx) {
        master->list = instance->next;
    } else {
        DetectEngineCtx *prev = instance;
        instance = instance->next; /* already checked first element */

        while (instance) {
            DetectEngineCtx *next = instance->next;

            if (instance == de_ctx) {
                prev->next = instance->next;
                break;
            }

            prev = instance;
            instance = next;
        }
        if (instance == NULL) {
            SCMutexUnlock(&master->lock);
            return -1;
        }
    }

    /* instance is now detached from list */
    instance->next = NULL;

    /* add to free list */
    if (master->free_list == NULL) {
        master->free_list = instance;
    } else {
        instance->next = master->free_list;
        master->free_list = instance;
    }
    SCLogDebug("detect engine %p moved to free list (%u refs)", de_ctx, de_ctx->ref_cnt);

    SCMutexUnlock(&master->lock);
    return 0;
}

void DetectEnginePruneFreeList(void)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);

    DetectEngineCtx *prev = NULL;
    DetectEngineCtx *instance = master->free_list;
    while (instance) {
        DetectEngineCtx *next = instance->next;

        SCLogDebug("detect engine %p has %u ref(s)", instance, instance->ref_cnt);

        if (instance->ref_cnt == 0) {
            if (prev == NULL) {
                master->free_list = next;
            } else {
                prev->next = next;
            }

            SCLogDebug("freeing detect engine %p", instance);
            DetectEngineCtxFree(instance);
            instance = NULL;
        }

        prev = instance;
        instance = next;
    }
    SCMutexUnlock(&master->lock);
}

static int reloads = 0;

/** \brief Reload the detection engine
 *
 *  \param filename YAML file to load for the detect config
 *
 *  \retval -1 error
 *  \retval 0 ok
 */
int DetectEngineReload(SCInstance *suri)
{
    DetectEngineCtx *new_de_ctx = NULL;
    DetectEngineCtx *old_de_ctx = NULL;

    char prefix[128];
    memset(prefix, 0, sizeof(prefix));

    SCLogNotice("rule reload starting");

    if (suri->conf_filename != NULL) {
        snprintf(prefix, sizeof(prefix), "detect-engine-reloads.%d", reloads++);
        if (ConfYamlLoadFileWithPrefix(suri->conf_filename, prefix) != 0) {
            SCLogError(SC_ERR_CONF_YAML_ERROR, "failed to load yaml %s",
                    suri->conf_filename);
            return -1;
        }

        ConfNode *node = ConfGetNode(prefix);
        if (node == NULL) {
            SCLogError(SC_ERR_CONF_YAML_ERROR, "failed to properly setup yaml %s",
                    suri->conf_filename);
            return -1;
        }
#if 0
        ConfDump();
#endif
    }

    /* get a reference to the current de_ctx */
    old_de_ctx = DetectEngineGetCurrent();
    if (old_de_ctx == NULL)
        return -1;
    SCLogDebug("get ref to old_de_ctx %p", old_de_ctx);

    /* get new detection engine */
    new_de_ctx = DetectEngineCtxInitWithPrefix(prefix);
    if (new_de_ctx == NULL) {
        SCLogError(SC_ERR_INITIALIZATION, "initializing detection engine "
                "context failed.");
        DetectEngineDeReference(&old_de_ctx);
        return -1;
    }
    if (SigLoadSignatures(new_de_ctx,
                          suri->sig_file, suri->sig_file_exclusive) != 0) {
        DetectEngineCtxFree(new_de_ctx);
        DetectEngineDeReference(&old_de_ctx);
        return -1;
    }
    SCThresholdConfInitContext(new_de_ctx, NULL);
    SCLogDebug("set up new_de_ctx %p", new_de_ctx);

    /* add to master */
    DetectEngineAddToMaster(new_de_ctx);

    /* move to old free list */
    DetectEngineMoveToFreeList(old_de_ctx);
    DetectEngineDeReference(&old_de_ctx);

    SCLogDebug("going to reload the threads to use new_de_ctx %p", new_de_ctx);
    /* update the threads */
    DetectEngineReloadThreads(new_de_ctx);
    SCLogDebug("threads now run new_de_ctx %p", new_de_ctx);

    /* walk free list, freeing the old_de_ctx */
    DetectEnginePruneFreeList();

    SCLogDebug("old_de_ctx should have been freed");

    SCLogNotice("rule reload complete");
    return 0;
}

static uint32_t TenantIdHash(HashTable *h, void *data, uint16_t data_len)
{
    DetectEngineThreadCtx *det_ctx = (DetectEngineThreadCtx *)data;
    return det_ctx->tenant_id % h->array_size;
}

static char TenantIdCompare(void *d1, uint16_t d1_len, void *d2, uint16_t d2_len)
{
    DetectEngineThreadCtx *det1 = (DetectEngineThreadCtx *)d1;
    DetectEngineThreadCtx *det2 = (DetectEngineThreadCtx *)d2;
    return (det1->tenant_id == det2->tenant_id);
}

static void TenantIdFree(void *d)
{
    DetectEngineThreadCtxFree(d);
}

int DetectEngineMTApply(void)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);

    if (master->tenant_selector == TENANT_SELECTOR_UNKNOWN) {
        SCLogInfo("error, no tenant selector");
        SCMutexUnlock(&master->lock);
        return -1;
    }

    DetectEngineCtx *minimal_de_ctx = NULL;
    /* if we have no tenants, we need a minimal one */
    if (master->list == NULL) {
        minimal_de_ctx = master->list = DetectEngineCtxInitMinimal();
        SCLogDebug("no tenants, using minimal %p", minimal_de_ctx);
    } else if (master->list->next == NULL && master->list->tenant_id == 0) {
        minimal_de_ctx = master->list;
        SCLogDebug("no tenants, using original %p", minimal_de_ctx);

    /* the default de_ctx should be in the list with tenant_id 0 */
    } else {
        DetectEngineCtx *list = master->list;
        for ( ; list != NULL; list = list->next) {
            SCLogInfo("list %p tenant %u", list, list->tenant_id);

            if (list->tenant_id == 0) {
                minimal_de_ctx = list;
                break;
            }
        }
    }

    /* update the threads */
    SCLogDebug("MT reload starting");
    DetectEngineReloadThreads(minimal_de_ctx);
    SCLogDebug("MT reload done");

    SCMutexUnlock(&master->lock);

    /* walk free list, freeing the old_de_ctx */
    DetectEnginePruneFreeList();

    SCLogDebug("old_de_ctx should have been freed");
    return 0;
}

const char *DetectSigmatchListEnumToString(enum DetectSigmatchListEnum type)
{
    switch (type) {
        case DETECT_SM_LIST_MATCH:
            return "packet";
        case DETECT_SM_LIST_PMATCH:
            return "packet/stream payload";

        case DETECT_SM_LIST_UMATCH:
            return "http uri";
        case DETECT_SM_LIST_HRUDMATCH:
            return "http raw uri";
        case DETECT_SM_LIST_HCBDMATCH:
            return "http client body";
        case DETECT_SM_LIST_FILEDATA:
            return "http server body";
        case DETECT_SM_LIST_HHDMATCH:
            return "http headers";
        case DETECT_SM_LIST_HRHDMATCH:
            return "http raw headers";
        case DETECT_SM_LIST_HSMDMATCH:
            return "http stat msg";
        case DETECT_SM_LIST_HSCDMATCH:
            return "http stat code";
        case DETECT_SM_LIST_HHHDMATCH:
            return "http host";
        case DETECT_SM_LIST_HRHHDMATCH:
            return "http raw host header";
        case DETECT_SM_LIST_HMDMATCH:
            return "http method";
        case DETECT_SM_LIST_HCDMATCH:
            return "http cookie";
        case DETECT_SM_LIST_HUADMATCH:
            return "http user-agent";
        case DETECT_SM_LIST_HRLMATCH:
            return "http request line";
        case DETECT_SM_LIST_APP_EVENT:
            return "app layer events";

        case DETECT_SM_LIST_AMATCH:
            return "generic app layer";
        case DETECT_SM_LIST_DMATCH:
            return "dcerpc";
        case DETECT_SM_LIST_TMATCH:
            return "tag";

        case DETECT_SM_LIST_FILEMATCH:
            return "file";

        case DETECT_SM_LIST_DNSQUERYNAME_MATCH:
            return "dns query name";
        case DETECT_SM_LIST_DNSREQUEST_MATCH:
            return "dns request";
        case DETECT_SM_LIST_DNSRESPONSE_MATCH:
            return "dns response";

        case DETECT_SM_LIST_TLSSNI_MATCH:
            return "tls sni extension";

        case DETECT_SM_LIST_MODBUS_MATCH:
            return "modbus";

        case DETECT_SM_LIST_BASE64_DATA:
            return "base64_data";

        case DETECT_SM_LIST_TEMPLATE_BUFFER_MATCH:
            return "template_buffer";

        case DETECT_SM_LIST_POSTMATCH:
            return "post-match";

        case DETECT_SM_LIST_SUPPRESS:
            return "suppress";
        case DETECT_SM_LIST_THRESHOLD:
            return "threshold";

        case DETECT_SM_LIST_MAX:
            return "max (internal)";
        case DETECT_SM_LIST_NOTSET:
            return "not set (internal)";
    }
    return "error";
}


/*************************************Unittest*********************************/

#ifdef UNITTESTS

static int DetectEngineInitYamlConf(char *conf)
{
    ConfCreateContextBackup();
    ConfInit();
    return ConfYamlLoadString(conf, strlen(conf));
}

static void DetectEngineDeInitYamlConf(void)
{
    ConfDeInit();
    ConfRestoreContextBackup();

    return;
}

static int DetectEngineTest01(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: medium\n"
        "  - custom-values:\n"
        "      toclient_src_groups: 2\n"
        "      toclient_dst_groups: 2\n"
        "      toclient_sp_groups: 2\n"
        "      toclient_dp_groups: 3\n"
        "      toserver_src_groups: 2\n"
        "      toserver_dst_groups: 4\n"
        "      toserver_sp_groups: 2\n"
        "      toserver_dp_groups: 25\n"
        "  - inspection-recursion-limit: 0\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (DetectEngineInitYamlConf(conf) == -1)
        return 0;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    result = (de_ctx->inspection_recursion_limit == -1);

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    return result;
}

static int DetectEngineTest02(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: medium\n"
        "  - custom-values:\n"
        "      toclient_src_groups: 2\n"
        "      toclient_dst_groups: 2\n"
        "      toclient_sp_groups: 2\n"
        "      toclient_dp_groups: 3\n"
        "      toserver_src_groups: 2\n"
        "      toserver_dst_groups: 4\n"
        "      toserver_sp_groups: 2\n"
        "      toserver_dp_groups: 25\n"
        "  - inspection-recursion-limit:\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (DetectEngineInitYamlConf(conf) == -1)
        return 0;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    result = (de_ctx->inspection_recursion_limit == -1);

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    return result;
}

static int DetectEngineTest03(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: medium\n"
        "  - custom-values:\n"
        "      toclient_src_groups: 2\n"
        "      toclient_dst_groups: 2\n"
        "      toclient_sp_groups: 2\n"
        "      toclient_dp_groups: 3\n"
        "      toserver_src_groups: 2\n"
        "      toserver_dst_groups: 4\n"
        "      toserver_sp_groups: 2\n"
        "      toserver_dp_groups: 25\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (DetectEngineInitYamlConf(conf) == -1)
        return 0;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    result = (de_ctx->inspection_recursion_limit ==
              DETECT_ENGINE_DEFAULT_INSPECTION_RECURSION_LIMIT);

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    return result;
}

static int DetectEngineTest04(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: medium\n"
        "  - custom-values:\n"
        "      toclient_src_groups: 2\n"
        "      toclient_dst_groups: 2\n"
        "      toclient_sp_groups: 2\n"
        "      toclient_dp_groups: 3\n"
        "      toserver_src_groups: 2\n"
        "      toserver_dst_groups: 4\n"
        "      toserver_sp_groups: 2\n"
        "      toserver_dp_groups: 25\n"
        "  - inspection-recursion-limit: 10\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (DetectEngineInitYamlConf(conf) == -1)
        return 0;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    result = (de_ctx->inspection_recursion_limit == 10);

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    return result;
}

int DummyTestAppInspectionEngine01(ThreadVars *tv,
                                   DetectEngineCtx *de_ctx,
                                   DetectEngineThreadCtx *det_ctx,
                                   Signature *sig,
                                   Flow *f,
                                   uint8_t flags,
                                   void *alstate,
                                   void *tx, uint64_t tx_id)
{
    return 0;
}

int DummyTestAppInspectionEngine02(ThreadVars *tv,
                                   DetectEngineCtx *de_ctx,
                                   DetectEngineThreadCtx *det_ctx,
                                   Signature *sig,
                                   Flow *f,
                                   uint8_t flags,
                                   void *alstate,
                                   void *tx, uint64_t tx_id)
{
    return 0;
}

int DetectEngineTest05(void)
{
    int result = 0;
    int ip = 0;

    DetectEngineAppInspectionEngine *engine_list[FLOW_PROTO_DEFAULT][ALPROTO_MAX][2];
    memset(engine_list, 0, sizeof(engine_list));

    DetectEngineRegisterAppInspectionEngine(IPPROTO_TCP,
                                            ALPROTO_HTTP,
                                            0 /* STREAM_TOSERVER */,
                                            DETECT_SM_LIST_UMATCH,
                                            DE_STATE_FLAG_URI_INSPECT,
                                            DummyTestAppInspectionEngine01,
                                            engine_list);

    int alproto = ALPROTO_UNKNOWN + 1;
    for (ip = 0; ip < FLOW_PROTO_DEFAULT; ip++) {
    for ( ; alproto < ALPROTO_FAILED; alproto++) {
        int dir = 0;
        for ( ; dir < 2; dir++) {
            if (alproto == ALPROTO_HTTP && dir == 0) {
                if (engine_list[ip][alproto][dir]->next != NULL) {
                    printf("more than one entry found\n");
                    goto end;
                }

                DetectEngineAppInspectionEngine *engine = engine_list[ip][alproto][dir];

                if (engine->alproto != alproto ||
                    engine->dir != dir ||
                    engine->sm_list != DETECT_SM_LIST_UMATCH ||
                    engine->inspect_flags != DE_STATE_FLAG_URI_INSPECT ||
                    engine->Callback != DummyTestAppInspectionEngine01) {
                    printf("failed for http and dir(0-toserver)\n");
                    goto end;
                }
            } /* if (alproto == ALPROTO_HTTP && dir == 0) */

            if (alproto == ALPROTO_HTTP && dir == 1) {
                if (engine_list[ip][alproto][dir] != NULL) {
                    printf("failed for http and dir(1-toclient)\n");
                    goto end;
                }
            }

            if (alproto != ALPROTO_HTTP &&
                engine_list[ip][alproto][0] != NULL &&
                engine_list[ip][alproto][1] != NULL) {
                printf("failed for protocol %d\n", alproto);
                goto end;
            }
        } /* for ( ; dir < 2 ..)*/
    } /* for ( ; alproto < ALPROTO_FAILED; ..) */
    }

    result = 1;
 end:
    return result;
}

int DetectEngineTest06(void)
{
    int result = 0;
    int ip = 0;

    DetectEngineAppInspectionEngine *engine_list[FLOW_PROTO_DEFAULT][ALPROTO_MAX][2];
    memset(engine_list, 0, sizeof(engine_list));

    DetectEngineRegisterAppInspectionEngine(IPPROTO_TCP,
                                            ALPROTO_HTTP,
                                            0 /* STREAM_TOSERVER */,
                                            DETECT_SM_LIST_UMATCH,
                                            DE_STATE_FLAG_URI_INSPECT,
                                            DummyTestAppInspectionEngine01,
                                            engine_list);
    DetectEngineRegisterAppInspectionEngine(IPPROTO_TCP,
                                            ALPROTO_HTTP,
                                            1 /* STREAM_TOCLIENT */,
                                            DETECT_SM_LIST_UMATCH,
                                            DE_STATE_FLAG_URI_INSPECT,
                                            DummyTestAppInspectionEngine02,
                                            engine_list);

    int alproto = ALPROTO_UNKNOWN + 1;
    for (ip = 0; ip < FLOW_PROTO_DEFAULT; ip++) {
    for ( ; alproto < ALPROTO_FAILED; alproto++) {
        int dir = 0;
        for ( ; dir < 2; dir++) {
            if (alproto == ALPROTO_HTTP && dir == 0) {
                if (engine_list[ip][alproto][dir]->next != NULL) {
                    printf("more than one entry found\n");
                    goto end;
                }

                DetectEngineAppInspectionEngine *engine = engine_list[ip][alproto][dir];

                if (engine->alproto != alproto ||
                    engine->dir != dir ||
                    engine->sm_list != DETECT_SM_LIST_UMATCH ||
                    engine->inspect_flags != DE_STATE_FLAG_URI_INSPECT ||
                    engine->Callback != DummyTestAppInspectionEngine01) {
                    printf("failed for http and dir(0-toserver)\n");
                    goto end;
                }
            } /* if (alproto == ALPROTO_HTTP && dir == 0) */

            if (alproto == ALPROTO_HTTP && dir == 1) {
                if (engine_list[ip][alproto][dir]->next != NULL) {
                    printf("more than one entry found\n");
                    goto end;
                }

                DetectEngineAppInspectionEngine *engine = engine_list[ip][alproto][dir];

                if (engine->alproto != alproto ||
                    engine->dir != dir ||
                    engine->sm_list != DETECT_SM_LIST_UMATCH ||
                    engine->inspect_flags != DE_STATE_FLAG_URI_INSPECT ||
                    engine->Callback != DummyTestAppInspectionEngine02) {
                    printf("failed for http and dir(0-toclient)\n");
                    goto end;
                }
            } /* if (alproto == ALPROTO_HTTP && dir == 1) */

            if (alproto != ALPROTO_HTTP &&
                engine_list[ip][alproto][0] != NULL &&
                engine_list[ip][alproto][1] != NULL) {
                printf("failed for protocol %d\n", alproto);
                goto end;
            }
        } /* for ( ; dir < 2 ..)*/
    } /* for ( ; alproto < ALPROTO_FAILED; ..) */
    }

    result = 1;
 end:
    return result;
}

int DetectEngineTest07(void)
{
    int result = 0;
    int ip = 0;

    DetectEngineAppInspectionEngine *engine_list[FLOW_PROTO_DEFAULT][ALPROTO_MAX][2];
    memset(engine_list, 0, sizeof(engine_list));

    struct test_data_t {
        int32_t sm_list;
        uint32_t inspect_flags;
        uint16_t dir;
        int (*Callback)(ThreadVars *tv,
                        DetectEngineCtx *de_ctx,
                        DetectEngineThreadCtx *det_ctx,
                        Signature *sig, Flow *f,
                        uint8_t flags, void *alstate,
                        void *tx, uint64_t tx_id);

    };

    struct test_data_t data[] = {
        { DETECT_SM_LIST_UMATCH,
          DE_STATE_FLAG_URI_INSPECT,
          0,
          DummyTestAppInspectionEngine01 },
        { DETECT_SM_LIST_HCBDMATCH,
          DE_STATE_FLAG_HCBD_INSPECT,
          0,
          DummyTestAppInspectionEngine02 },
        { DETECT_SM_LIST_FILEDATA,
          DE_STATE_FLAG_HSBD_INSPECT,
          1,
          DummyTestAppInspectionEngine02 },
        { DETECT_SM_LIST_HHDMATCH,
          DE_STATE_FLAG_HHD_INSPECT,
          0,
          DummyTestAppInspectionEngine01 },
        { DETECT_SM_LIST_HRHDMATCH,
          DE_STATE_FLAG_HRHD_INSPECT,
          0,
          DummyTestAppInspectionEngine01 },
        { DETECT_SM_LIST_HMDMATCH,
          DE_STATE_FLAG_HMD_INSPECT,
          0,
          DummyTestAppInspectionEngine02 },
        { DETECT_SM_LIST_HCDMATCH,
          DE_STATE_FLAG_HCD_INSPECT,
          0,
          DummyTestAppInspectionEngine01 },
        { DETECT_SM_LIST_HRUDMATCH,
          DE_STATE_FLAG_HRUD_INSPECT,
          0,
          DummyTestAppInspectionEngine01 },
        { DETECT_SM_LIST_FILEMATCH,
          DE_STATE_FLAG_FILE_TS_INSPECT,
          0,
          DummyTestAppInspectionEngine02 },
        { DETECT_SM_LIST_FILEMATCH,
          DE_STATE_FLAG_FILE_TC_INSPECT,
          1,
          DummyTestAppInspectionEngine02 },
        { DETECT_SM_LIST_HSMDMATCH,
          DE_STATE_FLAG_HSMD_INSPECT,
          0,
          DummyTestAppInspectionEngine01 },
        { DETECT_SM_LIST_HSCDMATCH,
          DE_STATE_FLAG_HSCD_INSPECT,
          0,
          DummyTestAppInspectionEngine01 },
        { DETECT_SM_LIST_HUADMATCH,
          DE_STATE_FLAG_HUAD_INSPECT,
          0,
          DummyTestAppInspectionEngine02 },
    };

    size_t i = 0;
    for ( ; i < sizeof(data) / sizeof(struct test_data_t); i++) {
        DetectEngineRegisterAppInspectionEngine(IPPROTO_TCP,
                                                ALPROTO_HTTP,
                                                data[i].dir /* STREAM_TOCLIENT */,
                                                data[i].sm_list,
                                                data[i].inspect_flags,
                                                data[i].Callback,
                                                engine_list);
    }

#if 0
    DetectEnginePrintAppInspectionEngines(engine_list);
#endif

    int alproto = ALPROTO_UNKNOWN + 1;
    for (ip = 0; ip < FLOW_PROTO_DEFAULT; ip++) {
    for ( ; alproto < ALPROTO_FAILED; alproto++) {
        int dir = 0;
        for ( ; dir < 2; dir++) {
            if (alproto == ALPROTO_HTTP) {
                DetectEngineAppInspectionEngine *engine = engine_list[ip][alproto][dir];

                size_t i = 0;
                for ( ; i < (sizeof(data) / sizeof(struct test_data_t)); i++) {
                    if (data[i].dir != dir)
                        continue;

                    if (engine->alproto != ALPROTO_HTTP ||
                        engine->dir != data[i].dir ||
                        engine->sm_list != data[i].sm_list ||
                        engine->inspect_flags != data[i].inspect_flags ||
                        engine->Callback != data[i].Callback) {
                        printf("failed for http\n");
                        goto end;
                    }
                    engine = engine->next;
                }
            } else {
                if (engine_list[ip][alproto][0] != NULL &&
                    engine_list[ip][alproto][1] != NULL) {
                    printf("failed for protocol %d\n", alproto);
                    goto end;
                }
            } /* else */
        } /* for ( ; dir < 2; dir++) */
    } /* for ( ; alproto < ALPROTO_FAILED; ..) */
    }

    result = 1;
 end:
    return result;
}

static int DetectEngineTest08(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: custom\n"
        "  - custom-values:\n"
        "      toclient-groups: 23\n"
        "      toserver-groups: 27\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (DetectEngineInitYamlConf(conf) == -1)
        return 0;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    if (de_ctx->max_uniq_toclient_groups == 23 &&
        de_ctx->max_uniq_toserver_groups == 27)
        result = 1;

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    return result;
}

/** \test bug 892 bad values */
static int DetectEngineTest09(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: custom\n"
        "  - custom-values:\n"
        "      toclient-groups: BA\n"
        "      toserver-groups: BA\n"
        "  - inspection-recursion-limit: 10\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (DetectEngineInitYamlConf(conf) == -1)
        return 0;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    if (de_ctx->max_uniq_toclient_groups == 20 &&
        de_ctx->max_uniq_toserver_groups == 40)
        result = 1;

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    return result;
}

#endif

void DetectEngineRegisterTests()
{

#ifdef UNITTESTS
    UtRegisterTest("DetectEngineTest01", DetectEngineTest01);
    UtRegisterTest("DetectEngineTest02", DetectEngineTest02);
    UtRegisterTest("DetectEngineTest03", DetectEngineTest03);
    UtRegisterTest("DetectEngineTest04", DetectEngineTest04);
    UtRegisterTest("DetectEngineTest05", DetectEngineTest05);
    UtRegisterTest("DetectEngineTest06", DetectEngineTest06);
    UtRegisterTest("DetectEngineTest07", DetectEngineTest07);
    UtRegisterTest("DetectEngineTest08", DetectEngineTest08);
    UtRegisterTest("DetectEngineTest09", DetectEngineTest09);
#endif

    return;
}
