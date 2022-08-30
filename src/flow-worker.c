/* Copyright (C) 2016-2022 Open Information Security Foundation
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
 * Flow Workers are single thread modules taking care of (almost)
 * everything related to packets with flows:
 *
 * - Lookup/creation
 * - Stream tracking, reassembly
 * - Applayer update
 * - Detection
 *
 * This all while holding the flow lock.
 */

#include "suricata-common.h"
#include "suricata.h"

#include "decode.h"
#include "detect.h"
#include "stream-tcp.h"
#include "app-layer.h"
#include "detect-engine.h"
#include "output.h"
#include "app-layer-parser.h"
#include "app-layer-frames.h"

#include "util-profiling.h"
#include "util-validate.h"
#include "util-time.h"
#include "tmqh-packetpool.h"

#include "flow-util.h"
#include "flow-manager.h"
#include "flow-timeout.h"
#include "flow-spare-pool.h"
#include "flow-worker.h"

typedef DetectEngineThreadCtx *DetectEngineThreadCtxPtr;

typedef struct FlowTimeoutCounters {
    uint32_t flows_aside_needs_work;
    uint32_t flows_aside_pkt_inject;
} FlowTimeoutCounters;

typedef struct FlowWorkerThreadData_ {
    DecodeThreadVars *dtv;

    union {
        StreamTcpThread *stream_thread;
        void *stream_thread_ptr;
    };

    SC_ATOMIC_DECLARE(DetectEngineThreadCtxPtr, detect_thread);

    void *output_thread; /* Output thread data. */
    void *output_thread_flow; /* Output thread data. */

    uint16_t local_bypass_pkts;
    uint16_t local_bypass_bytes;
    uint16_t both_bypass_pkts;
    uint16_t both_bypass_bytes;

    PacketQueueNoLock pq;
    FlowLookupStruct fls;

    struct {
        uint16_t flows_injected;
        uint16_t flows_removed;
        uint16_t flows_aside_needs_work;
        uint16_t flows_aside_pkt_inject;
    } cnt;
    FlowEndCounters fec;

} FlowWorkerThreadData;

static void FlowWorkerFlowTimeout(ThreadVars *tv, Packet *p, FlowWorkerThreadData *fw, void *detect_thread);
Packet *FlowForceReassemblyPseudoPacketGet(int direction, Flow *f, TcpSession *ssn);

/**
 * \internal
 * \brief Forces reassembly for flow if it needs it.
 *
 *        The function requires flow to be locked beforehand.
 *
 * \param f Pointer to the flow.
 *
 * \retval cnt number of packets injected
 */
static int FlowFinish(ThreadVars *tv, Flow *f, FlowWorkerThreadData *fw, void *detect_thread)
{
    Packet *p1 = NULL, *p2 = NULL;
    const int server = f->ffr_tc;
    const int client = f->ffr_ts;

    /* Get the tcp session for the flow */
    TcpSession *ssn = (TcpSession *)f->protoctx;

    /* The packets we use are based on what segments in what direction are
     * unprocessed.
     * p1 if we have client segments for reassembly purpose only.  If we
     * have no server segments p2 can be a toserver packet with dummy
     * seq/ack, and if we have server segments p2 has to carry out reassembly
     * for server segment as well, in which case we will also need a p3 in the
     * toclient which is now dummy since all we need it for is detection */

    /* insert a pseudo packet in the toserver direction */
    if (client == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION) {
        p1 = FlowForceReassemblyPseudoPacketGet(0, f, ssn);
        if (p1 == NULL) {
            return 0;
        }
        PKT_SET_SRC(p1, PKT_SRC_FFR);

        if (server == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION) {
            p2 = FlowForceReassemblyPseudoPacketGet(1, f, ssn);
            if (p2 == NULL) {
                FlowDeReference(&p1->flow);
                TmqhOutputPacketpool(NULL, p1);
                return 0;
            }
            PKT_SET_SRC(p2, PKT_SRC_FFR);
            p2->flowflags |= FLOW_PKT_LAST_PSEUDO;
        } else {
            p1->flowflags |= FLOW_PKT_LAST_PSEUDO;
        }
    } else {
        if (server == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION) {
            p1 = FlowForceReassemblyPseudoPacketGet(1, f, ssn);
            if (p1 == NULL) {
                return 0;
            }
            PKT_SET_SRC(p1, PKT_SRC_FFR);
            p1->flowflags |= FLOW_PKT_LAST_PSEUDO;
        } else {
            /* impossible */
            BUG_ON(1);
        }
    }
    f->flags |= FLOW_TIMEOUT_REASSEMBLY_DONE;

    FlowWorkerFlowTimeout(tv, p1, fw, detect_thread);
    PacketPoolReturnPacket(p1);
    if (p2) {
        FlowWorkerFlowTimeout(tv, p2, fw, detect_thread);
        PacketPoolReturnPacket(p2);
        return 2;
    }
    return 1;
}

static void CheckWorkQueue(ThreadVars *tv, FlowWorkerThreadData *fw,
        void *detect_thread, // TODO proper type?
        FlowTimeoutCounters *counters,
        FlowQueuePrivate *fq)
{
    Flow *f;
    while ((f = FlowQueuePrivateGetFromTop(fq)) != NULL) {
        FLOWLOCK_WRLOCK(f);
        f->flow_end_flags |= FLOW_END_FLAG_TIMEOUT; //TODO emerg

        if (f->proto == IPPROTO_TCP) {
            if (!(f->flags & FLOW_TIMEOUT_REASSEMBLY_DONE) && !FlowIsBypassed(f) &&
                    FlowForceReassemblyNeedReassembly(f) == 1 && f->ffr != 0) {
                int cnt = FlowFinish(tv, f, fw, detect_thread);
                counters->flows_aside_pkt_inject += cnt;
                counters->flows_aside_needs_work++;
            }
        }

        /* this should not be possible */
        BUG_ON(f->use_cnt > 0);

        /* no one is referring to this flow, use_cnt 0, removed from hash
         * so we can unlock it and pass it to the flow recycler */

        if (fw->output_thread_flow != NULL)
            (void)OutputFlowLog(tv, fw->output_thread_flow, f);

        FlowEndCountersUpdate(tv, &fw->fec, f);
        if (f->proto == IPPROTO_TCP && f->protoctx != NULL) {
            StatsDecr(tv, fw->dtv->counter_tcp_active_sessions);
        }
        StatsDecr(tv, fw->dtv->counter_flow_active);

        FlowClearMemory (f, f->protomap);
        FLOWLOCK_UNLOCK(f);
        if (fw->fls.spare_queue.len >= 200) { // TODO match to API? 200 = 2 * block size
            FlowSparePoolReturnFlow(f);
        } else {
            FlowQueuePrivatePrependFlow(&fw->fls.spare_queue, f);
        }
    }
}

/** \brief handle flow for packet
 *
 *  Handle flow creation/lookup
 */
static inline TmEcode FlowUpdate(ThreadVars *tv, FlowWorkerThreadData *fw, Packet *p)
{
    FlowHandlePacketUpdate(p->flow, p, tv, fw->dtv);

    int state = p->flow->flow_state;
    switch (state) {
#ifdef CAPTURE_OFFLOAD
        case FLOW_STATE_CAPTURE_BYPASSED: {
            StatsAddUI64(tv, fw->both_bypass_pkts, 1);
            StatsAddUI64(tv, fw->both_bypass_bytes, GET_PKT_LEN(p));
            Flow *f = p->flow;
            FlowDeReference(&p->flow);
            FLOWLOCK_UNLOCK(f);
            return TM_ECODE_DONE;
        }
#endif
        case FLOW_STATE_LOCAL_BYPASSED: {
            StatsAddUI64(tv, fw->local_bypass_pkts, 1);
            StatsAddUI64(tv, fw->local_bypass_bytes, GET_PKT_LEN(p));
            Flow *f = p->flow;
            FlowDeReference(&p->flow);
            FLOWLOCK_UNLOCK(f);
            return TM_ECODE_DONE;
        }
        default:
            return TM_ECODE_OK;
    }
}

static TmEcode FlowWorkerThreadDeinit(ThreadVars *tv, void *data);

static TmEcode FlowWorkerThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    FlowWorkerThreadData *fw = SCCalloc(1, sizeof(*fw));
    if (fw == NULL)
        return TM_ECODE_FAILED;

    SC_ATOMIC_INITPTR(fw->detect_thread);
    SC_ATOMIC_SET(fw->detect_thread, NULL);

    fw->local_bypass_pkts = StatsRegisterCounter("flow_bypassed.local_pkts", tv);
    fw->local_bypass_bytes = StatsRegisterCounter("flow_bypassed.local_bytes", tv);
    fw->both_bypass_pkts = StatsRegisterCounter("flow_bypassed.local_capture_pkts", tv);
    fw->both_bypass_bytes = StatsRegisterCounter("flow_bypassed.local_capture_bytes", tv);

    fw->cnt.flows_aside_needs_work = StatsRegisterCounter("flow.wrk.flows_evicted_needs_work", tv);
    fw->cnt.flows_aside_pkt_inject = StatsRegisterCounter("flow.wrk.flows_evicted_pkt_inject", tv);
    fw->cnt.flows_removed = StatsRegisterCounter("flow.wrk.flows_evicted", tv);
    fw->cnt.flows_injected = StatsRegisterCounter("flow.wrk.flows_injected", tv);

    fw->fls.dtv = fw->dtv = DecodeThreadVarsAlloc(tv);
    if (fw->dtv == NULL) {
        FlowWorkerThreadDeinit(tv, fw);
        return TM_ECODE_FAILED;
    }

    /* setup TCP */
    if (StreamTcpThreadInit(tv, NULL, &fw->stream_thread_ptr) != TM_ECODE_OK) {
        FlowWorkerThreadDeinit(tv, fw);
        return TM_ECODE_FAILED;
    }

    if (DetectEngineEnabled()) {
        /* setup DETECT */
        void *detect_thread = NULL;
        if (DetectEngineThreadCtxInit(tv, NULL, &detect_thread) != TM_ECODE_OK) {
            FlowWorkerThreadDeinit(tv, fw);
            return TM_ECODE_FAILED;
        }
        SC_ATOMIC_SET(fw->detect_thread, detect_thread);
    }

    /* Setup outputs for this thread. */
    if (OutputLoggerThreadInit(tv, initdata, &fw->output_thread) != TM_ECODE_OK) {
        FlowWorkerThreadDeinit(tv, fw);
        return TM_ECODE_FAILED;
    }
    if (OutputFlowLogThreadInit(tv, NULL, &fw->output_thread_flow) != TM_ECODE_OK) {
        SCLogError(SC_ERR_THREAD_INIT, "initializing flow log API for thread failed");
        FlowWorkerThreadDeinit(tv, fw);
        return TM_ECODE_FAILED;
    }

    DecodeRegisterPerfCounters(fw->dtv, tv);
    AppLayerRegisterThreadCounters(tv);
    FlowEndCountersRegister(tv, &fw->fec);

    /* setup pq for stream end pkts */
    memset(&fw->pq, 0, sizeof(PacketQueueNoLock));
    *data = fw;
    return TM_ECODE_OK;
}

static TmEcode FlowWorkerThreadDeinit(ThreadVars *tv, void *data)
{
    FlowWorkerThreadData *fw = data;

    DecodeThreadVarsFree(tv, fw->dtv);

    /* free TCP */
    StreamTcpThreadDeinit(tv, (void *)fw->stream_thread);

    /* free DETECT */
    void *detect_thread = SC_ATOMIC_GET(fw->detect_thread);
    if (detect_thread != NULL) {
        DetectEngineThreadCtxDeinit(tv, detect_thread);
        SC_ATOMIC_SET(fw->detect_thread, NULL);
    }

    /* Free output. */
    OutputLoggerThreadDeinit(tv, fw->output_thread);
    OutputFlowLogThreadDeinit(tv, fw->output_thread_flow);

    /* free pq */
    BUG_ON(fw->pq.len);

    Flow *f;
    while ((f = FlowQueuePrivateGetFromTop(&fw->fls.spare_queue)) != NULL) {
        FlowFree(f);
    }

    SCFree(fw);
    return TM_ECODE_OK;
}

TmEcode Detect(ThreadVars *tv, Packet *p, void *data);
TmEcode StreamTcp (ThreadVars *, Packet *, void *, PacketQueueNoLock *pq);

static inline void UpdateCounters(ThreadVars *tv,
        FlowWorkerThreadData *fw, const FlowTimeoutCounters *counters)
{
    if (counters->flows_aside_needs_work) {
        StatsAddUI64(tv, fw->cnt.flows_aside_needs_work,
                (uint64_t)counters->flows_aside_needs_work);
    }
    if (counters->flows_aside_pkt_inject) {
        StatsAddUI64(tv, fw->cnt.flows_aside_pkt_inject,
                (uint64_t)counters->flows_aside_pkt_inject);
    }
}

static void FlowPruneFiles(Packet *p)
{
    if (p->flow && p->flow->alstate) {
        Flow *f = p->flow;
        FileContainer *fc = AppLayerParserGetFiles(f,
                PKT_IS_TOSERVER(p) ? STREAM_TOSERVER : STREAM_TOCLIENT);
        if (fc != NULL) {
            FilePrune(fc);
        }
    }
}

/** \brief update stream engine
 *
 *  We can be called from both the flow timeout path as well as from the
 *  "real" traffic path. If in the timeout path any additional packets we
 *  forge for flushing pipelines should not leave our scope. If the original
 *  packet is real (or related to a real packet) we need to push the packets
 *  on, so IPS logic stays valid.
 */
static inline void FlowWorkerStreamTCPUpdate(ThreadVars *tv, FlowWorkerThreadData *fw, Packet *p,
        void *detect_thread, const bool timeout)
{
    FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_STREAM);
    StreamTcp(tv, p, fw->stream_thread, &fw->pq);
    FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_STREAM);

    if (FlowChangeProto(p->flow)) {
        StreamTcpDetectLogFlush(tv, fw->stream_thread, p->flow, p, &fw->pq);
        AppLayerParserStateSetFlag(p->flow->alparser, APP_LAYER_PARSER_EOF_TS);
        AppLayerParserStateSetFlag(p->flow->alparser, APP_LAYER_PARSER_EOF_TC);
    }

    /* Packets here can safely access p->flow as it's locked */
    SCLogDebug("packet %"PRIu64": extra packets %u", p->pcap_cnt, fw->pq.len);
    Packet *x;
    while ((x = PacketDequeueNoLock(&fw->pq))) {
        SCLogDebug("packet %"PRIu64" extra packet %p", p->pcap_cnt, x);

        if (detect_thread != NULL) {
            FLOWWORKER_PROFILING_START(x, PROFILE_FLOWWORKER_DETECT);
            Detect(tv, x, detect_thread);
            FLOWWORKER_PROFILING_END(x, PROFILE_FLOWWORKER_DETECT);
        }

        OutputLoggerLog(tv, x, fw->output_thread);

        if (timeout) {
            PacketPoolReturnPacket(x);
        } else {
            /* put these packets in the preq queue so that they are
             * by the other thread modules before packet 'p'. */
            PacketEnqueueNoLock(&tv->decode_pq, x);
        }
    }
}

static void FlowWorkerFlowTimeout(ThreadVars *tv, Packet *p, FlowWorkerThreadData *fw,
        void *detect_thread)
{
    DEBUG_VALIDATE_BUG_ON(p->pkt_src != PKT_SRC_FFR);

    SCLogDebug("packet %"PRIu64" is TCP. Direction %s", p->pcap_cnt, PKT_IS_TOSERVER(p) ? "TOSERVER" : "TOCLIENT");
    DEBUG_VALIDATE_BUG_ON(!(p->flow && PKT_IS_TCP(p)));
    DEBUG_ASSERT_FLOW_LOCKED(p->flow);

    /* handle TCP and app layer */
    FlowWorkerStreamTCPUpdate(tv, fw, p, detect_thread, true);

    PacketUpdateEngineEventCounters(tv, fw->dtv, p);

    /* handle Detect */
    SCLogDebug("packet %"PRIu64" calling Detect", p->pcap_cnt);
    if (detect_thread != NULL) {
        FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_DETECT);
        Detect(tv, p, detect_thread);
        FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_DETECT);
    }

    // Outputs.
    OutputLoggerLog(tv, p, fw->output_thread);

    /* Prune any stored files. */
    FlowPruneFiles(p);

    FramesPrune(p->flow, p);
    /*  Release tcp segments. Done here after alerting can use them. */
    FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_TCPPRUNE);
    StreamTcpPruneSession(p->flow, p->flowflags & FLOW_PKT_TOSERVER ?
            STREAM_TOSERVER : STREAM_TOCLIENT);
    FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_TCPPRUNE);

    /* run tx cleanup last */
    AppLayerParserTransactionsCleanup(p->flow);

    FlowDeReference(&p->flow);
    /* flow is unlocked later in FlowFinish() */
}

/** \internal
 *  \brief process flows injected into our queue by other threads
 */
static inline void FlowWorkerProcessInjectedFlows(ThreadVars *tv,
        FlowWorkerThreadData *fw, Packet *p, void *detect_thread)
{
    /* take injected flows and append to our work queue */
    FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_FLOW_INJECTED);
    FlowQueuePrivate injected = { NULL, NULL, 0 };
    if (SC_ATOMIC_GET(tv->flow_queue->non_empty) == true)
        injected = FlowQueueExtractPrivate(tv->flow_queue);
    if (injected.len > 0) {
        StatsAddUI64(tv, fw->cnt.flows_injected, (uint64_t)injected.len);

        FlowTimeoutCounters counters = { 0, 0, };
        CheckWorkQueue(tv, fw, detect_thread, &counters, &injected);
        UpdateCounters(tv, fw, &counters);
    }
    FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_FLOW_INJECTED);
}

/** \internal
 *  \brief process flows set aside locally during flow lookup
 */
static inline void FlowWorkerProcessLocalFlows(ThreadVars *tv,
        FlowWorkerThreadData *fw, Packet *p, void *detect_thread)
{
    FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_FLOW_EVICTED);
    if (fw->fls.work_queue.len) {
        StatsAddUI64(tv, fw->cnt.flows_removed, (uint64_t)fw->fls.work_queue.len);

        FlowTimeoutCounters counters = { 0, 0, };
        CheckWorkQueue(tv, fw, detect_thread, &counters, &fw->fls.work_queue);
        UpdateCounters(tv, fw, &counters);
    }
    FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_FLOW_EVICTED);
}

static TmEcode FlowWorker(ThreadVars *tv, Packet *p, void *data)
{
    FlowWorkerThreadData *fw = data;
    void *detect_thread = SC_ATOMIC_GET(fw->detect_thread);

    DEBUG_VALIDATE_BUG_ON(p == NULL);
    DEBUG_VALIDATE_BUG_ON(tv->flow_queue == NULL);

    SCLogDebug("packet %"PRIu64, p->pcap_cnt);

    /* update time */
    if (!(PKT_IS_PSEUDOPKT(p))) {
        TimeSetByThread(tv->id, &p->ts);
    }

    /* handle Flow */
    if (p->flags & PKT_WANTS_FLOW) {
        FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_FLOW);

        FlowHandlePacket(tv, &fw->fls, p);
        if (likely(p->flow != NULL)) {
            DEBUG_ASSERT_FLOW_LOCKED(p->flow);
            if (FlowUpdate(tv, fw, p) == TM_ECODE_DONE) {
                goto housekeeping;
            }
        }
        /* Flow is now LOCKED */

        FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_FLOW);

    /* if PKT_WANTS_FLOW is not set, but PKT_HAS_FLOW is, then this is a
     * pseudo packet created by the flow manager. */
    } else if (p->flags & PKT_HAS_FLOW) {
        FLOWLOCK_WRLOCK(p->flow);
        DEBUG_VALIDATE_BUG_ON(p->pkt_src != PKT_SRC_FFR);
    }

    SCLogDebug("packet %"PRIu64" has flow? %s", p->pcap_cnt, p->flow ? "yes" : "no");

    /* handle TCP and app layer */
    if (p->flow && PKT_IS_TCP(p)) {
        SCLogDebug("packet %"PRIu64" is TCP. Direction %s", p->pcap_cnt, PKT_IS_TOSERVER(p) ? "TOSERVER" : "TOCLIENT");
        DEBUG_ASSERT_FLOW_LOCKED(p->flow);

        /* if detect is disabled, we need to apply file flags to the flow
         * here on the first packet. */
        if (detect_thread == NULL &&
                ((PKT_IS_TOSERVER(p) && (p->flowflags & FLOW_PKT_TOSERVER_FIRST)) ||
                 (PKT_IS_TOCLIENT(p) && (p->flowflags & FLOW_PKT_TOCLIENT_FIRST))))
        {
            DisableDetectFlowFileFlags(p->flow);
        }

        FlowWorkerStreamTCPUpdate(tv, fw, p, detect_thread, false);

        /* handle the app layer part of the UDP packet payload */
    } else if (p->flow && p->proto == IPPROTO_UDP) {
        FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_APPLAYERUDP);
        AppLayerHandleUdp(tv, fw->stream_thread->ra_ctx->app_tctx, p, p->flow);
        FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_APPLAYERUDP);
    }

    PacketUpdateEngineEventCounters(tv, fw->dtv, p);

    /* handle Detect */
    DEBUG_ASSERT_FLOW_LOCKED(p->flow);
    SCLogDebug("packet %"PRIu64" calling Detect", p->pcap_cnt);
    if (detect_thread != NULL) {
        FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_DETECT);
        Detect(tv, p, detect_thread);
        FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_DETECT);
    }

    // Outputs.
    OutputLoggerLog(tv, p, fw->output_thread);

    /* Prune any stored files. */
    FlowPruneFiles(p);

    /*  Release tcp segments. Done here after alerting can use them. */
    if (p->flow != NULL) {
        DEBUG_ASSERT_FLOW_LOCKED(p->flow);

        if (FlowIsBypassed(p->flow)) {
            FlowCleanupAppLayer(p->flow);
            if (p->proto == IPPROTO_TCP) {
                StreamTcpSessionCleanup(p->flow->protoctx);
            }
        } else if (p->proto == IPPROTO_TCP && p->flow->protoctx) {
            FramesPrune(p->flow, p);
            FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_TCPPRUNE);
            StreamTcpPruneSession(p->flow, p->flowflags & FLOW_PKT_TOSERVER ?
                    STREAM_TOSERVER : STREAM_TOCLIENT);
            FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_TCPPRUNE);
        } else if (p->proto == IPPROTO_UDP) {
            FramesPrune(p->flow, p);
        }

        /* run tx cleanup last */
        AppLayerParserTransactionsCleanup(p->flow);

        Flow *f = p->flow;
        FlowDeReference(&p->flow);
        FLOWLOCK_UNLOCK(f);
    }

housekeeping:

    /* take injected flows and process them */
    FlowWorkerProcessInjectedFlows(tv, fw, p, detect_thread);

    /* process local work queue */
    FlowWorkerProcessLocalFlows(tv, fw, p, detect_thread);

    return TM_ECODE_OK;
}

void FlowWorkerReplaceDetectCtx(void *flow_worker, void *detect_ctx)
{
    FlowWorkerThreadData *fw = flow_worker;

    SC_ATOMIC_SET(fw->detect_thread, detect_ctx);
}

void *FlowWorkerGetDetectCtxPtr(void *flow_worker)
{
    FlowWorkerThreadData *fw = flow_worker;

    return SC_ATOMIC_GET(fw->detect_thread);
}

const char *ProfileFlowWorkerIdToString(enum ProfileFlowWorkerId fwi)
{
    switch (fwi) {
        case PROFILE_FLOWWORKER_FLOW:
            return "flow";
        case PROFILE_FLOWWORKER_STREAM:
            return "stream";
        case PROFILE_FLOWWORKER_APPLAYERUDP:
            return "app-layer";
        case PROFILE_FLOWWORKER_DETECT:
            return "detect";
        case PROFILE_FLOWWORKER_TCPPRUNE:
            return "tcp-prune";
        case PROFILE_FLOWWORKER_FLOW_INJECTED:
            return "flow-inject";
        case PROFILE_FLOWWORKER_FLOW_EVICTED:
            return "flow-evict";
        case PROFILE_FLOWWORKER_SIZE:
            return "size";
    }
    return "error";
}

static void FlowWorkerExitPrintStats(ThreadVars *tv, void *data)
{
    FlowWorkerThreadData *fw = data;
    OutputLoggerExitPrintStats(tv, fw->output_thread);
}

void TmModuleFlowWorkerRegister (void)
{
    tmm_modules[TMM_FLOWWORKER].name = "FlowWorker";
    tmm_modules[TMM_FLOWWORKER].ThreadInit = FlowWorkerThreadInit;
    tmm_modules[TMM_FLOWWORKER].Func = FlowWorker;
    tmm_modules[TMM_FLOWWORKER].ThreadDeinit = FlowWorkerThreadDeinit;
    tmm_modules[TMM_FLOWWORKER].ThreadExitPrintStats = FlowWorkerExitPrintStats;
    tmm_modules[TMM_FLOWWORKER].cap_flags = 0;
    tmm_modules[TMM_FLOWWORKER].flags = TM_FLAG_STREAM_TM|TM_FLAG_DETECT_TM;
}
