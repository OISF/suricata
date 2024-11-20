/* Copyright (C) 2016-2024 Open Information Security Foundation
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

#include "action-globals.h"
#include "packet.h"
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

    SC_ATOMIC_DECLARE(bool, flush_ack);

    void *output_thread; /* Output thread data. */
    void *output_thread_flow; /* Output thread data. */

    uint16_t local_bypass_pkts;
    uint16_t local_bypass_bytes;
    uint16_t both_bypass_pkts;
    uint16_t both_bypass_bytes;
    /** Queue to put pseudo packets that have been created by the stream (RST response) and by the
     * flush logic following a protocol change. */
    PacketQueueNoLock pq;
    FlowLookupStruct fls;

    struct {
        uint16_t flows_injected;
        uint16_t flows_injected_max;
        uint16_t flows_removed;
        uint16_t flows_aside_needs_work;
        uint16_t flows_aside_pkt_inject;
    } cnt;
    FlowEndCounters fec;

} FlowWorkerThreadData;

static void FlowWorkerFlowTimeout(
        ThreadVars *tv, Packet *p, FlowWorkerThreadData *fw, void *detect_thread);

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
    const int server = f->ffr_tc;
    const int client = f->ffr_ts;
    int cnt = 0;

    /* Get the tcp session for the flow */
    const TcpSession *ssn = (TcpSession *)f->protoctx;

    /* insert a pseudo packet in the toserver direction */
    if (client == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION) {
        Packet *p = FlowPseudoPacketGet(0, f, ssn);
        if (p != NULL) {
            PKT_SET_SRC(p, PKT_SRC_FFR);
            if (server == STREAM_HAS_UNPROCESSED_SEGMENTS_NONE) {
                p->flowflags |= FLOW_PKT_LAST_PSEUDO;
            }
            FlowWorkerFlowTimeout(tv, p, fw, detect_thread);
            PacketPoolReturnPacket(p);
            cnt++;
        }
    }

    /* handle toclient */
    if (server == STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION) {
        Packet *p = FlowPseudoPacketGet(1, f, ssn);
        if (p != NULL) {
            PKT_SET_SRC(p, PKT_SRC_FFR);
            p->flowflags |= FLOW_PKT_LAST_PSEUDO;
            FlowWorkerFlowTimeout(tv, p, fw, detect_thread);
            PacketPoolReturnPacket(p);
            f->flags |= FLOW_TIMEOUT_REASSEMBLY_DONE;
            cnt++;
        }
    }

    if (cnt > 0) {
        f->flags |= FLOW_TIMEOUT_REASSEMBLY_DONE;
    }
    return cnt;
}

/** \param[in] max_work Max flows to process. 0 if unlimited. */
static void CheckWorkQueue(ThreadVars *tv, FlowWorkerThreadData *fw, FlowTimeoutCounters *counters,
        FlowQueuePrivate *fq, const uint32_t max_work)
{
    FlowQueuePrivate ret_queue = { NULL, NULL, 0 };
    uint32_t i = 0;
    Flow *f;
    while ((f = FlowQueuePrivateGetFromTop(fq)) != NULL) {
        FLOWLOCK_WRLOCK(f);
        f->flow_end_flags |= FLOW_END_FLAG_TIMEOUT; //TODO emerg

        if (f->proto == IPPROTO_TCP) {
            if (!(f->flags & (FLOW_TIMEOUT_REASSEMBLY_DONE | FLOW_ACTION_DROP)) &&
                    !FlowIsBypassed(f) && FlowNeedsReassembly(f) && f->ffr != 0) {
                /* read detect thread in case we're doing a reload */
                void *detect_thread = SC_ATOMIC_GET(fw->detect_thread);
                int cnt = FlowFinish(tv, f, fw, detect_thread);
                counters->flows_aside_pkt_inject += cnt;
                counters->flows_aside_needs_work++;
            }
        }

        /* no one is referring to this flow, removed from hash
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

        if (fw->fls.spare_queue.len >= (FLOW_SPARE_POOL_BLOCK_SIZE * 2)) {
            FlowQueuePrivatePrependFlow(&ret_queue, f);
            if (ret_queue.len == FLOW_SPARE_POOL_BLOCK_SIZE) {
                FlowSparePoolReturnFlows(&ret_queue);
            }
        } else {
            FlowQueuePrivatePrependFlow(&fw->fls.spare_queue, f);
        }

        if (max_work != 0 && ++i == max_work)
            break;
    }
    if (ret_queue.len > 0) {
        FlowSparePoolReturnFlows(&ret_queue);
    }

    StatsAddUI64(tv, fw->cnt.flows_removed, (uint64_t)i);
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
    fw->cnt.flows_injected_max = StatsRegisterMaxCounter("flow.wrk.flows_injected_max", tv);

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
    if (OutputFlowLogThreadInit(tv, &fw->output_thread_flow) != TM_ECODE_OK) {
        SCLogError("initializing flow log API for thread failed");
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

    // this is the first packet that sets no payload inspection
    bool setting_nopayload =
            p->flow->alparser &&
            AppLayerParserStateIssetFlag(p->flow->alparser, APP_LAYER_PARSER_NO_INSPECTION) &&
            !(p->flags & PKT_NOPAYLOAD_INSPECTION);
    if (FlowChangeProto(p->flow) || setting_nopayload) {
        StreamTcpDetectLogFlush(tv, fw->stream_thread, p->flow, p, &fw->pq);
        if (setting_nopayload) {
            FlowSetNoPayloadInspectionFlag(p->flow);
        }
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

        FramesPrune(x->flow, x);
        /*  Release tcp segments. Done here after alerting can use them. */
        FLOWWORKER_PROFILING_START(x, PROFILE_FLOWWORKER_TCPPRUNE);
        StreamTcpPruneSession(
                x->flow, x->flowflags & FLOW_PKT_TOSERVER ? STREAM_TOSERVER : STREAM_TOCLIENT);
        FLOWWORKER_PROFILING_END(x, PROFILE_FLOWWORKER_TCPPRUNE);

        /* no need to keep a flow ref beyond this point */
        FlowDeReference(&x->flow);

        /* no further work to do for this pseudo packet, so we can return
         * it to the pool immediately. */
        if (timeout) {
            PacketPoolReturnPacket(x);
        } else {
            /* to support IPS verdict logic, in the non-timeout case we need to do a bit more */
            TmqhOutputPacketpool(tv, x);
        }
    }
    if (FlowChangeProto(p->flow) && p->flow->flags & FLOW_ACTION_DROP) {
        // in case f->flags & FLOW_ACTION_DROP was set by one of the dequeued packets
        PacketDrop(p, ACTION_DROP, PKT_DROP_REASON_FLOW_DROP);
    }
}

static void FlowWorkerFlowTimeout(ThreadVars *tv, Packet *p, FlowWorkerThreadData *fw,
        void *detect_thread)
{
    DEBUG_VALIDATE_BUG_ON(p->pkt_src != PKT_SRC_FFR);

    SCLogDebug("packet %"PRIu64" is TCP. Direction %s", p->pcap_cnt, PKT_IS_TOSERVER(p) ? "TOSERVER" : "TOCLIENT");
    DEBUG_VALIDATE_BUG_ON(!(p->flow && PacketIsTCP(p)));
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

    FramesPrune(p->flow, p);

    /*  Release tcp segments. Done here after alerting can use them. */
    FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_TCPPRUNE);
    StreamTcpPruneSession(p->flow, p->flowflags & FLOW_PKT_TOSERVER ?
            STREAM_TOSERVER : STREAM_TOCLIENT);
    FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_TCPPRUNE);

    /* run tx cleanup last */
    AppLayerParserTransactionsCleanup(p->flow, STREAM_FLAGS_FOR_PACKET(p));

    FlowDeReference(&p->flow);
    /* flow is unlocked later in FlowFinish() */
}

/** \internal
 *  \brief process flows injected into our queue by other threads
 */
static inline void FlowWorkerProcessInjectedFlows(
        ThreadVars *tv, FlowWorkerThreadData *fw, Packet *p)
{
    /* take injected flows and append to our work queue */
    FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_FLOW_INJECTED);
    FlowQueuePrivate injected = { NULL, NULL, 0 };
    if (SC_ATOMIC_GET(tv->flow_queue->non_empty) == true)
        injected = FlowQueueExtractPrivate(tv->flow_queue);
    if (injected.len > 0) {
        StatsAddUI64(tv, fw->cnt.flows_injected, (uint64_t)injected.len);
        if (p->pkt_src == PKT_SRC_WIRE)
            StatsSetUI64(tv, fw->cnt.flows_injected_max, (uint64_t)injected.len);

        /* move to local queue so we can process over the course of multiple packets */
        FlowQueuePrivateAppendPrivate(&fw->fls.work_queue, &injected);
    }
    FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_FLOW_INJECTED);
}

/** \internal
 *  \brief process flows set aside locally during flow lookup
 */
static inline void FlowWorkerProcessLocalFlows(ThreadVars *tv, FlowWorkerThreadData *fw, Packet *p)
{
    uint32_t max_work = 2;
    if (p->pkt_src == PKT_SRC_SHUTDOWN_FLUSH || p->pkt_src == PKT_SRC_CAPTURE_TIMEOUT)
        max_work = 0;

    FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_FLOW_EVICTED);
    if (fw->fls.work_queue.len) {
        FlowTimeoutCounters counters = { 0, 0, };
        CheckWorkQueue(tv, fw, &counters, &fw->fls.work_queue, max_work);
        UpdateCounters(tv, fw, &counters);
    }
    FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_FLOW_EVICTED);
}

/** \internal
 *  \brief apply Packet::app_update_direction to the flow flags
 */
static void PacketAppUpdate2FlowFlags(Packet *p)
{
    switch ((enum StreamUpdateDir)p->app_update_direction) {
        case UPDATE_DIR_NONE: // NONE implies pseudo packet
            SCLogDebug("pcap_cnt %" PRIu64 ", UPDATE_DIR_NONE", p->pcap_cnt);
            break;
        case UPDATE_DIR_PACKET:
            if (PKT_IS_TOSERVER(p)) {
                p->flow->flags |= FLOW_TS_APP_UPDATED;
                SCLogDebug("pcap_cnt %" PRIu64 ", FLOW_TS_APP_UPDATED set", p->pcap_cnt);
            } else {
                p->flow->flags |= FLOW_TC_APP_UPDATED;
                SCLogDebug("pcap_cnt %" PRIu64 ", FLOW_TC_APP_UPDATED set", p->pcap_cnt);
            }
            break;
        case UPDATE_DIR_BOTH:
            if (PKT_IS_TOSERVER(p)) {
                p->flow->flags |= FLOW_TS_APP_UPDATED | FLOW_TC_APP_UPDATE_NEXT;
                SCLogDebug("pcap_cnt %" PRIu64 ", FLOW_TS_APP_UPDATED|FLOW_TC_APP_UPDATE_NEXT set",
                        p->pcap_cnt);
            } else {
                p->flow->flags |= FLOW_TC_APP_UPDATED | FLOW_TS_APP_UPDATE_NEXT;
                SCLogDebug("pcap_cnt %" PRIu64 ", FLOW_TC_APP_UPDATED|FLOW_TS_APP_UPDATE_NEXT set",
                        p->pcap_cnt);
            }
            /* fall through */
        case UPDATE_DIR_OPPOSING:
            if (PKT_IS_TOSERVER(p)) {
                p->flow->flags |= FLOW_TC_APP_UPDATED | FLOW_TS_APP_UPDATE_NEXT;
                SCLogDebug("pcap_cnt %" PRIu64 ", FLOW_TC_APP_UPDATED|FLOW_TS_APP_UPDATE_NEXT set",
                        p->pcap_cnt);
            } else {
                p->flow->flags |= FLOW_TS_APP_UPDATED | FLOW_TC_APP_UPDATE_NEXT;
                SCLogDebug("pcap_cnt %" PRIu64 ", FLOW_TS_APP_UPDATED|FLOW_TC_APP_UPDATE_NEXT set",
                        p->pcap_cnt);
            }
            break;
    }
}

static TmEcode FlowWorker(ThreadVars *tv, Packet *p, void *data)
{
    FlowWorkerThreadData *fw = data;
    void *detect_thread = SC_ATOMIC_GET(fw->detect_thread);

    DEBUG_VALIDATE_BUG_ON(p == NULL);
    DEBUG_VALIDATE_BUG_ON(tv->flow_queue == NULL);

    SCLogDebug("packet %"PRIu64, p->pcap_cnt);

    /* update time */
    if (!(PKT_IS_PSEUDOPKT(p) || PKT_IS_FLUSHPKT(p))) {
        TimeSetByThread(tv->id, p->ts);
    }
    if ((PKT_IS_FLUSHPKT(p))) {
        SCLogDebug("thread %s flushing", tv->printable_name);
        OutputLoggerFlush(tv, p, fw->output_thread);
        /* Ack if a flush was requested */
        bool notset = false;
        SC_ATOMIC_CAS(&fw->flush_ack, notset, true);
        return TM_ECODE_OK;
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
    if (p->flow) {
        SCLogDebug("packet %" PRIu64
                   ": direction %s FLOW_TS_APP_UPDATE_NEXT %s FLOW_TC_APP_UPDATE_NEXT %s",
                p->pcap_cnt, PKT_IS_TOSERVER(p) ? "toserver" : "toclient",
                BOOL2STR((p->flow->flags & FLOW_TS_APP_UPDATE_NEXT) != 0),
                BOOL2STR((p->flow->flags & FLOW_TC_APP_UPDATE_NEXT) != 0));
        /* see if need to consider flags set by prev packets */
        if (PKT_IS_TOSERVER(p) && (p->flow->flags & FLOW_TS_APP_UPDATE_NEXT)) {
            p->flow->flags |= FLOW_TS_APP_UPDATED;
            p->flow->flags &= ~FLOW_TS_APP_UPDATE_NEXT;
            SCLogDebug("FLOW_TS_APP_UPDATED");
        } else if (PKT_IS_TOCLIENT(p) && (p->flow->flags & FLOW_TC_APP_UPDATE_NEXT)) {
            p->flow->flags |= FLOW_TC_APP_UPDATED;
            p->flow->flags &= ~FLOW_TC_APP_UPDATE_NEXT;
            SCLogDebug("FLOW_TC_APP_UPDATED");
        }

        if (PacketIsTCP(p)) {
            SCLogDebug("packet %" PRIu64 " is TCP. Direction %s", p->pcap_cnt,
                    PKT_IS_TOSERVER(p) ? "TOSERVER" : "TOCLIENT");
            DEBUG_ASSERT_FLOW_LOCKED(p->flow);

            /* if detect is disabled, we need to apply file flags to the flow
             * here on the first packet. */
            if (detect_thread == NULL &&
                    ((PKT_IS_TOSERVER(p) && (p->flowflags & FLOW_PKT_TOSERVER_FIRST)) ||
                            (PKT_IS_TOCLIENT(p) && (p->flowflags & FLOW_PKT_TOCLIENT_FIRST)))) {
                DisableDetectFlowFileFlags(p->flow);
            }

            FlowWorkerStreamTCPUpdate(tv, fw, p, detect_thread, false);
            PacketAppUpdate2FlowFlags(p);

            /* handle the app layer part of the UDP packet payload */
        } else if (p->proto == IPPROTO_UDP && !PacketCheckAction(p, ACTION_DROP)) {
            FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_APPLAYERUDP);
            AppLayerHandleUdp(tv, fw->stream_thread->ra_ctx->app_tctx, p, p->flow);
            FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_APPLAYERUDP);
            PacketAppUpdate2FlowFlags(p);
        }
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

    /*  Release tcp segments. Done here after alerting can use them. */
    if (p->flow != NULL) {
        DEBUG_ASSERT_FLOW_LOCKED(p->flow);

        if (FlowIsBypassed(p->flow)) {
            FlowCleanupAppLayer(p->flow);
            if (p->proto == IPPROTO_TCP) {
                StreamTcpSessionCleanup(p->flow->protoctx);
            }
        } else if (p->proto == IPPROTO_TCP && p->flow->protoctx && p->flags & PKT_STREAM_EST) {
            if ((p->flow->flags & FLOW_TS_APP_UPDATED) && PKT_IS_TOSERVER(p)) {
                FramesPrune(p->flow, p);
            } else if ((p->flow->flags & FLOW_TC_APP_UPDATED) && PKT_IS_TOCLIENT(p)) {
                FramesPrune(p->flow, p);
            }
            FLOWWORKER_PROFILING_START(p, PROFILE_FLOWWORKER_TCPPRUNE);
            StreamTcpPruneSession(p->flow, p->flowflags & FLOW_PKT_TOSERVER ?
                    STREAM_TOSERVER : STREAM_TOCLIENT);
            FLOWWORKER_PROFILING_END(p, PROFILE_FLOWWORKER_TCPPRUNE);
        } else if (p->proto == IPPROTO_UDP) {
            FramesPrune(p->flow, p);
        }

        if ((PKT_IS_PSEUDOPKT(p)) ||
                (p->flow->flags & (FLOW_TS_APP_UPDATED | FLOW_TC_APP_UPDATED))) {
            if ((p->flags & PKT_STREAM_EST) || p->proto != IPPROTO_TCP) {
                if (PKT_IS_TOSERVER(p)) {
                    if (PKT_IS_PSEUDOPKT(p) || (p->flow->flags & (FLOW_TS_APP_UPDATED))) {
                        AppLayerParserTransactionsCleanup(p->flow, STREAM_TOSERVER);
                        p->flow->flags &= ~FLOW_TS_APP_UPDATED;
                        SCLogDebug("~FLOW_TS_APP_UPDATED");
                    }
                } else {
                    if (PKT_IS_PSEUDOPKT(p) || (p->flow->flags & (FLOW_TC_APP_UPDATED))) {
                        AppLayerParserTransactionsCleanup(p->flow, STREAM_TOCLIENT);
                        p->flow->flags &= ~FLOW_TC_APP_UPDATED;
                        SCLogDebug("~FLOW_TC_APP_UPDATED");
                    }
                }
            }
        } else {
            SCLogDebug("not pseudo, no app update: skip");
        }

        if (p->flow->flags & FLOW_ACTION_DROP) {
            SCLogDebug("flow drop in place: remove app update flags");
            p->flow->flags &= ~(FLOW_TS_APP_UPDATED | FLOW_TC_APP_UPDATED);
        }

        Flow *f = p->flow;
        FlowDeReference(&p->flow);
        FLOWLOCK_UNLOCK(f);
    }

housekeeping:

    /* take injected flows and add them to our local queue */
    FlowWorkerProcessInjectedFlows(tv, fw, p);

    /* process local work queue */
    FlowWorkerProcessLocalFlows(tv, fw, p);

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

void *FlowWorkerGetThreadData(void *flow_worker)
{
    return (FlowWorkerThreadData *)flow_worker;
}

bool FlowWorkerGetFlushAck(void *flow_worker)
{
    FlowWorkerThreadData *fw = flow_worker;
    return SC_ATOMIC_GET(fw->flush_ack) == true;
}

void FlowWorkerSetFlushAck(void *flow_worker)
{
    FlowWorkerThreadData *fw = flow_worker;
    SC_ATOMIC_SET(fw->flush_ack, false);
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

static bool FlowWorkerIsBusy(ThreadVars *tv, void *flow_worker)
{
    FlowWorkerThreadData *fw = flow_worker;
    if (fw->pq.len)
        return true;
    if (fw->fls.work_queue.len)
        return true;

    if (tv->flow_queue) {
        FQLOCK_LOCK(tv->flow_queue);
        bool fq_done = (tv->flow_queue->qlen == 0);
        FQLOCK_UNLOCK(tv->flow_queue);
        if (!fq_done) {
            return true;
        }
    }

    return false;
}

void TmModuleFlowWorkerRegister (void)
{
    tmm_modules[TMM_FLOWWORKER].name = "FlowWorker";
    tmm_modules[TMM_FLOWWORKER].ThreadInit = FlowWorkerThreadInit;
    tmm_modules[TMM_FLOWWORKER].Func = FlowWorker;
    tmm_modules[TMM_FLOWWORKER].ThreadBusy = FlowWorkerIsBusy;
    tmm_modules[TMM_FLOWWORKER].ThreadDeinit = FlowWorkerThreadDeinit;
    tmm_modules[TMM_FLOWWORKER].cap_flags = 0;
    tmm_modules[TMM_FLOWWORKER].flags = TM_FLAG_STREAM_TM|TM_FLAG_DETECT_TM;
}
