/* Copyright (C) 2016 Open Information Security Foundation
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
 * \author Maxim Uvarov <maxim.uvarov@linaro.org>, Linaro
 *
 * OpenDataPlane ingress packet support
 */

#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-odp.h"
#include "log-httplog.h"
#include "output.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"
#include "util-runmodes.h"
#include "util-atomic.h"
#include "util-misc.h"
#include "util-privs.h"
#include "util-profiling.h"
#include "pkt-var.h"
#include "source-odp.h"

#ifdef HAVE_ODP
extern  odp_instance_t instance;

TmEcode ReceiveODPLoop(ThreadVars *tv, void *data, void *slot);

static volatile int odp_loop_break;

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct ODPThreadVars_
{
    ThreadVars *tv;
    TmSlot *slot;
    /** callback result -- set if one of the thread module failed. */
    int cb_result;

    LiveDevice *livedev;

    /* counters */
    uint64_t pkts;
    uint64_t bytes;
    uint64_t drops;
} ODPThreadVars;

/* Release Packet without sending. */
static void ODPReleasePacket(Packet *p)
{
    odp_packet_t pkt = p->pkt_odp;
    odp_packet_free(pkt);
}

static inline void ODPDumpCounters(ODPThreadVars *ptv)
{
    (void) SC_ATOMIC_ADD(ptv->livedev->drop, ptv->drops);
    (void) SC_ATOMIC_ADD(ptv->livedev->pkts, ptv->pkts);
    ptv->drops = 0;
    ptv->pkts = 0;
}

static TmEcode ReceiveODPThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    ODPIfaceConfig *conf = initdata;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        odp_loop_break = 1;
        SCReturnInt(TM_ECODE_FAILED);
    }

    ODPThreadVars *ptv = SCMalloc(sizeof(ODPThreadVars));
    if (unlikely(ptv == NULL)) {
        odp_loop_break = 1;
        SCReturnInt(TM_ECODE_FAILED);
    }

    memset(ptv, 0, sizeof(ODPThreadVars));

    ptv->livedev = LiveGetDevice(conf->iface_name);
    if (ptv->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to find Live device");
        odp_loop_break = 1;
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->tv = tv;
    *data = (void *)ptv;

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeODPThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeODPThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    odp_loop_break = 1;
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function passes off to link type decoders.
 *
 * DecodePcap reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into PcapThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 */
TmEcode DecodeODP(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ReceiveODPBreakLoop(ThreadVars *ptv, void *arg)
{
    odp_loop_break = 1;
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Registration Function for RecieveODP.
 * \todo Unit tests are needed for this module.
 */
void TmModuleReceiveODPRegister (void)
{
    tmm_modules[TMM_RECEIVEODP].name = "ReceiveODP";
    tmm_modules[TMM_RECEIVEODP].ThreadInit = ReceiveODPThreadInit;
    tmm_modules[TMM_RECEIVEODP].Func = NULL;
    tmm_modules[TMM_RECEIVEODP].PktAcqLoop = ReceiveODPLoop;
    tmm_modules[TMM_RECEIVEODP].PktAcqBreakLoop = ReceiveODPBreakLoop;
    tmm_modules[TMM_RECEIVEODP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEODP].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEODP].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEODP].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVEODP].flags = TM_FLAG_RECEIVE_TM;
}

static inline Packet *ODPProcessPacket(ODPThreadVars *ptv, odp_packet_t opkt)
{
    uint32_t pkt_len = odp_packet_len(opkt);
    uint8_t *pkt_data = odp_packet_data(opkt);
    Packet *p;

    /* make sure we have at least one packet in the packet pool, to prevent
     * us from alloc'ing packets at line rate */
    PacketPoolWait();

    p = PacketGetFromQueueOrAlloc();
    if (p == NULL)
        return NULL;

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    gettimeofday(&p->ts, NULL);
    PacketSetData(p, pkt_data, pkt_len);
    p->pkt_odp = opkt;
    p->ReleasePacket = ODPReleasePacket;
    p->datalink = LINKTYPE_ETHERNET;
    return p;
}

/**
 *  \brief Main ODP reading Loop function
 */
TmEcode ReceiveODPLoop(ThreadVars *tv, void *data, void *slot)
{
    ODPThreadVars *ptv = (ODPThreadVars *)data;
    TmSlot *s = (TmSlot *)slot;
    odp_event_t ev;
    odp_packet_t pkt;
    Packet *p = NULL;
    int ret;
    odp_time_t sync_time, cur_time;
    odp_pktio_t pktio;
    odp_queue_t inq;

    SCEnter();
    ret = odp_init_local(instance, ODP_THREAD_WORKER);
    if (ret) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "odp_init_local");
        SCReturnInt(TM_ECODE_FAILED);
    }

    pktio = odp_pktio_lookup(ptv->livedev->dev);
    if (pktio == ODP_PKTIO_INVALID) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "unable to look up pktio %s", ptv->livedev->dev);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (odp_pktin_event_queue(pktio, &inq, 1) != 1) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "unable to get event queue");
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->slot = s->slot_next;
    ptv->cb_result = TM_ECODE_OK;
    /* next counter sync in 1 second */
    sync_time = odp_time_sum(odp_time_local(),
                             odp_time_local_from_ns(ODP_TIME_SEC_IN_NS));

    SCLogInfo("ODP worker thread %d enter to loop", odp_thread_id());
    while (!odp_loop_break)
    {
        ev = odp_queue_deq(inq);
        if (ev == ODP_EVENT_INVALID) {
            ODPDumpCounters(ptv);
            StatsSyncCountersIfSignalled(tv);
            continue;
        }

        cur_time = odp_time_local();
        if (odp_time_cmp(sync_time, cur_time) < 0) {
            sync_time = odp_time_sum(cur_time, odp_time_local_from_ns(ODP_TIME_SEC_IN_NS));
            ODPDumpCounters(ptv);
            StatsSyncCountersIfSignalled(tv);
        }

        pkt = odp_packet_from_event(ev);
        if (!odp_packet_is_valid(pkt)) {
            ptv->drops++;
            continue;
	}

        p = ODPProcessPacket(ptv, pkt);
        if (!p) {
            odp_packet_free(pkt);
            ptv->drops++;
            break;
        }

        if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
            TmqhOutputPacketpool(ptv->tv, p);
            ptv->drops++;
            SCReturnInt(TM_ECODE_FAILED);
        }
        ptv->pkts++;
        ptv->bytes = odp_packet_len(pkt);
    }

    SCLogInfo("ODP worker thread exited");
    StatsSyncCountersIfSignalled(tv);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Registration Function for DecodeODP.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeODPRegister (void)
{
    tmm_modules[TMM_DECODEODP].name = "DecodeODP";
    tmm_modules[TMM_DECODEODP].ThreadInit = DecodeODPThreadInit;
    tmm_modules[TMM_DECODEODP].Func = DecodeODP;
    tmm_modules[TMM_DECODEODP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEODP].ThreadDeinit = DecodeODPThreadDeinit;
    tmm_modules[TMM_DECODEODP].RegisterTests = NULL;
    tmm_modules[TMM_DECODEODP].cap_flags = 0;
    tmm_modules[TMM_DECODEODP].flags = TM_FLAG_DECODE_TM;
}
#endif /* HAVE_ODP */
