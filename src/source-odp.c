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
} ODPThreadVars;

/* Release Packet without sending. */
static void ODPReleasePacket(Packet *p)
{
    odp_packet_t pkt = p->pkt_odp;
    odp_packet_free(pkt);
}

static TmEcode ReceiveODPThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    ODPThreadVars *ptv = SCMalloc(sizeof(ODPThreadVars));
    if (unlikely(ptv == NULL))
        SCReturnInt(TM_ECODE_FAILED);

    memset(ptv, 0, sizeof(ODPThreadVars));

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
    p->datalink = LINKTYPE_ETHERNET;
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
    uint64_t sched_wait = odp_schedule_wait_time(ODP_TIME_SEC_IN_NS * 1);
    odp_event_t ev;
    odp_packet_t pkt;
    Packet *p = NULL;
    int ret;

    SCEnter();
    ret = odp_init_local(instance, ODP_THREAD_WORKER);
    if (ret) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "odp_init_local");
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->slot = s->slot_next;
    ptv->cb_result = TM_ECODE_OK;

    SCLogInfo("ODP worker thread %d enter to loop", odp_thread_id());
    while (!odp_loop_break)
    {
        ev = odp_schedule(NULL, sched_wait);
        if (ev == ODP_EVENT_INVALID) {
                StatsSyncCountersIfSignalled(tv);
		continue;
        }

        pkt = odp_packet_from_event(ev);
        if (!odp_packet_is_valid(pkt))
            continue;

        p = ODPProcessPacket(ptv, pkt);
        if (!p) {
            odp_packet_free(pkt);
            break;
        }

        if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
            TmqhOutputPacketpool(ptv->tv, p);
            SCReturnInt(TM_ECODE_FAILED);
        }
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
