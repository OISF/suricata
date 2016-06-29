/* Copyright (C) 2016 Linaro
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
 * \author Maxim Uvarov <maxim.uvarov@linaro.org>
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

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 
     * Not implemented for ODP yet.
     */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        return TM_ECODE_OK;

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* call the decoder */
    switch(p->datalink) {
        case LINKTYPE_LINUX_SLL:
            DecodeSll(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p,GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_PPP:
            DecodePPP(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_RAW:
            DecodeRaw(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        case LINKTYPE_NULL:
            DecodeNull(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "Error: datalink type %" PRId32 " not yet supported in module DecodePcap", p->datalink);
            break;
    }

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
    tmm_modules[TMM_RECEIVEPCAP].name = "ReceiveODP";
    tmm_modules[TMM_RECEIVEPCAP].ThreadInit = ReceiveODPThreadInit;
    tmm_modules[TMM_RECEIVEPCAP].Func = NULL;
    tmm_modules[TMM_RECEIVEPCAP].PktAcqLoop = ReceiveODPLoop;
    tmm_modules[TMM_RECEIVEPCAP].PktAcqBreakLoop = ReceiveODPBreakLoop;
    tmm_modules[TMM_RECEIVEPCAP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEPCAP].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEPCAP].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEPCAP].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVEPCAP].flags = TM_FLAG_RECEIVE_TM;
}

static inline Packet *_odp_process_packet(ODPThreadVars *ptv, odp_packet_t opkt)
{

    uint32_t caplen = odp_packet_len(opkt);
    u_char *pkt = odp_packet_data(opkt);
    Packet *p;

    p = (Packet *)odp_packet_push_tail(opkt, sizeof(Packet));
    if (!p) {
        fprintf(stderr, "error push_tail\n");
        return NULL;
    }

    if (caplen == odp_packet_len(opkt)) {
        fprintf(stderr, "packet not resized error push_tail\n");
        return NULL;
    }

    /* @todo: remove PACKET_INITIALIZE, looks like it requires odp recompilation
     * with increasing ODP_CONFIG_PACKET_HEADROOM 66 bytes to sizeof(Packet)
     * which is about 500 bytes and place Packet to head instead of tail.
     */
    PACKET_INITIALIZE(p);
    PACKET_RECYCLE(p);
    PKT_SET_SRC(p, PKT_SRC_WIRE);

    gettimeofday(&p->ts, NULL);

    p->datalink = LINKTYPE_ETHERNET;
    PacketSetData(p, pkt, caplen);
    p->pkt_odp = opkt;
    p->ReleasePacket = ODPReleasePacket;
    p->flags |= PKT_IGNORE_CHECKSUM;
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
        fprintf(stderr, "error in odp_init_local\n");
        SCReturnInt(TM_ECODE_FAILED);
    }

    ptv->slot = s->slot_next;
    ptv->cb_result = TM_ECODE_OK;

    SCLogInfo("ODP worker thread enter to loop");
    while (!odp_loop_break)
    {
        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        ev = odp_schedule(NULL, sched_wait);
        if (ev == ODP_EVENT_INVALID)
		continue;

        pkt = odp_packet_from_event(ev);
        if (!odp_packet_is_valid(pkt))
            continue;

        p = _odp_process_packet(ptv, pkt);
        if (!p) {
            odp_packet_free(pkt);
            continue;
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
    tmm_modules[TMM_DECODEPCAP].name = "DecodeODP";
    tmm_modules[TMM_DECODEPCAP].ThreadInit = DecodeODPThreadInit;
    tmm_modules[TMM_DECODEPCAP].Func = DecodeODP;
    tmm_modules[TMM_DECODEPCAP].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPCAP].ThreadDeinit = DecodeODPThreadDeinit;
    tmm_modules[TMM_DECODEPCAP].RegisterTests = NULL;
    tmm_modules[TMM_DECODEPCAP].cap_flags = 0;
    tmm_modules[TMM_DECODEPCAP].flags = TM_FLAG_DECODE_TM;
}
#endif /* HAVE_ODP */
