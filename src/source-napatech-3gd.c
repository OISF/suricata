/* Copyright (C) 2012 Open Information Security Foundation
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
 * \author nPulse Technologies, LLC.
 * \author Matt Keeler <mk@npulsetech.com>
 *
 * Support for NAPATECH adapter with the 3GD Driver/API.
 * Requires libntapi from Napatech A/S.
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "threadvars.h"
#include "util-optimize.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "tm-modules.h"

#include "util-privs.h"
#include "tmqh-packetpool.h"

#ifndef HAVE_NAPATECH_3GD

TmEcode NoNapatech3GDSupportExit(ThreadVars *, void *, void **);


void TmModuleNapatech3GDStreamRegister (void) {
    tmm_modules[TMM_RECEIVENAPATECH3GD].name = "Napatech3GDStream";
    tmm_modules[TMM_RECEIVENAPATECH3GD].ThreadInit = NoNapatech3GDSupportExit;
    tmm_modules[TMM_RECEIVENAPATECH3GD].Func = NULL;
    tmm_modules[TMM_RECEIVENAPATECH3GD].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVENAPATECH3GD].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVENAPATECH3GD].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENAPATECH3GD].cap_flags = SC_CAP_NET_ADMIN;
}

void TmModuleNapatech3GDDecodeRegister (void) {
    tmm_modules[TMM_DECODENAPATECH3GD].name = "Napatech3GDDecode";
    tmm_modules[TMM_DECODENAPATECH3GD].ThreadInit = NoNapatech3GDSupportExit;
    tmm_modules[TMM_DECODENAPATECH3GD].Func = NULL;
    tmm_modules[TMM_DECODENAPATECH3GD].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENAPATECH3GD].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENAPATECH3GD].RegisterTests = NULL;
    tmm_modules[TMM_DECODENAPATECH3GD].cap_flags = 0;
    tmm_modules[TMM_DECODENAPATECH3GD].flags = TM_FLAG_DECODE_TM;
}

TmEcode NoNapatech3GDSupportExit(ThreadVars *tv, void *initdata, void **data)
{
    SCLogError(SC_ERR_NAPATECH_3GD_NOSUPPORT,
            "Error creating thread %s: you do not have support for Napatech 3GD adapter "
            "enabled please recompile with --enable-napatech-3gd", tv->name);
    exit(EXIT_FAILURE);
}

#else /* Implied we do have NAPATECH 3GD support */

#include "source-napatech-3gd.h"
#include <nt.h>

extern int max_pending_packets;
extern uint8_t suricata_ctl_flags;

typedef struct Napatech3GDThreadVars_ {
    ThreadVars *tv;
    NtNetStreamRx_t rx_stream;
    uint64_t stream_id;
    uint64_t pkts;
    uint64_t drops;
    uint64_t bytes;

    TmSlot *slot;
} Napatech3GDThreadVars;


TmEcode Napatech3GDStreamThreadInit(ThreadVars *, void *, void **);
void Napatech3GDStreamThreadExitStats(ThreadVars *, void *);
TmEcode Napatech3GDStreamLoop(ThreadVars *tv, void *data, void *slot);

TmEcode Napatech3GDDecodeThreadInit(ThreadVars *, void *, void **);
TmEcode Napatech3GDDecode(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

/**
 * \brief Register the Napatech 3GD receiver (reader) module.
 */
void TmModuleNapatech3GDStreamRegister(void)
{
    tmm_modules[TMM_RECEIVENAPATECH3GD].name = "Napatech3GDStream";
    tmm_modules[TMM_RECEIVENAPATECH3GD].ThreadInit = Napatech3GDStreamThreadInit;
    tmm_modules[TMM_RECEIVENAPATECH3GD].Func = NULL;
    tmm_modules[TMM_RECEIVENAPATECH3GD].PktAcqLoop = Napatech3GDStreamLoop;
    tmm_modules[TMM_RECEIVENAPATECH3GD].ThreadExitPrintStats = Napatech3GDStreamThreadExitStats;
    tmm_modules[TMM_RECEIVENAPATECH3GD].ThreadDeinit = Napatech3GDStreamThreadDeinit;
    tmm_modules[TMM_RECEIVENAPATECH3GD].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENAPATECH3GD].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVENAPATECH3GD].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Register the Napatech 3GD decoder module.
 */
void TmModuleNapatech3GDDecodeRegister(void)
{
    tmm_modules[TMM_DECODENAPATECH3GD].name = "Napatech3GDDecode";
    tmm_modules[TMM_DECODENAPATECH3GD].ThreadInit = Napatech3GDDecodeThreadInit;
    tmm_modules[TMM_DECODENAPATECH3GD].Func = Napatech3GDDecode;
    tmm_modules[TMM_DECODENAPATECH3GD].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENAPATECH3GD].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENAPATECH3GD].RegisterTests = NULL;
    tmm_modules[TMM_DECODENAPATECH3GD].cap_flags = 0;
    tmm_modules[TMM_DECODENAPATECH3GD].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief   Initialize the Napatech 3GD receiver thread, generate a single
 *          NapatechThreadVar structure for each thread, this will
 *          contain a NtNetStreamRx_t stream handle which is used when the
 *          thread executes to acquire the packets.
 *
 * \param tv        Thread variable to ThreadVars
 * \param initdata  Initial data to the adapter passed from the user,
 *                  this is processed by the user.
 *
 *                  For now, we assume that we have only a single name for the NAPATECH 3GD
 *                  adapter.
 *
 * \param data      data pointer gets populated with
 *
 */
TmEcode Napatech3GDStreamThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    struct Napatech3GDStreamDevConf *conf = (struct Napatech3GDStreamDevConf *)initdata;
    uintmax_t stream_id = conf->stream_id;
    *data = NULL;

    SCLogInfo("Napatech 3GD Thread Stream ID:%lu", stream_id);

    Napatech3GDThreadVars *ntv3 = SCMalloc(sizeof(Napatech3GDThreadVars));
    if (ntv3 == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
                "Failed to allocate memory for NAPATECH 3GD thread vars.");
        exit(EXIT_FAILURE);
    }

    memset(ntv3, 0, sizeof (Napatech3GDThreadVars));
    ntv3->stream_id = stream_id;
    ntv3->tv = tv;

    SCLogInfo("Started processing packets from NAPATECH 3GD Stream: %lu", ntv3->stream_id);

    *data = (void *)ntv3;

    SCReturnInt(TM_ECODE_OK);
}

/**
 *  \brief Main Napatech 3GD reading Loop function
 */
TmEcode Napatech3GDStreamLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    int32_t status;
    char errbuf[100];
    uint16_t packet_q_len = 0;
    uint64_t pkt_ts;
    NtNetBuf_t packet_buffer;
    Napatech3GDThreadVars *ntv3 = (Napatech3GDThreadVars *)data;
    NtNetRx_t stat_cmd;

    SCLogInfo("Opening NAPATECH 3GD Stream: %lu for processing", ntv3->stream_id);

    if ((status = NT_NetRxOpen(&(ntv3->rx_stream), "SuricataStream", NT_NET_INTERFACE_PACKET, ntv3->stream_id, -1)) != NT_SUCCESS) {
        NT_ExplainError(status, errbuf, sizeof(errbuf));
        SCLogError(SC_ERR_NAPATECH_3GD_OPEN_FAILED, "Failed to open NAPATECH 3GD Stream: %lu - %s", ntv3->stream_id, errbuf);
        SCFree(ntv3);
        SCReturnInt(TM_ECODE_FAILED);
    }

    stat_cmd.cmd = NT_NETRX_READ_CMD_STREAM_DROP;

    SCLogInfo("Napatech 3GD Packet Stream Loop Started for Stream ID: %lu", ntv3->stream_id);

    TmSlot *s = (TmSlot *)slot;
    ntv3->slot = s->slot_next;

    while (!(suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL))) {
        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        do {
            packet_q_len = PacketPoolSize();
            if (unlikely(packet_q_len == 0)) {
                PacketPoolWait();
            }
        } while (packet_q_len == 0);

        /*
         * Napatech 3GD returns packets 1 at a time
         */
        status = NT_NetRxGet(ntv3->rx_stream, &packet_buffer, 1000);
        if (unlikely(status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN)) {
            /*
             * no frames currently available
             */
            continue;
        } else if (unlikely(status != NT_SUCCESS)) {
            SCLogError(SC_ERR_NAPATECH_3GD_STREAM_NEXT_FAILED,
                       "Failed to read from Napatech 3GD Stream: %lu",
                       ntv3->stream_id);
            SCReturnInt(TM_ECODE_FAILED);
        }

        Packet *p = PacketGetFromQueueOrAlloc();
        if (unlikely(p == NULL)) {
            NT_NetRxRelease(ntv3->rx_stream, packet_buffer);
            SCReturnInt(TM_ECODE_FAILED);
        }

        pkt_ts = NT_NET_GET_PKT_TIMESTAMP(packet_buffer);

        /*
         * Handle the different timestamp forms that the napatech cards could use
         *   - NT_TIMESTAMP_TYPE_NATIVE is not supported due to having an base of 0 as opposed to NATIVE_UNIX which has a base of 1/1/1970
         */
        switch(NT_NET_GET_PKT_TIMESTAMP_TYPE(packet_buffer)) {
            case NT_TIMESTAMP_TYPE_NATIVE_UNIX:
                p->ts.tv_sec = pkt_ts / 100000000;
                p->ts.tv_usec = ((pkt_ts % 100000000) / 100) + (pkt_ts % 100) > 50 ? 1 : 0;
                break;
            case NT_TIMESTAMP_TYPE_PCAP:
                p->ts.tv_sec = pkt_ts >> 32;
                p->ts.tv_usec = pkt_ts & 0xFFFFFFFF;
                break;
            case NT_TIMESTAMP_TYPE_PCAP_NANOTIME:
                p->ts.tv_sec = pkt_ts >> 32;
                p->ts.tv_usec = ((pkt_ts & 0xFFFFFFFF) / 1000) + (pkt_ts % 1000) > 500 ? 1 : 0;
                break;
            case NT_TIMESTAMP_TYPE_NATIVE_NDIS:
                /* number of seconds between 1/1/1601 and 1/1/1970 */
                p->ts.tv_sec = (pkt_ts / 100000000) - 11644473600;
                p->ts.tv_usec = ((pkt_ts % 100000000) / 100) + (pkt_ts % 100) > 50 ? 1 : 0;
                break;
            default:
                SCLogError(SC_ERR_NAPATECH_3GD_TIMESTAMP_TYPE_NOT_SUPPORTED,
                           "Packet from Napatech 3GD Stream: %lu does not have a supported timestamp format",
                           ntv3->stream_id);
                NT_NetRxRelease(ntv3->rx_stream, packet_buffer);
                SCReturnInt(TM_ECODE_FAILED);
        }

        SCLogDebug("p->ts.tv_sec %"PRIuMAX"", (uintmax_t)p->ts.tv_sec);
        p->datalink = LINKTYPE_ETHERNET;

        ntv3->pkts++;
        ntv3->bytes += NT_NET_GET_PKT_WIRE_LENGTH(packet_buffer);

        // Update drop counter
        if (unlikely((status = NT_NetRxRead(ntv3->rx_stream, &stat_cmd)) != NT_SUCCESS))
        {
            NT_ExplainError(status, errbuf, sizeof(errbuf));
            SCLogWarning(SC_ERR_NAPATECH_3GD_STAT_DROPS_FAILED, "Couldn't retrieve drop statistics from the RX stream: %lu - %s", ntv3->stream_id, errbuf);
        }
        else
        {
            ntv3->drops += stat_cmd.u.streamDrop.pktsDropped;
        }

        if (unlikely(PacketCopyData(p, (uint8_t *)NT_NET_GET_PKT_L2_PTR(packet_buffer), NT_NET_GET_PKT_WIRE_LENGTH(packet_buffer)))) {
            TmqhOutputPacketpool(ntv3->tv, p);
            NT_NetRxRelease(ntv3->rx_stream, packet_buffer);
            SCReturnInt(TM_ECODE_FAILED);
        }

        if (unlikely(TmThreadsSlotProcessPkt(ntv3->tv, ntv3->slot, p) != TM_ECODE_OK)) {
            TmqhOutputPacketpool(ntv3->tv, p);
            NT_NetRxRelease(ntv3->rx_stream, packet_buffer);
            SCReturnInt(TM_ECODE_FAILED);
        }

        NT_NetRxRelease(ntv3->rx_stream, packet_buffer);
        SCPerfSyncCountersIfSignalled(tv, 0);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Print some stats to the log at program exit.
 *
 * \param tv Pointer to ThreadVars.
 * \param data Pointer to data, ErfFileThreadVars.
 */
void Napatech3GDStreamThreadExitStats(ThreadVars *tv, void *data)
{
    Napatech3GDThreadVars *ntv3 = (Napatech3GDThreadVars *)data;
    double percent = 0;
    if (ntv3->drops > 0)
        percent = (((double) ntv3->drops) / (ntv3->pkts+ntv3->drops)) * 100;

    SCLogInfo("Stream: %lu; Packets: %"PRIu64"; Drops: %"PRIu64" (%5.2f%%); Bytes: %"PRIu64, ntv3->stream_id, ntv3->pkts, ntv3->drops, percent, ntv3->bytes);
}

/**
 * \brief   Deinitializes the NAPATECH 3GD card.
 * \param   tv pointer to ThreadVars
 * \param   data pointer that gets cast into PcapThreadVars for ptv
 */
TmEcode Napatech3GDStreamThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    Napatech3GDThreadVars *ntv3 = (Napatech3GDThreadVars *)data;
    SCLogDebug("Closing Napatech 3GD Stream: %d", ntv3->stream_id);
    NT_NetRxClose(ntv3->rx_stream);
    SCReturnInt(TM_ECODE_OK);
}


/** Decode Napatech 3GD */

/**
 * \brief   This function passes off to link type decoders.
 *
 * Napatech3GDDecode reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into PcapThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 */
TmEcode Napatech3GDDecode(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
        PacketQueue *postpq)
{
    SCEnter();

    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterIncr(dtv->counter_pkts_per_sec, tv->sc_perf_pca);
    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));

    switch (p->datalink) {
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED,
                    "Error: datalink type %" PRId32 " not yet supported in module Napatech3GDDecode",
                    p->datalink);
            break;
    }
    SCReturnInt(TM_ECODE_OK);
}

TmEcode Napatech3GDDecodeThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;

    dtv = DecodeThreadVarsAlloc();

    if(dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

#endif /* HAVE_NAPATECH_3GD */

