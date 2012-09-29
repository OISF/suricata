/* Copyright (C) 2011 Open Information Security Foundation
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
 * \author Randy Caldejon <rc@npulsetech.com>
 *
 * Support for NAPATECH adapter.  Requires libntfeeds from nPulse Technologies
 * and libntcommoninterface from Napatech A/S.
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

#ifndef HAVE_NAPATECH

TmEcode NoNapatechSupportExit(ThreadVars *, void *, void **);


void TmModuleNapatechFeedRegister (void) {
    tmm_modules[TMM_RECEIVENAPATECH].name = "NapatechFeed";
    tmm_modules[TMM_RECEIVENAPATECH].ThreadInit = NoNapatechSupportExit;
    tmm_modules[TMM_RECEIVENAPATECH].Func = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].cap_flags = SC_CAP_NET_ADMIN;
}

void TmModuleNapatechDecodeRegister (void) {
    tmm_modules[TMM_DECODENAPATECH].name = "NapatechDecode";
    tmm_modules[TMM_DECODENAPATECH].ThreadInit = NoNapatechSupportExit;
    tmm_modules[TMM_DECODENAPATECH].Func = NULL;
    tmm_modules[TMM_DECODENAPATECH].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENAPATECH].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENAPATECH].RegisterTests = NULL;
    tmm_modules[TMM_DECODENAPATECH].cap_flags = 0;
    tmm_modules[TMM_DECODENAPATECH].flags = TM_FLAG_DECODE_TM;
}

TmEcode NoNapatechSupportExit(ThreadVars *tv, void *initdata, void **data)
{
    SCLogError(SC_ERR_NAPATECH_NOSUPPORT,
            "Error creating thread %s: you do not have support for Napatech adapter "
            "enabled please recompile with --enable-napatech", tv->name);
    exit(EXIT_FAILURE);
}

#else /* Implied we do have NAPATECH support */


#include "source-napatech.h"

extern int max_pending_packets;
extern uint8_t suricata_ctl_flags;

typedef struct NapatechThreadVars_ {
    ThreadVars *tv;
    NAPATECH_FEED feed;
    uint16_t adapter_number;
    uint16_t feed_number;
    uint32_t max_read_packets;
    uint64_t pkts;
    uint64_t drops;
    uint64_t bytes;

    TmSlot *slot;
} NapatechThreadVars;


TmEcode NapatechFeedThreadInit(ThreadVars *, void *, void **);
void NapatechFeedThreadExitStats(ThreadVars *, void *);
TmEcode NapatechFeedLoop(ThreadVars *tv, void *data, void *slot);

TmEcode NapatechDecodeThreadInit(ThreadVars *, void *, void **);
TmEcode NapatechDecode(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

/**
 * \brief Register the Napatech receiver (reader) module.
 */
void TmModuleNapatechFeedRegister(void)
{
    tmm_modules[TMM_RECEIVENAPATECH].name = "NapatechFeed";
    tmm_modules[TMM_RECEIVENAPATECH].ThreadInit = NapatechFeedThreadInit;
    tmm_modules[TMM_RECEIVENAPATECH].Func = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].PktAcqLoop = NapatechFeedLoop;
    tmm_modules[TMM_RECEIVENAPATECH].ThreadExitPrintStats = NapatechFeedThreadExitStats;
    tmm_modules[TMM_RECEIVENAPATECH].ThreadDeinit = NapatechFeedThreadDeinit;
    tmm_modules[TMM_RECEIVENAPATECH].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVENAPATECH].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Register the Napatech decoder module.
 */
void TmModuleNapatechDecodeRegister(void)
{
    tmm_modules[TMM_DECODENAPATECH].name = "NapatechDecode";
    tmm_modules[TMM_DECODENAPATECH].ThreadInit = NapatechDecodeThreadInit;
    tmm_modules[TMM_DECODENAPATECH].Func = NapatechDecode;
    tmm_modules[TMM_DECODENAPATECH].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENAPATECH].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENAPATECH].RegisterTests = NULL;
    tmm_modules[TMM_DECODENAPATECH].cap_flags = 0;
    tmm_modules[TMM_DECODENAPATECH].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief   Initialize the Napatech receiver thread, generate a single
 *          NapatechThreadVar structure for each thread, this will
 *          contain a NAPATECH file descriptor which is read when the
 *          thread executes.
 *
 * \param tv        Thread variable to ThreadVars
 * \param initdata  Initial data to the adapter passed from the user,
 *                  this is processed by the user.
 *
 *                  For now, we assume that we have only a single name for the NAPATECH
 *                  adapter.
 *
 * \param data      data pointer gets populated with
 *
 */
TmEcode NapatechFeedThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    char *feedName = (char *) initdata;
    *data = NULL;
    //TODO:
    if (initdata == NULL||*((char *)initdata+1)!=':') {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Error: No NAPATECH adapter provided.");
        SCReturnInt(TM_ECODE_FAILED);
    }

    NapatechThreadVars *ntv = SCMalloc(sizeof(NapatechThreadVars));
    if (unlikely(ntv == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for NAPATECH thread vars.");
        exit(EXIT_FAILURE);
    }

    memset(ntv, 0, sizeof (NapatechThreadVars));
    ntv->adapter_number = *(feedName)-'0';
    ntv->feed_number = atoi((feedName+2));
    ntv->tv = tv;

    /*  Use max_pending_packets as our maximum number of packets read
        from the NAPATECH buffer.
     */
    ntv->max_read_packets = max_pending_packets;
    SCLogInfo("Opening NAPATECH %d:%d for processing", ntv->adapter_number, ntv->feed_number);


    if ((ntv->feed = (NAPATECH_FEED) napatech_open(ntv->adapter_number, ntv->feed_number)) == NULL) {
        SCLogError(SC_ERR_NAPATECH_OPEN_FAILED, "Failed to open NAPATECH %d:%d", ntv->adapter_number, ntv->feed_number);
        SCFree(ntv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogInfo("Started processing packets from NAPATECH %d:%d", ntv->adapter_number, ntv->feed_number);

    *data = (void *)ntv;

    SCReturnInt(TM_ECODE_OK);
}


/**
 *  \brief Main Napatech reading Loop function
 */
TmEcode NapatechFeedLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    int32_t status;
    int32_t caplen;
    PCAP_HEADER *header;
    uint8_t *frame;
    uint16_t packet_q_len = 0;
    NapatechThreadVars *ntv = (NapatechThreadVars *)data;
    int r;
    TmSlot *s = (TmSlot *)slot;

    ntv->slot = s->slot_next;

    while (1) {
        if (suricata_ctl_flags & (SURICATA_STOP | SURICATA_KILL)) {
            SCReturnInt(TM_ECODE_OK);
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        do {
            packet_q_len = PacketPoolSize();
            if (unlikely(packet_q_len == 0)) {
                PacketPoolWait();
            }
        } while (packet_q_len == 0);

        /*
         * Napatech returns frames in segment chunks.  Function ntci_next_frame
         * returns 1 for a frame, 0 if the segment is empty, and -1 on error
         */
        status = napatech_next_frame (ntv->feed, &header, &frame);
        if (status == 0) {
            /*
             * no frames currently available
             */
            continue;
        } else if (status < 0) {
            SCLogError(SC_ERR_NAPATECH_FEED_NEXT_FAILED,
                       "Failed to read from Napatech feed %d:%d",
                       ntv->adapter_number, ntv->feed_number);
            SCReturnInt(TM_ECODE_FAILED);
        }
        // beware that storelen is aligned; therefore, it may be larger than "caplen"
        caplen = (header->wireLen < header->storeLen) ? header->wireLen : header->storeLen;
        Packet *p = PacketGetFromQueueOrAlloc();
        if (unlikely(p == NULL)) {
            SCReturnInt(TM_ECODE_FAILED);
        }
        PKT_SET_SRC(p, PKT_SRC_WIRE);

        p->ts.tv_sec = header->ts.tv_sec;
        p->ts.tv_usec = header->ts.tv_usec;
        SCLogDebug("p->ts.tv_sec %"PRIuMAX"", (uintmax_t)p->ts.tv_sec);
        p->datalink = LINKTYPE_ETHERNET;

        ntv->pkts++;
        ntv->bytes += caplen;

        if (unlikely(PacketCopyData(p, frame, caplen))) {
            TmqhOutputPacketpool(ntv->tv, p);
            SCReturnInt(TM_ECODE_FAILED);
        }

        if (TmThreadsSlotProcessPkt(ntv->tv, ntv->slot, p) != TM_ECODE_OK) {
            TmqhOutputPacketpool(ntv->tv, p);
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Print some stats to the log at program exit.
 *
 * \param tv Pointer to ThreadVars.
 * \param data Pointer to data, ErfFileThreadVars.
 */
void NapatechFeedThreadExitStats(ThreadVars *tv, void *data)
{
    NapatechThreadVars *ntv = (NapatechThreadVars *)data;
    if (napatech_statistics(ntv->feed, &ntv->pkts, &ntv->drops, &ntv->bytes)==0) {
        double percent = 0;
        if (ntv->drops > 0) {
            double drops = ntv->drops;
            percent = (drops / ( ntv->pkts+ntv->drops)) * 100;
        }
        SCLogInfo("Packets: %"PRIu64"; Drops: %"PRIu64" (%5.2f%%); Bytes: %"PRIu64, ntv->pkts, ntv->drops, percent, ntv->bytes);
    }
}

/**
 * \brief   Deinitializes the NAPATECH card.
 * \param   tv pointer to ThreadVars
 * \param   data pointer that gets cast into PcapThreadVars for ptv
 */
TmEcode NapatechFeedThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    NapatechThreadVars *ntv = (NapatechThreadVars *)data;
    SCLogDebug("Closing Napatech feed %d:%d", ntv->adapter_number, ntv->feed_number);
    napatech_close(ntv->feed);
    SCReturnInt(TM_ECODE_OK);
}

/** Decode Napatech */

/**
 * \brief   This function passes off to link type decoders.
 *
 * DecodeNapatech reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into PcapThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 */
TmEcode NapatechDecode(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
        PacketQueue *postpq)
{
    SCEnter();

    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterIncr(dtv->counter_pkts_per_sec, tv->sc_perf_pca);

    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, GET_PKT_LEN(p));
//    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, GET_PKT_LEN(p));
//    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
//            (GET_PKT_LEN(p) * 8)/1000000.0);

    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));

    switch (p->datalink) {
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED,
                    "Error: datalink type %" PRId32 " not yet supported in module DecodeNapatech",
                    p->datalink);
            break;
    }
    SCReturnInt(TM_ECODE_OK);
}

TmEcode NapatechDecodeThreadInit(ThreadVars *tv, void *initdata, void **data)
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

#endif /* HAVE_NAPATECH */
