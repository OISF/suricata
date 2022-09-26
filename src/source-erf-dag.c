/* Copyright (C) 2010-2020 Open Information Security Foundation
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
 * \author Endace Technology Limited.
 * \author Jason MacLulich <jason.maclulich@endace.com>
 *
 * Support for reading ERF records from a DAG card.
 *
 * Only ethernet supported at this time.
 */

#include "suricata-common.h"
#include "tm-threads.h"

#include "util-privs.h"
#include "source-erf-dag.h"

#ifndef HAVE_DAG

TmEcode NoErfDagSupportExit(ThreadVars *, const void *, void **);

void
TmModuleReceiveErfDagRegister(void)
{
    tmm_modules[TMM_RECEIVEERFDAG].name = "ReceiveErfDag";
    tmm_modules[TMM_RECEIVEERFDAG].ThreadInit = NoErfDagSupportExit;
    tmm_modules[TMM_RECEIVEERFDAG].Func = NULL;
    tmm_modules[TMM_RECEIVEERFDAG].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEERFDAG].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEERFDAG].cap_flags = SC_CAP_NET_ADMIN;
    tmm_modules[TMM_RECEIVEERFDAG].flags = TM_FLAG_RECEIVE_TM;
}

void
TmModuleDecodeErfDagRegister(void)
{
    tmm_modules[TMM_DECODEERFDAG].name = "DecodeErfDag";
    tmm_modules[TMM_DECODEERFDAG].ThreadInit = NoErfDagSupportExit;
    tmm_modules[TMM_DECODEERFDAG].Func = NULL;
    tmm_modules[TMM_DECODEERFDAG].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEERFDAG].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEERFDAG].cap_flags = 0;
    tmm_modules[TMM_DECODEERFDAG].flags = TM_FLAG_DECODE_TM;
}

TmEcode
NoErfDagSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogError(SC_ERR_DAG_NOSUPPORT,
        "Error creating thread %s: you do not have support for DAG cards "
        "enabled please recompile with --enable-dag", tv->name);
    exit(EXIT_FAILURE);
}

#else /* Implied we do have DAG support */

#include <dagapi.h>

/* Minimum amount of data to read from the DAG at a time. */
#define MINDATA 32768

/* Maximum time (us) to wait for MINDATA to be read. */
#define MAXWAIT 20000

/* Poll interval in microseconds. */
#define POLL_INTERVAL 1000;

/* Number of bytes per loop to process before fetching more data. */
#define BYTES_PER_LOOP (4 * 1024 * 1024) /* 4 MB */

extern int max_pending_packets;

typedef struct ErfDagThreadVars_ {
    ThreadVars *tv;
    TmSlot *slot;

    int dagfd;
    int dagstream;
    char dagname[DAGNAME_BUFSIZE];

    struct timeval maxwait, poll;   /* Could possibly be made static */

    LiveDevice *livedev;

    uint64_t bytes;
    uint16_t packets;
    uint16_t drops;

    /* Current location in the DAG stream input buffer.
     */
    uint8_t *top;
    uint8_t *btm;

} ErfDagThreadVars;

static inline TmEcode ProcessErfDagRecords(ErfDagThreadVars *ewtn, uint8_t *top,
    uint32_t *pkts_read);
static inline TmEcode ProcessErfDagRecord(ErfDagThreadVars *ewtn, char *prec);
TmEcode ReceiveErfDagLoop(ThreadVars *, void *data, void *slot);
TmEcode ReceiveErfDagThreadInit(ThreadVars *, void *, void **);
void ReceiveErfDagThreadExitStats(ThreadVars *, void *);
TmEcode ReceiveErfDagThreadDeinit(ThreadVars *, void *);
TmEcode DecodeErfDagThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeErfDagThreadDeinit(ThreadVars *tv, void *data);
TmEcode DecodeErfDag(ThreadVars *, Packet *, void *);
void ReceiveErfDagCloseStream(int dagfd, int stream);

/**
 * \brief Register the ERF file receiver (reader) module.
 */
void
TmModuleReceiveErfDagRegister(void)
{
    tmm_modules[TMM_RECEIVEERFDAG].name = "ReceiveErfDag";
    tmm_modules[TMM_RECEIVEERFDAG].ThreadInit = ReceiveErfDagThreadInit;
    tmm_modules[TMM_RECEIVEERFDAG].Func = NULL;
    tmm_modules[TMM_RECEIVEERFDAG].PktAcqLoop = ReceiveErfDagLoop;
    tmm_modules[TMM_RECEIVEERFDAG].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVEERFDAG].ThreadExitPrintStats =
        ReceiveErfDagThreadExitStats;
    tmm_modules[TMM_RECEIVEERFDAG].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEERFDAG].cap_flags = 0;
    tmm_modules[TMM_RECEIVEERFDAG].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Register the ERF file decoder module.
 */
void
TmModuleDecodeErfDagRegister(void)
{
    tmm_modules[TMM_DECODEERFDAG].name = "DecodeErfDag";
    tmm_modules[TMM_DECODEERFDAG].ThreadInit = DecodeErfDagThreadInit;
    tmm_modules[TMM_DECODEERFDAG].Func = DecodeErfDag;
    tmm_modules[TMM_DECODEERFDAG].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEERFDAG].ThreadDeinit = DecodeErfDagThreadDeinit;
    tmm_modules[TMM_DECODEERFDAG].cap_flags = 0;
    tmm_modules[TMM_DECODEERFDAG].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief   Initialize the ERF receiver thread, generate a single
 *          ErfDagThreadVar structure for each thread, this will
 *          contain a DAG file descriptor which is read when the
 *          thread executes.
 *
 * \param tv        Thread variable to ThreadVars
 * \param initdata  Initial data to the interface passed from the user,
 *                  this is processed by the user.
 *
 *                  We assume that we have only a single name for the DAG
 *                  interface.
 *
 * \param data      data pointer gets populated with
 *
 */
TmEcode
ReceiveErfDagThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    int stream_count = 0;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
            "Error: No DAG interface provided.");
        SCReturnInt(TM_ECODE_FAILED);
    }

    ErfDagThreadVars *ewtn = SCMalloc(sizeof(ErfDagThreadVars));
    if (unlikely(ewtn == NULL)) {
            FatalError(SC_ERR_FATAL,
                       "Failed to allocate memory for ERF DAG thread vars.");
    }

    memset(ewtn, 0, sizeof(*ewtn));

    /* dag_parse_name will return a DAG device name and stream number
     * to open for this thread.
     */
    if (dag_parse_name(initdata, ewtn->dagname, DAGNAME_BUFSIZE,
            &ewtn->dagstream) < 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
            "Failed to parse DAG interface: %s",
            (char*)initdata);
        SCFree(ewtn);
        exit(EXIT_FAILURE);
    }

    ewtn->livedev = LiveGetDevice(initdata);
    if (ewtn->livedev == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Unable to get %s live device",
            (char *)initdata);
        SCFree(ewtn);
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogInfo("Opening DAG: %s on stream: %d for processing",
        ewtn->dagname, ewtn->dagstream);

    if ((ewtn->dagfd = dag_open(ewtn->dagname)) < 0) {
        SCLogError(SC_ERR_ERF_DAG_OPEN_FAILED, "Failed to open DAG: %s",
            ewtn->dagname);
        SCFree(ewtn);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* Check to make sure the card has enough available streams to
     * support reading from the one specified.
     */
    if ((stream_count = dag_rx_get_stream_count(ewtn->dagfd)) < 0) {
        SCLogError(SC_ERR_ERF_DAG_OPEN_FAILED,
            "Failed to open stream: %d, DAG: %s, could not query stream count",
            ewtn->dagstream, ewtn->dagname);
        SCFree(ewtn);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* Check to make sure we have enough rx streams to open the stream
     * the user is asking for.
     */
    if (ewtn->dagstream > stream_count * 2) {
        SCLogError(SC_ERR_ERF_DAG_OPEN_FAILED,
            "Failed to open stream: %d, DAG: %s, insufficient streams: %d",
            ewtn->dagstream, ewtn->dagname, stream_count);
        SCFree(ewtn);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* If we are transmitting into a soft DAG card then set the stream
     * to act in reverse mode.
     */
    if (0 != (ewtn->dagstream & 0x01)) {
        /* Setting reverse mode for using with soft dag from daemon side */
        if (dag_set_mode(ewtn->dagfd, ewtn->dagstream, DAG_REVERSE_MODE)) {
            SCLogError(SC_ERR_ERF_DAG_STREAM_OPEN_FAILED,
                "Failed to set mode to DAG_REVERSE_MODE on stream: %d, DAG: %s",
                ewtn->dagstream, ewtn->dagname);
            SCFree(ewtn);
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    if (dag_attach_stream(ewtn->dagfd, ewtn->dagstream, 0, 0) < 0) {
        SCLogError(SC_ERR_ERF_DAG_STREAM_OPEN_FAILED,
            "Failed to open DAG stream: %d, DAG: %s",
            ewtn->dagstream, ewtn->dagname);
        SCFree(ewtn);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (dag_start_stream(ewtn->dagfd, ewtn->dagstream) < 0) {
        SCLogError(SC_ERR_ERF_DAG_STREAM_START_FAILED,
            "Failed to start DAG stream: %d, DAG: %s",
            ewtn->dagstream, ewtn->dagname);
        SCFree(ewtn);
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogInfo("Attached and started stream: %d on DAG: %s",
        ewtn->dagstream, ewtn->dagname);

    /*
     * Initialise DAG Polling parameters.
     */
    timerclear(&ewtn->maxwait);
    ewtn->maxwait.tv_usec = MAXWAIT;
    timerclear(&ewtn->poll);
    ewtn->poll.tv_usec = POLL_INTERVAL;

    /* 32kB minimum data to return -- we still restrict the number of
     * pkts that are processed to a maximum of dag_max_read_packets.
     */
    if (dag_set_stream_poll(ewtn->dagfd, ewtn->dagstream, MINDATA,
            &(ewtn->maxwait), &(ewtn->poll)) < 0) {
        SCLogError(SC_ERR_ERF_DAG_STREAM_SET_FAILED,
            "Failed to set poll parameters for stream: %d, DAG: %s",
            ewtn->dagstream, ewtn->dagname);
        SCFree(ewtn);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ewtn->packets = StatsRegisterCounter("capture.dag_packets", tv);
    ewtn->drops = StatsRegisterCounter("capture.dag_drops", tv);

    ewtn->tv = tv;
    *data = (void *)ewtn;

    DatalinkSetGlobalType(LINKTYPE_ETHERNET);

    SCLogInfo("Starting processing packets from stream: %d on DAG: %s",
        ewtn->dagstream, ewtn->dagname);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Receives packets from a DAG interface.
 *
 * \param tv pointer to ThreadVars
 * \param data pointer to ErfDagThreadVars
 * \param slot slot containing task information
 *
 * \retval TM_ECODE_OK on success
 * \retval TM_ECODE_FAILED on failure
 */
TmEcode
ReceiveErfDagLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    ErfDagThreadVars *dtv = (ErfDagThreadVars *)data;
    uint32_t diff = 0;
    int      err;
    uint8_t  *top = NULL;
    uint32_t pkts_read = 0;
    TmSlot *s = (TmSlot *)slot;

    dtv->slot = s->slot_next;

    while (1) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_OK);
        }

        top = dag_advance_stream(dtv->dagfd, dtv->dagstream, &(dtv->btm));
        if (top == NULL) {
            if (errno == EAGAIN) {
                if (dtv->dagstream & 0x1) {
                    TmThreadsCaptureHandleTimeout(tv, NULL);
                    usleep(10 * 1000);
                    dtv->btm = dtv->top;
                }
                continue;
            } else {
                SCLogError(SC_ERR_ERF_DAG_STREAM_READ_FAILED,
                    "Failed to read from stream: %d, DAG: %s when "
                    "using dag_advance_stream",
                    dtv->dagstream, dtv->dagname);
                SCReturnInt(TM_ECODE_FAILED);
            }
        }

        diff = top - dtv->btm;
        if (diff == 0) {
            continue;
        }

        assert(diff >= dag_record_size);

        err = ProcessErfDagRecords(dtv, top, &pkts_read);

        if (err == TM_ECODE_FAILED) {
            SCLogError(SC_ERR_ERF_DAG_STREAM_READ_FAILED,
                "Failed to read from stream: %d, DAG: %s",
                dtv->dagstream, dtv->dagname);
            ReceiveErfDagCloseStream(dtv->dagfd, dtv->dagstream);
            SCReturnInt(TM_ECODE_FAILED);
        }

        StatsSyncCountersIfSignalled(tv);

        SCLogDebug("Read %d records from stream: %d, DAG: %s",
            pkts_read, dtv->dagstream, dtv->dagname);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Process a chunk of records read from a DAG interface.
 *
 * This function takes a pointer to buffer read from the DAG interface
 * and processes it individual records.
 */
static inline TmEcode
ProcessErfDagRecords(ErfDagThreadVars *ewtn, uint8_t *top, uint32_t *pkts_read)
{
    SCEnter();

    int err = 0;
    dag_record_t *dr = NULL;
    char *prec = NULL;
    int rlen;
    char hdr_type = 0;
    int processed = 0;

    *pkts_read = 0;

    while (((top - ewtn->btm) >= dag_record_size) &&
        ((processed + dag_record_size) < BYTES_PER_LOOP)) {

        /* Make sure we have at least one packet in the packet pool,
         * to prevent us from alloc'ing packets at line rate. */
        PacketPoolWait();

        prec = (char *)ewtn->btm;
        dr = (dag_record_t*)prec;
        rlen = SCNtohs(dr->rlen);
        hdr_type = dr->type;

        /* If we don't have enough data to finish processing this ERF
         * record return and maybe next time we will.
         */
        if ((top - ewtn->btm) < rlen)
            SCReturnInt(TM_ECODE_OK);

        ewtn->btm += rlen;
        processed += rlen;

        /* Only support ethernet at this time. */
        switch (hdr_type & 0x7f) {
        case ERF_TYPE_PAD:
        case ERF_TYPE_META:
            /* Skip. */
            continue;
        case ERF_TYPE_DSM_COLOR_ETH:
        case ERF_TYPE_COLOR_ETH:
        case ERF_TYPE_COLOR_HASH_ETH:
            /* In these types the color value overwrites the lctr
             * (drop count). */
            break;
        case ERF_TYPE_ETH:
            if (dr->lctr) {
                StatsAddUI64(ewtn->tv, ewtn->drops, SCNtohs(dr->lctr));
            }
            break;
        default:
            SCLogError(SC_ERR_UNIMPLEMENTED,
                "Processing of DAG record type: %d not implemented.", dr->type);
            SCReturnInt(TM_ECODE_FAILED);
        }

        err = ProcessErfDagRecord(ewtn, prec);
        if (err != TM_ECODE_OK) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        (*pkts_read)++;
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief   Process a DAG record into a TM packet buffer.
 * \param   prec pointer to a DAG record.
 * \param
 */
static inline TmEcode
ProcessErfDagRecord(ErfDagThreadVars *ewtn, char *prec)
{
    SCEnter();

    int wlen = 0;
    int rlen = 0;
    int hdr_num = 0;
    char hdr_type = 0;
    dag_record_t  *dr = (dag_record_t*)prec;
    erf_payload_t *pload;
    Packet *p;

    hdr_type = dr->type;
    wlen = SCNtohs(dr->wlen);
    rlen = SCNtohs(dr->rlen);

    /* count extension headers */
    while (hdr_type & 0x80) {
        if (rlen < (dag_record_size + (hdr_num * 8))) {
            SCLogError(SC_ERR_UNIMPLEMENTED,
                "Insufficient captured packet length.");
            SCReturnInt(TM_ECODE_FAILED);
        }
        hdr_type = prec[(dag_record_size + (hdr_num * 8))];
        hdr_num++;
    }

    /* Check that the whole frame was captured */
    if (rlen < (dag_record_size + (8 * hdr_num) + 2 + wlen)) {
        SCLogInfo("Incomplete frame captured.");
        SCReturnInt(TM_ECODE_OK);
    }

    /* skip over extension headers */
    pload = (erf_payload_t *)(prec + dag_record_size + (8 * hdr_num));

    p = PacketGetFromQueueOrAlloc();
    if (p == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Failed to allocate a Packet on stream: %d, DAG: %s",
            ewtn->dagstream, ewtn->dagname);
        SCReturnInt(TM_ECODE_FAILED);
    }
    PKT_SET_SRC(p, PKT_SRC_WIRE);

    SET_PKT_LEN(p, wlen);
    p->datalink = LINKTYPE_ETHERNET;

    /* Take into account for link type Ethernet ETH frame starts
     * after ther ERF header + pad.
     */
    if (unlikely(PacketCopyData(p, pload->eth.dst, GET_PKT_LEN(p)))) {
        TmqhOutputPacketpool(ewtn->tv, p);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* Convert ERF time to timeval - from libpcap. */
    uint64_t ts = dr->ts;
    p->ts.tv_sec = ts >> 32;
    ts = (ts & 0xffffffffULL) * 1000000;
    ts += 0x80000000; /* rounding */
    p->ts.tv_usec = ts >> 32;
    if (p->ts.tv_usec >= 1000000) {
        p->ts.tv_usec -= 1000000;
        p->ts.tv_sec++;
    }

    StatsIncr(ewtn->tv, ewtn->packets);
    ewtn->bytes += wlen;

    if (TmThreadsSlotProcessPkt(ewtn->tv, ewtn->slot, p) != TM_ECODE_OK) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Print some stats to the log at program exit.
 *
 * \param tv Pointer to ThreadVars.
 * \param data Pointer to data, ErfFileThreadVars.
 */
void
ReceiveErfDagThreadExitStats(ThreadVars *tv, void *data)
{
    ErfDagThreadVars *ewtn = (ErfDagThreadVars *)data;

    (void)SC_ATOMIC_SET(ewtn->livedev->pkts,
        StatsGetLocalCounterValue(tv, ewtn->packets));
    (void)SC_ATOMIC_SET(ewtn->livedev->drop,
        StatsGetLocalCounterValue(tv, ewtn->drops));

    SCLogInfo("Stream: %d; Bytes: %"PRIu64"; Packets: %"PRIu64
        "; Drops: %"PRIu64,
        ewtn->dagstream,
        ewtn->bytes,
        StatsGetLocalCounterValue(tv, ewtn->packets),
        StatsGetLocalCounterValue(tv, ewtn->drops));
}

/**
 * \brief   Deinitializes the DAG card.
 * \param   tv pointer to ThreadVars
 * \param   data pointer that gets cast into PcapThreadVars for ptv
 */
TmEcode
ReceiveErfDagThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();

    ErfDagThreadVars *ewtn = (ErfDagThreadVars *)data;

    ReceiveErfDagCloseStream(ewtn->dagfd, ewtn->dagstream);

    SCReturnInt(TM_ECODE_OK);
}

void
ReceiveErfDagCloseStream(int dagfd, int stream)
{
    dag_stop_stream(dagfd, stream);
    dag_detach_stream(dagfd, stream);
    dag_close(dagfd);
}

/** Decode ErfDag */

/**
 * \brief   This function passes off to link type decoders.
 *
 * DecodeErfDag decodes packets from DAG and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into PcapThreadVars for ptv
 */
TmEcode
DecodeErfDag(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

        /* call the decoder */
    switch(p->datalink) {
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED,
                "Error: datalink type %" PRId32
                " not yet supported in module DecodeErfDag",
                p->datalink);
            break;
    }

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode
DecodeErfDagThreadInit(ThreadVars *tv, void *initdata, void **data)
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

TmEcode
DecodeErfDagThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

#endif /* HAVE_DAG */
