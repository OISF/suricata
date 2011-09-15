/* Copyright (C) 2010 Open Information Security Foundation
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
 * \author Jason MacLulich <jason.maclulich@eendace.com>
 *
 * Support for reading ERF records from a DAG card.
 *
 * Only ethernet supported at this time.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "tm-threads.h"

#include "util-privs.h"
#include "tmqh-packetpool.h"

#ifndef HAVE_DAG

TmEcode NoErfDagSupportExit(ThreadVars *, void *, void **);

void TmModuleReceiveErfDagRegister (void) {
    tmm_modules[TMM_RECEIVEERFDAG].name = "ReceiveErfDag";
    tmm_modules[TMM_RECEIVEERFDAG].ThreadInit = NoErfDagSupportExit;
    tmm_modules[TMM_RECEIVEERFDAG].Func = NULL;
    tmm_modules[TMM_RECEIVEERFDAG].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEERFDAG].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEERFDAG].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEERFDAG].cap_flags = SC_CAP_NET_ADMIN;
    tmm_modules[TMM_RECEIVEERFDAG].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleDecodeErfDagRegister (void) {
    tmm_modules[TMM_DECODEERFDAG].name = "DecodeErfDag";
    tmm_modules[TMM_DECODEERFDAG].ThreadInit = NoErfDagSupportExit;
    tmm_modules[TMM_DECODEERFDAG].Func = NULL;
    tmm_modules[TMM_DECODEERFDAG].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEERFDAG].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEERFDAG].RegisterTests = NULL;
    tmm_modules[TMM_DECODEERFDAG].cap_flags = 0;
}

TmEcode NoErfDagSupportExit(ThreadVars *tv, void *initdata, void **data)
{
    SCLogError(SC_ERR_DAG_NOSUPPORT,
               "Error creating thread %s: you do not have support for DAG cards "
               "enabled please recompile with --enable-dag", tv->name);
    exit(EXIT_FAILURE);
}

#else /* Implied we do have DAG support */

#define DAG_MAX_READ_PKTS 256

#include "source-erf-dag.h"
#include <dagapi.h>

extern int max_pending_packets;
extern uint8_t suricata_ctl_flags;

typedef struct ErfDagThreadVars_ {
    ThreadVars *tv;
    int dagfd;
    int dagstream;
    char dagname[DAGNAME_BUFSIZE];
    uint32_t dag_max_read_packets;

    struct timeval maxwait, poll;   /* Could possibly be made static */

    uint32_t pkts;
    uint64_t bytes;

    /* Track current location in the DAG stream input buffer
     */
    uint8_t* top;                   /* We track top as well so we don't have to
                                       call dag_advance_stream again if there
                                       are still pkts to process.

                                       JNM: Currently not used.
                                     */
    uint8_t* btm;

} ErfDagThreadVars;

TmEcode ReceiveErfDag(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode ReceiveErfDagThreadInit(ThreadVars *, void *, void **);
void ReceiveErfDagThreadExitStats(ThreadVars *, void *);
TmEcode ReceiveErfDagThreadDeinit(ThreadVars *, void *);
TmEcode ProcessErfDagRecords(ErfDagThreadVars *ewtn, Packet *p, uint8_t* top,
                             PacketQueue *postpq, uint32_t *pkts_read);
TmEcode ProcessErfDagRecord(ErfDagThreadVars *ewtn, char *prec, Packet *p);

TmEcode DecodeErfDagThreadInit(ThreadVars *, void *, void **);
TmEcode DecodeErfDag(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
void ReceiveErfDagCloseStream(int dagfd, int stream);

/**
 * \brief Register the ERF file receiver (reader) module.
 */
void
TmModuleReceiveErfDagRegister(void)
{
    tmm_modules[TMM_RECEIVEERFDAG].name = "ReceiveErfDag";
    tmm_modules[TMM_RECEIVEERFDAG].ThreadInit = ReceiveErfDagThreadInit;
    tmm_modules[TMM_RECEIVEERFDAG].Func = ReceiveErfDag;
    tmm_modules[TMM_RECEIVEERFDAG].ThreadExitPrintStats =
        ReceiveErfDagThreadExitStats;
    tmm_modules[TMM_RECEIVEERFDAG].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEERFDAG].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEERFDAG].cap_flags = 0;
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
    tmm_modules[TMM_DECODEERFDAG].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEERFDAG].RegisterTests = NULL;
    tmm_modules[TMM_DECODEERFDAG].cap_flags = 0;
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
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Error: No DAG interface provided.");
        SCReturnInt(TM_ECODE_FAILED);
    }

    ErfDagThreadVars *ewtn = SCMalloc(sizeof(ErfDagThreadVars));
    if (ewtn == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
                   "Failed to allocate memory for ERF DAG thread vars.");
        exit(EXIT_FAILURE);
    }

    memset(ewtn, 0, sizeof(*ewtn));

    /*  Use max_pending_packets as our maximum number of packets read
     from the DAG buffer.
     */
    ewtn->dag_max_read_packets = (DAG_MAX_READ_PKTS < max_pending_packets) ?
        DAG_MAX_READ_PKTS : max_pending_packets;


    /* dag_parse_name will return a DAG device name and stream number
     * to open for this thread.
     */
    if (dag_parse_name(initdata, ewtn->dagname, DAGNAME_BUFSIZE,
                       &ewtn->dagstream) < 0)
    {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "Failed to parse DAG interface: %s",
                   (char*)initdata);
        SCFree(ewtn);
        exit(EXIT_FAILURE);
    }

    SCLogInfo("Opening DAG: %s on stream: %d for processing",
        ewtn->dagname, ewtn->dagstream);

    if ((ewtn->dagfd = dag_open(ewtn->dagname)) < 0)
    {
        SCLogError(SC_ERR_ERF_DAG_OPEN_FAILED, "Failed to open DAG: %s",
                   ewtn->dagname);
        SCFree(ewtn);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* Check to make sure the card has enough available streams to
     * support reading from the one specified.
     */
    if ((stream_count = dag_rx_get_stream_count(ewtn->dagfd)) < 0)
    {
        SCLogError(SC_ERR_ERF_DAG_OPEN_FAILED,
                   "Failed to open stream: %d, DAG: %s, could not query stream count",
                   ewtn->dagstream, ewtn->dagname);
        SCFree(ewtn);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* Check to make sure we have enough rx streams to open the stream
     * the user is asking for.
     */
    if (ewtn->dagstream > stream_count*2)
    {
        SCLogError(SC_ERR_ERF_DAG_OPEN_FAILED,
                   "Failed to open stream: %d, DAG: %s, insufficient streams: %d",
                   ewtn->dagstream, ewtn->dagname, stream_count);
        SCFree(ewtn);
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* If we are transmitting into a soft DAG card then set the stream
     * to act in reverse mode.
     */
    if (0 != (ewtn->dagstream & 0x01))
    {
        /* Setting reverse mode for using with soft dag from daemon side */
        if(dag_set_mode(ewtn->dagfd, ewtn->dagstream, DAG_REVERSE_MODE)) {
            SCLogError(SC_ERR_ERF_DAG_STREAM_OPEN_FAILED,
                       "Failed to set mode to DAG_REVERSE_MODE on stream: %d, DAG: %s",
                       ewtn->dagstream, ewtn->dagname);
            SCFree(ewtn);
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    if (dag_attach_stream(ewtn->dagfd, ewtn->dagstream, 0, 0) < 0)
    {
        SCLogError(SC_ERR_ERF_DAG_STREAM_OPEN_FAILED,
                   "Failed to open DAG stream: %d, DAG: %s",
                   ewtn->dagstream, ewtn->dagname);
        SCFree(ewtn);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (dag_start_stream(ewtn->dagfd, ewtn->dagstream) < 0)
    {
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
    ewtn->maxwait.tv_usec = 100 * 1000; /* 100ms timeout */
    timerclear(&ewtn->poll);
    ewtn->poll.tv_usec = 10 * 1000; /* 10ms poll interval */

    /* 32kB minimum data to return -- we still restrict the number of
     * pkts that are processed to a maximum of dag_max_read_packets.
     */
    if (dag_set_stream_poll(ewtn->dagfd, ewtn->dagstream, 32*1024, &(ewtn->maxwait), &(ewtn->poll)) < 0)
    {
        SCLogError(SC_ERR_ERF_DAG_STREAM_SET_FAILED,
                   "Failed to set poll parameters for stream: %d, DAG: %s",
                   ewtn->dagstream, ewtn->dagname);
        SCFree(ewtn);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ewtn->tv = tv;
    *data = (void *)ewtn;

    SCLogInfo("Starting processing packets from stream: %d on DAG: %s",
              ewtn->dagstream, ewtn->dagname);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief   Thread entry function for reading ERF records from a DAG card.
 *
 *          Reads a new ERF record the DAG input buffer and copies it to
 *          an internal Suricata packet buffer -- similar to the way the
 *          pcap packet handler works.
 *
 *          We create new packet structures using PacketGetFromQueueOrAlloc
 *          for each packet between the top and btm pointers except for
 *          the first packet for which a Packet buffer is provided
 *          from the packetpool.
 *
 *          We always read up to dag_max_read_packets ERF packets from the
 *          DAG buffer, but we might read less. This differs from the
 *          ReceivePcap handler -- it will only read pkts up to a maximum
 *          of either the packetpool count or the pcap_max_read_packets.
 *
 * \param   tv pointer to ThreadVars
 * \param   p data pointer
 * \param   data
 * \param   pq pointer to the PacketQueue (not used here)
 * \param   postpq
 * \retval  TM_ECODE_FAILED on failure and TM_ECODE_OK on success.
 * \note    We also use the packetpool hack first used in the source-pcap
 *          handler so we don't keep producing packets without any dying.
 *          This implies that if we are in this situation we run the risk
 *          of dropping packets at the interface.
 */
TmEcode
ReceiveErfDag(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
               PacketQueue *postpq)
{
    SCEnter();

    uint16_t packet_q_len = 0;
    uint32_t diff = 0;
    int      err;
    uint8_t  *top = NULL;
    uint32_t pkts_read = 0;

    assert(p);
    assert(pq);
    assert(postpq);

    ErfDagThreadVars *ewtn = (ErfDagThreadVars *)data;

    /* NOTE/JNM: Hack copied from source-pcap.c
     *
     * Make sure we have at least one packet in the packet pool, to
     * prevent us from alloc'ing packets at line rate
     */
    while (packet_q_len == 0) {
        packet_q_len = PacketPoolSize();
        if (packet_q_len == 0) {
            PacketPoolWait();
        }
    }

    if (postpq == NULL) {
        ewtn->dag_max_read_packets = 1;
    }

    while(pkts_read == 0)
    {
	    if (suricata_ctl_flags != 0) {
            break;
        }

        /* NOTE/JNM: This might not work well if we start restricting the
	     * number of ERF records processed per call to a small number as
	     * the over head required here could exceed the time it takes to
	     * process a small number of ERF records.
	     *
	     * XXX/JNM: Possibly process the DAG stream buffer first if there
	     * are ERF packets or else call dag_advance_stream and then process
	     * the DAG stream buffer.
	     */
	    top = dag_advance_stream(ewtn->dagfd, ewtn->dagstream, &(ewtn->btm));

	    if (NULL == top)
	    {
	        if((ewtn->dagstream & 0x1) && (errno == EAGAIN)) {
	            usleep(10 * 1000);
	            ewtn->btm = ewtn->top;
                continue;
	        }
	        else {
	            SCLogError(SC_ERR_ERF_DAG_STREAM_READ_FAILED,
	                       "Failed to read from stream: %d, DAG: %s when using dag_advance_stream",
	                       ewtn->dagstream, ewtn->dagname);
	            SCReturnInt(TM_ECODE_FAILED);
	        }
	    }

	    diff = top - ewtn->btm;
	    if (diff == 0)
	    {
	        continue;
	    }

	    assert(diff >= dag_record_size);

	    err = ProcessErfDagRecords(ewtn, p, top, postpq, &pkts_read);

        if (err == TM_ECODE_FAILED) {
             SCLogError(SC_ERR_ERF_DAG_STREAM_READ_FAILED,
                   "Failed to read from stream: %d, DAG: %s",
                   ewtn->dagstream, ewtn->dagname);
            ReceiveErfDagCloseStream(ewtn->dagfd, ewtn->dagstream);
            SCReturnInt(err);
        }
    }

    SCLogDebug("Read %d records from stream: %d, DAG: %s",
        pkts_read, ewtn->dagstream, ewtn->dagname);

    if (suricata_ctl_flags != 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(err);
}

TmEcode ProcessErfDagRecords(ErfDagThreadVars *ewtn,
                             Packet *p,
                             uint8_t* top,
                             PacketQueue *postpq,
                             uint32_t *pkts_read)
{
    SCEnter();

    int     err = 0;
    dag_record_t* dr = NULL;
    char    *prec = NULL;
    int     rlen;

    *pkts_read = 0;

    while(((top-(ewtn->btm))>=dag_record_size) &&
          ((*pkts_read)<(ewtn->dag_max_read_packets)))
    {
        prec = (char*)ewtn->btm;
        dr = (dag_record_t*)prec;

        rlen = ntohs(dr->rlen);

        if (rlen == 20) {
            rlen = 28;
            SCLogWarning(SC_WARN_ERF_DAG_REC_LEN_CHANGED,
                "Warning, adjusted the length of ERF from 20 to 28 on stream: %d, DAG: %s",
                ewtn->dagstream, ewtn->dagname);
        }

        /* If we don't have enough data to finsih processing this ERF record
         * return and maybe next time we will.
         */
        if ((top-(ewtn->btm)) < rlen)
            SCReturnInt(TM_ECODE_OK);

        p = p ? p : PacketGetFromQueueOrAlloc();

        if (p == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC,
                       "Failed to allocate a Packet on stream: %d, DAG: %s",
                       ewtn->dagstream, ewtn->dagname);
            SCReturnInt(TM_ECODE_FAILED);
        }

        err = ProcessErfDagRecord(ewtn, prec, p);

        if (err != TM_ECODE_OK)
            SCReturnInt(err);

        ewtn->btm += rlen;

        /* XXX/JNM: Hack to get around the fact that the first Packet from
         * Suricata is added explicitly by the Slot code and shouldn't go
         * onto the post queue -- else it is added twice to the next queue.
         */
        if (*pkts_read) {
            PacketEnqueue(postpq, p);
        }

        (*pkts_read)++;

        p = NULL;
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief   Process a DAG record into a TM packet buffer.
 * \param   prec pointer to a DAG record.
 * \param
 */
TmEcode ProcessErfDagRecord(ErfDagThreadVars *ewtn, char *prec, Packet *p)
{
    SCEnter();

    int wlen = 0;
    dag_record_t  *dr = (dag_record_t*)prec;
    erf_payload_t *pload;

    assert(prec);
    assert(p);

    if (p == NULL) SCReturnInt(TM_ECODE_OK);

    /* Only support ethernet at this time. */
    if (dr->type != TYPE_ETH &&
	    dr->type != TYPE_DSM_COLOR_ETH &&
	    dr->type != TYPE_COLOR_ETH &&
	    dr->type != TYPE_COLOR_HASH_ETH) {
        SCLogError(SC_ERR_UNIMPLEMENTED,
                   "Processing of DAG record type: %d not implemented.", dr->type);
        SCReturnInt(TM_ECODE_FAILED);
    }

    wlen = ntohs(dr->wlen);

    pload = &(dr->rec);

    SET_PKT_LEN(p, wlen - 4);   /* Trim the FCS... */
    p->datalink = LINKTYPE_ETHERNET;

    /* Take into account for link type Ethernet ETH frame starts
     * after ther ERF header + pad.
     */
    PacketCopyData(p, pload->eth.dst, GET_PKT_LEN(p));

    SCLogDebug("pktlen: %" PRIu32 " (pkt %02x, pkt data %02x)",
               GET_PKT_LEN(p), *p, *GET_PKT_DATA(p));

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

    ewtn->pkts++;
    ewtn->bytes += wlen;

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

    SCLogInfo("Packets: %"PRIu32"; Bytes: %"PRIu64, ewtn->pkts, ewtn->bytes);
}

/**
 * \brief   Deinitializes the DAG card.
 * \param   tv pointer to ThreadVars
 * \param   data pointer that gets cast into PcapThreadVars for ptv
 */
TmEcode ReceiveErfDagThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();

    ErfDagThreadVars *ewtn = (ErfDagThreadVars *)data;

    ReceiveErfDagCloseStream(ewtn->dagfd, ewtn->dagstream);

    SCReturnInt(TM_ECODE_OK);
}

void ReceiveErfDagCloseStream(int dagfd, int stream)
{
    dag_stop_stream(dagfd, stream);
    dag_detach_stream(dagfd, stream);
    dag_close(dagfd);
}

/** Decode ErfDag */

/**
 * \brief   This function passes off to link type decoders.
 *
 * DecodeErfDag reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into PcapThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 */
TmEcode DecodeErfDag(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
                   PacketQueue *postpq)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* update counters */
    SCPerfCounterIncr(dtv->counter_pkts, tv->sc_perf_pca);
    SCPerfCounterIncr(dtv->counter_pkts_per_sec, tv->sc_perf_pca);

    SCPerfCounterAddUI64(dtv->counter_bytes, tv->sc_perf_pca, GET_PKT_LEN(p));
#if 0
    SCPerfCounterAddDouble(dtv->counter_bytes_per_sec, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterAddDouble(dtv->counter_mbit_per_sec, tv->sc_perf_pca,
                           (GET_PKT_LEN(p) * 8)/1000000.0);
#endif

    SCPerfCounterAddUI64(dtv->counter_avg_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));
    SCPerfCounterSetUI64(dtv->counter_max_pkt_size, tv->sc_perf_pca, GET_PKT_LEN(p));

        /* call the decoder */
    switch(p->datalink) {
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED,
                "Error: datalink type %" PRId32 " not yet supported in module DecodeErfDag",
                p->datalink);
            break;
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeErfDagThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;

   // if ( (dtv = SCMalloc(sizeof(DecodeThreadVars))) == NULL)
   //     SCReturnInt(TM_ECODE_FAILED);
   // memset(dtv, 0, sizeof(DecodeThreadVars));

    dtv = DecodeThreadVarsAlloc();

    if(dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

#endif /* HAVE_DAG */
