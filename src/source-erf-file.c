/* Copyright (C) 2010-2014 Open Information Security Foundation
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
 *
 * Support for reading ERF files.
 *
 * Only ethernet supported at this time.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "tm-threads.h"
#include "source-erf-file.h"
#include "util-datalink.h"

#define ERF_HEADER_LEN  16
#define ERF_EXT_LEN     8
#define ERF_ETH_PAD_LEN 2

#ifndef HAVE_DAG
#define ERF_TYPE_MASK           0x7f
#define ERF_TYPE_MORE_EXT       0x80
#define ERF_TYPE_ETH            2
#define ERF_TYPE_COLOR_ETH      11
#define ERF_TYPE_DSM_COLOR_ETH  16
#define ERF_TYPE_COLOR_HASH_ETH 20

#else /* Implied we do have DAG support */
#include <dagapi.h>
#endif

typedef struct DagFlags_ {
    uint8_t iface:2;
    uint8_t vlen:1;
    uint8_t trunc:1;
    uint8_t rxerror:1;
    uint8_t dserror:1;
    uint8_t reserved:1;
    uint8_t direction:1;
} DagFlags;

typedef struct DagRecord_ {
    uint64_t ts;
    uint8_t type;
    DagFlags flags;
    uint16_t rlen;
    uint16_t lctr;
    uint16_t wlen;
} __attribute__((packed)) DagRecord;

typedef struct ErfFileThreadVars_ {
    ThreadVars *tv;
    TmSlot *slot;

    FILE *erf;

    uint32_t pkts;
    uint64_t bytes;

    uint8_t buffer[MAX_PAYLOAD_SIZE];
} ErfFileThreadVars;

static inline TmEcode ReadErfRecord(ThreadVars *, Packet *, void *);
TmEcode ReceiveErfFileLoop(ThreadVars *, void *, void *);
TmEcode ReceiveErfFileThreadInit(ThreadVars *, const void *, void **);
void ReceiveErfFileThreadExitStats(ThreadVars *, void *);
TmEcode ReceiveErfFileThreadDeinit(ThreadVars *, void *);

static TmEcode DecodeErfFileThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodeErfFileThreadDeinit(ThreadVars *tv, void *data);
static TmEcode DecodeErfFile(ThreadVars *, Packet *, void *);

/**
 * \brief Register the ERF file receiver (reader) module.
 */
void
TmModuleReceiveErfFileRegister(void)
{
    tmm_modules[TMM_RECEIVEERFFILE].name = "ReceiveErfFile";
    tmm_modules[TMM_RECEIVEERFFILE].ThreadInit = ReceiveErfFileThreadInit;
    tmm_modules[TMM_RECEIVEERFFILE].Func = NULL;
    tmm_modules[TMM_RECEIVEERFFILE].PktAcqLoop = ReceiveErfFileLoop;
    tmm_modules[TMM_RECEIVEERFFILE].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVEERFFILE].ThreadExitPrintStats =
        ReceiveErfFileThreadExitStats;
    tmm_modules[TMM_RECEIVEERFFILE].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEERFFILE].cap_flags = 0;
    tmm_modules[TMM_RECEIVEERFFILE].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Register the ERF file decoder module.
 */
void
TmModuleDecodeErfFileRegister(void)
{
    tmm_modules[TMM_DECODEERFFILE].name = "DecodeErfFile";
    tmm_modules[TMM_DECODEERFFILE].ThreadInit = DecodeErfFileThreadInit;
    tmm_modules[TMM_DECODEERFFILE].Func = DecodeErfFile;
    tmm_modules[TMM_DECODEERFFILE].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEERFFILE].ThreadDeinit = DecodeErfFileThreadDeinit;
    tmm_modules[TMM_DECODEERFFILE].cap_flags = 0;
    tmm_modules[TMM_DECODEERFFILE].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief ERF file reading loop.
 */
TmEcode ReceiveErfFileLoop(ThreadVars *tv, void *data, void *slot)
{
    Packet *p = NULL;
    ErfFileThreadVars *etv = (ErfFileThreadVars *)data;

    etv->slot = ((TmSlot *)slot)->slot_next;

    // Indicate that the thread is actually running its application level code (i.e., it can poll
    // packets)
    TmThreadsSetFlag(tv, THV_RUNNING);

    while (1) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_OK);
        }

        /* Make sure we have at least one packet in the packet pool,
         * to prevent us from alloc'ing packets at line rate. */
        PacketPoolWait();

        if (p == NULL) {
            p = PacketGetFromQueueOrAlloc();
        }
        if (unlikely(p == NULL)) {
            SCLogError("Failed to allocate a packet.");
            EngineStop();
            SCReturnInt(TM_ECODE_FAILED);
        }
        PKT_SET_SRC(p, PKT_SRC_WIRE);

        if (ReadErfRecord(tv, p, data) != TM_ECODE_OK) {
            TmqhOutputPacketpool(etv->tv, p);
            EngineStop();
            SCReturnInt(TM_ECODE_FAILED);
        }
        if (GET_PKT_LEN(p) == 0) {
            continue;
        }

        if (TmThreadsSlotProcessPkt(etv->tv, etv->slot, p) != TM_ECODE_OK) {
            EngineStop();
            SCReturnInt(TM_ECODE_FAILED);
        }
        p = NULL;
    }
    SCReturnInt(TM_ECODE_FAILED);
}

static inline TmEcode ReadErfRecord(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();

    ErfFileThreadVars *etv = (ErfFileThreadVars *)data;
    DagRecord dr;
    unsigned int hdr_num = 0;
    char ext_hdr[ERF_EXT_LEN];

    size_t r = fread(&dr, sizeof(DagRecord), 1, etv->erf);
    if (r < 1) {
        if (feof(etv->erf)) {
            SCLogInfo("End of ERF file reached");
        }
        else {
            SCLogInfo("Error reading ERF record");
        }
        SCReturnInt(TM_ECODE_FAILED);
    }
    uint8_t hdr_type = dr.type;
    uint16_t rlen = SCNtohs(dr.rlen);
    if (rlen < ERF_HEADER_LEN) {
        SCLogError("Bad ERF record, "
                   "record length less than size of header");
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* count extension headers */
    while (hdr_type & ERF_TYPE_MORE_EXT) {
        if (rlen < (ERF_HEADER_LEN + ((hdr_num + 1) * 8))) {
            SCLogError("Insufficient captured packet length.");
            SCReturnInt(TM_ECODE_FAILED);
        }
        r = fread(ext_hdr, ERF_EXT_LEN, 1, etv->erf);
        if (r < 1) {
            if (feof(etv->erf)) {
                SCLogInfo("End of ERF file reached");
            } else {
                SCLogInfo("Error reading ERF record");
            }
            SCReturnInt(TM_ECODE_FAILED);
        }
        hdr_type = ext_hdr[0];
        hdr_num++;
    }

    /* read and discard ERF Ethernet pad */
    if (rlen < (ERF_HEADER_LEN + (hdr_num * ERF_EXT_LEN) + ERF_ETH_PAD_LEN)) {
        SCLogError("Insufficient captured packet length.");
        SCReturnInt(TM_ECODE_FAILED);
    }
    r = fread(ext_hdr, ERF_ETH_PAD_LEN, 1, etv->erf);
    if (r < 1) {
        if (feof(etv->erf)) {
            SCLogInfo("End of ERF file reached");
        } else {
            SCLogInfo("Error reading ERF record");
        }
        SCReturnInt(TM_ECODE_FAILED);
    }

    uint32_t caplen = rlen - (hdr_num * ERF_EXT_LEN) - ERF_HEADER_LEN - ERF_ETH_PAD_LEN;
    if (caplen > MAX_PACKET_SIZE) {
        SCLogError("Bad ERF record, capture length %u exceeds max %d", caplen, MAX_PACKET_SIZE);
        SCReturnInt(TM_ECODE_FAILED);
    }

    r = fread(etv->buffer, caplen, 1, etv->erf);
    if (r < 1) {
        if (feof(etv->erf)) {
            SCLogInfo("End of ERF file reached");
        }
        else {
            SCLogInfo("Error reading ERF record");
        }
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* Only support ethernet at this time. Return TM_ECODE_OK with pkt len = 0 to indicate skipped
     * record */
    switch (dr.type & ERF_TYPE_MASK) {
        case ERF_TYPE_DSM_COLOR_ETH:
        case ERF_TYPE_COLOR_ETH:
        case ERF_TYPE_COLOR_HASH_ETH:
        case ERF_TYPE_ETH:
            break;
        default:
            SCReturnInt(TM_ECODE_OK);
    }

    if (PacketCopyData(p, etv->buffer, caplen) != 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    p->datalink = LINKTYPE_ETHERNET;

    /* Convert ERF time to SCTime_t */
    uint64_t ts = dr.ts;
    p->ts = SCTIME_FROM_SECS(ts >> 32);
    ts = (ts & 0xffffffffULL) * 1000000;
    ts += 0x80000000; /* rounding */
    uint64_t usecs = (ts >> 32);
    p->ts = SCTIME_ADD_USECS(p->ts, usecs);

    etv->pkts++;
    etv->bytes += caplen;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Initialize the ERF receiver thread.
 */
TmEcode
ReceiveErfFileThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();

    if (initdata == NULL) {
        SCLogError("Error: No filename provided.");
        SCReturnInt(TM_ECODE_FAILED);
    }

    FILE *erf = fopen((const char *)initdata, "r");
    if (erf == NULL) {
        SCLogError("Failed to open %s: %s", (char *)initdata, strerror(errno));
        exit(EXIT_FAILURE);
    }

    ErfFileThreadVars *etv = SCCalloc(1, sizeof(ErfFileThreadVars));
    if (unlikely(etv == NULL)) {
        SCLogError("Failed to allocate memory for ERF file thread vars.");
        fclose(erf);
        SCReturnInt(TM_ECODE_FAILED);
    }
    etv->erf = erf;
    etv->tv = tv;
    *data = (void *)etv;

    SCLogInfo("Processing ERF file %s", (char *)initdata);

    DatalinkSetGlobalType(LINKTYPE_ETHERNET);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Initialize the ERF decoder thread.
 */
TmEcode
DecodeErfFileThreadInit(ThreadVars *tv, const void *initdata, void **data)
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

TmEcode DecodeErfFileThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Decode the ERF file.
 *
 * This function ups the decoder counters and then passes the packet
 * off to the ethernet decoder.
 */
TmEcode
DecodeErfFile(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* Update counters. */
    DecodeUpdatePacketCounters(tv, dtv, p);

    DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Print some stats to the log at program exit.
 *
 * \param tv Pointer to ThreadVars.
 * \param data Pointer to data, ErfFileThreadVars.
 */
void
ReceiveErfFileThreadExitStats(ThreadVars *tv, void *data)
{
    ErfFileThreadVars *etv = (ErfFileThreadVars *)data;

    SCLogInfo("Packets: %"PRIu32"; Bytes: %"PRIu64, etv->pkts, etv->bytes);
}
