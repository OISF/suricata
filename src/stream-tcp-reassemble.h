/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 */

#ifndef __STREAM_TCP_REASSEMBLE_H__
#define __STREAM_TCP_REASSEMBLE_H__

#include "stream-tcp-private.h"
#include "stream-tcp-private.h"

#ifdef UNITTESTS
#include "suricata.h"
#endif

/** Supported OS list and default OS policy is BSD */
enum
{
    OS_POLICY_NONE = 1,
    OS_POLICY_BSD,
    OS_POLICY_BSD_RIGHT,
    OS_POLICY_OLD_LINUX,
    OS_POLICY_LINUX,
    OS_POLICY_OLD_SOLARIS,
    OS_POLICY_SOLARIS,
    OS_POLICY_HPUX10,
    OS_POLICY_HPUX11,
    OS_POLICY_IRIX,
    OS_POLICY_MACOS,
    OS_POLICY_WINDOWS,
    OS_POLICY_VISTA,
    OS_POLICY_WINDOWS2K3,
    OS_POLICY_FIRST,
    OS_POLICY_LAST
};

enum StreamUpdateDir {
    UPDATE_DIR_PACKET,
    UPDATE_DIR_OPPOSING,
    UPDATE_DIR_BOTH,
};

typedef struct TcpReassemblyThreadCtx_ {
    void *app_tctx;

    int segment_thread_pool_id;

    /** TCP segments which are not being reassembled due to memcap was reached */
    uint16_t counter_tcp_segment_memcap;
    /** number of streams that stop reassembly because their depth is reached */
    uint16_t counter_tcp_stream_depth;
    /** count number of streams with a unrecoverable stream gap (missing pkts) */
    uint16_t counter_tcp_reass_gap;

    /** count packet data overlaps */
    uint16_t counter_tcp_reass_overlap;
    /** count overlaps with different data */
    uint16_t counter_tcp_reass_overlap_diff_data;

    uint16_t counter_tcp_reass_data_normal_fail;
    uint16_t counter_tcp_reass_data_overlap_fail;
} TcpReassemblyThreadCtx;

#define OS_POLICY_DEFAULT   OS_POLICY_BSD

void StreamTcpReassembleInitMemuse(void);
int StreamTcpReassembleHandleSegment(ThreadVars *, TcpReassemblyThreadCtx *, TcpSession *, TcpStream *, Packet *, PacketQueueNoLock *);
int StreamTcpReassembleInit(bool);
void StreamTcpReassembleFree(bool);
void *StreamTcpReassembleRealloc(void *optr, size_t orig_size, size_t size);
void StreamTcpReassembleRegisterTests(void);
TcpReassemblyThreadCtx *StreamTcpReassembleInitThreadCtx(ThreadVars *tv);
void StreamTcpReassembleFreeThreadCtx(TcpReassemblyThreadCtx *);
int StreamTcpReassembleAppLayer (ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                                 TcpSession *ssn, TcpStream *stream,
                                 Packet *p, enum StreamUpdateDir dir);

void StreamTcpCreateTestPacket(uint8_t *, uint8_t, uint8_t, uint8_t);

void StreamTcpSetSessionNoReassemblyFlag(TcpSession *, char);
void StreamTcpSetSessionBypassFlag(TcpSession *);
void StreamTcpSetDisableRawReassemblyFlag(TcpSession *, char);

void StreamTcpSetOSPolicy(TcpStream *, Packet *);

int StreamTcpReassembleHandleSegmentHandleData(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
        TcpSession *ssn, TcpStream *stream, Packet *p);
int StreamTcpReassembleInsertSegment(ThreadVars *, TcpReassemblyThreadCtx *, TcpStream *, TcpSegment *, Packet *, uint32_t pkt_seq, uint8_t *pkt_data, uint16_t pkt_datalen);
TcpSegment *StreamTcpGetSegment(ThreadVars *, TcpReassemblyThreadCtx *);

void StreamTcpReturnStreamSegments(TcpStream *);
void StreamTcpSegmentReturntoPool(TcpSegment *);

void StreamTcpReassembleTriggerRawReassembly(TcpSession *, int direction);

void StreamTcpPruneSession(Flow *, uint8_t);
int StreamTcpReassembleDepthReached(Packet *p);

void StreamTcpReassembleIncrMemuse(uint64_t size);
void StreamTcpReassembleDecrMemuse(uint64_t size);
int StreamTcpReassembleSetMemcap(uint64_t size);
uint64_t StreamTcpReassembleGetMemcap(void);
int StreamTcpReassembleCheckMemcap(uint64_t size);
uint64_t StreamTcpReassembleMemuseGlobalCounter(void);

void StreamTcpDisableAppLayer(Flow *f);
int StreamTcpAppLayerIsDisabled(Flow *f);

#ifdef UNITTESTS
int StreamTcpCheckStreamContents(uint8_t *, uint16_t , TcpStream *);
#endif

bool StreamReassembleRawHasDataReady(TcpSession *ssn, Packet *p);
void StreamTcpReassemblySetMinInspectDepth(TcpSession *ssn, int direction, uint32_t depth);

bool IsTcpSessionDumpingEnabled(void);
void EnableTcpSessionDumping(void);

static inline bool STREAM_LASTACK_GT_BASESEQ(const TcpStream *stream)
{
    /* last ack not yet initialized */
    if (STREAM_BASE_OFFSET(stream) == 0 && (stream->tcp_flags & TH_ACK) == 0) {
#ifdef UNITTESTS
        if (RunmodeIsUnittests() && stream->last_ack == 0)
            return false;
#else
        return false;
#endif
    }
    if (SEQ_GT(stream->last_ack, stream->base_seq))
        return true;
    return false;
}

uint32_t StreamDataAvailableForProtoDetect(TcpStream *stream);

#endif /* __STREAM_TCP_REASSEMBLE_H__ */

