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
#include "stream.h"
#include "app-layer-detect-proto.h"
#include "stream-tcp-private.h"

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

typedef struct TcpReassemblyThreadCtx_ {
    void *app_tctx;
    /** TCP segments which are not being reassembled due to memcap was reached */
    uint16_t counter_tcp_segment_memcap;
    /** number of streams that stop reassembly because their depth is reached */
    uint16_t counter_tcp_stream_depth;
    /** count number of streams with a unrecoverable stream gap (missing pkts) */
    uint16_t counter_tcp_reass_gap;
#ifdef DEBUG
    uint64_t fp1;
    uint64_t fp2;
    uint64_t sp;
#endif
} TcpReassemblyThreadCtx;

#define OS_POLICY_DEFAULT   OS_POLICY_BSD

int StreamTcpReassembleHandleSegment(ThreadVars *, TcpReassemblyThreadCtx *, TcpSession *, TcpStream *, Packet *, PacketQueue *);
int StreamTcpReassembleInit(char);
void StreamTcpReassembleFree(char);
void StreamTcpReassembleRegisterTests(void);
TcpReassemblyThreadCtx *StreamTcpReassembleInitThreadCtx(ThreadVars *tv);
void StreamTcpReassembleFreeThreadCtx(TcpReassemblyThreadCtx *);
int StreamTcpReassembleAppLayer (ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                                 TcpSession *ssn, TcpStream *stream,
                                 Packet *p);

void StreamTcpCreateTestPacket(uint8_t *, uint8_t, uint8_t, uint8_t);

void StreamTcpSetSessionNoReassemblyFlag (TcpSession *, char );
void StreamTcpSetDisableRawReassemblyFlag (TcpSession *ssn, char direction);

void StreamTcpSetOSPolicy(TcpStream *, Packet *);
void StreamTcpReassemblePause (TcpSession *, char );
void StreamTcpReassembleUnPause (TcpSession *, char );
int StreamTcpCheckStreamContents(uint8_t *, uint16_t , TcpStream *);

int StreamTcpReassembleInsertSegment(ThreadVars *, TcpReassemblyThreadCtx *, TcpStream *, TcpSegment *, Packet *);
TcpSegment* StreamTcpGetSegment(ThreadVars *, TcpReassemblyThreadCtx *, uint16_t);

void StreamTcpReturnStreamSegments(TcpStream *);
void StreamTcpSegmentReturntoPool(TcpSegment *);

void StreamTcpReassembleTriggerRawReassembly(TcpSession *);

void StreamTcpPruneSession(Flow *, uint8_t);
int StreamTcpReassembleDepthReached(Packet *p);

void StreamTcpReassembleIncrMemuse(uint64_t size);
void StreamTcpReassembleDecrMemuse(uint64_t size);
int StreamTcpReassembleCheckMemcap(uint32_t size);

void StreamTcpDisableAppLayer(Flow *f);
int StreamTcpAppLayerIsDisabled(Flow *f);

#endif /* __STREAM_TCP_REASSEMBLE_H__ */

