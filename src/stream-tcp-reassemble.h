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

#define PSUEDO_PKT_SET_IPV4HDR(nipv4h,ipv4h) do { \
        (nipv4h)->ip_src = IPV4_GET_RAW_IPDST(ipv4h); \
        (nipv4h)->ip_dst = IPV4_GET_RAW_IPSRC(ipv4h); \
    } while (0)

#define PSUEDO_PKT_SET_IPV6HDR(nipv6h,ipv6h) do { \
        (nipv6h)->ip6_src[0] = (ipv6h)->ip6_dst[0]; \
        (nipv6h)->ip6_src[1] = (ipv6h)->ip6_dst[1]; \
        (nipv6h)->ip6_src[2] = (ipv6h)->ip6_dst[2]; \
        (nipv6h)->ip6_src[3] = (ipv6h)->ip6_dst[3]; \
        (nipv6h)->ip6_dst[0] = (ipv6h)->ip6_src[0]; \
        (nipv6h)->ip6_dst[1] = (ipv6h)->ip6_src[1]; \
        (nipv6h)->ip6_dst[2] = (ipv6h)->ip6_src[2]; \
        (nipv6h)->ip6_dst[3] = (ipv6h)->ip6_src[3]; \
    } while (0)

#define PSUEDO_PKT_SET_TCPHDR(ntcph,tcph) do { \
        COPY_PORT((tcph)->th_dport, (ntcph)->th_sport); \
        COPY_PORT((tcph)->th_sport, (ntcph)->th_dport); \
        (ntcph)->th_seq = (tcph)->th_ack; \
        (ntcph)->th_ack = (tcph)->th_seq; \
    } while (0)

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
    StreamMsgQueue *stream_q;
    AlpProtoDetectThreadCtx dp_ctx;   /**< proto detection thread data */
    /** TCP segments which are not being reassembled due to memcap was reached */
    uint16_t counter_tcp_segment_memcap;
    /** number of streams that stop reassembly because their depth is reached */
    uint16_t counter_tcp_stream_depth;
} TcpReassemblyThreadCtx;

#define OS_POLICY_DEFAULT   OS_POLICY_BSD

int StreamTcpReassembleHandleSegment(ThreadVars *, TcpReassemblyThreadCtx *, TcpSession *, TcpStream *, Packet *, PacketQueue *);
int StreamTcpReassembleInit(char);
void StreamTcpReassembleFree(char);
void StreamTcpReassembleRegisterTests(void);
TcpReassemblyThreadCtx *StreamTcpReassembleInitThreadCtx(void);
void StreamTcpReassembleFreeThreadCtx(TcpReassemblyThreadCtx *);
int StreamTcpReassembleProcessAppLayer(TcpReassemblyThreadCtx *);

void StreamTcpCreateTestPacket(uint8_t *, uint8_t, uint8_t, uint8_t);

void StreamTcpSetSessionNoReassemblyFlag (TcpSession *, char );

void StreamTcpSetOSPolicy(TcpStream *, Packet *);
void StreamTcpReassemblePause (TcpSession *, char );
void StreamTcpReassembleUnPause (TcpSession *, char );
int StreamTcpCheckStreamContents(uint8_t *, uint16_t , TcpStream *);

#endif /* __STREAM_TCP_REASSEMBLE_H__ */

