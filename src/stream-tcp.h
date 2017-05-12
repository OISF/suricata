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

#ifndef __STREAM_TCP_H__
#define __STREAM_TCP_H__

#include "stream-tcp-private.h"

#include "stream.h"
#include "stream-tcp-reassemble.h"

#define STREAM_VERBOSE    FALSE
/* Flag to indicate that the checksum validation for the stream engine
   has been enabled */
#define STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION    BIT_U8(0)
#define STREAMTCP_INIT_FLAG_DROP_INVALID           BIT_U8(1)
#define STREAMTCP_INIT_FLAG_BYPASS                 BIT_U8(2)
#define STREAMTCP_INIT_FLAG_INLINE                 BIT_U8(3)

/*global flow data*/
typedef struct TcpStreamCnf_ {
    /** stream tracking
     *
     * max stream mem usage
     */
    uint64_t memcap;
    uint64_t reassembly_memcap; /**< max memory usage for stream reassembly */

    uint16_t stream_init_flags; /**< new stream flags will be initialized to this */

    /* coccinelle: TcpStreamCnf:flags:STREAMTCP_INIT_ */
    uint8_t flags;
    uint8_t max_synack_queued;

    uint32_t prealloc_sessions; /**< ssns to prealloc per stream thread */
    uint32_t prealloc_segments; /**< segments to prealloc per stream thread */
    int midstream;
    int async_oneside;
    uint32_t reassembly_depth;  /**< Depth until when we reassemble the stream */

    uint16_t reassembly_toserver_chunk_size;
    uint16_t reassembly_toclient_chunk_size;

    bool streaming_log_api;

    StreamingBufferConfig sbcnf;
} TcpStreamCnf;

typedef struct StreamTcpThread_ {
    int ssn_pool_id;

    /** queue for pseudo packet(s) that were created in the stream
     *  process and need further handling. Currently only used when
     *  receiving (valid) RST packets */
    PacketQueue pseudo_queue;

    uint16_t counter_tcp_sessions;
    /** sessions not picked up because memcap was reached */
    uint16_t counter_tcp_ssn_memcap;
    /** pseudo packets processed */
    uint16_t counter_tcp_pseudo;
    /** pseudo packets failed to setup */
    uint16_t counter_tcp_pseudo_failed;
    /** packets rejected because their csum is invalid */
    uint16_t counter_tcp_invalid_checksum;
    /** TCP packets with no associated flow */
    uint16_t counter_tcp_no_flow;
    /** sessions reused */
    uint16_t counter_tcp_reused_ssn;
    /** syn pkts */
    uint16_t counter_tcp_syn;
    /** syn/ack pkts */
    uint16_t counter_tcp_synack;
    /** rst pkts */
    uint16_t counter_tcp_rst;

    /** tcp reassembly thread data */
    TcpReassemblyThreadCtx *ra_ctx;
} StreamTcpThread;

TcpStreamCnf stream_config;
void StreamTcpInitConfig (char);
void StreamTcpFreeConfig(char);
void StreamTcpRegisterTests (void);

void StreamTcpSessionPktFree (Packet *);

void StreamTcpInitMemuse(void);
void StreamTcpIncrMemuse(uint64_t);
void StreamTcpDecrMemuse(uint64_t);
int StreamTcpCheckMemcap(uint64_t);
uint64_t StreamTcpMemuseCounter(void);
uint64_t StreamTcpReassembleMemuseGlobalCounter(void);

Packet *StreamTcpPseudoSetup(Packet *, uint8_t *, uint32_t);

int StreamTcpSegmentForEach(const Packet *p, uint8_t flag,
                        StreamSegmentCallback CallbackFunc,
                        void *data);
void StreamTcpReassembleConfigEnableOverlapCheck(void);
void TcpSessionSetReassemblyDepth(TcpSession *ssn, uint32_t size);

typedef int (*StreamReassembleRawFunc)(void *data, const uint8_t *input, const uint32_t input_len);

int StreamReassembleLog(TcpSession *ssn, TcpStream *stream,
        StreamReassembleRawFunc Callback, void *cb_data,
        uint64_t progress_in,
        uint64_t *progress_out, bool eof);
int StreamReassembleRaw(TcpSession *ssn, const Packet *p,
        StreamReassembleRawFunc Callback, void *cb_data, uint64_t *progress_out);
void StreamReassembleRawUpdateProgress(TcpSession *ssn, Packet *p, uint64_t progress);

void StreamTcpDetectLogFlush(ThreadVars *tv, StreamTcpThread *stt, Flow *f, Packet *p, PacketQueue *pq);


/** ------- Inline functions: ------ */

/**
  * \brief If we are on IPS mode, and got a drop action triggered from
  * the IP only module, or from a reassembled msg and/or from an
  * applayer detection, then drop the rest of the packets of the
  * same stream and avoid inspecting it any further
  * \param p pointer to the Packet to check
  * \retval 1 if we must drop this stream
  * \retval 0 if the stream still legal
  */
static inline int StreamTcpCheckFlowDrops(Packet *p)
{
    /* If we are on IPS mode, and got a drop action triggered from
     * the IP only module, or from a reassembled msg and/or from an
     * applayer detection, then drop the rest of the packets of the
     * same stream and avoid inspecting it any further */
    if (EngineModeIsIPS() && (p->flow->flags & FLOW_ACTION_DROP))
        return 1;

    return 0;
}

/**
 *  \brief  Function to flip the direction When we missed the SYN packet,
 *          SYN/ACK is considered as sent by server, but our engine flagged the
 *          packet as from client for the host whose packet is received first in
 *          the session.
 *
 *  \param  ssn TcpSession to whom this packet belongs
 *  \param  p   Packet whose flag has to be changed
 */
static inline void StreamTcpPacketSwitchDir(TcpSession *ssn, Packet *p)
{
    SCLogDebug("ssn %p: switching pkt direction", ssn);

    if (PKT_IS_TOSERVER(p)) {
        p->flowflags &= ~FLOW_PKT_TOSERVER;
        p->flowflags |= FLOW_PKT_TOCLIENT;

        if (p->flowflags & FLOW_PKT_TOSERVER_FIRST) {
            p->flowflags &= ~FLOW_PKT_TOSERVER_FIRST;
            p->flowflags |= FLOW_PKT_TOCLIENT_FIRST;
        }
    } else {
        p->flowflags &= ~FLOW_PKT_TOCLIENT;
        p->flowflags |= FLOW_PKT_TOSERVER;

        if (p->flowflags & FLOW_PKT_TOCLIENT_FIRST) {
            p->flowflags &= ~FLOW_PKT_TOCLIENT_FIRST;
            p->flowflags |= FLOW_PKT_TOSERVER_FIRST;
        }
    }
}

enum {
    /* stream has no segments for forced reassembly, nor for detection */
    STREAM_HAS_UNPROCESSED_SEGMENTS_NONE = 0,
    /* stream has no segments for forced reassembly, but only segments that
     * have been sent for detection, but are stuck in the detection queues */
    STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION = 1,
};

TmEcode StreamTcp (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
int StreamNeedsReassembly(const TcpSession *ssn, uint8_t direction);
TmEcode StreamTcpThreadInit(ThreadVars *, void *, void **);
TmEcode StreamTcpThreadDeinit(ThreadVars *tv, void *data);
void StreamTcpRegisterTests (void);

int StreamTcpPacket (ThreadVars *tv, Packet *p, StreamTcpThread *stt,
                     PacketQueue *pq);
/* clear ssn and return to pool */
void StreamTcpSessionClear(void *ssnptr);
/* cleanup ssn, but don't free ssn */
void StreamTcpSessionCleanup(TcpSession *ssn);
/* cleanup stream, but don't free the stream */
void StreamTcpStreamCleanup(TcpStream *stream);
/* check if bypass is enabled */
int StreamTcpBypassEnabled(void);
int StreamTcpInlineDropInvalid(void);
int StreamTcpInlineMode(void);

int TcpSessionPacketSsnReuse(const Packet *p, const Flow *f, const void *tcp_ssn);

#endif /* __STREAM_TCP_H__ */

