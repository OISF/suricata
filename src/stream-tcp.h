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

#define COUNTER_STREAMTCP_STREAMS 1

#include "app-layer-detect-proto.h"
#include "util-mpm.h"
#include "stream.h"
#include "stream-tcp-reassemble.h"

#define STREAM_VERBOSE    FALSE
/* Flag to indicate that the checksum validation for the stream engine
   has been enabled */
#define STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION    0x01

/*global flow data*/
typedef struct TcpStreamCnf_ {
    /** stream tracking
     *
     * max stream mem usage
     */
    uint64_t memcap;
    uint64_t reassembly_memcap; /**< max memory usage for stream reassembly */

    uint32_t ssn_init_flags; /**< new ssn flags will be initialized to this */
    uint8_t segment_init_flags; /**< new seg flags will be initialized to this */

    uint16_t zero_copy_size;    /**< use zero copy for app layer above segments
                                 *   of this size */

    uint32_t prealloc_sessions; /**< ssns to prealloc per stream thread */
    int midstream;
    int async_oneside;
    uint32_t reassembly_depth;  /**< Depth until when we reassemble the stream */

    uint16_t reassembly_toserver_chunk_size;
    uint16_t reassembly_toclient_chunk_size;

    int check_overlap_different_data;

    /** reassembly -- inline mode
     *
     *  sliding window size for raw stream reassembly
     */
    uint32_t reassembly_inline_window;
    uint8_t flags;
    uint8_t max_synack_queued;
} TcpStreamCnf;

typedef struct StreamTcpThread_ {
    int ssn_pool_id;

    /** if set to true, we activate the TCP tuple reuse code in the
     *  stream engine. */
    int runmode_flow_stream_async;

    uint64_t pkts;

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
void TmModuleStreamTcpRegister (void);
void StreamTcpInitConfig (char);
void StreamTcpFreeConfig(char);
void StreamTcpRegisterTests (void);

void StreamTcpSessionPktFree (Packet *);

void StreamTcpIncrMemuse(uint64_t);
void StreamTcpDecrMemuse(uint64_t);
int StreamTcpCheckMemcap(uint64_t);

Packet *StreamTcpPseudoSetup(Packet *, uint8_t *, uint32_t);

int StreamTcpSegmentForEach(const Packet *p, uint8_t flag,
                        StreamSegmentCallback CallbackFunc,
                        void *data);
void StreamTcpReassembleConfigEnableOverlapCheck(void);

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
    /* stream seems to have segments that need to be forced reassembled */
    STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY = 1,
    /* stream has no segments for forced reassembly, but only segments that
     * have been sent for detection, but are stuck in the detection queues */
    STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION = 2,
};

static inline int StreamNeedsReassembly(TcpSession *ssn, int direction)
{
    /* server tcp state */
    if (direction) {
        if (ssn->server.seg_list != NULL &&
            (!(ssn->server.seg_list_tail->flags & SEGMENTTCP_FLAG_RAW_PROCESSED) ||
             !(ssn->server.seg_list_tail->flags & SEGMENTTCP_FLAG_APPLAYER_PROCESSED)) ) {
            return STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY;
        } else if (ssn->toclient_smsg_head != NULL) {
            return STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
        } else {
            return STREAM_HAS_UNPROCESSED_SEGMENTS_NONE;
        }
    } else {
        if (ssn->client.seg_list != NULL &&
            (!(ssn->client.seg_list_tail->flags & SEGMENTTCP_FLAG_RAW_PROCESSED) ||
             !(ssn->client.seg_list_tail->flags & SEGMENTTCP_FLAG_APPLAYER_PROCESSED)) ) {
            return STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_REASSEMBLY;
        } else if (ssn->toserver_smsg_head != NULL) {
            return STREAM_HAS_UNPROCESSED_SEGMENTS_NEED_ONLY_DETECTION;
        } else {
            return STREAM_HAS_UNPROCESSED_SEGMENTS_NONE;
        }
    }
}

TmEcode StreamTcpThreadInit(ThreadVars *, void *, void **);
TmEcode StreamTcpThreadDeinit(ThreadVars *tv, void *data);
int StreamTcpPacket (ThreadVars *tv, Packet *p, StreamTcpThread *stt,
                     PacketQueue *pq);
void StreamTcpSessionClear(void *ssnptr);
uint32_t StreamTcpGetStreamSize(TcpStream *stream);

#endif /* __STREAM_TCP_H__ */

