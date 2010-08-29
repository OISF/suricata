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
    uint32_t memcap; /** max stream mem usage */
    uint32_t max_sessions;
    uint32_t prealloc_sessions;
    int midstream;
    int async_oneside;
    uint32_t reassembly_memcap; /**< max memory usage for stream reassembly */
    uint32_t reassembly_depth;  /**< Depth until when we reassemble the stream */
    uint8_t flags;
} TcpStreamCnf;

TcpStreamCnf stream_config;
void TmModuleStreamTcpRegister (void);
void StreamTcpInitConfig (char);
void StreamTcpFreeConfig(char);
void StreamTcpRegisterTests (void);

void StreamTcpSessionPktFree (Packet *);

void StreamTcpIncrMemuse(uint32_t);
void StreamTcpDecrMemuse(uint32_t);
int StreamTcpCheckMemcap(uint32_t);


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
static inline int StreamTcpCheckFlowDrops(Packet *p) {
    extern uint8_t engine_mode;
    /* If we are on IPS mode, and got a drop action triggered from
     * the IP only module, or from a reassembled msg and/or from an
     * applayer detection, then drop the rest of the packets of the
     * same stream and avoid inspecting it any further */
    if (IS_ENGINE_MODE_IPS(engine_mode) && (p->flow->flags & FLOW_ACTION_DROP))
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
    } else {
        p->flowflags &= ~FLOW_PKT_TOCLIENT;
        p->flowflags |= FLOW_PKT_TOSERVER;
    }
}


#endif /* __STREAM_TCP_H__ */

