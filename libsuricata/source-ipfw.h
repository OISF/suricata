/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * \author Nick Rogness <nick@rogness.net>
 * \author Eric Leblond <eric@regit.org>
 */

#ifndef __SOURCE_IPFW_H__
#define __SOURCE_IPFW_H__

#define IPFW_MAX_QUEUE 16

/* per packet IPFW vars (Not used) */
typedef struct IPFWPacketVars_
{
    int ipfw_index;
} IPFWPacketVars;

typedef struct IPFWQueueVars_
{
    int fd;
    SCMutex socket_lock;
    uint8_t use_mutex;
    /* this one should be not changing after init */
    uint16_t port_num;
    /* position into the ipfw queue var array */
    uint16_t ipfw_index;
    struct sockaddr_in ipfw_sin;
    socklen_t ipfw_sinlen;

#ifdef DBG_PERF
    int dbg_maxreadsize;
#endif /* DBG_PERF */

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;
    uint32_t accepted;
    uint32_t dropped;
    uint32_t replaced;

} IPFWQueueVars;

void *IPFWGetThread(int number);
int IPFWRegisterQueue(char *queue);

void TmModuleReceiveIPFWRegister (void);
void TmModuleVerdictIPFWRegister (void);
void TmModuleDecodeIPFWRegister (void);


#endif /* __SOURCE_IPFW_H__ */
