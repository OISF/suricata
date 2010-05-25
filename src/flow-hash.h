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
 *  \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 */

#ifndef __FLOW_HASH_H__
#define __FLOW_HASH_H__

/* flow hash bucket -- the hash is basically an array of these buckets.
 * Each bucket contains a flow or list of flows. All these flows have
 * the same hashkey (the hash is a chained hash). When doing modifications
 * to the list, the entire bucket is locked. */
typedef struct FlowBucket_ {
    Flow *f;
//    SCMutex m;
    SCSpinlock s;
} FlowBucket;

/* prototypes */

Flow *FlowGetFlowFromHash(Packet *);

/** enable to print stats on hash lookups in flow-debug.log */
//#define FLOW_DEBUG_STATS

#ifdef FLOW_DEBUG_STATS
void FlowHashDebugInit(void);
void FlowHashDebugDeinit(void);
void FlowHashDebugPrint(uint32_t);
#else
#define FlowHashDebugInit(...)
#define FlowHashDebugPrint(...)
#define FlowHashDebugDeinit(...)
#endif

#endif /* __FLOW_HASH_H__ */

