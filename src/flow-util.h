/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 */

#ifndef __FLOW_UTIL_H__
#define __FLOW_UTIL_H__

#include "detect-engine-state.h"
#include "tmqh-flow.h"

#define COPY_TIMESTAMP(src,dst) ((dst)->tv_sec = (src)->tv_sec, (dst)->tv_usec = (src)->tv_usec)

#define RESET_COUNTERS(f) do { \
        (f)->todstpktcnt = 0; \
        (f)->tosrcpktcnt = 0; \
        (f)->todstbytecnt = 0; \
        (f)->tosrcbytecnt = 0; \
    } while (0)

#define FLOW_INITIALIZE(f) do { \
        (f)->sp = 0; \
        (f)->dp = 0; \
        (f)->proto = 0; \
        SC_ATOMIC_INIT((f)->flow_state); \
        SC_ATOMIC_INIT((f)->use_cnt); \
        (f)->tenant_id = 0; \
        (f)->probing_parser_toserver_alproto_masks = 0; \
        (f)->probing_parser_toclient_alproto_masks = 0; \
        (f)->flags = 0; \
        (f)->lastts.tv_sec = 0; \
        (f)->lastts.tv_usec = 0; \
        FLOWLOCK_INIT((f)); \
        (f)->protoctx = NULL; \
        (f)->flow_end_flags = 0; \
        (f)->alproto = 0; \
        (f)->alproto_ts = 0; \
        (f)->alproto_tc = 0; \
        (f)->data_al_so_far[0] = 0; \
        (f)->data_al_so_far[1] = 0; \
        (f)->de_ctx_id = 0; \
        (f)->thread_id = 0; \
        (f)->detect_alversion[0] = 0; \
        (f)->detect_alversion[1] = 0; \
        (f)->alparser = NULL; \
        (f)->alstate = NULL; \
        (f)->de_state = NULL; \
        (f)->sgh_toserver = NULL; \
        (f)->sgh_toclient = NULL; \
        (f)->flowvar = NULL; \
        (f)->hnext = NULL; \
        (f)->hprev = NULL; \
        (f)->lnext = NULL; \
        (f)->lprev = NULL; \
        SC_ATOMIC_INIT((f)->autofp_tmqh_flow_qid);  \
        (void) SC_ATOMIC_SET((f)->autofp_tmqh_flow_qid, -1);  \
        RESET_COUNTERS((f)); \
    } while (0)

/** \brief macro to recycle a flow before it goes into the spare queue for reuse.
 *
 *  Note that the lnext, lprev, hnext, hprev fields are untouched, those are
 *  managed by the queueing code. Same goes for fb (FlowBucket ptr) field.
 */
#define FLOW_RECYCLE(f) do { \
        FlowCleanupAppLayer((f)); \
        (f)->sp = 0; \
        (f)->dp = 0; \
        (f)->proto = 0; \
        SC_ATOMIC_RESET((f)->flow_state); \
        SC_ATOMIC_RESET((f)->use_cnt); \
        (f)->tenant_id = 0; \
        (f)->probing_parser_toserver_alproto_masks = 0; \
        (f)->probing_parser_toclient_alproto_masks = 0; \
        (f)->flags = 0; \
        (f)->lastts.tv_sec = 0; \
        (f)->lastts.tv_usec = 0; \
        (f)->protoctx = NULL; \
        (f)->flow_end_flags = 0; \
        (f)->alparser = NULL; \
        (f)->alstate = NULL; \
        (f)->alproto = 0; \
        (f)->alproto_ts = 0; \
        (f)->alproto_tc = 0; \
        (f)->data_al_so_far[0] = 0; \
        (f)->data_al_so_far[1] = 0; \
        (f)->de_ctx_id = 0; \
        (f)->thread_id = 0; \
        (f)->detect_alversion[0] = 0; \
        (f)->detect_alversion[1] = 0; \
        if ((f)->de_state != NULL) { \
            DetectEngineStateReset((f)->de_state, (STREAM_TOSERVER | STREAM_TOCLIENT)); \
        } \
        (f)->sgh_toserver = NULL; \
        (f)->sgh_toclient = NULL; \
        GenericVarFree((f)->flowvar); \
        (f)->flowvar = NULL; \
        if (SC_ATOMIC_GET((f)->autofp_tmqh_flow_qid) != -1) {   \
            (void) SC_ATOMIC_SET((f)->autofp_tmqh_flow_qid, -1);   \
        }                                       \
        RESET_COUNTERS((f)); \
    } while(0)

#define FLOW_DESTROY(f) do { \
        FlowCleanupAppLayer((f)); \
        SC_ATOMIC_DESTROY((f)->flow_state); \
        SC_ATOMIC_DESTROY((f)->use_cnt); \
        \
        FLOWLOCK_DESTROY((f)); \
        if ((f)->de_state != NULL) { \
            DetectEngineStateFlowFree((f)->de_state); \
        } \
        GenericVarFree((f)->flowvar); \
        SC_ATOMIC_DESTROY((f)->autofp_tmqh_flow_qid);   \
    } while(0)

/** \brief check if a memory alloc would fit in the memcap
 *
 *  \param size memory allocation size to check
 *
 *  \retval 1 it fits
 *  \retval 0 no fit
 */
#define FLOW_CHECK_MEMCAP(size) \
    ((((uint64_t)SC_ATOMIC_GET(flow_memuse) + (uint64_t)(size)) <= flow_config.memcap))

Flow *FlowAlloc(void);
Flow *FlowAllocDirect(void);
void FlowFree(Flow *);
uint8_t FlowGetProtoMapping(uint8_t);
void FlowInit(Flow *, const Packet *);
uint8_t FlowGetReverseProtoMapping(uint8_t rproto);

#endif /* __FLOW_UTIL_H__ */

