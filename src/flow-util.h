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
 */

#ifndef __FLOW_UTIL_H__
#define __FLOW_UTIL_H__

#include "detect-engine-state.h"

#define COPY_TIMESTAMP(src,dst) ((dst)->tv_sec = (src)->tv_sec, (dst)->tv_usec = (src)->tv_usec)

#ifdef DEBUG
#define RESET_COUNTERS(f) do { \
        (f)->todstpktcnt = 0; \
        (f)->tosrcpktcnt = 0; \
        (f)->bytecnt = 0; \
    } while (0)
#else
#define RESET_COUNTERS(f)
#endif

#define FLOW_INITIALIZE(f) do { \
        (f)->sp = 0; \
        (f)->dp = 0; \
        SC_ATOMIC_INIT((f)->use_cnt); \
        (f)->flags = 0; \
        (f)->lastts_sec = 0; \
        SCMutexInit(&(f)->m, NULL); \
        (f)->protoctx = NULL; \
        (f)->alproto = 0; \
        (f)->probing_parser_toserver_al_proto_masks = 0; \
        (f)->probing_parser_toclient_al_proto_masks = 0; \
        (f)->aldata = NULL; \
        (f)->de_state = NULL; \
        (f)->sgh_toserver = NULL; \
        (f)->sgh_toclient = NULL; \
        (f)->tag_list = NULL; \
        (f)->flowvar = NULL; \
        SCMutexInit(&(f)->de_state_m, NULL); \
        (f)->hnext = NULL; \
        (f)->hprev = NULL; \
        (f)->lnext = NULL; \
        (f)->lprev = NULL; \
        RESET_COUNTERS((f)); \
    } while (0)

/** \brief macro to recycle a flow before it goes into the spare queue for reuse.
 *
 *  Note that the lnext, lprev, hnext, hprev fields are untouched, those are
 *  managed by the queueing code. Same goes for fb (FlowBucket ptr) field.
 */
#define FLOW_RECYCLE(f) do { \
        (f)->sp = 0; \
        (f)->dp = 0; \
        SC_ATOMIC_RESET((f)->use_cnt); \
        (f)->flags = 0; \
        (f)->lastts_sec = 0; \
        (f)->protoctx = NULL; \
        FlowL7DataPtrFree(f); \
        (f)->alproto = 0; \
        (f)->probing_parser_toserver_al_proto_masks = 0; \
        (f)->probing_parser_toclient_al_proto_masks = 0; \
        if ((f)->de_state != NULL) { \
            DetectEngineStateReset((f)->de_state); \
        } \
        (f)->sgh_toserver = NULL; \
        (f)->sgh_toclient = NULL; \
        DetectTagDataListFree((f)->tag_list); \
        (f)->tag_list = NULL; \
        GenericVarFree((f)->flowvar); \
        (f)->flowvar = NULL; \
        RESET_COUNTERS((f)); \
    } while(0)

#define FLOW_DESTROY(f) do { \
        SC_ATOMIC_DESTROY((f)->use_cnt); \
        \
        SCMutexDestroy(&(f)->m); \
        if ((f)->de_state != NULL) { \
            DetectEngineStateFree((f)->de_state); \
        } \
        /* clear app layer related memory */ \
        FlowL7DataPtrFree(f); \
        DetectTagDataListFree((f)->tag_list); \
        GenericVarFree((f)->flowvar); \
        SCMutexDestroy(&(f)->de_state_m); \
    } while(0)

Flow *FlowAlloc(void);
Flow *FlowAllocDirect(void);
void FlowFree(Flow *);
uint8_t FlowGetProtoMapping(uint8_t);
void FlowInit(Flow *, Packet *);

#endif /* __FLOW_UTIL_H__ */

