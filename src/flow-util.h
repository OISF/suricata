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

#define COPY_TIMESTAMP(src,dst) ((dst)->tv_sec = (src)->tv_sec, (dst)->tv_usec = (src)->tv_usec)

#define FLOW_INITIALIZE(f) do { \
        SCMutexInit(&(f)->m, NULL); \
        SCMutexInit(&(f)->de_state_m, NULL); \
        (f)->lnext = NULL; \
        (f)->lprev = NULL; \
        (f)->hnext = NULL; \
        (f)->hprev = NULL; \
        (f)->sp = 0; \
        (f)->dp = 0; \
        (f)->flags = 0; \
        (f)->todstpktcnt = 0; \
        (f)->tosrcpktcnt = 0; \
        (f)->bytecnt = 0; \
        (f)->lastts.tv_sec = 0; \
        (f)->lastts.tv_usec = 0; \
        (f)->flowvar = NULL; \
        (f)->protoctx = NULL; \
        SC_ATOMIC_INIT((f)->use_cnt); \
        (f)->de_state = NULL; \
        (f)->sgh_toserver = NULL; \
        (f)->sgh_toclient = NULL; \
        (f)->aldata = NULL; \
        (f)->alflags = 0; \
        (f)->alproto = 0; \
        (f)->tag_list = NULL; \
    } while (0)

/** \brief macro to recycle a flow before it goes into the spare queue for reuse.
 *
 *  Note that the lnext, lprev, hnext, hprev fields are untouched, those are
 *  managed by the queueing code. Same goes for fb (FlowBucket ptr) field.
 */
#define FLOW_RECYCLE(f) do { \
        (f)->sp = 0; \
        (f)->dp = 0; \
        (f)->flags = 0; \
        (f)->todstpktcnt = 0; \
        (f)->tosrcpktcnt = 0; \
        (f)->bytecnt = 0; \
        (f)->lastts.tv_sec = 0; \
        (f)->lastts.tv_usec = 0; \
        GenericVarFree((f)->flowvar); \
        (f)->flowvar = NULL; \
        (f)->protoctx = NULL; \
        SC_ATOMIC_RESET((f)->use_cnt); \
        if ((f)->de_state != NULL) { \
            DetectEngineStateReset((f)->de_state); \
        } \
        (f)->sgh_toserver = NULL; \
        (f)->sgh_toclient = NULL; \
        AppLayerParserCleanupState(f); \
        FlowL7DataPtrFree(f); \
        if ((f)->aldata != NULL) { \
            SCFree((f)->aldata); \
            (f)->aldata = NULL; \
        } \
        (f)->alflags = 0; \
        (f)->alproto = 0; \
        DetectTagDataListFree((f)->tag_list); \
        (f)->tag_list = NULL; \
    } while(0)

#define FLOW_DESTROY(f) do { \
        SCMutexDestroy(&(f)->m); \
        SCMutexDestroy(&(f)->de_state_m); \
        GenericVarFree((f)->flowvar); \
        (f)->flowvar = NULL; \
        (f)->protoctx = NULL; \
        SC_ATOMIC_DESTROY((f)->use_cnt); \
        if ((f)->de_state != NULL) { \
            DetectEngineStateFree((f)->de_state); \
        } \
        (f)->de_state = NULL; \
        AppLayerParserCleanupState(f); \
        FlowL7DataPtrFree(f); \
        if ((f)->aldata != NULL) { \
            SCFree((f)->aldata); \
            (f)->aldata = NULL; \
        } \
        (f)->alflags = 0; \
        (f)->alproto = 0; \
        DetectTagDataListFree((f)->tag_list); \
        (f)->tag_list = NULL; \
    } while(0)

Flow *FlowAlloc(void);
Flow *FlowAllocDirect(void);
void FlowFree(Flow *);
uint8_t FlowGetProtoMapping(uint8_t);
void FlowInit(Flow *, Packet *);

#endif /* __FLOW_UTIL_H__ */

