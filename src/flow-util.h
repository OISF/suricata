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

/* only clear the parts that won't be overwritten
 * in FlowInit anyway */
#define CLEAR_FLOW(f) { \
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
    (f)->use_cnt = 0; \
    DetectEngineStateFree((f)->de_state); \
    (f)->de_state = NULL; \
}

Flow *FlowAlloc(void);
void FlowFree(Flow *);
uint8_t FlowGetProtoMapping(uint8_t);
void FlowInit(Flow *, Packet *);

#endif /* __FLOW_UTIL_H__ */

