/* Copyright (C) 2024 Open Information Security Foundation
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
 * \author Shivani Bhardwaj <shivani@oisf.net>
 */

#ifndef __UTIL_INTERVAL_TREE_H__
#define __UTIL_INTERVAL_TREE_H__

#include "interval-tree.h"
#include "detect.h"

typedef struct SCIntervalNode {
    uint16_t port;  /* low port of a port range */
    uint16_t port2; /* high port of a port range */
    uint16_t max;   /* max value of the high port in the subtree rooted at this node */
    uint8_t flags;  /* port specific flags */

    struct SigGroupHead_ *sh; /* SGHs corresponding to this port */

    IRB_ENTRY(SCIntervalNode) irb; /* parent entry of the interval tree */
} SCIntervalNode;

IRB_HEAD(PI, SCIntervalNode); /* head of the interval tree */
IRB_PROTOTYPE(
        PI, SCIntervalNode, irb, SCIntervalCompare); /* prototype definition of the interval tree */

typedef struct SCIntervalTree_ {
    struct PI tree;
    SCIntervalNode *head;
} SCIntervalTree;

SCIntervalTree *SCIntervalTreeInit(void);
void SCIntervalTreeFree(DetectEngineCtx *, SCIntervalTree *);
int PIInsertPort(DetectEngineCtx *, SCIntervalTree *, struct PI *, const DetectPort *);
void PISearchOverlappingPortRanges(
        DetectEngineCtx *, uint16_t, uint16_t, struct PI *, DetectPort **);
#if 0
void printIT(DetectEngineCtx *de_ctx, SCIntervalNode *node, int space,
        void (*Print)(DetectEngineCtx *, SigGroupHead *));
void printIT_SigGroupHeadSigs(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
#endif
#endif /* __UTIL_INTERVAL_TREE_H__ */
