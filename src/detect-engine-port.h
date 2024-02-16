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

#ifndef __DETECT_PORT_H__
#define __DETECT_PORT_H__

#include "interval-tree.h"
#include "detect.h"

typedef struct SCPortIntervalNode {
    uint16_t port;  /* low port of a port range */
    uint16_t port2; /* high port of a port range */
    uint16_t max;   /* max value of the high port in the subtree rooted at this node */

    struct SigGroupHead_ *sh; /* SGHs corresponding to this port */

    IRB_ENTRY(SCPortIntervalNode) irb; /* parent entry of the interval tree */
} SCPortIntervalNode;

IRB_HEAD(PI, SCPortIntervalNode); /* head of the interval tree */
IRB_PROTOTYPE(PI, SCPortIntervalNode, irb,
        SCPortIntervalCompare); /* prototype definition of the interval tree */

typedef struct SCPortIntervalTree_ {
    struct PI tree;
    SCPortIntervalNode *head;
} SCPortIntervalTree;

SCPortIntervalTree *SCPortIntervalTreeInit(void);
void SCPortIntervalTreeFree(DetectEngineCtx *, SCPortIntervalTree *);
int SCPortIntervalInsert(DetectEngineCtx *, SCPortIntervalTree *, const DetectPort *);
void SCPortIntervalFindOverlappingRanges(
        DetectEngineCtx *, const uint16_t, const uint16_t, const struct PI *, DetectPort **);

/* prototypes */
int DetectPortParse(const DetectEngineCtx *, DetectPort **head, const char *str);

DetectPort *DetectPortCopySingle(DetectEngineCtx *, DetectPort *);
int DetectPortInsert(DetectEngineCtx *,DetectPort **, DetectPort *);
void DetectPortCleanupList (const DetectEngineCtx *de_ctx, DetectPort *head);

DetectPort *DetectPortLookupGroup(DetectPort *dp, uint16_t port);

bool DetectPortListsAreEqual(DetectPort *list1, DetectPort *list2);

void DetectPortPrint(DetectPort *);
void DetectPortPrintList(DetectPort *head);
int DetectPortCmp(DetectPort *, DetectPort *);
DetectPort *DetectPortInit(void);
void DetectPortFree(const DetectEngineCtx *de_ctx, DetectPort *);

int DetectPortTestConfVars(void);

DetectPort *DetectPortHashLookup(DetectEngineCtx *de_ctx, DetectPort *dp);
void DetectPortHashFree(DetectEngineCtx *de_ctx);
int DetectPortHashAdd(DetectEngineCtx *de_ctx, DetectPort *dp);
int DetectPortHashInit(DetectEngineCtx *de_ctx);

#ifdef UNITTESTS
void DetectPortTests(void);
#endif

#endif /* __DETECT_PORT_H__ */

