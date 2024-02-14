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
    uint16_t port;
    uint16_t port2;
    uint16_t max;
    uint8_t flags;

    struct SigGroupHead_ *sh;

    IRB_ENTRY(SCIntervalNode) irb;
} __attribute__((__packed__)) SCIntervalNode;

IRB_HEAD(PI, SCIntervalNode);
IRB_PROTOTYPE(PI, SCIntervalNode, irb, SCIntervalCompare);

typedef struct SCIntervalTree_ {
    struct PI tree;
    SCIntervalNode *head;
} SCIntervalTree;

SCIntervalTree *SCIntervalTreeInit(void);
void SCIntervalNodeFree(SCIntervalTree *);
void SCIntervalTreeFree(SCIntervalTree *);
int PIInsertPort(SCIntervalTree *, struct PI *, DetectPort *);
void PISearchOverlappingPortRanges(DetectEngineCtx *, uint16_t, uint16_t, struct PI *, DetectPort **);
#if 1
void printIT(struct SCIntervalNode *node, int space);
#endif
#endif /* __UTIL_INTERVAL_TREE_H__ */
