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

#include "util-interval-tree.h"
#include "util-validate.h"
#include "detect-engine-siggroup.h"
#include "detect-engine-port.h"

static int PICompare(SCIntervalNode *a, SCIntervalNode *b)
{
    if (a->port > b->port) {
        if (a->port2 > b->max) {
            b->max = a->port2;
        }
        SCReturnInt(1);
    }
    SCReturnInt(-1);
}

IRB_GENERATE(PI, SCIntervalNode, irb, PICompare);

SCIntervalTree *SCIntervalTreeInit(void)
{
    SCIntervalTree *it = SCCalloc(1, sizeof(SCIntervalTree));
    if (it == NULL) {
        return NULL;
    }

    return it;
}

static void SCIntervalNodeFree(DetectEngineCtx *de_ctx, SCIntervalTree *it)
{
    SCIntervalNode *node = NULL, *safe = NULL;
    IRB_FOREACH_SAFE(node, PI, &it->tree, safe)
    {
        SigGroupHeadFree(de_ctx, node->sh);
        PI_IRB_REMOVE(&it->tree, node);
        SCFree(node);
    }
    it->head = NULL;
}

void SCIntervalTreeFree(DetectEngineCtx *de_ctx, SCIntervalTree *it)
{
    if (it) {
        SCIntervalNodeFree(de_ctx, it);
        SCFree(it);
    }
}

#if 1
int COUNT = 20;
void printIT(SCIntervalNode *node, int space)
{
    // Base case
    if (node == NULL)
        return;

    // Increase distance between levels
    space += COUNT;

    // Process right child first
    printIT(IRB_RIGHT(node, irb), space);

    // Print current node after space
    // count
    printf("\n\n");
    for (int i = COUNT; i < space; i++)
        printf(" ");
    printf("[%d, %d]: %d; p = %d; max = %d\n", node->port, node->port2, IRB_COLOR(node, irb),
            IRB_PARENT(node, irb) ? IRB_PARENT(node, irb)->port : 0, node->max);

    // Process left child
    printIT(IRB_LEFT(node, irb), space);
}
#endif

int PIInsertPort(DetectEngineCtx *de_ctx, SCIntervalTree *it, struct PI *head, DetectPort *p)
{
    DEBUG_VALIDATE_BUG_ON(p->port > p->port2);

    SCIntervalNode *pi = SCCalloc(1, sizeof(*pi));
    if (pi == NULL) {
        return -1;
    }
    pi->port = p->port;
    pi->port2 = p->port2;
    pi->flags = p->flags;
    // STODO see if the cleanup of these SGHs will be done automatically
    SigGroupHeadCopySigs(de_ctx, p->sh, &pi->sh);
    if (PI_IRB_INSERT(&it->tree, pi) != NULL) {
        SCLogNotice("Node wasn't added to the tree: port: %d, port2: %d", pi->port, pi->port2);
        SCFree(pi);
        return SC_EINVAL;
    }
#if 0
    SCIntervalNode *root = IRB_ROOT(&it->tree);
    SCLogNotice("Inserted [%d, %d]; %d, ROOT: [%d, %d]; %d", pi->port, pi->port2,
            IRB_COLOR(pi, irb), root->port, root->port2, IRB_COLOR(root, irb));
    printIT(IRB_ROOT(&it->tree), 0);
#endif
    return SC_OK;
}

static uint16_t cnt_overlaps = 0;

static bool IsOverlap(uint16_t port, uint16_t port2, SCIntervalNode *ptr)
{
    if ((port <= ptr->port2) && (ptr->port < port2)) {
        SCLogNotice("Found overlap with [%d, %d]", ptr->port, ptr->port2);
        cnt_overlaps++;
        return true;
    }
    SCLogDebug("No overlap found for [%d, %d) w [%d, %d]", port, port2, ptr->port, ptr->port2);
    return false;
}

static void FindOverlaps(DetectEngineCtx *de_ctx, uint16_t port, uint16_t port2, SCIntervalNode *ptr, DetectPort **list)
{
    SCIntervalNode *prev_ptr = NULL;
    bool is_overlap = false;
    DetectPort *new_port = NULL;
    while (ptr != prev_ptr) {
        prev_ptr = ptr;
        is_overlap = IsOverlap(port, port2, ptr);
        if (is_overlap && (cnt_overlaps == 1)) {
            // Allocate memory for port obj
            new_port = DetectPortInit();
            if (new_port == NULL) {
                goto error;
            }
            new_port->port = port;
            new_port->port2 = port2 - 1; // As we're checking against right open interval
            SigGroupHeadCopySigs(de_ctx, ptr->sh, &new_port->sh);
            if (*list == NULL) {
                *list = new_port;
                (*list)->last = new_port;
            } else {
                // STODO last is good to have as the list is already sorted
                // but figure out how to ensure the linked list is correctly set up
                // such that the regular traversal works as well
                (*list)->last->next = new_port;
                (*list)->last = new_port;
            }
        } else if (new_port != NULL && is_overlap && cnt_overlaps > 1) {
            SigGroupHeadCopySigs(de_ctx, ptr->sh, &new_port->sh);
        }
        SCIntervalNode *node = IRB_LEFT(ptr, irb);
        if ((node != NULL) && (node->max >= port)) {
            ptr = node;
        } else {
            node = IRB_RIGHT(ptr, irb);
            if ((node != NULL) && (ptr->port < port2) && (node->max >= port)) {
                ptr = node;
            }
        }
    }
    cnt_overlaps = 0;
    return;
error:
    if (new_port != NULL)
        DetectPortFree(de_ctx, new_port);
    return;
}

void PISearchOverlappingPortRanges(DetectEngineCtx *de_ctx,
        uint16_t port, uint16_t port2, struct PI *head, DetectPort **list)
{
    SCIntervalNode *ptr = IRB_ROOT(head);
    SCLogNotice("Finding overlaps for the range [%d, %d)", port, port2);
    FindOverlaps(de_ctx, port, port2, ptr, &*list);
}
