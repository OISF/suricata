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

void SCIntervalNodeFree(SCIntervalTree *it)
{
    SCIntervalNode *node = NULL, *safe = NULL;
    IRB_FOREACH_SAFE(node, PI, &it->tree, safe)
    {
        PI_IRB_REMOVE(&it->tree, node);
        SCFree(node);
    }
    it->head = NULL;
}

void SCIntervalTreeFree(SCIntervalTree *it)
{
    if (it) {
        SCIntervalNodeFree(it);
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

int PIInsertPort(SCIntervalTree *it, struct PI *head, DetectPort *p)
{
    DEBUG_VALIDATE_BUG_ON(p->port > p->port2);

    SCIntervalNode *pi = SCCalloc(1, sizeof(*pi));
    if (pi == NULL) {
        return -1;
    }
    pi->port = p->port;
    pi->port2 = p->port2;
    pi->flags = p->flags;
    //    pi->sh = p->sh; // STODO this is likely wrong, we should prob copy the sgh
    // update indeed wrong, ASAN flagged it
    if (PI_IRB_INSERT(&it->tree, pi) != NULL) {
        SCLogNotice("Node wasn't added to the tree: port: %d, port2: %d", pi->port, pi->port2);
        SCFree(pi);
        return SC_EINVAL;
    }
    SCIntervalNode *root = IRB_ROOT(&it->tree);
    SCLogNotice("Inserted [%d, %d]; %d, ROOT: [%d, %d]; %d", pi->port, pi->port2,
            IRB_COLOR(pi, irb), root->port, root->port2, IRB_COLOR(root, irb));
    printIT(IRB_ROOT(&it->tree), 0);
    return SC_OK;
}

bool PISearchOverlappingPortRanges(
        uint16_t port, uint16_t port2, struct PI *head, SigGroupHead **sgh_array)
{
    SCIntervalNode *ptr = IRB_ROOT(head);
    SCIntervalNode *tmp = NULL;
    bool overlaps = false;
    SCLogNotice("Finding overlaps for the range [%d, %d]", port, port2);
    // Only finds single overlap for now, needs to be changed and accomodate SGHs
    while ((ptr != NULL) && (port2 <= ptr->max)) {
        tmp = ptr;
        SCLogNotice("comparing with port: %d, port2: %d", ptr->port, ptr->port2);
        if ((port <= ptr->port2) && (ptr->port <= port2)) {
            overlaps = true;
            SCLogNotice("Found overlap with [%d, %d]", tmp->port, tmp->port2);
            break;
        }
        SCIntervalNode *node = IRB_LEFT(ptr, irb);
        if ((node != NULL) && (node->max >= port)) {
            ptr = node;
        } else {
            ptr = IRB_RIGHT(ptr, irb);
        }
    }
    return overlaps;
}
