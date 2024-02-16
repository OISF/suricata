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

/**
 *  \brief Function to compare two interval nodes. This defines the order
 *          of insertion of a node in the interval tree.
 *
 *  \param a First node to compare
 *  \param b Second node to compare
 *
 *  \return 1 if low of node a is bigger, -1 otherwise
 */
static int PICompareAndUpdate(const SCIntervalNode *a, SCIntervalNode *b)
{
    SCLogDebug("a: [%u:%u, max %u] b: [%u:%u, max %u]", a->port, a->port2, a->max, b->port,
            b->port2, b->max);

    if (a->port >= b->port) {
        if (a->port2 > b->max) {
            b->max = a->port2;
            SCLogDebug("a: [%u:%u, max %u] b: [%u:%u, max %u] MAX UPDATED", a->port, a->port2,
                    a->max, b->port, b->port2, b->max);
        }
        SCLogDebug("a: [%u:%u, max %u] b: [%u:%u, max %u] => 1", a->port, a->port2, a->max, b->port,
                b->port2, b->max);
        SCReturnInt(1);
    }
    SCLogDebug("a: [%u:%u, max %u] b: [%u:%u, max %u] => -1", a->port, a->port2, a->max, b->port,
            b->port2, b->max);
    SCReturnInt(-1);
}

IRB_GENERATE(PI, SCIntervalNode, irb, PICompareAndUpdate);

/**
 * \brief Function to initialize the interval tree.
 *
 * \return Pointer to the newly created interval tree
 */
SCIntervalTree *SCIntervalTreeInit(void)
{
    SCIntervalTree *it = SCCalloc(1, sizeof(SCIntervalTree));
    if (it == NULL) {
        return NULL;
    }

    return it;
}

/**
 * \brief Helper function to free a given node in the interval tree.
 *
 * \param de_ctx Detection Engine Context
 * \param it Pointer to the interval tree
 */
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

/**
 * \brief Function to free an entire interval tree.
 *
 * \param de_ctx Detection Engine Context
 * \param it Pointer to the interval tree
 */
void SCIntervalTreeFree(DetectEngineCtx *de_ctx, SCIntervalTree *it)
{
    if (it) {
        SCIntervalNodeFree(de_ctx, it);
        SCFree(it);
    }
}

/**
 * \brief Function to insert a node in the interval tree.
 *
 * \param de_ctx Detection Engine Context
 * \param it Pointer to the interval tree
 * \param head Pointer to the head of the tree named PI
 * \param p Pointer to a DetectPort object
 *
 * \return SC_OK if the node was inserted successfully, SC_EINVAL otherwise
 */
int PIInsertPort(DetectEngineCtx *de_ctx, SCIntervalTree *it, struct PI *head, const DetectPort *p)
{
    DEBUG_VALIDATE_BUG_ON(p->port > p->port2);

    SCIntervalNode *pi = SCCalloc(1, sizeof(*pi));
    if (pi == NULL) {
        return SC_EINVAL;
    }

    pi->port = p->port;
    pi->port2 = p->port2;
    pi->flags = p->flags;
    SigGroupHeadCopySigs(de_ctx, p->sh, &pi->sh);

    if (PI_IRB_INSERT(&it->tree, pi) != NULL) {
        SCLogDebug("Node wasn't added to the tree: port: %d, port2: %d", pi->port, pi->port2);
        SCFree(pi);
        return SC_EINVAL;
    }
    return SC_OK;
}

/**
 * \brief Function to check if a port range overlaps with a given set of ports
 *
 * \param port Given low port
 * \param port2 Given high port
 * \param ptr Pointer to the node in the tree to be checked against
 *
 * \return true if an overlaps was found, false otherwise
 */
static bool IsOverlap(const uint16_t port, const uint16_t port2, const SCIntervalNode *ptr)
{
    if (port <= ptr->port && port2 > ptr->port) {
        SCLogDebug("range [%u:%u] overlaps tree range [%u:%u]", port, port2, ptr->port, ptr->port2);
        return true;
    } else if (port > ptr->port && port2 <= ptr->port2) {
        SCLogDebug("range [%u:%u] overlaps tree range [%u:%u]", port, port2, ptr->port, ptr->port2);
        return true;
    } else if (port < ptr->port2 && port2 > ptr->port2) {
        SCLogDebug("range [%u:%u] overlaps tree range [%u:%u]", port, port2, ptr->port, ptr->port2);
        return true;
    } else if (port == ptr->port && port2 == ptr->port2) {
        SCLogDebug("range [%u:%u] overlaps tree range [%u:%u]", port, port2, ptr->port, ptr->port2);
        return true;
    }

#if 0
    if ((port < ptr->port2) && (ptr->port < port2)) {
        SCLogDebug("Found overlap with [%d, %d] vs [%u:%u]", ptr->port, ptr->port2, port, port2);
        return true;
    }
#endif
    SCLogDebug("No overlap found for [%d, %d] w [%d, %d]", port, port2, ptr->port, ptr->port2);
    return false;
}

void PrintSigGroupHeadSigs(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
void PrintSigGroupHeadSigs(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    for (uint32_t sig = 0; sig < sgh->init->max_sig_id + 1; sig++) {
        if (sgh->init->sig_array[sig / 8] & (1 << (sig % 8))) {
            SCLogDebug("sig %u enabled", de_ctx->sig_array[sig]->id);
        }
    }
}

void printIT_SigGroupHeadSigs(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
void printIT_SigGroupHeadSigs(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    for (uint32_t sig = 0; sig < sgh->init->max_sig_id + 1; sig++) {
        if (sgh->init->sig_array[sig / 8] & (1 << (sig % 8))) {
            printf(" %u", de_ctx->sig_array[sig]->id);
        }
    }
}

int COUNT = 4;
void printIT(DetectEngineCtx *de_ctx, SCIntervalNode *node, int space,
        void (*Print)(DetectEngineCtx *, SigGroupHead *));
void printIT(DetectEngineCtx *de_ctx, SCIntervalNode *node, int space,
        void (*Print)(DetectEngineCtx *, SigGroupHead *))
{
    // Base case
    if (node == NULL)
        return;

    // Increase distance between levels
    space += COUNT;

    // Process right child first
    printIT(de_ctx, IRB_RIGHT(node, irb), space, Print);

    // Print current node after space
    // count
    printf("\n\n");
    for (int i = COUNT; i < space; i++)
        printf(" ");
    printf("[%d, %d]: %s; p = %d; max = %d, sids:", node->port, node->port2,
            IRB_COLOR(node, irb) ? "RED" : "BLACK",
            IRB_PARENT(node, irb) ? IRB_PARENT(node, irb)->port : 0, node->max);
    Print(de_ctx, node->sh);
    printf("\n");

    // Process left child
    printIT(de_ctx, IRB_LEFT(node, irb), space, Print);
}

/**
 * \brief Function to find all the overlaps of given ports with the existing
 *        port ranges in the interval tree
 * \param de_ctx Detection Engine Context
 * \param port Given low port
 * \param port2 Given high port
 * \param ptr Pointer to the root of the tree
 * \param list A list of DetectPort objects to be filled
 */
static void FindOverlaps(DetectEngineCtx *de_ctx, uint16_t port, uint16_t port2,
        SCIntervalNode *root, DetectPort **list)
{
    SCLogDebug("\nfind overlaps for [%u:%u]", port, port2);
    SCIntervalNode *ptr = root;
    DetectPort *new_port = NULL;
    int cnt_overlaps = 0;
#if 0
    printIT(de_ctx, root, 1, printIT_SigGroupHeadSigs);
#endif
    SCIntervalNode *stack[100], *current = root;
    memset(&stack, 0, sizeof(stack));
    int stack_depth = 0;
    //            stack[stack_depth++] = current;

    //    SCLogDebug("ROOT! [%u:%u]: current:%p", current->port, current->port2, current);
    while (current || stack_depth) {
        SCLogDebug("stack_depth %d", stack_depth);
        for (int x = 0; x < stack_depth && x < 100 && stack[x] != NULL; x++)
            SCLogDebug("stack[%d]: %p", x, stack[x]);

        while (current != NULL) {
            SCLogDebug("%s! [%u:%u]: current:%p",
                    IRB_PARENT(current, irb) == NULL ? "ROOT" : "LEAF", current->port,
                    current->port2, current);
            if (current->max < port) {
                current = NULL;
                break;
            }

            ptr = current;
            const bool is_overlap = IsOverlap(port, port2, ptr);
            if (is_overlap) {
                cnt_overlaps++;
            }

            if (is_overlap && (cnt_overlaps == 1)) {
                // Allocate memory for port obj only if it's first overlap
                new_port = DetectPortInit();
                if (new_port == NULL) {
                    goto error;
                }

                SCLogDebug("find overlaps for [%u:%u]: creating new_port for [%u:%u]", port, port2,
                        port, port2);
                new_port->port = port;
                new_port->port2 = port2;

                // PrintSigGroupHeadSigs(de_ctx, ptr->sh);
                SigGroupHeadCopySigs(de_ctx, ptr->sh, &new_port->sh);
                // PrintSigGroupHeadSigs(de_ctx, new_port->sh);

                // Since it is guaranteed that the ports received by this stage
                // will be sorted, insert any new ports to the end of the list
                // and avoid walking the entire list
                if (*list == NULL) {
                    *list = new_port;
                    (*list)->last = new_port;
                } else {
                    DEBUG_VALIDATE_BUG_ON(new_port->port < (*list)->last->port);
                    (*list)->last->next = new_port;
                    (*list)->last = new_port;
                }
            } else if (new_port != NULL && is_overlap && cnt_overlaps > 1) {
                SCLogDebug("find overlaps for [%u:%u]: adding sigs to new_port [%u:%u]", port,
                        port2, port, port2);
                // Only copy the relevant SGHs on later overlaps
                // PrintSigGroupHeadSigs(de_ctx, ptr->sh);
                SigGroupHeadCopySigs(de_ctx, ptr->sh, &new_port->sh);
                // PrintSigGroupHeadSigs(de_ctx, new_port->sh);
            }

            stack[stack_depth++] = current;
            current = IRB_LEFT(current, irb);
            if (current != NULL) {
            } else {
                SCLogDebug("LEFT dead end");
            }
        }
        SCLogDebug("stack_depth %d", stack_depth);
        for (int x = 0; x < stack_depth && x < 100 && stack[x] != NULL; x++)
            SCLogDebug("stack[%d]: %p", x, stack[x]);

        if (stack_depth == 0)
            break;

        SCIntervalNode *popped = stack[stack_depth - 1];
        stack_depth--;
        SCLogDebug("popped %p", popped);
        BUG_ON(popped == NULL);
        current = IRB_RIGHT(popped, irb);
    }
#if 0

    SCIntervalNode *prev_ptr = NULL;
    while (ptr && ptr != prev_ptr) {
        SCLogNotice("find overlaps for [%u:%u] => tree node [%u:%u]", port, port2, ptr->port, ptr->port2);
        prev_ptr = ptr;

        const bool is_overlap = IsOverlap(port, port2, ptr);
        if (is_overlap) {
            cnt_overlaps++;
        }

        if (is_overlap && (cnt_overlaps == 1)) {
            // Allocate memory for port obj only if it's first overlap
            new_port = DetectPortInit();
            if (new_port == NULL) {
                goto error;
            }

            SCLogNotice("find overlaps for [%u:%u]: creating new_port for [%u:%u]", port, port2, port, port2);
            new_port->port = port;
            new_port->port2 = port2;

            PrintSigGroupHeadSigs(de_ctx, ptr->sh);
            SigGroupHeadCopySigs(de_ctx, ptr->sh, &new_port->sh);
            PrintSigGroupHeadSigs(de_ctx, new_port->sh);

            // Since it is guaranteed that the ports received by this stage
            // will be sorted, insert any new ports to the end of the list
            // and avoid walking the entire list
            if (*list == NULL) {
                *list = new_port;
                (*list)->last = new_port;
            } else {
                DEBUG_VALIDATE_BUG_ON(new_port->port < (*list)->last->port);
                (*list)->last->next = new_port;
                (*list)->last = new_port;
            }
        } else if (new_port != NULL && is_overlap && cnt_overlaps > 1) {
            SCLogNotice("find overlaps for [%u:%u]: adding sigs to new_port [%u:%u]", port, port2, port, port2);
            // Only copy the relevant SGHs on later overlaps
            PrintSigGroupHeadSigs(de_ctx, ptr->sh);
            SigGroupHeadCopySigs(de_ctx, ptr->sh, &new_port->sh);
            PrintSigGroupHeadSigs(de_ctx, new_port->sh);
        }

        SCIntervalNode *pptr = ptr;
        SCIntervalNode *node = IRB_LEFT(ptr, irb);
        if ((node != NULL) && (node->max >= port)) {
            ptr = node;
            if (ptr)
                SCLogNotice("find overlaps for [%u:%u] => LEFT tree node [%u:%u, max:%u]", port, port2, ptr->port, ptr->port2, ptr->max);
        }

        node = IRB_RIGHT(pptr, irb);
        if (node != NULL && (node->max >= port)) {
            ptr = node;
            if (ptr)
                SCLogNotice("find overlaps for [%u:%u] => RIGHT tree node [%u:%u, max:%u]", port, port2, ptr->port, ptr->port2, ptr->max);
#if 0
            if ((node != NULL) && (ptr->port < port2) && (node->max >= port)) {
                ptr = node;
            }
#endif
        }
    }
    SCLogNotice("find overlaps for [%u:%u] DONE", port, port2);
    return;
#endif
    return;
error:
    if (new_port != NULL)
        DetectPortFree(de_ctx, new_port);
    return;
}

/**
 * \brief Function to find all overlapping port ranges as asked by detection engine
 *        during signature grouping.
 * \param de_ctx Detection Engine Context
 * \param port Given low port
 * \param port2 Given high port
 * \param head Pointer to the head of the tree named PI
 * \param list Pointer to the list of port objects that needs to be filled/updated
 */
void PISearchOverlappingPortRanges(
        DetectEngineCtx *de_ctx, uint16_t port, uint16_t port2, struct PI *head, DetectPort **list)
{
    if (head == NULL) {
        SCLogDebug("Tree head should not be NULL. Nothing to do further.");
        return;
    }
    SCIntervalNode *ptr = IRB_ROOT(head);
    SCLogDebug("Finding overlaps for the range [%d, %d]", port, port2);
    FindOverlaps(de_ctx, port, port2, ptr, list);
}
