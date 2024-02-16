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
    if (a->port > b->port) {
        if (a->port2 > b->max) {
            b->max = a->port2;
        }
        SCReturnInt(1);
    }
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

// Global variable to keep track of the number of overlaps
static uint16_t cnt_overlaps = 0;

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
    if ((port <= ptr->port2) && (ptr->port <= port2)) {
        SCLogDebug("Found overlap with [%d, %d]", ptr->port, ptr->port2);
        cnt_overlaps++;
        return true;
    }
    SCLogDebug("No overlap found for [%d, %d] w [%d, %d]", port, port2, ptr->port, ptr->port2);
    return false;
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
        SCIntervalNode *ptr, DetectPort **list)
{
    SCIntervalNode *prev_ptr = NULL;
    bool is_overlap = false;
    DetectPort *new_port = NULL;

    while (ptr != prev_ptr) {
        prev_ptr = ptr;

        is_overlap = IsOverlap(port, port2, ptr);
        if (is_overlap && (cnt_overlaps == 1)) {
            // Allocate memory for port obj only if it's first overlap
            new_port = DetectPortInit();
            if (new_port == NULL) {
                goto error;
            }

            new_port->port = port;
            new_port->port2 = port2;
            SigGroupHeadCopySigs(de_ctx, ptr->sh, &new_port->sh);

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
            // Only copy the relevant SGHs on later overlaps
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
