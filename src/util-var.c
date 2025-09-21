/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 *
 * Generic variable utility functions
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine-threshold.h"

#include "util-var.h"

#include "flow-var.h"
#include "flow-bit.h"
#include "pkt-var.h"
#include "host-bit.h"
#include "ippair-bit.h"
#include "util-validate.h"
#include "util-debug.h"

void XBitFree(XBit *fb)
{
    if (fb == NULL)
        return;

    SCFree(fb);
}

void SCGenericVarFree(GenericVar *gv)
{
    if (gv == NULL)
        return;

    SCLogDebug("gv %p, gv->type %" PRIu32 "", gv, gv->type);
    GenericVar *next_gv = gv->next;

    switch (gv->type) {
        case DETECT_FLOWBITS:
        {
            FlowBit *fb = (FlowBit *)gv;
            // printf("SCGenericVarFree: fb %p, removing\n", fb);
            FlowBitFree(fb);
            break;
        }
        case DETECT_XBITS:
        {
            XBit *fb = (XBit *)gv;
            // printf("SCGenericVarFree: fb %p, removing\n", fb);
            XBitFree(fb);
            break;
        }
        case DETECT_THRESHOLD: {
            FlowThresholdVarFree(gv);
            break;
        }
        case DETECT_FLOWVAR:
        {
            FlowVar *fv = (FlowVar *)gv;
            FlowVarFree(fv);
            break;
        }
        case DETECT_PKTVAR:
        {
            PktVar *pv = (PktVar *)gv;
            PktVarFree(pv);
            break;
        }
        default:
        {
            SCLogDebug("SCGenericVarFree unknown type %" PRIu32, gv->type);
            DEBUG_VALIDATE_BUG_ON(1);
            break;
        }
    }

    SCGenericVarFree(next_gv);
}

void GenericVarAppend(GenericVar **list, GenericVar *gv)
{
    gv->next = NULL;

    if (*list == NULL) {
        *list = gv;
    } else {
        GenericVar *tgv = *list;
        while(tgv) {
            if (tgv->next == NULL) {
                tgv->next = gv;
                return;
            }

            tgv = tgv->next;
        }
    }
}

void GenericVarRemove(GenericVar **list, GenericVar *gv)
{
    if (*list == NULL)
        return;

    GenericVar *listgv = *list, *prevgv = NULL;
    while (listgv != NULL) {
        if (listgv == gv) {
            if (prevgv == NULL)
                *list = gv->next;
            else
                prevgv->next = gv->next;

            return;
        }

        prevgv = listgv;
        listgv = listgv->next;
    }
}

// Checks if a variable is already in a resolve list and if it's not, adds it.
int AddVariableToResolveList(ResolvedVariablesList *list, const char *var)
{
    ResolvedVariable *p_item;

    if (list == NULL || var == NULL)
        return 0;

    if (var[0] != '$') {
        return 0;
    }

    TAILQ_FOREACH(p_item, list, next) {
        if (!strcmp(p_item->var_name, var)) {
            return -1;
        }
    }

    p_item = SCMalloc(sizeof(ResolvedVariable));

    if (unlikely(p_item == NULL)) {
        return -1;
    }

    strlcpy(p_item->var_name, var, sizeof(p_item->var_name) - 1);
    TAILQ_INSERT_TAIL(list, p_item, next);

    return 0;
}

void CleanVariableResolveList(ResolvedVariablesList *var_list)
{
    if (var_list == NULL) {
        return;
    }

    ResolvedVariable *p_item;

    while ((p_item = TAILQ_FIRST(var_list))) {
        TAILQ_REMOVE(var_list, p_item, next);
        SCFree(p_item);
    }
}
