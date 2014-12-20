/* Copyright (C) 2007-2013 Open Information Security Foundation
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

#include "util-var.h"

#include "flow-var.h"
#include "flow-bit.h"
#include "pkt-var.h"
#include "host-bit.h"
#include "ippair-bit.h"

#include "util-debug.h"

static void XBitFree(XBit *fb)
{
    if (fb == NULL)
        return;

    SCFree(fb);
}

void GenericVarFree(GenericVar *gv)
{
    if (gv == NULL)
        return;

    SCLogDebug("gv %p, gv->type %" PRIu32 "", gv, gv->type);
    GenericVar *next_gv = gv->next;

    switch (gv->type) {
        case DETECT_FLOWBITS:
        {
            FlowBit *fb = (FlowBit *)gv;
            //printf("GenericVarFree: fb %p, removing\n", fb);
            FlowBitFree(fb);
            break;
        }
        case DETECT_XBITS:
        {
            XBit *fb = (XBit *)gv;
            //printf("GenericVarFree: fb %p, removing\n", fb);
            XBitFree(fb);
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
            printf("ERROR: GenericVarFree unknown type %" PRIu32 "\n", gv->type);
            break;
        }
    }

    GenericVarFree(next_gv);
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
