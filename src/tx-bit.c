/* Copyright (C) 2014-2021 Open Information Security Foundation
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
 * Implements per ippair bits. Actually, not a bit,
 * but called that way because of Snort's flowbits.
 * It's a binary storage.
 *
 * \todo move away from a linked list implementation
 * \todo use different datatypes, such as string, int, etc.
 */

#include "suricata-common.h"
#include "threads.h"
#include "tx-bit.h"
#include "detect.h"
#include "util-var.h"
#include "util-debug.h"
#include "rust.h"

static XBit *TxBitGet(AppLayerTxData *txd, uint32_t idx)
{
    for (GenericVar *gv = txd->txbits; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_XBITS && gv->idx == idx) {
            return (XBit *)gv;
        }
    }

    return NULL;
}

static int TxBitAdd(AppLayerTxData *txd, uint32_t idx)
{
    XBit *xb = TxBitGet(txd, idx);
    if (xb == NULL) {
        xb = SCMalloc(sizeof(XBit));
        if (unlikely(xb == NULL))
            return -1;

        xb->type = DETECT_XBITS;
        xb->idx = idx;
        xb->next = NULL;
        SCTIME_INIT(xb->expire); // not used by tx bits

        GenericVarAppend(&txd->txbits, (GenericVar *)xb);
        return 1;
    }
    return 0;
}

int TxBitIsset(AppLayerTxData *txd, uint32_t idx)
{
    XBit *xb = TxBitGet(txd, idx);
    if (xb != NULL) {
        SCLogDebug("isset %u return 1", idx);
        return 1;
    }
    SCLogDebug("isset %u r 0", idx);
    return 0;
}

int TxBitSet(AppLayerTxData *txd, uint32_t idx)
{
    int r = TxBitAdd(txd, idx);
    SCLogDebug("set %u r %d", idx, r);
    return (r == 1);
}
