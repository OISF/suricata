/* Copyright (C) 2025 Open Information Security Foundation
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
 * \ingroup decode
 *
 * @{
 */

/**
 * \file
 *
 * \author Jeff Lucovsky <jeff.lucovsky@corelight.com>
 *
 * Decodes Sll2
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-sll2.h"
#include "decode-events.h"

#include "util-validate.h"
#include "util-debug.h"

int DecodeSll2(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    StatsIncr(tv, dtv->counter_sll2);

    if (unlikely(len < SLL2_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, SLL2_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }
    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    Sll2Hdr *sll2h = (Sll2Hdr *)pkt;

    SCLogDebug("p %p pkt %p sll2_protocol %04x", p, pkt, SCNtohs(sll2h->sll_protocol));

    DecodeNetworkLayer(
            tv, dtv, SCNtohs(sll2h->sll_protocol), p, pkt + SLL2_HEADER_LEN, len - SLL2_HEADER_LEN);

    return TM_ECODE_OK;
}
/**
 * @}
 */
