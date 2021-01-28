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
 * \ingroup decode
 *
 * @{
 */


/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Decodes Sll
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-sll.h"
#include "decode-events.h"
#include "util-debug.h"

int DecodeSll(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint32_t len)
{
    StatsIncr(tv, dtv->counter_sll);

    if (unlikely(len < SLL_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, SLL_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }
    PACKET_INCREASE_CHECK_LAYERS(p);

    SllHdr *sllh = (SllHdr *)pkt;
    if (unlikely(sllh == NULL))
        return TM_ECODE_FAILED;

    SCLogDebug("p %p pkt %p sll_protocol %04x", p, pkt, SCNtohs(sllh->sll_protocol));

    DecodeNetworkLayer(tv, dtv, SCNtohs(sllh->sll_protocol), p,
            pkt + SLL_HEADER_LEN, len - SLL_HEADER_LEN);

    return TM_ECODE_OK;
}
/**
 * @}
 */
