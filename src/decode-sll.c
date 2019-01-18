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

int DecodeSll(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint32_t len, PacketQueue *pq)
{
    StatsIncr(tv, dtv->counter_sll);

    if (unlikely(len < SLL_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, SLL_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    SllHdr *sllh = (SllHdr *)pkt;
    if (unlikely(sllh == NULL))
        return TM_ECODE_FAILED;

    SCLogDebug("p %p pkt %p sll_protocol %04x", p, pkt, SCNtohs(sllh->sll_protocol));

    switch (SCNtohs(sllh->sll_protocol)) {
        case ETHERNET_TYPE_IP:
            if (unlikely(len > SLL_HEADER_LEN + USHRT_MAX)) {
                return TM_ECODE_FAILED;
            }
            DecodeIPV4(tv, dtv, p, pkt + SLL_HEADER_LEN,
                       len - SLL_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_IPV6:
            if (unlikely(len > SLL_HEADER_LEN + USHRT_MAX)) {
                return TM_ECODE_FAILED;
            }
            DecodeIPV6(tv, dtv, p, pkt + SLL_HEADER_LEN,
                       len - SLL_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_VLAN:
            DecodeVLAN(tv, dtv, p, pkt + SLL_HEADER_LEN,
                                 len - SLL_HEADER_LEN, pq);
            break;
        default:
            SCLogDebug("p %p pkt %p sll type %04x not supported", p,
                       pkt, SCNtohs(sllh->sll_protocol));
    }

    return TM_ECODE_OK;
}
/**
 * @}
 */
