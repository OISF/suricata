/* Copyright (C) 2015 Open Information Security Foundation
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
 * Decodes ERSPAN
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-erspan.h"

#include "util-unittest.h"
#include "util-debug.h"

/**
 * \brief Function to decode ERSPAN packets
 */

int DecodeERSPAN(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    StatsIncr(tv, dtv->counter_erspan);

    if (len < sizeof(ErspanHdr)) {
        ENGINE_SET_EVENT(p,ERSPAN_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    const ErspanHdr *ehdr = (const ErspanHdr *)pkt;
    uint16_t version = ntohs(ehdr->ver_vlan) >> 12;
    uint16_t vlan_id = ntohs(ehdr->ver_vlan) & 0x0fff;

    SCLogDebug("ERSPAN: version %u vlan %u", version, vlan_id);

    /* only v1 is tested at this time */
    if (version != 1) {
        ENGINE_SET_EVENT(p,ERSPAN_UNSUPPORTED_VERSION);
        return TM_ECODE_FAILED;
    }

    if (vlan_id > 0 && dtv->vlan_disabled == 0) {
        if (p->vlan_idx >= 2) {
            ENGINE_SET_EVENT(p,ERSPAN_TOO_MANY_VLAN_LAYERS);
            return TM_ECODE_FAILED;
        }
        p->vlan_id[p->vlan_idx] = vlan_id;
        p->vlan_idx++;
    }

    return DecodeEthernet(tv, dtv, p, pkt + sizeof(ErspanHdr), len - sizeof(ErspanHdr), pq);
}

/**
 * @}
 */
