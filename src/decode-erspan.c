/* Copyright (C) 2020-2021 Open Information Security Foundation
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
 * Decodes ERSPAN Types I and II
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-erspan.h"

#include "util-validate.h"
#include "util-unittest.h"
#include "util-debug.h"

/**
 * \brief Functions to decode ERSPAN Type I and II packets
 */

/*
 * \brief ERSPAN Type I was configurable in 5.0.x but is no longer configurable.
 *
 * Issue a warning if a configuration setting is found.
 */
void DecodeERSPANConfig(void)
{
    int enabled = 0;
    if (ConfGetBool("decoder.erspan.typeI.enabled", &enabled) == 1) {
        SCLogWarning(SC_WARN_ERSPAN_CONFIG,
                     "ERSPAN Type I is no longer configurable and it is always"
                     " enabled; ignoring configuration setting.");
    }
}

/**
 * \brief ERSPAN Type I
 */
int DecodeERSPANTypeI(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                      const uint8_t *pkt, uint32_t len)
{
    StatsIncr(tv, dtv->counter_erspan);

    return DecodeEthernet(tv, dtv, p, pkt, len);
}

/**
 * \brief ERSPAN Type II
 */
int DecodeERSPAN(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    StatsIncr(tv, dtv->counter_erspan);

    if (len < sizeof(ErspanHdr)) {
        ENGINE_SET_EVENT(p,ERSPAN_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }
    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    const ErspanHdr *ehdr = (const ErspanHdr *)pkt;
    uint16_t version = SCNtohs(ehdr->ver_vlan) >> 12;
    uint16_t vlan_id = SCNtohs(ehdr->ver_vlan) & 0x0fff;

    SCLogDebug("ERSPAN: version %u vlan %u", version, vlan_id);

    /* only v1 is tested at this time */
    if (version != 1) {
        ENGINE_SET_EVENT(p,ERSPAN_UNSUPPORTED_VERSION);
        return TM_ECODE_FAILED;
    }

    if (vlan_id > 0) {
        if (p->vlan_idx > VLAN_MAX_LAYER_IDX) {
            ENGINE_SET_EVENT(p,ERSPAN_TOO_MANY_VLAN_LAYERS);
            return TM_ECODE_FAILED;
        }
        p->vlan_id[p->vlan_idx] = vlan_id;
        p->vlan_idx++;
    }

    return DecodeEthernet(tv, dtv, p, pkt + sizeof(ErspanHdr), len - sizeof(ErspanHdr));
}

/**
 * @}
 */
