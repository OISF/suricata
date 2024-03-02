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
 *
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-arp.h"
#include "decode-events.h"

int DecodeARP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    StatsIncr(tv, dtv->counter_arp);

    if (unlikely(len < ARP_HEADER_MIN_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ARP_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    const ARPHdr *arph = PacketSetARP(p, pkt);
    if (unlikely(arph == NULL))
        return TM_ECODE_FAILED;

    if (SCNtohs(arph->hw_type) != ARP_HW_TYPE_ETHERNET) {
        ENGINE_SET_INVALID_EVENT(p, ARP_UNSUPPORTED_HARDWARE);
        return TM_ECODE_FAILED;
    }

    if (SCNtohs(arph->proto_type) != ETHERNET_TYPE_IP) {
        ENGINE_SET_INVALID_EVENT(p, ARP_UNSUPPORTED_PROTOCOL);
        return TM_ECODE_FAILED;
    }

    if (unlikely(len != ARP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ARP_UNSUPPORTED_PKT);
        return TM_ECODE_FAILED;
    }

    if (arph->hw_size != ARP_HW_SIZE) {
        ENGINE_SET_INVALID_EVENT(p, ARP_INVALID_HARDWARE_SIZE);
        return TM_ECODE_FAILED;
    }

    if (arph->proto_size != ARP_PROTO_SIZE) {
        ENGINE_SET_INVALID_EVENT(p, ARP_INVALID_PROTOCOL_SIZE);
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}
