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

#include "util-unittest.h"
#include "util-debug.h"

int DecodeARP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    StatsIncr(tv, dtv->counter_arp);

    if (unlikely(len < ARP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ARP_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (unlikely(len > ARP_HEADER_LEN + USHRT_MAX)) {
        return TM_ECODE_FAILED;
    }

    p->arph = (ArpHdr *)pkt;
    if (unlikely(p->arph == NULL))
        return TM_ECODE_FAILED;

    return TM_ECODE_OK;
}
