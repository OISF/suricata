/* Copyright (C) 2016 Open Information Security Foundation
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
 * \author Endace Technology Limited, Jason Ish <jason.ish@endace.com>
 *
 * Decoder for Cisco HDLC.
 */

#include "suricata-common.h"
#include "decode-chdlc.h"
#include "decode-ethernet.h"

int DecodeCHDLC(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
    uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    if (unlikely(len < sizeof(CHDLCHdr))) {
        ENGINE_SET_INVALID_EVENT(p, CHDLC_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    p->chdlch = (CHDLCHdr *)pkt;
    if (unlikely(p->chdlch == NULL)) {
        return TM_ECODE_FAILED;
    }

    int offset = sizeof(CHDLCHdr);

    /* Switch on the protocol field, which contains the same values as
     * ethertypes in ethernet. */
    switch (ntohs(p->chdlch->protocol)) {
        case ETHERNET_TYPE_IP:
            DecodeIPV4(tv, dtv, p, pkt + offset, len - offset, pq);
            break;
        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(tv, dtv, p, pkt + offset, len - offset, pq);
            break;
        default:
            SCLogNotice("Unsupport CHDLC protocol: %d", p->chdlch->protocol);
            break;
    }

    return TM_ECODE_OK;
}

/**
 * @}
 */
