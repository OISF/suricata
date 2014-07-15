/* Copyright (C) 2014 Open Information Security Foundation
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
 * \author Jason Ish <jason.ish@emulex.com>
 *
 * MPLS decoder.
 */

#include "suricata-common.h"
#include "decode.h"

#define MPLS_HEADER_LEN    4
#define MPLS_BOTTOM(shim)  ((ntohl(shim) >> 8) & 0x1)
#define MPLS_PROTO_IPV4    4
#define MPLS_PROTO_IPV6    6

int DecodeMPLS(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt,
    uint16_t len, PacketQueue *pq)
{
    if (len < MPLS_HEADER_LEN) {
        return TM_ECODE_FAILED;
    }

    uint32_t shim;
    do {
        shim = *(uint32_t *)pkt;
        pkt += MPLS_HEADER_LEN;
        len -= MPLS_HEADER_LEN;
    } while (MPLS_BOTTOM(shim) == 0);

    /* Best guess at inner packet. */
    uint8_t ip_ver = pkt[0] >> 4;

    switch (ip_ver) {
    case MPLS_PROTO_IPV4:
        return DecodeIPV4(tv, dtv, p, pkt, len, pq);
        break;
    case MPLS_PROTO_IPV6:
        return DecodeIPV6(tv, dtv, p, pkt, len, pq);
        break;
    default:
        break;
    }

    return TM_ECODE_FAILED;
}
