/* Copyright (C) 2012 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * Decode Teredo Tunneling protocol
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-ipv6.h"
#include "util-debug.h"

/**
 * \brief Function to decode Teredo packets
 *
 * \retval 0 if packet is not a Teredo packet, 1 if it is
 */
int DecodeTeredo(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{

    unsigned char *start = p->payload;

    /* Is this packet to short to contain an IPv6 packet ? */
    if (UDP_GET_LEN(p) < UDP_HEADER_LEN + IPV6_HEADER_LEN)
        return 0;

    /* Teredo encapsulate IPv6 in UDP and can add some custom message
     * part before the IPv6 packet. Here we iter on the messages to get
     * on the IPv6 packet. */
    while (start[0] == 0x0) {
        switch (p->payload[1]) {
            /* origin indication: compatible with tunnel */
            case 0x0:
                if (UDP_GET_LEN(p) >= 8 + UDP_HEADER_LEN + IPV6_HEADER_LEN)
                    start = p->payload + 8;
                else
                    return 0;
                break;
            /* authentication: negotiation not real tunnel */
            case 0x1:
                return 0;
            /* this case is not possible in Teredo: not that protocol */
            default:
                return 0;
        }
    }

    if (IP_GET_RAW_VER(start) == 6) {
        IPV6Hdr *thdr = (IPV6Hdr *)start;
        /* This does looks like Teredo protocol, let's pray together */
        if (UDP_GET_LEN(p) ==  UDP_HEADER_LEN + IPV6_HEADER_LEN +
                IPV6_GET_RAW_PLEN(thdr) + (start - p->payload)) {
            if (pq != NULL) {
                /* spawn off tunnel packet */
                Packet *tp = PacketPseudoPktSetup(p, start,
                        IPV4_GET_IPLEN(p) - (start - p->payload),
                        IPPROTO_IPV6);
                if (tp != NULL) {
                    /* send that to the Tunnel decoder */
                    DecodeTunnel(tv, dtv, tp, GET_PKT_DATA(tp),
                            GET_PKT_LEN(tp), pq, IPPROTO_IPV6);

                    /* add the tp to the packet queue. */
                    PacketEnqueue(pq,tp);
                }
                return 1;
            }
        }
        return 0;
    }

    return 0;
}

/**
 * @}
 */
