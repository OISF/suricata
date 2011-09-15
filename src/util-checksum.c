/* Copyright (C) 2011 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * Util functions for checskum.
 */

#include "suricata-common.h"

int ReCalculateChecksum(Packet *p)
{
    if (PKT_IS_IPV4(p)) {
        if (PKT_IS_TCP(p)) {
            /* TCP */
            p->tcph->th_sum = 0;
            p->tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p->ip4h->ip_src),
                    (uint16_t *)p->tcph, (p->payload_len + TCP_GET_HLEN(p)));
        } else if (PKT_IS_UDP(p)) {
            p->udph->uh_sum = 0;
            p->udph->uh_sum = UDPV4CalculateChecksum((uint16_t *)&(p->ip4h->ip_src),
                    (uint16_t *)p->udph, (p->payload_len + UDP_HEADER_LEN));
        }
        /* IPV4 */
        p->ip4h->ip_csum = 0;
        p->ip4h->ip_csum = IPV4CalculateChecksum((uint16_t *)p->ip4h,
                IPV4_GET_RAW_HLEN(p->ip4h));
    } else if (PKT_IS_IPV6(p)) {
        /* just TCP for IPV6 */
        if (PKT_IS_TCP(p)) {
            p->tcph->th_sum = 0;
            p->tcph->th_sum = TCPV6CalculateChecksum((uint16_t *)&(p->ip6h->ip6_src),
                    (uint16_t *)p->tcph, (p->payload_len + TCP_GET_HLEN(p)));
        } else if (PKT_IS_UDP(p)) {
            p->udph->uh_sum = 0;
            p->udph->uh_sum = UDPV6CalculateChecksum((uint16_t *)&(p->ip6h->ip6_src),
                    (uint16_t *)p->udph, (p->payload_len + UDP_HEADER_LEN));
        }
    }

    return 0;
}
