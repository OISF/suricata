/* Copyright (C) 2011-2012 Open Information Security Foundation
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

#include "util-checksum.h"

int ReCalculateChecksum(Packet *p)
{
    if (PKT_IS_IPV4(p)) {
        if (PKT_IS_TCP(p)) {
            /* TCP */
            p->tcph->th_sum = 0;
            p->tcph->th_sum = TCPCalculateChecksum(p->ip4h->s_ip_addrs,
                    (uint16_t *)p->tcph, (p->payload_len + TCP_GET_HLEN(p)));
        } else if (PKT_IS_UDP(p)) {
            p->udph->uh_sum = 0;
            p->udph->uh_sum = UDPV4CalculateChecksum(p->ip4h->s_ip_addrs,
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
            p->tcph->th_sum = TCPV6CalculateChecksum(p->ip6h->s_ip6_addrs,
                    (uint16_t *)p->tcph, (p->payload_len + TCP_GET_HLEN(p)));
        } else if (PKT_IS_UDP(p)) {
            p->udph->uh_sum = 0;
            p->udph->uh_sum = UDPV6CalculateChecksum(p->ip6h->s_ip6_addrs,
                    (uint16_t *)p->udph, (p->payload_len + UDP_HEADER_LEN));
        }
    }

    return 0;
}

/**
 *  \brief Check if the number of invalid checksums indicate checksum
 *         offloading in place.
 *
 *  \retval 1 yes, offloading in place
 *  \retval 0 no, no offloading used
 */
int ChecksumAutoModeCheck(uint32_t thread_count,
        unsigned int iface_count, unsigned int iface_fail)
{
    if (thread_count == CHECKSUM_SAMPLE_COUNT) {
        if (iface_fail != 0) {
            if ((iface_count / iface_fail) < CHECKSUM_INVALID_RATIO) {
                SCLogInfo("More than 1/%dth of packets have an invalid "
                        "checksum, assuming checksum offloading is used (%u/%u)",
                        CHECKSUM_INVALID_RATIO, iface_fail, iface_count);
                return 1;
            } else {
                SCLogInfo("Less than 1/%dth of packets have an invalid "
                        "checksum, assuming checksum offloading is NOT used (%u/%u)",
                        CHECKSUM_INVALID_RATIO, iface_fail, iface_count);
            }
        } else {
            SCLogInfo("No packets with invalid checksum, assuming checksum offloading is NOT used");
        }
    }
    return 0;
}
