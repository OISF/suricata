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
 * Util functions for checksum.
 */

#include "suricata-common.h"
#include "util-checksum.h"

int ReCalculateChecksum(Packet *p)
{
    if (PacketIsIPv4(p)) {
        IPV4Hdr *ip4h = p->l3.hdrs.ip4h;
        if (PacketIsTCP(p)) {
            /* TCP */
            p->l4.hdrs.tcph->th_sum = 0;
            p->l4.hdrs.tcph->th_sum = TCPChecksum(ip4h->s_ip_addrs, (uint16_t *)p->l4.hdrs.tcph,
                    (p->payload_len + TCP_GET_RAW_HLEN(p->l4.hdrs.tcph)), 0);
        } else if (PacketIsUDP(p)) {
            p->l4.hdrs.udph->uh_sum = 0;
            p->l4.hdrs.udph->uh_sum = UDPV4Checksum(ip4h->s_ip_addrs, (uint16_t *)p->l4.hdrs.udph,
                    (p->payload_len + UDP_HEADER_LEN), 0);
        }
        /* IPV4 */
        ip4h->ip_csum = 0;
        ip4h->ip_csum = IPV4Checksum((uint16_t *)ip4h, IPV4_GET_RAW_HLEN(ip4h), 0);
    } else if (PacketIsIPv6(p)) {
        IPV6Hdr *ip6h = p->l3.hdrs.ip6h;
        if (PacketIsTCP(p)) {
            p->l4.hdrs.tcph->th_sum = 0;
            p->l4.hdrs.tcph->th_sum = TCPV6Checksum(ip6h->s_ip6_addrs, (uint16_t *)p->l4.hdrs.tcph,
                    (p->payload_len + TCP_GET_RAW_HLEN(p->l4.hdrs.tcph)), 0);
        } else if (PacketIsUDP(p)) {
            p->l4.hdrs.udph->uh_sum = 0;
            p->l4.hdrs.udph->uh_sum = UDPV6Checksum(ip6h->s_ip6_addrs, (uint16_t *)p->l4.hdrs.udph,
                    (p->payload_len + UDP_HEADER_LEN), 0);
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
int ChecksumAutoModeCheck(uint64_t thread_count,
        uint64_t iface_count, uint64_t iface_fail)
{
    if (thread_count == CHECKSUM_SAMPLE_COUNT) {
        if (iface_fail != 0) {
            if ((iface_count / iface_fail) < CHECKSUM_INVALID_RATIO) {
                SCLogInfo("More than 1/%dth of packets have an invalid "
                        "checksum, assuming checksum offloading is used "
                        "(%"PRIu64"/%"PRIu64")",
                        CHECKSUM_INVALID_RATIO, iface_fail, iface_count);
                return 1;
            } else {
                SCLogInfo("Less than 1/%dth of packets have an invalid "
                        "checksum, assuming checksum offloading is NOT used "
                        "(%"PRIu64"/%"PRIu64")", CHECKSUM_INVALID_RATIO,
                        iface_fail, iface_count);
            }
        } else {
            SCLogInfo("No packets with invalid checksum, assuming "
                    "checksum offloading is NOT used");
        }
    }
    return 0;
}
