/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * CIDR utility functions
 */

#include "suricata-common.h"
#include "util-cidr.h"

uint32_t CIDRGet(int cidr)
{
    if (cidr <= 0 || cidr > 32)
        return 0;
    uint32_t netmask = htonl(0xFFFFFFFF << (32UL - (uint32_t)cidr));
    SCLogDebug("CIDR %d -> netmask %08X", cidr, netmask);
    return netmask;
}

/**
 * \brief Creates a cidr ipv6 netblock, based on the cidr netblock value.
 *
 *        For example if we send a cidr of 7 as argument, an ipv6 address
 *        mask of the value FE:00:00:00:00:00:00:00 is created and updated
 *        in the argument struct in6_addr *in6.
 *
 * \todo I think for the final section: while (cidr > 0), we can simply
 *       replace it with a
 *       if (cidr > 0) {
 *           in6->s6_addr[i] = -1 << (8 - cidr);
 *
 * \param cidr The value of the cidr.
 * \param in6  Pointer to an ipv6 address structure(struct in6_addr) which will
 *             hold the cidr netblock result.
 */
void CIDRGetIPv6(int cidr, struct in6_addr *in6)
{
    int i = 0;

    memset(in6, 0, sizeof(struct in6_addr));

    while (cidr > 8) {
        in6->s6_addr[i] = 0xff;
        cidr -= 8;
        i++;
    }

    while (cidr > 0) {
        in6->s6_addr[i] |= 0x80;
        if (--cidr > 0)
            in6->s6_addr[i] = in6->s6_addr[i] >> 1;
    }
}
