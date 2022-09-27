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

#ifdef UNITTESTS
#include "util-unittest.h"
#endif
/** \brief turn 32 bit mask into CIDR
 *  \retval cidr cidr value or -1 if the netmask can't be expressed as cidr
 */
int CIDRFromMask(uint32_t netmask)
{
    netmask = ntohl(netmask);
    if (netmask == 0) {
        return 0;
    }
    int p = 0;
    bool seen_1 = false;
    while (netmask > 0) {
        if (netmask & 1) {
            seen_1 = true;
            p++;
        } else {
            if (seen_1) {
                return -1;
            }
        }
        netmask >>= 1;
    }
    return p;
}

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

#ifdef UNITTESTS

static int CIDRFromMaskTest01(void)
{
    struct in_addr in;
    int v = inet_pton(AF_INET, "255.255.255.0", &in);

    FAIL_IF(v <= 0);
    FAIL_IF_NOT(24 == CIDRFromMask(in.s_addr));

    PASS;
}

static int CIDRFromMaskTest02(void)
{
    struct in_addr in;
    int v = inet_pton(AF_INET, "255.255.0.42", &in);

    FAIL_IF(v <= 0);
    FAIL_IF_NOT(-1 == CIDRFromMask(in.s_addr));

    PASS;
}

static int CIDRFromMaskTest03(void)
{
    struct in_addr in;
    int v = inet_pton(AF_INET, "0.0.0.0", &in);

    FAIL_IF(v <= 0);
    FAIL_IF_NOT(0 == CIDRFromMask(in.s_addr));

    PASS;
}

static int CIDRFromMaskTest04(void)
{
    struct in_addr in;
    int v = inet_pton(AF_INET, "255.255.255.255", &in);

    FAIL_IF(v <= 0);
    FAIL_IF_NOT(32 == CIDRFromMask(in.s_addr));

    PASS;
}

#endif /* UNITTESTS */

void UtilCIDRTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("CIDRFromMaskTest01", CIDRFromMaskTest01);
    UtRegisterTest("CIDRFromMaskTest02", CIDRFromMaskTest02);
    UtRegisterTest("CIDRFromMaskTest03", CIDRFromMaskTest03);
    UtRegisterTest("CIDRFromMaskTest04", CIDRFromMaskTest04);
#endif /* UNITTESTS */
}
