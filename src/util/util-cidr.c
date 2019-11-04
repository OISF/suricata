/* Copyright (C) 2007-2010 Open Information Security Foundation
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

static uint32_t cidrs[33];

void CIDRInit(void)
{
    int i = 0;

    /* skip 0 as it will result in 0xffffffff */
    cidrs[0] = 0;
    for (i = 1; i < 33; i++) {
        cidrs[i] = htonl(0xFFFFFFFF << (32 - i));
        //printf("CIDRInit: cidrs[%02d] = 0x%08X\n", i, cidrs[i]);
    }
}

uint32_t CIDRGet(int cidr)
{
    if (cidr < 0 || cidr > 32)
        return 0;
    return cidrs[cidr];
}

