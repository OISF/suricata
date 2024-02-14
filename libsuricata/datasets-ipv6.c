/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Eric Leblond <el@stamus-networks.com>
 */

#include "suricata-common.h"
#include "conf.h"
#include "datasets.h"
#include "datasets-ipv6.h"
#include "util-thash.h"
#include "util-print.h"

int IPv6Set(void *dst, void *src)
{
    IPv6Type *src_s = src;
    IPv6Type *dst_s = dst;
    memcpy(dst_s->ipv6, src_s->ipv6, sizeof(dst_s->ipv6));
    dst_s->rep = src_s->rep;
    return 0;
}

bool IPv6Compare(void *a, void *b)
{
    const IPv6Type *as = a;
    const IPv6Type *bs = b;

    return (memcmp(as->ipv6, bs->ipv6, sizeof(as->ipv6)) == 0);
}

uint32_t IPv6Hash(void *s)
{
    const IPv6Type *str = s;
    uint32_t hash = 5381;

    for (int i = 0; i < (int)sizeof(str->ipv6); i++) {
        hash = ((hash << 5) + hash) + str->ipv6[i]; /* hash * 33 + c */
    }
    return hash;
}

// data stays in hash
void IPv6Free(void *s)
{
}
