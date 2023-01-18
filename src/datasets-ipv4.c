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
#include "datasets-ipv4.h"
#include "util-thash.h"
#include "util-print.h"

int IPv4Set(void *dst, void *src)
{
    IPv4Type *src_s = src;
    IPv4Type *dst_s = dst;
    memcpy(dst_s->ipv4, src_s->ipv4, sizeof(dst_s->ipv4));
    dst_s->rep = src_s->rep;
    return 0;
}

bool IPv4Compare(void *a, void *b)
{
    const IPv4Type *as = a;
    const IPv4Type *bs = b;

    return (memcmp(as->ipv4, bs->ipv4, sizeof(as->ipv4)) == 0);
}

uint32_t IPv4Hash(void *s)
{
    const IPv4Type *str = s;
    uint32_t hash = 5381;

    for (int i = 0; i < (int)sizeof(str->ipv4); i++) {
        hash = ((hash << 5) + hash) + str->ipv4[i]; /* hash * 33 + c */
    }
    return hash;
}

// data stays in hash
void IPv4Free(void *s)
{
}
