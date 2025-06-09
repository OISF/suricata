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
#include "util-hash-lookup3.h"
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

int IPv4JsonSet(void *dst, void *src)
{
    if (IPv4Set(dst, src) < 0)
        return -1;

    IPv4Type *src_s = src;
    IPv4Type *dst_s = dst;

    if (DatajsonCopyJson(&dst_s->json, &src_s->json) < 0)
        return -1;

    return 0;
}

bool IPv4Compare(void *a, void *b)
{
    const IPv4Type *as = a;
    const IPv4Type *bs = b;

    return (memcmp(as->ipv4, bs->ipv4, sizeof(as->ipv4)) == 0);
}

uint32_t IPv4Hash(uint32_t hash_seed, void *s)
{
    const IPv4Type *str = s;
    return hashword((uint32_t *)str->ipv4, 1, hash_seed);
}

// data stays in hash
void IPv4Free(void *s)
{
}

void IPv4JsonFree(void *s)
{
    const IPv4Type *as = s;
    if (as->json.value) {
        SCFree(as->json.value);
    }
}

uint32_t IPv4JsonGetLength(void *s)
{
    const IPv4Type *as = s;
    return as->json.len;
}
