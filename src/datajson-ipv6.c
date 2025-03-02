/* Copyright (C) 2024 Open Information Security Foundation
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
#include "datajson.h"
#include "datajson-ipv6.h"
#include "util-hash-lookup3.h"
#include "util-thash.h"
#include "util-print.h"

int IPv6JsonSet(void *dst, void *src)
{
    IPv6TypeJson *src_s = src;
    IPv6TypeJson *dst_s = dst;
    memcpy(dst_s->ipv6, src_s->ipv6, sizeof(dst_s->ipv6));
    dst_s->json.value = src_s->json.value;
    dst_s->json.len = src_s->json.len;

    return 0;
}

bool IPv6JsonCompare(void *a, void *b)
{
    const IPv6TypeJson *as = a;
    const IPv6TypeJson *bs = b;

    return (memcmp(as->ipv6, bs->ipv6, sizeof(as->ipv6)) == 0);
}

uint32_t IPv6JsonHash(uint32_t hash_seed, void *s)
{
    const IPv6TypeJson *str = s;
    return hashword((uint32_t *)str->ipv6, 4, hash_seed);
}

void IPv6JsonFree(void *s)
{
    const IPv6TypeJson *as = s;
    if (as->json.value) {
        SCFree(as->json.value);
    }
}
