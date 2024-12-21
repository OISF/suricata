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
#include "datajson-ipv4.h"
#include "util-hash-lookup3.h"
#include "util-thash.h"
#include "util-print.h"

int IPv4JsonSet(void *dst, void *src)
{
    IPv4TypeJson *src_s = src;
    IPv4TypeJson *dst_s = dst;
    memcpy(dst_s->ipv4, src_s->ipv4, sizeof(dst_s->ipv4));
    dst_s->json.value = src_s->json.value;
    dst_s->json.len = src_s->json.len;

    return 0;
}

bool IPv4JsonCompare(void *a, void *b)
{
    const IPv4TypeJson *as = a;
    const IPv4TypeJson *bs = b;

    return (memcmp(as->ipv4, bs->ipv4, sizeof(as->ipv4)) == 0);
}

uint32_t IPv4JsonHash(uint32_t hash_seed, void *s)
{
    const IPv4TypeJson *str = s;
    return hashword((uint32_t *)str->ipv4, 1, hash_seed);
}

void IPv4JsonFree(void *s)
{
    const IPv4TypeJson *as = s;
    if (as->json.value) {
        SCFree(as->json.value);
    }
}
