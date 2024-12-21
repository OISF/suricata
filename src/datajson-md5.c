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
#include "datasets.h"
#include "datajson.h"
#include "datajson-md5.h"
#include "util-hash-lookup3.h"

#include "util-thash.h"
#include "util-print.h"

int Md5StrJsonSet(void *dst, void *src)
{
    Md5TypeJson *src_s = src;
    Md5TypeJson *dst_s = dst;
    memcpy(dst_s->md5, src_s->md5, sizeof(dst_s->md5));
    dst_s->json.value = src_s->json.value;
    dst_s->json.len = src_s->json.len;
    return 0;
}

bool Md5StrJsonCompare(void *a, void *b)
{
    const Md5TypeJson *as = a;
    const Md5TypeJson *bs = b;

    return (memcmp(as->md5, bs->md5, sizeof(as->md5)) == 0);
}

uint32_t Md5StrJsonHash(uint32_t hash_seed, void *s)
{
    const Md5TypeJson *str = s;
    return hashword((uint32_t *)str->md5, sizeof(str->md5) / 4, hash_seed);
}

void Md5StrJsonFree(void *s)
{
    const Md5TypeJson *as = s;
    if (as->json.value) {
        SCFree(as->json.value);
    }
}
