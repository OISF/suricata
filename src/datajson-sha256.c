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
#include "datajson-sha256.h"
#include "util-hash-lookup3.h"
#include "util-thash.h"

int Sha256StrJsonSet(void *dst, void *src)
{
    Sha256TypeJson *src_s = src;
    Sha256TypeJson *dst_s = dst;
    memcpy(dst_s->sha256, src_s->sha256, sizeof(dst_s->sha256));
    dst_s->json.value = src_s->json.value;
    dst_s->json.len = src_s->json.len;
    return 0;
}

bool Sha256StrJsonCompare(void *a, void *b)
{
    Sha256TypeJson *as = a;
    Sha256TypeJson *bs = b;

    return (memcmp(as->sha256, bs->sha256, sizeof(as->sha256)) == 0);
}

uint32_t Sha256StrJsonHash(uint32_t hash_seed, void *s)
{
    Sha256TypeJson *str = s;
    return hashword((uint32_t *)str->sha256, sizeof(str->sha256) / 4, hash_seed);
}

void Sha256StrJsonFree(void *s)
{
    const Sha256TypeJson *as = s;
    if (as->json.value) {
        SCFree(as->json.value);
    }
}