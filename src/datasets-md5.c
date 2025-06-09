/* Copyright (C) 2017-2024 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "conf.h"
#include "datasets.h"
#include "datasets-context-json.h"
#include "datasets-md5.h"
#include "util-hash-lookup3.h"

#include "util-thash.h"
#include "util-print.h"

int Md5StrSet(void *dst, void *src)
{
    Md5Type *src_s = src;
    Md5Type *dst_s = dst;
    memcpy(dst_s->md5, src_s->md5, sizeof(dst_s->md5));
    dst_s->rep = src_s->rep;
    return 0;
}

int Md5StrJsonSet(void *dst, void *src)
{
    if (Md5StrSet(dst, src) < 0)
        return -1;

    Md5Type *src_s = src;
    Md5Type *dst_s = dst;

    if (DatajsonCopyJson(&dst_s->json, &src_s->json) < 0)
        return -1;

    return 0;
}

bool Md5StrCompare(void *a, void *b)
{
    const Md5Type *as = a;
    const Md5Type *bs = b;

    return (memcmp(as->md5, bs->md5, sizeof(as->md5)) == 0);
}

uint32_t Md5StrHash(uint32_t hash_seed, void *s)
{
    const Md5Type *str = s;
    return hashword((uint32_t *)str->md5, sizeof(str->md5) / 4, hash_seed);
}

// data stays in hash
void Md5StrFree(void *s)
{
}

void Md5StrJsonFree(void *s)
{
    const Md5Type *as = s;
    if (as->json.value) {
        SCFree(as->json.value);
    }
}

uint32_t Md5StrJsonGetLength(void *s)
{
    const Md5Type *as = s;
    return as->json.len;
}
