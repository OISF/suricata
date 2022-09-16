/* Copyright (C) 2017-2019 Open Information Security Foundation
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
#include "datasets-sha256.h"

int Sha256StrSet(void *dst, void *src)
{
    Sha256Type *src_s = src;
    Sha256Type *dst_s = dst;
    memcpy(dst_s->sha256, src_s->sha256, sizeof(dst_s->sha256));
    dst_s->rep = src_s->rep;
    return 0;
}

bool Sha256StrCompare(void *a, void *b)
{
    Sha256Type *as = a;
    Sha256Type *bs = b;

    return (memcmp(as->sha256, bs->sha256, sizeof(as->sha256)) == 0);
}

uint32_t Sha256StrHash(void *s)
{
    Sha256Type *str = s;
    uint32_t hash = 5381;

    for (int i = 0; i < (int)sizeof(str->sha256); i++) {
        hash = ((hash << 5) + hash) + str->sha256[i]; /* hash * 33 + c */
    }
    return hash;
}

// data stays in hash
void Sha256StrFree(void *s)
{
    // no dynamic data
}
