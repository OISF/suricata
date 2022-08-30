/* Copyright (C) 2017-2022 Open Information Security Foundation
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
#include "datasets-md5.h"
#include "util-thash.h"
#include "util-print.h"
#include "util-base64.h"    // decode base64

int Md5StrSet(void *dst, void *src)
{
    Md5Type *src_s = src;
    Md5Type *dst_s = dst;
    memcpy(dst_s->md5, src_s->md5, sizeof(dst_s->md5));
    dst_s->rep = src_s->rep;
    return 0;
}

bool Md5StrCompare(void *a, void *b)
{
    const Md5Type *as = a;
    const Md5Type *bs = b;

    return (memcmp(as->md5, bs->md5, sizeof(as->md5)) == 0);
}

uint32_t Md5StrHash(void *s)
{
    const Md5Type *str = s;
    uint32_t hash = 5381;

    for (int i = 0; i < (int)sizeof(str->md5); i++) {
        hash = ((hash << 5) + hash) + str->md5[i]; /* hash * 33 + c */
    }
    return hash;
}

// data stays in hash
void Md5StrFree(void *s)
{
}
