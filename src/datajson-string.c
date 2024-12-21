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
#include "datajson-string.h"
#include "util-thash.h"
#include "util-print.h"
#include "util-hash-lookup3.h"
#include "rust.h"

int StringJsonAsBase64(const void *s, char *out, size_t out_size)
{
    const StringTypeJson *str = s;

    unsigned long len = Base64EncodeBufferSize(str->len);
    uint8_t encoded_data[len];
    if (Base64Encode((unsigned char *)str->ptr, str->len, encoded_data, &len) != SC_BASE64_OK)
        return 0;

    strlcpy(out, (const char *)encoded_data, out_size);
    strlcat(out, "\n", out_size);
    return strlen(out);
}

int StringJsonSet(void *dst, void *src)
{
    StringTypeJson *src_s = src;
    StringTypeJson *dst_s = dst;
    SCLogDebug("dst %p src %p, src_s->ptr %p src_s->len %u", dst, src, src_s->ptr, src_s->len);

    dst_s->len = src_s->len;
    dst_s->ptr = SCMalloc(dst_s->len);
    BUG_ON(dst_s->ptr == NULL);
    memcpy(dst_s->ptr, src_s->ptr, dst_s->len);

    dst_s->json.value = src_s->json.value;
    dst_s->json.len = src_s->json.len;

    SCLogDebug("dst %p src %p, dst_s->ptr %p dst_s->len %u", dst, src, dst_s->ptr, dst_s->len);
    return 0;
}

bool StringJsonCompare(void *a, void *b)
{
    const StringTypeJson *as = a;
    const StringTypeJson *bs = b;

    if (as->len != bs->len)
        return false;

    return (memcmp(as->ptr, bs->ptr, as->len) == 0);
}

uint32_t StringJsonHash(uint32_t hash_seed, void *s)
{
    StringTypeJson *str = s;
    return hashlittle_safe(str->ptr, str->len, hash_seed);
}

// base data stays in hash
void StringJsonFree(void *s)
{
    StringTypeJson *str = s;
    SCFree(str->ptr);
    if (str->json.value) {
        SCFree(str->json.value);
    }
}
