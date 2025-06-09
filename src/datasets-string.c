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
#include "datasets-string.h"
#include "util-thash.h"
#include "util-print.h"
#include "util-hash-lookup3.h"
#include "rust.h"

#if 0
static int StringAsAscii(const void *s, char *out, size_t out_size)
{
    const StringType *str = s;
    uint32_t offset = 0;
    PrintRawUriBuf(out, &offset, out_size, str->ptr, str->len);
    if (out[0] == '\0')
        return 0;
    strlcat(out, "\n", out_size);
    return strlen(out);
}
#endif

int StringAsBase64(const void *s, char *out, size_t out_size)
{
    const StringType *str = s;

    unsigned long len = SCBase64EncodeBufferSize(str->len);
    uint8_t encoded_data[len];
    if (SCBase64Encode((unsigned char *)str->ptr, str->len, encoded_data, &len) != SC_BASE64_OK)
        return 0;

    strlcpy(out, (const char *)encoded_data, out_size);
    strlcat(out, "\n", out_size);
    return (int)strlen(out);
}

int StringSet(void *dst, void *src)
{
    StringType *src_s = src;
    StringType *dst_s = dst;
    SCLogDebug("dst %p src %p, src_s->ptr %p src_s->len %u", dst, src, src_s->ptr, src_s->len);

    dst_s->len = src_s->len;
    dst_s->ptr = SCMalloc(dst_s->len);
    if (dst_s->ptr == NULL) {
        SCLogError("Failed to allocate memory for string of length %u", dst_s->len);
        return -1;
    }
    memcpy(dst_s->ptr, src_s->ptr, dst_s->len);

    dst_s->rep = src_s->rep;
    SCLogDebug("dst %p src %p, dst_s->ptr %p dst_s->len %u", dst, src, dst_s->ptr, dst_s->len);
    return 0;
}

int StringJsonSet(void *dst, void *src)
{
    if (StringSet(dst, src) < 0)
        return -1;

    StringType *src_s = src;
    StringType *dst_s = dst;

    if (DatajsonCopyJson(&dst_s->json, &src_s->json) < 0) {
        SCFree(dst_s->ptr);
        return -1;
    }

    return 0;
}

bool StringCompare(void *a, void *b)
{
    const StringType *as = a;
    const StringType *bs = b;

    if (as->len != bs->len)
        return false;

    return (memcmp(as->ptr, bs->ptr, as->len) == 0);
}

uint32_t StringHash(uint32_t hash_seed, void *s)
{
    StringType *str = s;
    return hashlittle_safe(str->ptr, str->len, hash_seed);
}

uint32_t StringGetLength(void *s)
{
    StringType *str = s;
    return str->len;
}

// base data stays in hash
void StringFree(void *s)
{
    StringType *str = s;
    SCFree(str->ptr);
}

void StringJsonFree(void *s)
{
    StringType *str = s;
    SCFree(str->ptr);
    if (str->json.value) {
        SCFree(str->json.value);
    }
}

uint32_t StringJsonGetLength(void *s)
{
    StringType *str = s;
    return str->json.len + str->len;
}
