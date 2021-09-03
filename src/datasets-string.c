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
#include "conf.h"
#include "datasets.h"
#include "datasets-string.h"
#include "util-thash.h"
#include "util-print.h"
#include "util-base64.h"    // decode base64
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

    unsigned long len = Base64EncodeBufferSize(str->len);
    uint8_t encoded_data[len];
    if (Base64Encode((unsigned char *)str->ptr, str->len,
        encoded_data, &len) != SC_BASE64_OK)
        return 0;

    strlcpy(out, (const char *)encoded_data, out_size);
    strlcat(out, "\n", out_size);
    return strlen(out);
}

int StringSet(void *dst, void *src)
{
    StringType *src_s = src;
    StringType *dst_s = dst;
    SCLogDebug("dst %p src %p, src_s->ptr %p src_s->len %u", dst, src, src_s->ptr, src_s->len);

    dst_s->len = src_s->len;
    dst_s->ptr = SCMalloc(dst_s->len);
    BUG_ON(dst_s->ptr == NULL);
    memcpy(dst_s->ptr, src_s->ptr, dst_s->len);

    dst_s->rep = src_s->rep;
    SCLogDebug("dst %p src %p, dst_s->ptr %p dst_s->len %u", dst, src, dst_s->ptr, dst_s->len);
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

uint32_t StringHash(void *s)
{
    uint32_t hash = 5381;
    StringType *str = s;

    for (uint32_t i = 0; i < str->len; i++) {
        int c = str->ptr[i];
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}

// base data stays in hash
void StringFree(void *s)
{
    StringType *str = s;
    SCFree(str->ptr);
}
