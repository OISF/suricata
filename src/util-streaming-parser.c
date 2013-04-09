/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * The Test() are made to look like they don't move the data pointer forward,
 * but internally we move the pointer forward and store the data in a temp
 * buffer.  The reason behind this logic being, we request data of a
 * particular size(say 8 bytes), but the state has < 8 bytes, in which case
 * we return RDATA.
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-streaming-parser.h"

typedef struct StreamingParserCtx_ {
    /* struct members structured to have as little padding as possible */
    uint8_t *data;
    union {
        uint8_t u8[8];
        uint16_t u16[4];
        uint32_t u32[2];
        uint64_t u64;
    } buffer;
    uint8_t buffer_len;
    uint16_t data_len;
} StreamingParserCtx;

void *StreamingParserNewContext(void)
{
    void *p = SCMalloc(sizeof(StreamingParserCtx));
    if (p == NULL)
        return NULL;
    memset(p, 0, sizeof(StreamingParserCtx));
    return p;
}

void StreamingParserFreeContext(void *ctx)
{
    SCFree(ctx);
}

void StreamingParserSetData(void *ctx, uint8_t *data, uint16_t data_len)
{
    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;
    tctx->data = data;
    tctx->data_len = data_len;

    return;
}

/*****Get functions*****/

static int StreamingParserGet8(void *ctx, uint8_t *ret_input)
{
    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;

    if (tctx->buffer_len > 0) {
        *ret_input = tctx->buffer.u8[0];
        tctx->buffer.u64 >>= 8;
        tctx->buffer_len--;
        return STREAMING_PARSER_ROK;
    }

    if (tctx->data_len == 0)
        return STREAMING_PARSER_RDATA;

    *ret_input = *(tctx->data++);
    tctx->data_len--;

    return STREAMING_PARSER_ROK;
}

int StreamingParserGetU8(void *ctx, uint8_t *ret_input)
{
    return StreamingParserGet8(ctx, ret_input);
}

int StreamingParserGetI8(void *ctx, int8_t *ret_input)
{
    return StreamingParserGet8(ctx, (uint8_t *)ret_input);
}

static int StreamingParserGetValue(void *ctx, void *ret_input, uint8_t psize)
{
    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;
    uint16_t u;

    if (psize <= tctx->buffer_len) {
        if (psize == 2) {
            *((uint16_t *)ret_input) = tctx->buffer.u16[0];
        } else if (psize == 4) {
            *((uint32_t *)ret_input) = tctx->buffer.u32[0];
        } else {
            *((uint64_t *)ret_input) = tctx->buffer.u64;
        }
        /* Since a type can't be shifted by a value >= width of the type, we
         * need to split it */
        tctx->buffer.u64 >>= (psize * 8 - 1);
        tctx->buffer.u64 >>= 1;
        tctx->buffer_len -= psize;

        return STREAMING_PARSER_ROK;
    }

    /* not engouh data, let's buffer and get out */
    if (tctx->data_len < (psize - tctx->buffer_len) ) {
        for (u = 0; u < tctx->data_len; u++)
            tctx->buffer.u8[tctx->buffer_len++] = tctx->data[u];
        tctx->data_len = 0;

        return STREAMING_PARSER_RDATA;
    } else {
        if (tctx->buffer_len == 0) {
            if (psize == 2)
                *((uint16_t *)ret_input) = *((uint16_t *)tctx->data);
            else if (psize == 4)
                *((uint32_t *)ret_input) = *((uint32_t *)tctx->data);
            else
                *((uint64_t *)ret_input) = *((uint64_t *)tctx->data);
            tctx->data += psize;
            tctx->data_len -= psize;
        } else {
            int r_size = psize - tctx->buffer_len;
            for (u = 0; u < r_size; u++)
                tctx->buffer.u8[tctx->buffer_len++] = tctx->data[u];

            tctx->data += r_size;
            tctx->data_len -= r_size;
            tctx->buffer_len = 0;
            if (psize == 2)
                *((uint16_t *)ret_input) = tctx->buffer.u16[0];
            else if (psize == 4)
                *((uint32_t *)ret_input) = tctx->buffer.u32[0];
            else
                *((uint64_t *)ret_input) = tctx->buffer.u64;
            tctx->buffer.u64 = 0;
        }

        return STREAMING_PARSER_ROK;
    }
}

int StreamingParserGetU16(void *ctx, uint16_t *ret_input)
{
    return StreamingParserGetValue(ctx, (void *)ret_input, sizeof(uint16_t));
}

int StreamingParserGetI16(void *ctx, int16_t *ret_input)
{
    return StreamingParserGetValue(ctx, (void *)ret_input, sizeof(int16_t));
}

int StreamingParserGetU32(void *ctx, uint32_t *ret_input)
{
    return StreamingParserGetValue(ctx, (void *)ret_input, sizeof(uint32_t));
}

int StreamingParserGetI32(void *ctx, int32_t *ret_input)
{
    return StreamingParserGetValue(ctx, (void *)ret_input, sizeof(int32_t));
}

int StreamingParserGetU64(void *ctx, uint64_t *ret_input)
{
    return StreamingParserGetValue(ctx, (void *)ret_input, sizeof(uint64_t));
}

int StreamingParserGetI64(void *ctx, int64_t *ret_input)
{
    return StreamingParserGetValue(ctx, (void *)ret_input, sizeof(int64_t));
}

/*****Byte order specific Get functions*****/

static int StreamingParserGet16WithBO(void *ctx, uint16_t *ret_input, uint8_t bo)
{
    uint16_t value;
    int retval = StreamingParserGetValue(ctx, (void *)&value, sizeof(uint16_t));
    if (retval == STREAMING_PARSER_RDATA)
        return STREAMING_PARSER_RDATA;

#if __BYTE_ORDER == __BIG_ENDIAN
    if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
        *ret_input = value;
    else
        *ret_input = SCByteSwap16(value);
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
        *ret_input = SCByteSwap16(value);
    else
        *ret_input = value;
#else
#error "Unable to determine endianness of the machine."
#endif

    return STREAMING_PARSER_ROK;
}

int StreamingParserGetU16WithBO(void *ctx, uint16_t *ret_input, uint8_t bo)
{
    return StreamingParserGet16WithBO(ctx, ret_input, bo);
}

int StreamingParserGetI16WithBO(void *ctx, int16_t *ret_input, uint8_t bo)
{
    return StreamingParserGet16WithBO(ctx, (uint16_t *)ret_input, bo);
}

static int StreamingParserGet32WithBO(void *ctx, uint32_t *ret_input, uint8_t bo)
{
    uint32_t value;
    int retval = StreamingParserGetValue(ctx, (void *)&value, sizeof(uint32_t));
    if (retval == STREAMING_PARSER_RDATA)
        return STREAMING_PARSER_RDATA;

#if __BYTE_ORDER == __BIG_ENDIAN
    if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
        *ret_input = value;
    else
        *ret_input = SCByteSwap32(value);
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
        *ret_input = SCByteSwap32(value);
    else
        *ret_input = value;
#else
#error "Unable to determine endianness of the machine."
#endif

    return STREAMING_PARSER_ROK;
}

int StreamingParserGetU32WithBO(void *ctx, uint32_t *ret_input, uint8_t bo)
{
    return StreamingParserGet32WithBO(ctx, ret_input, bo);
}

int StreamingParserGetI32WithBO(void *ctx, int32_t *ret_input, uint8_t bo)
{
    return StreamingParserGet32WithBO(ctx, (uint32_t *)ret_input, bo);
}

static int StreamingParserGet64WithBO(void *ctx, uint64_t *ret_input, uint8_t bo)
{
    uint64_t value;
    int retval = StreamingParserGetValue(ctx, (void *)&value, sizeof(uint64_t));
    if (retval == STREAMING_PARSER_RDATA)
        return STREAMING_PARSER_RDATA;

#if __BYTE_ORDER == __BIG_ENDIAN
    if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
        *ret_input = value;
    else
        *ret_input = SCByteSwap64(value);
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
        *ret_input = SCByteSwap64(value);
    else
        *ret_input = value;
#else
#error "Unable to determine endianness of the machine."
#endif

    return STREAMING_PARSER_ROK;
}

int StreamingParserGetU64WithBO(void *ctx, uint64_t *ret_input, uint8_t bo)
{
    return StreamingParserGet64WithBO(ctx, ret_input, bo);
}

int StreamingParserGetI64WithBO(void *ctx, int64_t *ret_input, uint8_t bo)
{
    return StreamingParserGet64WithBO(ctx, (uint64_t *)ret_input, bo);
}

/*****Test functions*****/

static int StreamingParserTest8(void *ctx, uint8_t *ret_input)
{
    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;

    if (tctx->buffer_len > 0) {
        *ret_input = tctx->buffer.u8[0];
        return STREAMING_PARSER_ROK;
    }

    if (tctx->data_len == 0)
        return STREAMING_PARSER_RDATA;

    *ret_input = *(tctx->data++);
    tctx->data_len--;
    tctx->buffer.u8[0] = *ret_input;
    tctx->buffer_len++;

    return STREAMING_PARSER_ROK;
}

int StreamingParserTestU8(void *ctx, uint8_t *ret_input)
{
    return StreamingParserTest8(ctx, ret_input);
}

int StreamingParserTestI8(void *ctx, int8_t *ret_input)
{
    return StreamingParserTest8(ctx, (uint8_t *)ret_input);
}

static int StreamingParserTestValue(void *ctx, void *ret_input, uint8_t psize)
{
    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;
    uint16_t u;

    if (psize <= tctx->buffer_len) {
        if (psize == 2)
            *((uint16_t *)ret_input) = tctx->buffer.u16[0];
        else if (psize == 4)
            *((uint32_t *)ret_input) = tctx->buffer.u32[0];
        else
            *((uint64_t *)ret_input) = tctx->buffer.u64;

        return STREAMING_PARSER_ROK;
    }

    if (tctx->data_len < (psize - tctx->buffer_len) ) {
        for (u = 0; u < tctx->data_len; u++)
            tctx->buffer.u8[tctx->buffer_len++] = tctx->data[u];
        tctx->data_len = 0;

        return STREAMING_PARSER_RDATA;
    } else {
        if (tctx->buffer_len == 0) {
            if (psize == 2) {
                *((uint16_t *)ret_input) = *((uint16_t *)tctx->data);
                tctx->buffer.u64 = *((uint16_t *)ret_input);
            } else if (psize == 4) {
                *((uint32_t *)ret_input) = *((uint32_t *)tctx->data);
                tctx->buffer.u64 = *((uint32_t *)ret_input);
            } else {
                *((uint64_t *)ret_input) = *((uint64_t *)tctx->data);
                tctx->buffer.u64 = *((uint64_t *)ret_input);
            }
            tctx->buffer_len = psize;
            tctx->data += psize;
            tctx->data_len -= psize;
        } else {
            int r_size = psize - tctx->buffer_len;
            for (u = 0; u < r_size; u++)
                tctx->buffer.u8[tctx->buffer_len++] = tctx->data[u];

            tctx->data += r_size;
            tctx->data_len -= r_size;
            tctx->buffer_len = psize;
            if (psize == 2)
                *((uint16_t *)ret_input) = tctx->buffer.u16[0];
            else if (psize == 4)
                *((uint32_t *)ret_input) = tctx->buffer.u32[0];
            else
                *((uint64_t *)ret_input) = tctx->buffer.u64;
        }

        return STREAMING_PARSER_ROK;
    }
}

int StreamingParserTestU16(void *ctx, uint16_t *ret_input)
{
    return StreamingParserTestValue(ctx, (void *)ret_input, sizeof(uint16_t));
}

int StreamingParserTestI16(void *ctx, int16_t *ret_input)
{
    return StreamingParserTestValue(ctx, (void *)ret_input, sizeof(int16_t));
}

int StreamingParserTestU32(void *ctx, uint32_t *ret_input)
{
    return StreamingParserTestValue(ctx, (void *)ret_input, sizeof(uint32_t));
}

int StreamingParserTestI32(void *ctx, int32_t *ret_input)
{
    return StreamingParserTestValue(ctx, (void *)ret_input, sizeof(int32_t));
}

int StreamingParserTestU64(void *ctx, uint64_t *ret_input)
{
    return StreamingParserTestValue(ctx, (void *)ret_input, sizeof(uint64_t));
}

int StreamingParserTestI64(void *ctx, int64_t *ret_input)
{
    return StreamingParserTestValue(ctx, (void *)ret_input, sizeof(int64_t));
}

/*****Byte order specific Test functions*****/

static int StreamingParserTest16WithBO(void *ctx, uint16_t *ret_input, uint8_t bo)
{
    uint16_t value;
    int retval = StreamingParserTestValue(ctx, (void *)&value, sizeof(uint16_t));
    if (retval == STREAMING_PARSER_RDATA)
        return STREAMING_PARSER_RDATA;

#if __BYTE_ORDER == __BIG_ENDIAN
    if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
        *ret_input = value;
    else
        *ret_input = SCByteSwap16(value);
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
        *ret_input = SCByteSwap16(value);
    else
        *ret_input = value;
#else
#error "Unable to determine endianness of the machine."
#endif

    return STREAMING_PARSER_ROK;
}

int StreamingParserTestU16WithBO(void *ctx, uint16_t *ret_input, uint8_t bo)
{
    return StreamingParserTest16WithBO(ctx, ret_input, bo);
}

int StreamingParserTestI16WithBO(void *ctx, int16_t *ret_input, uint8_t bo)
{
    return StreamingParserTest16WithBO(ctx, (uint16_t *)ret_input, bo);
}

static int StreamingParserTest32WithBO(void *ctx, uint32_t *ret_input, uint8_t bo)
{
    uint32_t value;
    int retval = StreamingParserTestValue(ctx, (void *)&value, sizeof(uint32_t));
    if (retval == STREAMING_PARSER_RDATA)
        return STREAMING_PARSER_RDATA;

#if __BYTE_ORDER == __BIG_ENDIAN
    if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
        *ret_input = value;
    else
        *ret_input = SCByteSwap32(value);
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
        *ret_input = SCByteSwap32(value);
    else
        *ret_input = value;
#else
#error "Unable to determine endianness of the machine."
#endif

    return STREAMING_PARSER_ROK;
}

int StreamingParserTestU32WithBO(void *ctx, uint32_t *ret_input, uint8_t bo)
{
    return StreamingParserTest32WithBO(ctx, ret_input, bo);
}

int StreamingParserTestI32WithBO(void *ctx, int32_t *ret_input, uint8_t bo)
{
    return StreamingParserTest32WithBO(ctx, (uint32_t *)ret_input, bo);
}

static int StreamingParserTest64WithBO(void *ctx, uint64_t *ret_input, uint8_t bo)
{
    uint64_t value;
    int retval = StreamingParserTestValue(ctx, (void *)&value, sizeof(uint64_t));
    if (retval == STREAMING_PARSER_RDATA)
        return STREAMING_PARSER_RDATA;

#if __BYTE_ORDER == __BIG_ENDIAN
    if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
        *ret_input = value;
    else
        *ret_input = SCByteSwap64(value);
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
        *ret_input = SCByteSwap64(value);
    else
        *ret_input = value;
#else
#error "Unable to determine endianness of the machine."
#endif

    return STREAMING_PARSER_ROK;
}

int StreamingParserTestU64WithBO(void *ctx, uint64_t *ret_input, uint8_t bo)
{
    return StreamingParserTest64WithBO(ctx, ret_input, bo);
}

int StreamingParserTestI64WithBO(void *ctx, int64_t *ret_input, uint8_t bo)
{
    return StreamingParserTest64WithBO(ctx, (uint64_t *)ret_input, bo);
}

/*****Chunk Retrieval*****/

int StreamingParserGetChunk(void *ctx, uint8_t *buffer, uint16_t copy, uint16_t *copied)
{
    *copied = 0;

    if (copy == 0)
        return STREAMING_PARSER_ROK;

    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;
    uint16_t u;

    for (u = 0; u < tctx->buffer_len && u < copy; u++) {
        buffer[u] = tctx->buffer.u8[u];
    }
    tctx->buffer_len -= u;
    tctx->buffer.u64 >>= (u * 8 - 1);
    tctx->buffer.u64 >>= 1;
    *copied += u;

    if (tctx->data_len < (copy - *copied)) {
        memcpy(buffer + *copied, tctx->data, tctx->data_len);
        *copied += tctx->data_len;
        tctx->data_len = 0;

        return STREAMING_PARSER_RDATA;
    } else {
        memcpy(buffer + *copied, tctx->data, (copy - *copied));
        tctx->data += (copy - *copied);
        tctx->data_len -= (copy - *copied);
        *copied = copy;

        return STREAMING_PARSER_ROK;
    }

}

/*****Jump*****/

int StreamingParserJump(void *ctx, uint16_t jump, uint16_t *jumped)
{
    *jumped = 0;

    if (jump == 0)
        return STREAMING_PARSER_ROK;

    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;

    if (tctx->buffer_len != 0) {
        if (jump < tctx->buffer_len) {
            tctx->buffer.u64 >>= (jump * 8);
            tctx->buffer_len -= jump;
            *jumped = jump;

            return STREAMING_PARSER_ROK;
        }

        *jumped = tctx->buffer_len;
        tctx->buffer.u64 = 0;
        tctx->buffer_len = 0;

        if (*jumped == jump)
            return STREAMING_PARSER_ROK;
    }

    if (tctx->data_len < (jump - *jumped)) {
        *jumped += tctx->data_len;
        tctx->data_len = 0;

        return STREAMING_PARSER_RDATA;
    } else {
        tctx->data += (jump - *jumped);
        tctx->data_len -= (jump - *jumped);
        *jumped = jump;

        return STREAMING_PARSER_ROK;
    }
}

/**********Unittests**********/

#ifdef UNITTESTS

static int StreamingParserTest01(void)
{
    int retval = 0;

    uint32_t u;
    StreamingParserCtx *ctx;
    uint8_t u_value;
    int8_t i_value;

    uint8_t data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xFE
    };
    uint16_t data_len = sizeof(data);

    ctx = StreamingParserNewContext();
    if (ctx == NULL) {
        printf("if (ctx == NULL)\n");
        goto end;
    }

    StreamingParserSetData(ctx, data, data_len);
    for (u = 0; u < data_len; u++) {
        if (StreamingParserGetU8(ctx, &u_value) != STREAMING_PARSER_ROK) {
            printf("index - %"PRIu32" retval != STREAMING_PARSER_ROK\n", u);
            goto end;
        }

        if (u_value != data[u]) {
            printf("if (u_value(%"PRIu8") != data[u](%"PRIu8"))\n", u_value, data[u]);
            goto end;
        }
    }
    if (StreamingParserGetU8(ctx, &u_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    StreamingParserSetData(ctx, data, data_len);
    for (u = 0; u < data_len; u++) {
        if (StreamingParserGetI8(ctx, &i_value) != STREAMING_PARSER_ROK) {
            printf("index - %"PRIu32" retval != STREAMING_PARSER_ROK\n", u);
            goto end;
        }

        if (i_value != (int8_t)data[u]) {
            printf("if (i_value(%d) != data[u](%"PRIu8"))\n", i_value, data[u]);
            goto end;
        }
    }
    if (StreamingParserGetI8(ctx, &i_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    retval = 1;
 end:
    return retval;
}

static int StreamingParserTest02(void)
{
    int retval = 0;

    uint32_t u;
    StreamingParserCtx *ctx;
    uint16_t u_value;
    int16_t i_value;

    uint8_t data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFE, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    uint16_t data_len = sizeof(data);

    ctx = StreamingParserNewContext();
    if (ctx == NULL) {
        printf("if (ctx == NULL)\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data, data_len);
    for (u = 0; u < data_len / sizeof(uint16_t); u++) {
        if (StreamingParserGetU16(ctx, &u_value) != STREAMING_PARSER_ROK) {
            printf("index - %"PRIu32" retval != STREAMING_PARSER_ROK\n", u);
            goto end;
        }

        if (u_value != *((uint16_t *)data + u)) {
            printf("index(%"PRIu32") - if (u_value(%"PRIu16") != data[u](%"PRIu16"))\n",
                   u, u_value, *((uint16_t *)data + u));
            goto end;
        }
    }
    if (StreamingParserGetU16(ctx, &u_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data, data_len);
    for (u = 0; u < data_len / sizeof(uint16_t); u++) {
        if (StreamingParserGetI16(ctx, &i_value) != STREAMING_PARSER_ROK) {
            printf("index - %"PRIu32" retval != STREAMING_PARSER_ROK\n", u);
            goto end;
        }

        if (i_value != *((int16_t *)data + u)) {
            printf("if (i_value(%d) != data[u](%hd)\n", i_value, *((int16_t *)data + u));
            goto end;
        }
    }
    if (StreamingParserGetI16(ctx, &i_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    retval = 1;
 end:
    return retval;
}

static int StreamingParserTest03(void)
{
    int retval = 0;

    uint32_t u;
    StreamingParserCtx *ctx;
    uint32_t u_value;
    int32_t i_value;

    uint8_t data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFE, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    uint16_t data_len = sizeof(data);

    ctx = StreamingParserNewContext();
    if (ctx == NULL) {
        printf("if (ctx == NULL)\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data, data_len);
    for (u = 0; u < data_len / sizeof(uint32_t); u++) {
        if (StreamingParserGetU32(ctx, &u_value) != STREAMING_PARSER_ROK) {
            printf("index - %"PRIu32" retval != STREAMING_PARSER_ROK\n", u);
            goto end;
        }

        if (u_value != *((uint32_t *)data + u)) {
            printf("index(%"PRIu32") - if (u_value(%"PRIu32") != data[u](%"PRIu32"))\n",
                   u, u_value, *((uint32_t *)data + u));
            goto end;
        }
    }
    if (StreamingParserGetU32(ctx, &u_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data, data_len);
    for (u = 0; u < data_len / sizeof(uint32_t); u++) {
        if (StreamingParserGetI32(ctx, &i_value) != STREAMING_PARSER_ROK) {
            printf("index - %"PRIu32" retval != STREAMING_PARSER_ROK\n", u);
            goto end;
        }

        if (i_value != *((int32_t *)data + u)) {
            printf("if (i_value(%d) != data[u](%d)\n", i_value, *((int32_t *)data + u));
            goto end;
        }
    }
    if (StreamingParserGetI32(ctx, &i_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    retval = 1;
 end:
    return retval;
}

static int StreamingParserTest04(void)
{
    int retval = 0;

    uint32_t u;
    StreamingParserCtx *ctx;
    uint64_t u_value;
    int64_t i_value;

    uint8_t data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFE, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    uint16_t data_len = sizeof(data);

    ctx = StreamingParserNewContext();
    if (ctx == NULL) {
        printf("if (ctx == NULL)\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data, data_len);
    for (u = 0; u < data_len / sizeof(uint64_t); u++) {
        if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
            printf("index - %"PRIu32" retval != STREAMING_PARSER_ROK\n", u);
            goto end;
        }

        if (u_value != *((uint64_t *)data + u)) {
            printf("index(%"PRIu32") - if (u_value(%"PRIu64") != data[u](%"PRIu64"))\n",
                   u, u_value, *((uint64_t *)data + u));
            goto end;
        }
    }
    if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data, data_len);
    for (u = 0; u < data_len / sizeof(uint64_t); u++) {
        if (StreamingParserGetI64(ctx, &i_value) != STREAMING_PARSER_ROK) {
            printf("index - %"PRIu32" retval != STREAMING_PARSER_ROK\n", u);
            goto end;
        }

        if (i_value != *((int64_t *)data + u)) {
            printf("if (i_value(%"PRId64") != data[u](%"PRId64")\n", i_value, *((int64_t *)data + u));
            goto end;
        }
    }
    if (StreamingParserGetI64(ctx, &i_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    retval = 1;
 end:
    return retval;
}

static int StreamingParserTest05(void)
{
    int retval = 0;

    StreamingParserCtx *ctx;
    uint16_t u_value;

    uint8_t data1[] = {
        0x01, 0x02,
        0x05,
    };
    uint16_t data1_len = sizeof(data1);

    uint8_t data2[] = {
        0x06,
        0x09, 0x0A,
    };
    uint16_t data2_len = sizeof(data2);

    uint8_t boundary_value[] = {
        0x05, 0x06,
    };

    ctx = StreamingParserNewContext();
    if (ctx == NULL) {
        printf("if (ctx == NULL)\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data1, data1_len);
    if (StreamingParserGetU16(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("failure 1\n");
        goto end;
    }
    if (u_value != *((uint16_t *)data1)) {
        printf("1 - if (u_value(%"PRIu16") != data[u](%"PRIu16"))\n",
               u_value, *((uint16_t *)data1));
        goto end;
    }

    if (StreamingParserGetU16(ctx, &u_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data2, data2_len);
    if (StreamingParserGetU16(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("failure 2\n");
        goto end;
    }
    if (u_value != *((uint16_t *)boundary_value)) {
        printf("2 - if (u_value(%"PRIu16") != data[u](%"PRIu16")\n",
               u_value, *((uint16_t *)boundary_value));
        goto end;
    }

    if (StreamingParserGetU16(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("failure 3\n");
        goto end;
    }
    if (u_value != *((uint16_t *)(data2 + 1))) {
        printf("3 - if (u_value(%"PRIu16") != data[u](%"PRIu16")\n",
               u_value, *((uint16_t *)(data2 + 1)));
        goto end;
    }

    if (StreamingParserGetU16(ctx, &u_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    retval = 1;
 end:
    return retval;
}

static int StreamingParserTest06(void)
{
    int retval = 0;

    StreamingParserCtx *ctx;
    uint32_t u_value;

    uint8_t data1[] = {
        0x01, 0x02, 0x03, 0x04,
        0x05,
    };
    uint16_t data1_len = sizeof(data1);

    uint8_t data2[] = {
        0x06, 0xFE, 0x07,
        0x09, 0x0A, 0x0B, 0x0C,
    };
    uint16_t data2_len = sizeof(data2);

    uint8_t boundary_value[] = {
        0x05, 0x06, 0xFE, 0x07,
    };

    ctx = StreamingParserNewContext();
    if (ctx == NULL) {
        printf("if (ctx == NULL)\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data1, data1_len);
    if (StreamingParserGetU32(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("failure 1\n");
        goto end;
    }
    if (u_value != *((uint32_t *)data1)) {
        printf("1 - if (u_value(%"PRIu32") != data[u](%"PRIu32"))\n",
               u_value, *((uint32_t *)data1));
        goto end;
    }

    if (StreamingParserGetU32(ctx, &u_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data2, data2_len);
    if (StreamingParserGetU32(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("failure 2\n");
        goto end;
    }
    if (u_value != *((uint32_t *)boundary_value)) {
        printf("2 - if (u_value(%"PRIu32") != data[u](%"PRIu32")\n",
               u_value, *((uint32_t *)boundary_value));
        goto end;
    }

    if (StreamingParserGetU32(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("failure 3\n");
        goto end;
    }
    if (u_value != *((uint32_t *)(data2 + 3))) {
        printf("3 - if (u_value(%"PRIu32") != data[u](%"PRIu32")\n",
               u_value, *((uint32_t *)(data2 + 7)));
        goto end;
    }

    if (StreamingParserGetU32(ctx, &u_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    retval = 1;
 end:
    return retval;
}

static int StreamingParserTest07(void)
{
    int retval = 0;

    StreamingParserCtx *ctx;
    uint64_t u_value;

    uint8_t data1[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFE, 0x07,
        0x08,
    };
    uint16_t data1_len = sizeof(data1);

    uint8_t data2[] = {
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    uint16_t data2_len = sizeof(data2);

    uint8_t boundary_value[] = {
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };

    ctx = StreamingParserNewContext();
    if (ctx == NULL) {
        printf("if (ctx == NULL)\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data1, data1_len);
    if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("failure 1\n");
        goto end;
    }
    if (u_value != *((uint64_t *)data1)) {
        printf("1 - if (u_value(%"PRIu64") != data[u](%"PRIu64"))\n",
               u_value, *((uint64_t *)data1));
        goto end;
    }

    if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data2, data2_len);
    if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("failure 2\n");
        goto end;
    }
    if (u_value != *((uint64_t *)boundary_value)) {
        printf("2 - if (u_value(%"PRIu64") != data[u](%"PRIu64")\n",
               u_value, *((uint64_t *)boundary_value));
        goto end;
    }

    if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("failure 3\n");
        goto end;
    }
    if (u_value != *((uint64_t *)(data2 + 7))) {
        printf("3 - if (u_value(%"PRIu64") != data[u](%"PRIu64")\n",
               u_value, *((uint64_t *)(data2 + 7)));
        goto end;
    }

    if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    retval = 1;
 end:
    return retval;
}

static int StreamingParserTest08(void)
{
    int retval = 0;

    StreamingParserCtx *ctx;
    uint64_t u_value;

    uint8_t data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFE, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x09, 0x01, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x0E, 0x0F, 0x0E, 0x0F, 0x0E, 0x0F, 0x0E, 0x0F,
    };
    uint16_t data_len = sizeof(data);

    ctx = StreamingParserNewContext();
    if (ctx == NULL) {
        printf("if (ctx == NULL)\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data, data_len);

    if (StreamingParserTestU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("1 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u_value != *((uint64_t *)data)) {
        printf("1 - if (u_value(%"PRIu64") != data(%"PRIu64"))\n",
               u_value, *((uint64_t *)data));
        goto end;
    }

    if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("2 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u_value != *((uint64_t *)data)) {
        printf("2 - if (u_value(%"PRIu64") != data(%"PRIu64"))\n",
               u_value, *((uint64_t *)data));
        goto end;
    }

    if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("3 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u_value != *((uint64_t *)data + 1)) {
        printf("3 - if (u_value(%"PRIu64") != data(%"PRIu64"))\n",
               u_value, *((uint64_t *)data + 1));
        goto end;
    }

    if (StreamingParserTestU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("4 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u_value != *((uint64_t *)data + 2)) {
        printf("4 - if (u_value(%"PRIu64") != data(%"PRIu64"))\n",
               u_value, *((uint64_t *)data + 2 ));
        goto end;
    }

    if (StreamingParserTestU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("5 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u_value != *((uint64_t *)data + 2)) {
        printf("5 - if (u_value(%"PRIu64") != data(%"PRIu64"))\n",
               u_value, *((uint64_t *)data + 2));
        goto end;
    }

    if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("6 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u_value != *((uint64_t *)data + 2)) {
        printf("6 - if (u_value(%"PRIu64") != data(%"PRIu64"))\n",
               u_value, *((uint64_t *)data + 2));
        goto end;
    }

    if (StreamingParserTestU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("7 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u_value != *((uint64_t *)data + 3)) {
        printf("7 - if (u_value(%"PRIu64") != data(%"PRIu64"))\n",
               u_value, *((uint64_t *)data + 3));
        goto end;
    }

    if (StreamingParserTestU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("8 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u_value != *((uint64_t *)data + 3)) {
        printf("8 - if (u_value(%"PRIu64") != data(%"PRIu64"))\n",
               u_value, *((uint64_t *)data + 3));
        goto end;
    }

    if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("9 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u_value != *((uint64_t *)data + 3)) {
        printf("9 - if (u_value(%"PRIu64") != data(%"PRIu64"))\n",
               u_value, *((uint64_t *)data + 3));
        goto end;
    }

    if (StreamingParserTestU64(ctx, &u_value) != STREAMING_PARSER_RDATA) {
        printf("8 - retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    retval = 1;
 end:
    return retval;
}

static int StreamingParserTest09(void)
{
    int retval = 0;

    StreamingParserCtx *ctx;
    uint8_t u8_value;
    uint16_t u16_value;
    uint32_t u32_value;
    uint64_t u64_value;

    uint8_t data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFE, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x09, 0x01, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x0E, 0x0F, 0x0E, 0x0F, 0x0E, 0x0F, 0x0E, 0x0F,
    };
    uint16_t data_len = sizeof(data);

    ctx = StreamingParserNewContext();
    if (ctx == NULL) {
        printf("if (ctx == NULL)\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data, data_len);

    u8_value = 0;
    if (StreamingParserTestU8(ctx, &u8_value) != STREAMING_PARSER_ROK) {
        printf("1 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u8_value != *((uint8_t *)data)) {
        printf("1 - if (u_value(%u) != data(%u))\n",
               u8_value, *((uint8_t *)data));
        goto end;
    }

    u16_value = 0;
    if (StreamingParserTestU16(ctx, &u16_value) != STREAMING_PARSER_ROK) {
        printf("2 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u16_value != *((uint16_t *)data)) {
        printf("2 - if (u_value(%hu) != data(%hu))\n",
               u16_value, *((uint16_t *)data));
        goto end;
    }

    u64_value = 0;
    if (StreamingParserTestU64(ctx, &u64_value) != STREAMING_PARSER_ROK) {
        printf("3 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u64_value != *((uint64_t *)data)) {
        printf("3 - if (u_value(%"PRIu64") != data(%"PRIu64"))\n",
               u64_value, *((uint64_t *)data));
        goto end;
    }

    u16_value = 0;
    if (StreamingParserTestU16(ctx, &u16_value) != STREAMING_PARSER_ROK) {
        printf("4 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u16_value != *((uint16_t *)data)) {
        printf("4 - if (u_value(%hu) != data(%hu))\n",
               u16_value, *((uint16_t *)data));
        goto end;
    }

    u8_value = 0;
    if (StreamingParserTestU8(ctx, &u8_value) != STREAMING_PARSER_ROK) {
        printf("5 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u8_value != *((uint8_t *)data)) {
        printf("5 - if (u_value(%u) != data(%u))\n",
               u8_value, *((uint8_t *)data));
        goto end;
    }

    u32_value = 0;
    if (StreamingParserTestU32(ctx, &u32_value) != STREAMING_PARSER_ROK) {
        printf("6 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u32_value != *((uint32_t *)data)) {
        printf("6 - if (u_value(%"PRIu32") != data(%"PRIu32"))\n",
               u32_value, *((uint32_t *)data));
        goto end;
    }

    u64_value = 0;
    if (StreamingParserTestU64(ctx, &u64_value) != STREAMING_PARSER_ROK) {
        printf("7 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u64_value != *((uint64_t *)data)) {
        printf("7 - if (u_value(%"PRIu64") != data(%"PRIu64"))\n",
               u64_value, *((uint64_t *)data));
        goto end;
    }

    retval = 1;
 end:
    return retval;
}

static int StreamingParserTest10(void)
{
    int retval = 0;

    StreamingParserCtx *ctx;
    uint8_t u8_value;
    uint16_t u16_value;
    uint32_t u32_value;
    uint64_t u64_value;

    uint8_t data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFE, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x09, 0x01, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x0E, 0x0F, 0x0E, 0x0F, 0x0E, 0x0F, 0x0E, 0x0F,
    };
    uint16_t data_len = sizeof(data);

    ctx = StreamingParserNewContext();
    if (ctx == NULL) {
        printf("if (ctx == NULL)\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data, data_len);

    u64_value = 0;
    if (StreamingParserTestU64(ctx, &u64_value) != STREAMING_PARSER_ROK) {
        printf("1 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u64_value != *((uint64_t *)data)) {
        printf("1 - if (u_value(%"PRIu64") != data(%"PRIu64"))\n",
               u64_value, *((uint64_t *)data));
        goto end;
    }

    u8_value = 0;
    if (StreamingParserGetU8(ctx, &u8_value) != STREAMING_PARSER_ROK) {
        printf("2 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u8_value != *((uint8_t *)data)) {
        printf("2 - if (u_value(%u) != data(%u))\n",
               u8_value, *((uint8_t *)data));
        goto end;
    }

    u16_value = 0;
    if (StreamingParserTestU16(ctx, &u16_value) != STREAMING_PARSER_ROK) {
        printf("3 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u16_value != *((uint16_t *)(data + 1))) {
        printf("3 - if (u_value(%hu) != data(%hu))\n",
               u16_value, *((uint16_t *)(data + 1)));
        goto end;
    }

    u64_value = 0;
    if (StreamingParserTestU64(ctx, &u64_value) != STREAMING_PARSER_ROK) {
        printf("4 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u64_value != *((uint64_t *)(data + 1))) {
        printf("4 - if (u_value(%"PRIu64") != data(%"PRIu64"))\n",
               u64_value, *((uint64_t *)(data + 1)));
        goto end;
    }

    u16_value = 0;
    if (StreamingParserTestU16(ctx, &u16_value) != STREAMING_PARSER_ROK) {
        printf("5 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u16_value != *((uint16_t *)(data + 1))) {
        printf("5 - if (u_value(%hu) != data(%hu))\n",
               u16_value, *((uint16_t *)(data + 1)));
        goto end;
    }

    u32_value = 0;
    if (StreamingParserTestU32(ctx, &u32_value) != STREAMING_PARSER_ROK) {
        printf("6 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u32_value != *((uint32_t *)(data + 1))) {
        printf("6 - if (u_value(%hu) != data(%hu))\n",
               u16_value, *((uint32_t *)(data + 1)));
        goto end;
    }

    u32_value = 0;
    if (StreamingParserGetU32(ctx, &u32_value) != STREAMING_PARSER_ROK) {
        printf("7 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u32_value != *((uint32_t *)(data + 1))) {
        printf("7 - if (u_value(%hu) != data(%hu))\n",
               u16_value, *((uint32_t *)(data + 1)));
        goto end;
    }

    u32_value = 0;
    if (StreamingParserTestU32(ctx, &u32_value) != STREAMING_PARSER_ROK) {
        printf("8 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u32_value != *((uint32_t *)(data + 5))) {
        printf("8 - if (u_value(%hu) != data(%hu))\n",
               u16_value, *((uint32_t *)(data + 5)));
        goto end;
    }

    u32_value = 0;
    if (StreamingParserGetU32(ctx, &u32_value) != STREAMING_PARSER_ROK) {
        printf("9 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u32_value != *((uint32_t *)(data + 5))) {
        printf("9 - if (u_value(%hu) != data(%hu))\n",
               u16_value, *((uint32_t *)(data + 5)));
        goto end;
    }

    u64_value = 0;
    if (StreamingParserTestU64(ctx, &u64_value) != STREAMING_PARSER_ROK) {
        printf("10 - retval != STREAMING_PARSER_ROK\n");
        goto end;
    }
    if (u64_value != *((uint64_t *)(data + 9))) {
        printf("10 - if (u_value(%"PRIu64") != data(%"PRIu64"))\n",
               u64_value, *((uint64_t *)(data + 9)));
        goto end;
    }

    retval = 1;
 end:
    return retval;
}

static int StreamingParserTest11(void)
{
    int retval = 0;

    StreamingParserCtx *ctx;
    uint64_t u_value;

    uint8_t data1[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFE, 0x07,
        0x08,
    };
    uint16_t data1_len = sizeof(data1);

    uint8_t data2[] = {
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    uint16_t data2_len = sizeof(data2);

    /* supplied value */
    uint64_t s_value1 = 0x010203040506FE07;
    uint64_t s_value2 = 0x08090A0B0C0D0E0F;
    uint64_t s_value3 = 0x0807060504030201;

    ctx = StreamingParserNewContext();
    if (ctx == NULL) {
        printf("if (ctx == NULL)\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data1, data1_len);
    if (StreamingParserGetU64WithBO(ctx, &u_value, STREAMING_PARSER_BO_BIG_ENDIAN) != STREAMING_PARSER_ROK) {
        printf("failure 1\n");
        goto end;
    }
    if (u_value != s_value1) {
        printf("1 - if (u_value(%"PRIu64") != s_value1(%"PRIu64"))\n",
               u_value, s_value1);
        goto end;
    }

    if (StreamingParserGetU64WithBO(ctx, &u_value, STREAMING_PARSER_BO_BIG_ENDIAN) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data2, data2_len);
    if (StreamingParserGetU64WithBO(ctx, &u_value, STREAMING_PARSER_BO_BIG_ENDIAN) != STREAMING_PARSER_ROK) {
        printf("failure 2\n");
        goto end;
    }
    if (u_value != s_value2) {
        printf("2 - if (u_value(%"PRIu64") != s_value2(%"PRIu64")\n",
               u_value, s_value2);
        goto end;
    }

    if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("failure 3\n");
        goto end;
    }
    if (u_value != s_value3) {
        printf("3 - if (u_value(%"PRIu64") != s_value3(%"PRIu64")\n",
               u_value, s_value3);
        goto end;
    }

    if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    retval = 1;
 end:
    return retval;
}

static int StreamingParserTest12(void)
{
    int retval = 0;

    StreamingParserCtx *ctx;
    uint64_t u_value;

    uint8_t data1[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFE, 0x07,
        0x08,
    };
    uint16_t data1_len = sizeof(data1);

    uint8_t data2[] = {
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    uint16_t data2_len = sizeof(data2);

    /* supplied value */
    uint64_t s_value1 = 0x010203040506FE07;
    uint64_t s_value2 = 0x08090A0B0C0D0E0F;
    uint64_t s_value3 = 0x0807060504030201;

    ctx = StreamingParserNewContext();
    if (ctx == NULL) {
        printf("if (ctx == NULL)\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data1, data1_len);
    if (StreamingParserTestU64WithBO(ctx, &u_value, STREAMING_PARSER_BO_BIG_ENDIAN) != STREAMING_PARSER_ROK) {
        printf("failure 1\n");
        goto end;
    }
    if (u_value != s_value1) {
        printf("1 - if (u_value(%"PRIu64") != s_value1(%"PRIu64"))\n",
               u_value, s_value1);
        goto end;
    }

    if (StreamingParserGetU64WithBO(ctx, &u_value, STREAMING_PARSER_BO_BIG_ENDIAN) != STREAMING_PARSER_ROK) {
        printf("failure 2\n");
        goto end;
    }
    if (u_value != s_value1) {
        printf("2 - if (u_value(%"PRIu64") != s_value2(%"PRIu64")\n",
               u_value, s_value1);
        goto end;
    }

    if (StreamingParserTestU64WithBO(ctx, &u_value, STREAMING_PARSER_BO_BIG_ENDIAN) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    StreamingParserSetData(ctx, (uint8_t *)data2, data2_len);
    if (StreamingParserTestU64WithBO(ctx, &u_value, STREAMING_PARSER_BO_BIG_ENDIAN) != STREAMING_PARSER_ROK) {
        printf("failure 2\n");
        goto end;
    }
    if (u_value != s_value2) {
        printf("3 - if (u_value(%"PRIu64") != s_value2(%"PRIu64")\n",
               u_value, s_value2);
        goto end;
    }

    if (StreamingParserGetU64WithBO(ctx, &u_value, STREAMING_PARSER_BO_BIG_ENDIAN) != STREAMING_PARSER_ROK) {
        printf("failure 2\n");
        goto end;
    }
    if (u_value != s_value2) {
        printf("4 - if (u_value(%"PRIu64") != s_value2(%"PRIu64")\n",
               u_value, s_value2);
        goto end;
    }

    if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_ROK) {
        printf("failure 2\n");
        goto end;
    }
    if (u_value != s_value3) {
        printf("5 - if (u_value(%"PRIu64") != s_value2(%"PRIu64")\n",
               u_value, s_value3);
        goto end;
    }

    if (StreamingParserGetU64(ctx, &u_value) != STREAMING_PARSER_RDATA) {
        printf("retval != STREAMING_PARSER_RDATA\n");
        goto end;
    }

    retval = 1;
 end:
    return retval;
}

/**
 * \brief Test chunk retrieval.
 */
static int StreamingParserTest13(void)
{
    int retval = 0;

    StreamingParserCtx *ctx;
    uint16_t u = 0;
    uint16_t copied = 0;
    uint8_t buffer[24];
    uint16_t u16_value = 0;

    uint8_t data1[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFE, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    uint16_t data1_len = sizeof(data1);

    uint8_t data2[] = {
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
        0x04, 0x05, 0x06, 0xFE,
    };
    uint16_t data2_len = sizeof(data2);

    uint8_t data3[] = {
        0x0C, 0x0D, 0x0E, 0x0F, 0x08, 0x09, 0x0A, 0x0B,
        0x04, 0x05, 0x06, 0xFE, 0x02, 0x03, 0x04,
    };
    uint16_t data3_len = sizeof(data3);

    ctx = StreamingParserNewContext();
    if (ctx == NULL) {
        printf("if (ctx == NULL)\n");
        goto end;
    }

    /* first chunk */
    StreamingParserSetData(ctx, (uint8_t *)data1, data1_len);

    if (StreamingParserGetChunk(ctx, buffer, 8, &copied) != STREAMING_PARSER_ROK) {
        printf("failure 1\n");
        goto end;
    }
    if (copied != 8) {
        printf("failure 2\n");
        goto end;
    }
    for (u = 0; u < 8; u++) {
        if (buffer[u] != data1[u]) {
            printf("failure 3\n");
            goto end;
        }
    }

    if (StreamingParserGetChunk(ctx, buffer, 8, &copied) != STREAMING_PARSER_ROK) {
        printf("failure 4\n");
        goto end;
    }
    if (copied != 8) {
        printf("failure 5\n");
        goto end;
    }
    for (u = 0; u < 8; u++) {
        if (buffer[u] != data1[u + 8]) {
            printf("failure 6\n");
            goto end;
        }
    }

    if (StreamingParserGetChunk(ctx, buffer, 8, &copied) != STREAMING_PARSER_ROK) {
        printf("failure 7\n");
        goto end;
    }
    if (copied != 8) {
        printf("failure 8\n");
        goto end;
    }
    for (u = 0; u < 8; u++) {
        if (buffer[u] != data1[u + 16]) {
            printf("failure 9\n");
            goto end;
        }
    }

    if (StreamingParserGetChunk(ctx, buffer, 8, &copied) != STREAMING_PARSER_RDATA) {
        printf("failure 10\n");
        goto end;
    }
    if (copied != 0) {
        printf("failure 11\n");
        goto end;
    }

    if (StreamingParserGetChunk(ctx, buffer, 8, &copied) != STREAMING_PARSER_RDATA) {
        printf("failure 12\n");
        goto end;
    }
    if (copied != 0) {
        printf("failure 13\n");
        goto end;
    }



    /* second chunk */

    StreamingParserSetData(ctx, (uint8_t *)data2, data2_len);

    if (StreamingParserGetChunk(ctx, buffer, 8, &copied) != STREAMING_PARSER_ROK) {
        printf("failure 14\n");
        goto end;
    }
    if (copied != 8) {
        printf("failure 15\n");
        goto end;
    }
    for (u = 0; u < 8; u++) {
        if (buffer[u] != data2[u]) {
            printf("failure 16\n");
            goto end;
        }
    }

    if (StreamingParserGetChunk(ctx, buffer, 8, &copied) != STREAMING_PARSER_ROK) {
        printf("failure 17\n");
        goto end;
    }
    if (copied != 8) {
        printf("failure 18\n");
        goto end;
    }
    for (u = 0; u < 8; u++) {
        if (buffer[u] != data2[u + 8]) {
            printf("failure 19\n");
            goto end;
        }
    }

    if (StreamingParserGetChunk(ctx, buffer, 8, &copied) != STREAMING_PARSER_RDATA) {
        printf("failure 20\n");
        goto end;
    }
    if (copied != 4) {
        printf("failure 21\n");
        goto end;
    }
    for (u = 0; u < 4; u++) {
        if (buffer[u] != data2[u + 16]) {
            printf("failure 22\n");
            goto end;
        }
    }

    if (StreamingParserGetChunk(ctx, buffer, 1, &copied) != STREAMING_PARSER_RDATA) {
        printf("failure 23\n");
        goto end;
    }
    if (copied != 0) {
        printf("failure 24\n");
        goto end;
    }

    if (StreamingParserGetChunk(ctx, buffer, 1, &copied) != STREAMING_PARSER_RDATA) {
        printf("failure 25\n");
        goto end;
    }
    if (copied != 0) {
        printf("failure 26\n");
        goto end;
    }



    /* third chunk */

    StreamingParserSetData(ctx, (uint8_t *)data3, data3_len);
    if (StreamingParserTestU16(ctx, &u16_value) != STREAMING_PARSER_ROK) {
        printf("failure 27\n");
        goto end;
    }
    if (u16_value != *((uint16_t *)data3)) {
        printf("failure 28\n");
        goto end;
    }

    if (StreamingParserGetChunk(ctx, buffer, 4, &copied) != STREAMING_PARSER_ROK) {
        printf("failure 29\n");
        goto end;
    }
    if (copied != 4) {
        printf("failure 30\n");
        goto end;
    }
    if (*((uint16_t *)buffer) != u16_value &&
        buffer[2] != data3[2] && buffer[3] != data3[3]) {
        printf("failure 31\n");
        goto end;
    }

    if (StreamingParserGetU16(ctx, &u16_value) != STREAMING_PARSER_ROK) {
        printf("failure 32\n");
        goto end;
    }
    if (u16_value != *((uint16_t *)(data3 + 4))) {
        printf("failure 33\n");
        goto end;
    }

    if (StreamingParserGetChunk(ctx, buffer, 6, &copied) != STREAMING_PARSER_ROK) {
        printf("failure 34\n");
        goto end;
    }
    if (copied != 6) {
        printf("failure 35\n");
        goto end;
    }
    for (u = 0; u < 6; u++) {
        if (buffer[u] != data3[u + 6]) {
            printf("failure 36\n");
            goto end;
        }
    }

    if (StreamingParserTestU16(ctx, &u16_value) != STREAMING_PARSER_ROK) {
        printf("failure 37\n");
        goto end;
    }
    if (u16_value != *((uint16_t *)(data3 + 12))) {
        printf("failure 38\n");
        goto end;
    }

    if (StreamingParserGetChunk(ctx, buffer, 4, &copied) != STREAMING_PARSER_RDATA) {
        printf("failure 39\n");
        goto end;
    }
    if (copied != 3) {
        printf("failure 40\n");
        goto end;
    }
    if (*((uint16_t *)buffer + 12) != u16_value &&
        buffer[2] != data3[14]) {
        printf("failure 41\n");
        goto end;
    }

    if (StreamingParserGetChunk(ctx, buffer, 1, &copied) != STREAMING_PARSER_RDATA) {
        printf("failure 42\n");
        goto end;
    }
    if (copied != 0) {
        printf("failure 43\n");
        goto end;
    }

    retval = 1;
 end:
    return retval;
}

/**
 * \brief Test jump.
 */
static int StreamingParserTest14(void)
{
    int retval = 0;

    StreamingParserCtx *ctx;
    uint16_t jumped = 0;
    uint16_t u16_value = 0;

    uint8_t data1[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFE, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };
    uint16_t data1_len = sizeof(data1);

    uint8_t data2[] = {
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
        0x04, 0x05, 0x06, 0xFE,
    };
    uint16_t data2_len = sizeof(data2);

    uint8_t data3[] = {
        0x0C, 0x0D, 0x0E, 0x0F, 0x08, 0x09, 0x0A, 0x0B,
        0x04, 0x05, 0x06, 0xFE, 0x02, 0x03, 0x04,
    };
    uint16_t data3_len = sizeof(data3);

    ctx = StreamingParserNewContext();
    if (ctx == NULL) {
        printf("if (ctx == NULL)\n");
        goto end;
    }

    /* first chunk */
    StreamingParserSetData(ctx, (uint8_t *)data1, data1_len);

    if (StreamingParserJump(ctx, 8, &jumped) != STREAMING_PARSER_ROK) {
        printf("failure 1\n");
        goto end;
    }
    if (jumped != 8) {
        printf("failure 2\n");
        goto end;
    }

    if (StreamingParserJump(ctx, 8, &jumped) != STREAMING_PARSER_ROK) {
        printf("failure 4\n");
        goto end;
    }
    if (jumped != 8) {
        printf("failure 5\n");
        goto end;
    }

    if (StreamingParserJump(ctx, 8, &jumped) != STREAMING_PARSER_ROK) {
        printf("failure 7\n");
        goto end;
    }
    if (jumped != 8) {
        printf("failure 8\n");
        goto end;
    }

    if (StreamingParserJump(ctx, 8, &jumped) != STREAMING_PARSER_RDATA) {
        printf("failure 10\n");
        goto end;
    }
    if (jumped != 0) {
        printf("failure 11\n");
        goto end;
    }

    if (StreamingParserJump(ctx, 8, &jumped) != STREAMING_PARSER_RDATA) {
        printf("failure 12\n");
        goto end;
    }
    if (jumped != 0) {
        printf("failure 13\n");
        goto end;
    }


    /* second chunk */

    StreamingParserSetData(ctx, (uint8_t *)data2, data2_len);

    if (StreamingParserJump(ctx, 8, &jumped) != STREAMING_PARSER_ROK) {
        printf("failure 14\n");
        goto end;
    }
    if (jumped != 8) {
        printf("failure 15\n");
        goto end;
    }

    if (StreamingParserJump(ctx, 8, &jumped) != STREAMING_PARSER_ROK) {
        printf("failure 17\n");
        goto end;
    }
    if (jumped != 8) {
        printf("failure 18\n");
        goto end;
    }

    if (StreamingParserJump(ctx, 8, &jumped) != STREAMING_PARSER_RDATA) {
        printf("failure 20\n");
        goto end;
    }
    if (jumped != 4) {
        printf("failure 21\n");
        goto end;
    }

    if (StreamingParserJump(ctx, 1, &jumped) != STREAMING_PARSER_RDATA) {
        printf("failure 23\n");
        goto end;
    }
    if (jumped != 0) {
        printf("failure 24\n");
        goto end;
    }

    if (StreamingParserJump(ctx, 1, &jumped) != STREAMING_PARSER_RDATA) {
        printf("failure 25\n");
        goto end;
    }
    if (jumped != 0) {
        printf("failure 26\n");
        goto end;
    }


    /* third chunk */

    StreamingParserSetData(ctx, (uint8_t *)data3, data3_len);
    if (StreamingParserTestU16(ctx, &u16_value) != STREAMING_PARSER_ROK) {
        printf("failure 27\n");
        goto end;
    }
    if (u16_value != *((uint16_t *)data3)) {
        printf("failure 28\n");
        goto end;
    }

    if (StreamingParserJump(ctx, 4, &jumped) != STREAMING_PARSER_ROK) {
        printf("failure 29\n");
        goto end;
    }
    if (jumped != 4) {
        printf("failure 30\n");
        goto end;
    }

    if (StreamingParserGetU16(ctx, &u16_value) != STREAMING_PARSER_ROK) {
        printf("failure 32\n");
        goto end;
    }
    if (u16_value != *((uint16_t *)(data3 + 4))) {
        printf("failure 33\n");
        goto end;
    }

    if (StreamingParserJump(ctx, 6, &jumped) != STREAMING_PARSER_ROK) {
        printf("failure 34\n");
        goto end;
    }
    if (jumped != 6) {
        printf("failure 35\n");
        goto end;
    }

    if (StreamingParserTestU16(ctx, &u16_value) != STREAMING_PARSER_ROK) {
        printf("failure 37\n");
        goto end;
    }
    if (u16_value != *((uint16_t *)(data3 + 12))) {
        printf("failure 38\n");
        goto end;
    }

    if (StreamingParserJump(ctx, 4, &jumped) != STREAMING_PARSER_RDATA) {
        printf("failure 39\n");
        goto end;
    }
    if (jumped != 3) {
        printf("failure 40\n");
        goto end;
    }

    if (StreamingParserJump(ctx, 1, &jumped) != STREAMING_PARSER_RDATA) {
        printf("failure 42\n");
        goto end;
    }
    if (jumped != 0) {
        printf("failure 43\n");
        goto end;
    }

    retval = 1;
 end:
    return retval;
}

#endif /* UNITTESTS */

void StreamingParserRegisterUnittets(void)
{
#ifdef UNITTESTS
    UtRegisterTest("StreamingParserTest01", StreamingParserTest01, 1);
    UtRegisterTest("StreamingParserTest02", StreamingParserTest02, 1);
    UtRegisterTest("StreamingParserTest03", StreamingParserTest03, 1);
    UtRegisterTest("StreamingParserTest04", StreamingParserTest04, 1);
    UtRegisterTest("StreamingParserTest05", StreamingParserTest05, 1);
    UtRegisterTest("StreamingParserTest06", StreamingParserTest06, 1);
    UtRegisterTest("StreamingParserTest07", StreamingParserTest07, 1);
    UtRegisterTest("StreamingParserTest08", StreamingParserTest08, 1);
    UtRegisterTest("StreamingParserTest09", StreamingParserTest09, 1);
    UtRegisterTest("StreamingParserTest10", StreamingParserTest10, 1);
    UtRegisterTest("StreamingParserTest11", StreamingParserTest11, 1);
    UtRegisterTest("StreamingParserTest12", StreamingParserTest12, 1);
    UtRegisterTest("StreamingParserTest13", StreamingParserTest13, 1);
    UtRegisterTest("StreamingParserTest14", StreamingParserTest14, 1);
#endif

    return;
}
