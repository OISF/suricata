/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-streaming-parser.h"

typedef struct StreamingParserCtx_ {
    /* strut members structured to have as little padding as possible */
    uint8_t *data;
    uint64_t temp_buffer;
    uint8_t temp_buffer_len;
    uint16_t data_len;
} StreamingParserCtx;

void *StreamingParserNewContext(void)
{
    void *p = SCMalloc(sizeof(StreamingParserCtx));
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

int StreamingParserGetU8(void *ctx, uint8_t *ret_input)
{
    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;

    if (tctx->temp_buffer_len > 0) {
        *ret_input = tctx->temp_buffer & 0x000000000000FF;
        tctx->temp_buffer = tctx->temp_buffer >> 8;
        tctx->temp_buffer_len--;
        return STREAMING_PARSER_ROK;
    }

    if (tctx->data_len == 0)
        return STREAMING_PARSER_RDATA;

    *ret_input = *(tctx->data++);
    tctx->data_len--;

    return STREAMING_PARSER_ROK;
}

int StreamingParserGetI8(void *ctx, int8_t *ret_input)
{
    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;

    if (tctx->temp_buffer_len > 0) {
        *ret_input = tctx->temp_buffer & 0x000000000000FF;
        tctx->temp_buffer = tctx->temp_buffer >> 8;
        tctx->temp_buffer_len--;
        return STREAMING_PARSER_ROK;
    }

    if (tctx->data_len == 0)
        return STREAMING_PARSER_RDATA;

    *ret_input = *((int8_t *)tctx->data++);
    tctx->data_len--;

    return STREAMING_PARSER_ROK;
}

static int StreamingParserGetValue(void *ctx, void *ret_input, uint8_t psize)
{
    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;
    uint16_t u;

    if (psize <= tctx->temp_buffer_len) {
        if (psize == 2) {
            *((uint16_t *)ret_input) = tctx->temp_buffer & 0x000000000000FFFF;
        } else if (psize == 4) {
            *((uint32_t *)ret_input) = tctx->temp_buffer & 0x00000000FFFFFFFF;
        } else {
            *((uint64_t *)ret_input) = tctx->temp_buffer & 0xFFFFFFFFFFFFFFFF;
        }
        /* Since a type can't be shifted by a value >= width of the type, we
         * need to split it */
        tctx->temp_buffer = tctx->temp_buffer >> (psize * 8 - 1);
        tctx->temp_buffer = tctx->temp_buffer >> 1;
        tctx->temp_buffer_len -= psize;

        return STREAMING_PARSER_ROK;
    }

    if (tctx->data_len < (psize - tctx->temp_buffer_len) ) {
        for (u = 0; u < tctx->data_len; u++) {
#if __BYTE_ORDER == __BIG_ENDIAN
            tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * (psize - 1 - tctx->temp_buffer_len));
#elif __BYTE_ORDER == __LITTLE_ENDIAN
            tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * tctx->temp_buffer_len);
#else
            #error byte_order_not_defined_hence_compile_time_failure;
#endif
            tctx->temp_buffer_len++;
        }
        tctx->data_len = 0;

        return STREAMING_PARSER_RDATA;
    } else {
        if (tctx->temp_buffer_len == 0) {
            if (psize == 2)
                *((uint16_t *)ret_input) = *((uint16_t *)tctx->data);
            else if (psize == 4)
                *((uint32_t *)ret_input) = *((uint32_t *)tctx->data);
            else
                *((uint64_t *)ret_input) = *((uint64_t *)tctx->data);
            tctx->data += psize;
            tctx->data_len -= psize;
        } else {
            int r_size = psize - tctx->temp_buffer_len;
            for (u = 0; u < r_size; u++) {
#if __BYTE_ORDER == __BIG_ENDIAN
                tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * (psize - 1 - tctx->temp_buffer_len));
#elif __BYTE_ORDER == __LITTLE_ENDIAN
                tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * tctx->temp_buffer_len);
#else
                #error byte_order_not_defined_hence_compile_time_failure;
#endif
                tctx->temp_buffer_len++;
            }

            tctx->data += r_size;
            tctx->data_len -= r_size;
            tctx->temp_buffer_len = 0;
            if (psize == 2)
                *((uint16_t *)ret_input) = tctx->temp_buffer;
            else if (psize == 4)
                *((uint32_t *)ret_input) = tctx->temp_buffer;
            else
                *((uint64_t *)ret_input) = tctx->temp_buffer;
            tctx->temp_buffer = 0;
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

static int StreamingParserGetValueWithBO(void *ctx, void *ret_input, uint8_t psize, uint8_t bo)
{
    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;
    uint16_t u;

    if (psize <= tctx->temp_buffer_len) {
        if (psize == 2) {
            *((uint16_t *)ret_input) = tctx->temp_buffer & 0x000000000000FFFF;
        } else if (psize == 4) {
            *((uint32_t *)ret_input) = tctx->temp_buffer & 0x00000000FFFFFFFF;
        } else {
            *((uint64_t *)ret_input) = tctx->temp_buffer & 0xFFFFFFFFFFFFFFFF;
        }
        tctx->temp_buffer = tctx->temp_buffer >> (psize * 8 - 1);
        tctx->temp_buffer = tctx->temp_buffer >> 1;
        tctx->temp_buffer_len -= psize;

        return STREAMING_PARSER_ROK;
    }

    if (tctx->data_len < (psize - tctx->temp_buffer_len) ) {
        for (u = 0; u < tctx->data_len; u++) {
            if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
                tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * (psize - 1 - tctx->temp_buffer_len));
            else
                tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * tctx->temp_buffer_len);
            tctx->temp_buffer_len++;
        }
        tctx->data_len = 0;

        return STREAMING_PARSER_RDATA;
    } else {
        if (tctx->temp_buffer_len == 0) {
            if (bo == STREAMING_PARSER_BO_BIG_ENDIAN) {
#if __BYTE_ORDER == __BIG_ENDIAN
                if (psize == 2)
                    *((uint16_t *)ret_input) = *((uint16_t *)tctx->data);
                else if (psize == 4)
                    *((uint32_t *)ret_input) = *((uint32_t *)tctx->data);
                else
                    *((uint64_t *)ret_input) = *((uint64_t *)tctx->data);
#else
                for (u = 0; u < psize; u++) {
                    tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * (psize - 1 - u));
                }
                if (psize == 2)
                    *((uint16_t *)ret_input) = tctx->temp_buffer;
                else if (psize == 4)
                    *((uint32_t *)ret_input) = tctx->temp_buffer;
                else
                    *((uint64_t *)ret_input) = tctx->temp_buffer;
                tctx->temp_buffer = 0;
#endif
            } else {
#if __BYTE_ORDER == __LITTLE_ENDIAN
                if (psize == 2)
                    *((uint16_t *)ret_input) = *((uint16_t *)tctx->data);
                else if (psize == 4)
                    *((uint32_t *)ret_input) = *((uint32_t *)tctx->data);
                else
                    *((uint64_t *)ret_input) = *((uint64_t *)tctx->data);
#else
                for (u = 0; u < psize; u++) {
                    tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * u);
                }
                if (psize == 2)
                    *((uint16_t *)ret_input) = tctx->temp_buffer;
                else if (psize == 4)
                    *((uint32_t *)ret_input) = tctx->temp_buffer;
                else
                    *((uint64_t *)ret_input) = tctx->temp_buffer;
                tctx->temp_buffer = 0;
#endif
            }

            tctx->data += psize;
            tctx->data_len -= psize;
        } else {
            int r_size = psize - tctx->temp_buffer_len;
            for (u = 0; u < r_size; u++) {
                if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
                    tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * (psize - 1 - tctx->temp_buffer_len));
                else
                    tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * tctx->temp_buffer_len);
                tctx->temp_buffer_len++;
            }

            tctx->data += r_size;
            tctx->data_len -= r_size;
            tctx->temp_buffer_len = 0;
            if (psize == 2)
                *((uint16_t *)ret_input) = tctx->temp_buffer;
            else if (psize == 4)
                *((uint32_t *)ret_input) = tctx->temp_buffer;
            else
                *((uint64_t *)ret_input) = tctx->temp_buffer;
            tctx->temp_buffer = 0;
        }

        return STREAMING_PARSER_ROK;
    }
}

int StreamingParserGetU16WithBO(void *ctx, uint16_t *ret_input, uint8_t bo)
{
    return StreamingParserGetValueWithBO(ctx, (void *)ret_input, sizeof(uint16_t), bo);
}

int StreamingParserGetI16WithBO(void *ctx, int16_t *ret_input, uint8_t bo)
{
    return StreamingParserGetValueWithBO(ctx, (void *)ret_input, sizeof(int16_t), bo);
}

int StreamingParserGetU32WithBO(void *ctx, uint32_t *ret_input, uint8_t bo)
{
    return StreamingParserGetValueWithBO(ctx, (void *)ret_input, sizeof(uint32_t), bo);
}

int StreamingParserGetI32WithBO(void *ctx, int32_t *ret_input, uint8_t bo)
{
    return StreamingParserGetValueWithBO(ctx, (void *)ret_input, sizeof(int32_t), bo);
}

int StreamingParserGetU64WithBO(void *ctx, uint64_t *ret_input, uint8_t bo)
{
    return StreamingParserGetValueWithBO(ctx, (void *)ret_input, sizeof(uint64_t), bo);
}

int StreamingParserGetI64WithBO(void *ctx, int64_t *ret_input, uint8_t bo)
{
    return StreamingParserGetValueWithBO(ctx, (void *)ret_input, sizeof(int64_t), bo);
}

/*****Test functions*****/

int StreamingParserTestU8(void *ctx, uint8_t *ret_input)
{
    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;

    if (tctx->temp_buffer_len > 0) {
        *ret_input = tctx->temp_buffer & 0x000000000000FF;
        return STREAMING_PARSER_ROK;
    }

    if (tctx->data_len == 0)
        return STREAMING_PARSER_RDATA;

    *ret_input = *(tctx->data++);
    tctx->data_len--;
    tctx->temp_buffer = *ret_input;
    tctx->temp_buffer_len++;

    return STREAMING_PARSER_ROK;
}

int StreamingParserTestI8(void *ctx, int8_t *ret_input)
{
    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;

    if (tctx->temp_buffer_len > 0) {
        *ret_input = tctx->temp_buffer & 0x000000000000FF;
        return STREAMING_PARSER_ROK;
    }

    if (tctx->data_len == 0)
        return STREAMING_PARSER_RDATA;

    *ret_input = *(tctx->data++);
    tctx->data_len--;
    tctx->temp_buffer = *ret_input;
    tctx->temp_buffer_len++;

    return STREAMING_PARSER_ROK;
}

static int StreamingParserTestValue(void *ctx, void *ret_input, uint8_t psize)
{
    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;
    uint16_t u;

    if (psize <= tctx->temp_buffer_len) {
        if (psize == 2)
            *((uint16_t *)ret_input) = tctx->temp_buffer & 0x000000000000FFFF;
        else if (psize == 4)
            *((uint32_t *)ret_input) = tctx->temp_buffer & 0x00000000FFFFFFFF;
        else
            *((uint64_t *)ret_input) = tctx->temp_buffer & 0xFFFFFFFFFFFFFFFF;

        return STREAMING_PARSER_ROK;
    }

    if (tctx->data_len < (psize - tctx->temp_buffer_len) ) {
        for (u = 0; u < tctx->data_len; u++) {
#if __BYTE_ORDER == __BIG_ENDIAN
            tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * (psize - 1 - tctx->temp_buffer_len));
#elif __BYTE_ORDER == __LITTLE_ENDIAN
            tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * tctx->temp_buffer_len);
#else
            #error byte_order_not_defined_hence_compile_time_failure;
#endif
            tctx->temp_buffer_len++;
        }
        tctx->data_len = 0;

        return STREAMING_PARSER_RDATA;
    } else {
        if (tctx->temp_buffer_len == 0) {
            if (psize == 2) {
                *((uint16_t *)ret_input) = *((uint16_t *)tctx->data);
                tctx->temp_buffer = *((uint16_t *)ret_input);
            } else if (psize == 4) {
                *((uint32_t *)ret_input) = *((uint32_t *)tctx->data);
                tctx->temp_buffer = *((uint32_t *)ret_input);
            } else {
                *((uint64_t *)ret_input) = *((uint64_t *)tctx->data);
                tctx->temp_buffer = *((uint64_t *)ret_input);
            }
            tctx->temp_buffer_len = psize;
            tctx->data += psize;
            tctx->data_len -= psize;
        } else {
            int r_size = psize - tctx->temp_buffer_len;
            for (u = 0; u < r_size; u++) {
#if __BYTE_ORDER == __BIG_ENDIAN
                tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * (psize - 1 - tctx->temp_buffer_len));
#elif __BYTE_ORDER == __LITTLE_ENDIAN
                tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * tctx->temp_buffer_len);
#else
                #error byte_order_not_defined_hence_compile_time_failure;
#endif
                tctx->temp_buffer_len++;
            }

            tctx->data += r_size;
            tctx->data_len -= r_size;
            tctx->temp_buffer_len = psize;
            if (psize == 2)
                *((uint16_t *)ret_input) = tctx->temp_buffer;
            else if (psize == 4)
                *((uint32_t *)ret_input) = tctx->temp_buffer;
            else
                *((uint64_t *)ret_input) = tctx->temp_buffer;
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

static int StreamingParserTestValueWithBO(void *ctx, void *ret_input, uint8_t psize, uint8_t bo)
{
    StreamingParserCtx *tctx = (StreamingParserCtx *)ctx;
    uint16_t u;

    if (psize <= tctx->temp_buffer_len) {
        if (psize == 2)
            *((uint16_t *)ret_input) = tctx->temp_buffer & 0x000000000000FFFF;
        else if (psize == 4)
            *((uint32_t *)ret_input) = tctx->temp_buffer & 0x00000000FFFFFFFF;
        else
            *((uint64_t *)ret_input) = tctx->temp_buffer & 0xFFFFFFFFFFFFFFFF;

        return STREAMING_PARSER_ROK;
    }

    if (tctx->data_len < (psize - tctx->temp_buffer_len) ) {
        for (u = 0; u < tctx->data_len; u++) {
            if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
                tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * (psize - 1 - tctx->temp_buffer_len));
            else
                tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * tctx->temp_buffer_len);
            tctx->temp_buffer_len++;
        }
        tctx->data_len = 0;

        return STREAMING_PARSER_RDATA;
    } else {
        if (tctx->temp_buffer_len == 0) {
            if (bo == STREAMING_PARSER_BO_BIG_ENDIAN) {
#if __BYTE_ORDER == __BIG_ENDIAN
                if (psize == 2) {
                    *((uint16_t *)ret_input) = *((uint16_t *)tctx->data);
                    tctx->temp_buffer = *((uint16_t *)ret_input);
                } else if (psize == 4) {
                    *((uint32_t *)ret_input) = *((uint32_t *)tctx->data);
                    tctx->temp_buffer = *((uint32_t *)ret_input);
                } else {
                    *((uint64_t *)ret_input) = *((uint64_t *)tctx->data);
                    tctx->temp_buffer = *((uint64_t *)ret_input);
                }
#else
                for (u = 0; u < psize; u++) {
                    tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * (psize - 1 - u));
                }
                if (psize == 2) {
                    *((uint16_t *)ret_input) = tctx->temp_buffer;
                } else if (psize == 4) {
                    *((uint32_t *)ret_input) = tctx->temp_buffer;
                } else {
                    *((uint64_t *)ret_input) = tctx->temp_buffer;
                }
#endif
            } else {
#if __BYTE_ORDER == __LITTLE_ENDIAN
                if (psize == 2) {
                    *((uint16_t *)ret_input) = *((uint16_t *)tctx->data);
                    tctx->temp_buffer = *((uint16_t *)ret_input);
                } else if (psize == 4) {
                    *((uint32_t *)ret_input) = *((uint32_t *)tctx->data);
                    tctx->temp_buffer = *((uint32_t *)ret_input);
                } else {
                    *((uint64_t *)ret_input) = *((uint64_t *)tctx->data);
                    tctx->temp_buffer = *((uint64_t *)ret_input);
                }
#else
                for (u = 0; u < psize; u++) {
                    tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * u);
                }
                if (psize == 2) {
                    *((uint16_t *)ret_input) = tctx->temp_buffer;
                } else if (psize == 4) {
                    *((uint32_t *)ret_input) = tctx->temp_buffer;
                } else {
                    *((uint64_t *)ret_input) = tctx->temp_buffer;
                }
#endif
            }

            tctx->temp_buffer_len = psize;
            tctx->data += psize;
            tctx->data_len -= psize;
        } else {
            int r_size = psize - tctx->temp_buffer_len;
            for (u = 0; u < r_size; u++) {
                if (bo == STREAMING_PARSER_BO_BIG_ENDIAN)
                    tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * (psize - 1 - tctx->temp_buffer_len));
                else
                    tctx->temp_buffer |= (uint64_t)tctx->data[u] << (8 * tctx->temp_buffer_len);
                tctx->temp_buffer_len++;
            }

            tctx->data += r_size;
            tctx->data_len -= r_size;
            tctx->temp_buffer_len = psize;
            if (psize == 2)
                *((uint16_t *)ret_input) = tctx->temp_buffer;
            else if (psize == 4)
                *((uint32_t *)ret_input) = tctx->temp_buffer;
            else
                *((uint64_t *)ret_input) = tctx->temp_buffer;
        }

        return STREAMING_PARSER_ROK;
    }

}

int StreamingParserTestU16WithBO(void *ctx, uint16_t *ret_input, uint8_t bo)
{
    return StreamingParserTestValueWithBO(ctx, (void *)ret_input, sizeof(uint16_t), bo);
}

int StreamingParserTestI16WithBO(void *ctx, int16_t *ret_input, uint8_t bo)
{
    return StreamingParserTestValueWithBO(ctx, (void *)ret_input, sizeof(int16_t), bo);
}

int StreamingParserTestU32WithBO(void *ctx, uint32_t *ret_input, uint8_t bo)
{
    return StreamingParserTestValueWithBO(ctx, (void *)ret_input, sizeof(uint32_t), bo);
}

int StreamingParserTestI32WithBO(void *ctx, int32_t *ret_input, uint8_t bo)
{
    return StreamingParserTestValueWithBO(ctx, (void *)ret_input, sizeof(int32_t), bo);
}

int StreamingParserTestU64WithBO(void *ctx, uint64_t *ret_input, uint8_t bo)
{
    return StreamingParserTestValueWithBO(ctx, (void *)ret_input, sizeof(uint64_t), bo);
}

int StreamingParserTestI64WithBO(void *ctx, int64_t *ret_input, uint8_t bo)
{
    return StreamingParserTestValueWithBO(ctx, (void *)ret_input, sizeof(int64_t), bo);
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
#endif

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
#endif

    return;
}
