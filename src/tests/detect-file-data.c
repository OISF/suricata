/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Giuseppe Longo <giuseppelng@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#ifdef UNITTESTS

#include "../stream-tcp.h"
#include "../detect.h"
#include "../detect-isdataat.h"
#include "../detect-engine-inspect-buffer.h"
#include "../util-file-decompression.h"
#include "../util-file-swf-decompression.h"
#include "../app-layer-events.h"
#include "../app-layer-htp.h"

#include <zlib.h>

static uint8_t *DetectFiledataSwfCreateCws(const uint8_t *plain, uint32_t plain_len,
        uint32_t file_len, int compression_level, uint32_t *cws_len)
{
    uLongf compressed_len = compressBound(plain_len);
    uint8_t *cws = SCMalloc(SWF_HEADER_LEN + compressed_len);
    if (cws == NULL)
        return NULL;

    cws[0] = 'C';
    cws[1] = 'W';
    cws[2] = 'S';
    cws[3] = 0x06;
    cws[4] = (uint8_t)file_len;
    cws[5] = (uint8_t)(file_len >> 8);
    cws[6] = (uint8_t)(file_len >> 16);
    cws[7] = (uint8_t)(file_len >> 24);

    int r = compress2(cws + SWF_HEADER_LEN, &compressed_len, plain, plain_len, compression_level);
    if (r != Z_OK || compressed_len > UINT32_MAX - SWF_HEADER_LEN) {
        SCFree(cws);
        return NULL;
    }
    *cws_len = SWF_HEADER_LEN + (uint32_t)compressed_len;
    return cws;
}

// clang-format off
static const uint8_t swf_lzma_fixture[] = {
    0x5a, 0x57, 0x53, 0x17, 0x5c, 0x24, 0x00, 0x00, 0xb7, 0x21, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x20,
    0x00, 0x00, 0x3b, 0xff, 0xfc, 0x8e, 0x19, 0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85,
    0xf5, 0x75, 0x6f, 0xd0, 0x7e, 0x61, 0x35, 0x1b, 0x1a, 0x8b, 0x16, 0x4d, 0xdf, 0x05, 0x32, 0xfe,
    0xa4, 0x4c, 0x46, 0x49, 0xb7, 0x7b, 0x6b, 0x75, 0xf9, 0x2b, 0x5c, 0x37, 0x29, 0x0b, 0x91, 0x37,
    0x01, 0x37, 0x0e, 0xe9, 0xf2, 0xe1, 0xfc, 0x9e, 0x64, 0xda, 0x6c, 0x11, 0x21, 0x33, 0xed, 0xa0,
    0x0e, 0x76, 0x70, 0xa0, 0xcd, 0x98, 0x2e, 0x76, 0x80, 0xf0, 0xe0, 0x59, 0x56, 0x06, 0x08, 0xe9,
    0xca, 0xeb, 0xa2, 0xc6, 0xdb, 0x5a, 0x86,
};
// clang-format on

/**
 * \test A malicious SWF whose header claims a huge decompressed size but
 *       carries only a few bytes of body must not drive a large allocation
 *       of the inspection buffer.
 */
static int DetectFiledataSwfDecompressAllocTest01(void)
{
    uint8_t buffer[] = { 'C', 'W', 'S', 0x06, 0x80, 0xF0, 0xFA, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07 };

    DetectEngineThreadCtx *det_ctx = SCCalloc(1, sizeof(*det_ctx));
    FAIL_IF_NULL(det_ctx);

    InspectionBuffer out_buffer;
    memset(&out_buffer, 0, sizeof(out_buffer));

    int r = FileSwfDecompression(buffer, (uint32_t)sizeof(buffer), det_ctx, &out_buffer,
            HTTP_SWF_COMPRESSION_ZLIB, 0, 0);

    FAIL_IF(r != 0);
    FAIL_IF(out_buffer.size > SWF_DECOMPRESS_INITIAL_BUFFER_LEN);

    InspectionBufferFree(&out_buffer);
    AppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);
    SCFree(det_ctx);
    PASS;
}

/**
 * \test A valid, small CWS with a forged large FileLength must only retain the
 *       buffer needed for its actual output.
 */
static int DetectFiledataSwfDecompressAllocTest02(void)
{
    const uint8_t plain[] = "small compressed SWF body";
    const uint32_t file_len = MAX_SWF_DECOMPRESSED_LEN;
    uint32_t cws_len = 0;
    uint8_t *cws = DetectFiledataSwfCreateCws(
            plain, sizeof(plain), file_len, Z_BEST_COMPRESSION, &cws_len);
    FAIL_IF_NULL(cws);

    DetectEngineThreadCtx *det_ctx = SCCalloc(1, sizeof(*det_ctx));
    FAIL_IF_NULL(det_ctx);
    InspectionBuffer out_buffer = { 0 };

    int r = FileSwfDecompression(
            cws, cws_len, det_ctx, &out_buffer, HTTP_SWF_COMPRESSION_ZLIB, 0, 0);

    FAIL_IF(r != 1);
    FAIL_IF(out_buffer.size > SWF_DECOMPRESS_INITIAL_BUFFER_LEN);
    FAIL_IF(out_buffer.len != SWF_HEADER_LEN + sizeof(plain));
    FAIL_IF(memcmp(out_buffer.buf + 4, cws + 4, 4) != 0);
    FAIL_IF(memcmp(out_buffer.buf + SWF_HEADER_LEN, plain, sizeof(plain)) != 0);

    InspectionBufferFree(&out_buffer);
    AppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);
    SCFree(det_ctx);
    SCFree(cws);
    PASS;
}

/**
 * \test A weakly compressed CWS must not reserve the maximum possible zlib
 *       expansion in the per-thread inspection buffer.
 */
static int DetectFiledataSwfDecompressAllocTest03(void)
{
    const uint32_t plain_len = 48 * 1024;
    uint8_t *plain = SCMalloc(plain_len);
    FAIL_IF_NULL(plain);
    for (uint32_t i = 0; i < plain_len; i++)
        plain[i] = (uint8_t)i;

    uint32_t cws_len = 0;
    uint8_t *cws = DetectFiledataSwfCreateCws(
            plain, plain_len, plain_len + SWF_HEADER_LEN, Z_NO_COMPRESSION, &cws_len);
    FAIL_IF_NULL(cws);

    DetectEngineThreadCtx *det_ctx = SCCalloc(1, sizeof(*det_ctx));
    FAIL_IF_NULL(det_ctx);
    InspectionBuffer out_buffer = { 0 };

    int r = FileSwfDecompression(
            cws, cws_len, det_ctx, &out_buffer, HTTP_SWF_COMPRESSION_ZLIB, 0, 0);

    FAIL_IF(r != 1);
    FAIL_IF(out_buffer.size > 64 * 1024);
    FAIL_IF(out_buffer.len != SWF_HEADER_LEN + plain_len);
    FAIL_IF(memcmp(out_buffer.buf + SWF_HEADER_LEN, plain, plain_len) != 0);

    InspectionBufferFree(&out_buffer);
    AppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);
    SCFree(det_ctx);
    SCFree(cws);
    SCFree(plain);
    PASS;
}

/**
 * \test A ZWS with a forged large FileLength and invalid LZMA properties must
 *       fail without growing the inspection buffer.
 */
static int DetectFiledataSwfDecompressAllocTest04(void)
{
    uint8_t buffer[] = { 'Z', 'W', 'S', 0x0D, 0x80, 0xF0, 0xFA, 0x02, 0x01, 0x00, 0x00, 0x00, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00 };

    DetectEngineThreadCtx *det_ctx = SCCalloc(1, sizeof(*det_ctx));
    FAIL_IF_NULL(det_ctx);
    InspectionBuffer out_buffer = { 0 };

    int r = FileSwfDecompression(buffer, (uint32_t)sizeof(buffer), det_ctx, &out_buffer,
            HTTP_SWF_COMPRESSION_LZMA, 0, 0);

    FAIL_IF(r != 0);
    FAIL_IF(out_buffer.size > SWF_DECOMPRESS_INITIAL_BUFFER_LEN);

    InspectionBufferFree(&out_buffer);
    AppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);
    SCFree(det_ctx);
    PASS;
}

/**
 * \test A CWS FileLength value of one must not truncate decompression or
 *       discard content beyond the first output byte.
 */
static int DetectFiledataSwfDecompressFileLengthTest01(void)
{
    const uint32_t plain_len = 16 * 1024;
    uint8_t *plain = SCMalloc(plain_len);
    FAIL_IF_NULL(plain);
    memset(plain, 'A', plain_len);
    plain[plain_len - 1] = 'B';

    uint32_t cws_len = 0;
    uint8_t *cws = DetectFiledataSwfCreateCws(plain, plain_len, 1, Z_BEST_COMPRESSION, &cws_len);
    FAIL_IF_NULL(cws);

    DetectEngineThreadCtx *det_ctx = SCCalloc(1, sizeof(*det_ctx));
    FAIL_IF_NULL(det_ctx);
    InspectionBuffer out_buffer = { 0 };

    int r = FileSwfDecompression(
            cws, cws_len, det_ctx, &out_buffer, HTTP_SWF_COMPRESSION_ZLIB, 0, 0);

    FAIL_IF(r != 1);
    FAIL_IF(out_buffer.len != SWF_HEADER_LEN + plain_len);
    FAIL_IF(out_buffer.buf[out_buffer.len - 1] != 'B');
    FAIL_IF(memcmp(out_buffer.buf + 4, cws + 4, 4) != 0);

    InspectionBufferFree(&out_buffer);
    AppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);
    SCFree(det_ctx);
    SCFree(cws);
    SCFree(plain);
    PASS;
}

/**
 * \test A ZWS FileLength value of one must not truncate decompression.
 */
static int DetectFiledataSwfDecompressFileLengthTest02(void)
{
    uint8_t zws[sizeof(swf_lzma_fixture)];
    memcpy(zws, swf_lzma_fixture, sizeof(zws));
    zws[4] = 1;
    zws[5] = 0;
    zws[6] = 0;
    zws[7] = 0;

    DetectEngineThreadCtx *det_ctx = SCCalloc(1, sizeof(*det_ctx));
    FAIL_IF_NULL(det_ctx);
    InspectionBuffer out_buffer = { 0 };

    int r = FileSwfDecompression(
            zws, (uint32_t)sizeof(zws), det_ctx, &out_buffer, HTTP_SWF_COMPRESSION_LZMA, 0, 0);

    FAIL_IF(r != 1);
    FAIL_IF(out_buffer.len <= SWF_HEADER_LEN + 1);
    FAIL_IF(memcmp(out_buffer.buf + 4, zws + 4, 4) != 0);

    InspectionBufferFree(&out_buffer);
    AppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);
    SCFree(det_ctx);
    PASS;
}

/**
 * \test A valid small FileLength is preserved in the synthesized FWS header.
 */
static int DetectFiledataSwfDecompressHeaderTest01(void)
{
    const uint8_t plain[] = "small body";
    const uint32_t file_len = SWF_HEADER_LEN + sizeof(plain);
    uint32_t cws_len = 0;
    uint8_t *cws = DetectFiledataSwfCreateCws(
            plain, sizeof(plain), file_len, Z_BEST_COMPRESSION, &cws_len);
    FAIL_IF_NULL(cws);

    DetectEngineThreadCtx *det_ctx = SCCalloc(1, sizeof(*det_ctx));
    FAIL_IF_NULL(det_ctx);
    InspectionBuffer out_buffer = { 0 };

    int r = FileSwfDecompression(
            cws, cws_len, det_ctx, &out_buffer, HTTP_SWF_COMPRESSION_ZLIB, 0, 0);

    FAIL_IF(r != 1);
    FAIL_IF(memcmp(out_buffer.buf + 4, cws + 4, 4) != 0);

    InspectionBufferFree(&out_buffer);
    AppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);
    SCFree(det_ctx);
    SCFree(cws);
    PASS;
}

/**
 * \test The configured decompression depth remains the CWS output limit.
 */
static int DetectFiledataSwfDecompressDepthTest01(void)
{
    const uint32_t plain_len = 16 * 1024;
    const uint32_t decompress_depth = 5000;
    uint8_t *plain = SCMalloc(plain_len);
    FAIL_IF_NULL(plain);
    memset(plain, 'A', plain_len);
    plain[plain_len - 1] = 'B';

    uint32_t cws_len = 0;
    uint8_t *cws = DetectFiledataSwfCreateCws(
            plain, plain_len, plain_len + SWF_HEADER_LEN, Z_BEST_COMPRESSION, &cws_len);
    FAIL_IF_NULL(cws);

    DetectEngineThreadCtx *det_ctx = SCCalloc(1, sizeof(*det_ctx));
    FAIL_IF_NULL(det_ctx);
    InspectionBuffer out_buffer = { 0 };

    int r = FileSwfDecompression(
            cws, cws_len, det_ctx, &out_buffer, HTTP_SWF_COMPRESSION_ZLIB, decompress_depth, 0);

    FAIL_IF(r != 1);
    FAIL_IF(out_buffer.len != SWF_HEADER_LEN + decompress_depth);
    FAIL_IF(memcmp(out_buffer.buf + SWF_HEADER_LEN, plain, decompress_depth) != 0);

    InspectionBufferFree(&out_buffer);
    AppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);
    SCFree(det_ctx);
    SCFree(cws);
    SCFree(plain);
    PASS;
}

/**
 * \test The configured decompression depth remains the ZWS output limit.
 */
static int DetectFiledataSwfDecompressDepthTest02(void)
{
    const uint32_t decompress_depth = 1;
    DetectEngineThreadCtx *det_ctx = SCCalloc(1, sizeof(*det_ctx));
    FAIL_IF_NULL(det_ctx);
    InspectionBuffer out_buffer = { 0 };

    int r = FileSwfDecompression(swf_lzma_fixture, (uint32_t)sizeof(swf_lzma_fixture), det_ctx,
            &out_buffer, HTTP_SWF_COMPRESSION_LZMA, decompress_depth, 0);

    FAIL_IF(r != 1);
    FAIL_IF(out_buffer.len != SWF_HEADER_LEN + decompress_depth);

    InspectionBufferFree(&out_buffer);
    AppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);
    SCFree(det_ctx);
    PASS;
}

/**
 * \test SWF decompression rejects depth values above the supported limits.
 */
static int DetectFiledataSwfDecompressDepthTest03(void)
{
    DetectEngineThreadCtx *det_ctx = SCCalloc(1, sizeof(*det_ctx));
    FAIL_IF_NULL(det_ctx);
    InspectionBuffer out_buffer = { 0 };

    int r = FileSwfDecompression(swf_lzma_fixture, (uint32_t)sizeof(swf_lzma_fixture), det_ctx,
            &out_buffer, HTTP_SWF_COMPRESSION_LZMA, MAX_SWF_DECOMPRESS_DEPTH + 1, 0);
    FAIL_IF(r != 0);
    FAIL_IF_NOT_NULL(out_buffer.buf);

    r = FileSwfDecompression(swf_lzma_fixture, (uint32_t)sizeof(swf_lzma_fixture), det_ctx,
            &out_buffer, HTTP_SWF_COMPRESSION_LZMA, 0, MAX_SWF_COMPRESS_DEPTH + 1);
    FAIL_IF(r != 0);
    FAIL_IF_NOT_NULL(out_buffer.buf);

    AppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);
    SCFree(det_ctx);
    PASS;
}

static int DetectEngineSMTPFiledataTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NOT(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert smtp any any -> any any "
                                                 "(msg:\"file_data smtp test\"; "
                                                 "file_data; content:\"message\"; sid:1;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NOT(s->flags & SIG_FLAG_TOSERVER);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Test the file_data fails with flow:to_server.
 */
static int DetectFiledataParseTest04(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert smtp any any -> any any "
            "(msg:\"test\"; flow:to_client,established; file_data; content:\"abc\"; sid:1;)");
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

void DetectFiledataRegisterTests(void)
{
    UtRegisterTest(
            "DetectFiledataSwfDecompressAllocTest01", DetectFiledataSwfDecompressAllocTest01);
    UtRegisterTest(
            "DetectFiledataSwfDecompressAllocTest02", DetectFiledataSwfDecompressAllocTest02);
    UtRegisterTest(
            "DetectFiledataSwfDecompressAllocTest03", DetectFiledataSwfDecompressAllocTest03);
    UtRegisterTest(
            "DetectFiledataSwfDecompressAllocTest04", DetectFiledataSwfDecompressAllocTest04);
    UtRegisterTest("DetectFiledataSwfDecompressFileLengthTest01",
            DetectFiledataSwfDecompressFileLengthTest01);
    UtRegisterTest("DetectFiledataSwfDecompressFileLengthTest02",
            DetectFiledataSwfDecompressFileLengthTest02);
    UtRegisterTest(
            "DetectFiledataSwfDecompressHeaderTest01", DetectFiledataSwfDecompressHeaderTest01);
    UtRegisterTest(
            "DetectFiledataSwfDecompressDepthTest01", DetectFiledataSwfDecompressDepthTest01);
    UtRegisterTest(
            "DetectFiledataSwfDecompressDepthTest02", DetectFiledataSwfDecompressDepthTest02);
    UtRegisterTest(
            "DetectFiledataSwfDecompressDepthTest03", DetectFiledataSwfDecompressDepthTest03);
    UtRegisterTest("DetectEngineSMTPFiledataTest02", DetectEngineSMTPFiledataTest02);
    UtRegisterTest("DetectFiledataParseTest04", DetectFiledataParseTest04);
}
#endif
