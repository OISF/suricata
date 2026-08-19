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
    SCAppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);
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
    SCAppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);
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
    SCAppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);
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
    SCAppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);
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
    UtRegisterTest("DetectEngineSMTPFiledataTest02", DetectEngineSMTPFiledataTest02);
    UtRegisterTest("DetectFiledataParseTest04", DetectFiledataParseTest04);
}
#endif
