/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 *
 * Implements the nocase keyword
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-parse.h"
#include "detect-transform-compress-whitespace.h"

#include "util-unittest.h"
#include "util-print.h"

static int DetectTransformCompressWhitespaceSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectTransformCompressWhitespaceRegisterTests(void);

static void TransformCompressWhitespace(InspectionBuffer *buffer);

void DetectTransformCompressWhitespaceRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].name = "compress_whitespace";
    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].desc =
        "modify buffer to strip whitespace before inspection";
    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].url =
        DOC_URL DOC_VERSION "/rules/transforms.html#compress-whitespace";
    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].Transform =
        TransformCompressWhitespace;
    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].Setup =
        DetectTransformCompressWhitespaceSetup;
    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].RegisterTests =
        DetectTransformCompressWhitespaceRegisterTests;

    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].flags |= SIGMATCH_NOOPT;
}

/**
 *  \internal
 *  \brief Apply the nocase keyword to the last pattern match, either content or uricontent
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param nullstr should be null
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformCompressWhitespaceSetup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_COMPRESS_WHITESPACE);
    SCReturnInt(r);
}

static void TransformCompressWhitespace(InspectionBuffer *buffer)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    uint8_t output[input_len]; // we can only shrink
    uint8_t *oi = output, *os = output;

    //PrintRawDataFp(stdout, input, input_len);
    for (uint32_t i = 0; i < input_len; ) {
        if (!(isspace(*input))) {
            *oi++ = *input++;
            i++;
        } else {
            *oi++ = *input++;
            i++;

            while (i < input_len && isspace(*input)) {
                input++;
                i++;
            }
        }
    }
    uint32_t output_size = oi - os;
    //PrintRawDataFp(stdout, output, output_size);

    InspectionBufferCopy(buffer, os, output_size);
}

#ifdef UNITTESTS
static int TransformDoubleWhitespace(InspectionBuffer *buffer)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    uint8_t output[input_len * 2]; // if all chars are whitespace this fits
    uint8_t *oi = output, *os = output;

    PrintRawDataFp(stdout, input, input_len);
    for (uint32_t i = 0; i < input_len; i++) {
        if (isspace(*input)) {
            *oi++ = *input;
        }
        *oi++ = *input;
        input++;
    }
    uint32_t output_size = oi - os;
    PrintRawDataFp(stdout, output, output_size);

    InspectionBufferCopy(buffer, os, output_size);
    return 0;
}

static int DetectTransformCompressWhitespaceTest01(void)
{
    const uint8_t *input = (const uint8_t *)" A B C D ";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 8);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformCompressWhitespace(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformCompressWhitespaceTest02(void)
{
    const uint8_t *input = (const uint8_t *)" A B C D ";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 8);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDoubleWhitespace(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDoubleWhitespace(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformCompressWhitespace(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformCompressWhitespaceTest03(void)
{
    const char rule[] = "alert http any any -> any any (http_request_line; strip_whitespace; content:\"GET/HTTP\"; sid:1;)";
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    Signature *s = DetectEngineAppendSig(de_ctx, rule);
    FAIL_IF_NULL(s);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

#endif

static void DetectTransformCompressWhitespaceRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectTransformCompressWhitespaceTest01",
            DetectTransformCompressWhitespaceTest01);
    UtRegisterTest("DetectTransformCompressWhitespaceTest02",
            DetectTransformCompressWhitespaceTest02);
    UtRegisterTest("DetectTransformCompressWhitespaceTest03",
            DetectTransformCompressWhitespaceTest03);
#endif
}
