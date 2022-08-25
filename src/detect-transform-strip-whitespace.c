/* Copyright (C) 2007-2020 Open Information Security Foundation
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
#include "detect-transform-strip-whitespace.h"

#include "util-unittest.h"
#include "util-print.h"

static int DetectTransformStripWhitespaceSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectTransformStripWhitespaceRegisterTests(void);
#endif
static void TransformStripWhitespace(InspectionBuffer *buffer, void *options);
static bool TransformStripWhitespaceValidate(const uint8_t *content, uint16_t content_len, void *options);

void DetectTransformStripWhitespaceRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_STRIP_WHITESPACE].name = "strip_whitespace";
    sigmatch_table[DETECT_TRANSFORM_STRIP_WHITESPACE].desc =
        "modify buffer to strip whitespace before inspection";
    sigmatch_table[DETECT_TRANSFORM_STRIP_WHITESPACE].url =
        "/rules/transforms.html#strip-whitespace";
    sigmatch_table[DETECT_TRANSFORM_STRIP_WHITESPACE].Transform =
        TransformStripWhitespace;
    sigmatch_table[DETECT_TRANSFORM_STRIP_WHITESPACE].TransformValidate =
        TransformStripWhitespaceValidate;
    sigmatch_table[DETECT_TRANSFORM_STRIP_WHITESPACE].Setup =
        DetectTransformStripWhitespaceSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TRANSFORM_STRIP_WHITESPACE].RegisterTests =
        DetectTransformStripWhitespaceRegisterTests;
#endif
    sigmatch_table[DETECT_TRANSFORM_STRIP_WHITESPACE].flags |= SIGMATCH_NOOPT;
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
static int DetectTransformStripWhitespaceSetup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_STRIP_WHITESPACE, NULL);
    SCReturnInt(r);
}

/*
 *  \brief Validate content bytes to see if it's compatible with this transform
 *  \param content Byte array to check for compatibility
 *  \param content_len Number of bytes to check
 *  \param options Ignored
 *  \retval false If the string contains spaces
 *  \retval true Otherwise.
 */
static bool TransformStripWhitespaceValidate(const uint8_t *content,
        uint16_t content_len, void *options)
{
    if (content) {
        for (uint32_t i = 0; i < content_len; i++) {
            if (isspace(*content++)) {
                return false;
            }
        }
    }
    return true;
}

static void TransformStripWhitespace(InspectionBuffer *buffer, void *options)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    if (input_len == 0) {
        return;
    }
    uint8_t output[input_len]; // we can only shrink
    uint8_t *oi = output, *os = output;

    //PrintRawDataFp(stdout, input, input_len);
    for (uint32_t i = 0; i < input_len; i++) {
        if (!isspace(*input)) {
            *oi++ = *input;
        }
        input++;
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

static int DetectTransformStripWhitespaceTest01(void)
{
    const uint8_t *input = (const uint8_t *)" A B C D ";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 8);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformStripWhitespace(&buffer, NULL);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformStripWhitespaceTest02(void)
{
    const uint8_t *input = (const uint8_t *)" A B C D ";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 8);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDoubleWhitespace(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDoubleWhitespace(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformStripWhitespace(&buffer, NULL);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformStripWhitespaceTest03(void)
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

static void DetectTransformStripWhitespaceRegisterTests(void)
{
    UtRegisterTest("DetectTransformStripWhitespaceTest01",
            DetectTransformStripWhitespaceTest01);
    UtRegisterTest("DetectTransformStripWhitespaceTest02",
            DetectTransformStripWhitespaceTest02);
    UtRegisterTest("DetectTransformStripWhitespaceTest03",
            DetectTransformStripWhitespaceTest03);
}
#endif
