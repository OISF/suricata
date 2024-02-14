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
 * Implements the compress_whitespace transform keyword
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
#ifdef UNITTESTS
static void DetectTransformCompressWhitespaceRegisterTests(void);
#endif
static void TransformCompressWhitespace(InspectionBuffer *buffer, void *options);
static bool TransformCompressWhitespaceValidate(
        const uint8_t *content, uint16_t content_len, void *options);

void DetectTransformCompressWhitespaceRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].name = "compress_whitespace";
    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].desc =
        "modify buffer to compress consecutive whitespace characters "
        "into a single one before inspection";
    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].url =
        "/rules/transforms.html#compress-whitespace";
    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].Transform =
        TransformCompressWhitespace;
    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].TransformValidate =
            TransformCompressWhitespaceValidate;
    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].Setup =
        DetectTransformCompressWhitespaceSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].RegisterTests =
        DetectTransformCompressWhitespaceRegisterTests;
#endif
    sigmatch_table[DETECT_TRANSFORM_COMPRESS_WHITESPACE].flags |= SIGMATCH_NOOPT;
}

/**
 *  \internal
 *  \brief Apply the compress_whitespace keyword to the last pattern match
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param nullstr should be null
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformCompressWhitespaceSetup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_COMPRESS_WHITESPACE, NULL);
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
static bool TransformCompressWhitespaceValidate(
        const uint8_t *content, uint16_t content_len, void *options)
{
    if (content) {
        for (uint32_t i = 0; i < content_len; i++) {
            if (!isspace(*content++)) {
                continue;
            }
            if ((i + 1) < content_len && isspace(*content)) {
                return false;
            }
        }
    }
    return true;
}

static void TransformCompressWhitespace(InspectionBuffer *buffer, void *options)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    if (input_len == 0) {
        return;
    }

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
    InspectionBufferInit(&buffer, 9);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformCompressWhitespace(&buffer, NULL);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformCompressWhitespaceTest02(void)
{
    const uint8_t *input = (const uint8_t *)" A B C D ";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 9);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDoubleWhitespace(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDoubleWhitespace(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformCompressWhitespace(&buffer, NULL);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformCompressWhitespaceTest03(void)
{
    const uint8_t *input = (const uint8_t *)" A B C D  ";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 10);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF(TransformCompressWhitespaceValidate(buffer.inspect, buffer.inspect_len, NULL));
    PASS;
}

static int DetectTransformCompressWhitespaceTest04(void)
{
    const uint8_t *input = (const uint8_t *)" A B C D ";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 9);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    TransformDoubleWhitespace(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF(TransformCompressWhitespaceValidate(buffer.inspect, buffer.inspect_len, NULL));
    PASS;
}

static void DetectTransformCompressWhitespaceRegisterTests(void)
{
    UtRegisterTest("DetectTransformCompressWhitespaceTest01",
            DetectTransformCompressWhitespaceTest01);
    UtRegisterTest("DetectTransformCompressWhitespaceTest02",
            DetectTransformCompressWhitespaceTest02);
    UtRegisterTest(
            "DetectTransformCompressWhitespaceTest03", DetectTransformCompressWhitespaceTest03);
    UtRegisterTest(
            "DetectTransformCompressWhitespaceTest04", DetectTransformCompressWhitespaceTest04);
}
#endif
