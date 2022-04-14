/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 *
 * Implements the from_base64 transformation keyword
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-parse.h"
#include "detect-transform-base64.h"

#include "util-base64.h"
#include "util-unittest.h"
#include "util-print.h"
#include "rust.h"

static int DetectTransformFromBase64Setup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectTransformFromBase64RegisterTests(void);
#endif
static void TransformFromBase64(InspectionBuffer *buffer, void *options);

void DetectTransformBase64Register(void)
{
    sigmatch_table[DETECT_TRANSFORM_BASE64].name = "from_base64";
    sigmatch_table[DETECT_TRANSFORM_BASE64].desc = "convert the base64 decode of the buffer";
    sigmatch_table[DETECT_TRANSFORM_BASE64].url = "/rules/transforms.html#from-base64";
    sigmatch_table[DETECT_TRANSFORM_BASE64].Setup = DetectTransformFromBase64Setup;
    sigmatch_table[DETECT_TRANSFORM_BASE64].Transform = TransformFromBase64;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TRANSFORM_BASE64].RegisterTests = DetectTransformFromBase64RegisterTests;
#endif
    sigmatch_table[DETECT_TRANSFORM_BASE64].flags |= SIGMATCH_NOOPT;
}

/**
 *  \internal
 *  \brief Base64 decode the input buffer
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param nullstr should be null
 *  \retval 0 No decodee
 *  \retval >0 Decoded byte count
 */
static int DetectTransformFromBase64Setup(
        DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_BASE64, NULL);
    SCReturnInt(r);
}

static void TransformFromBase64(InspectionBuffer *buffer, void *options)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    uint8_t output[input_len];

    // PrintRawDataFp(stdout, input, input_len);
    int decoded_length = DecodeBase64(output, input, sizeof(output), 1);
    if (decoded_length) {
        InspectionBufferCopy(buffer, output, decoded_length);
    }
}

#ifdef UNITTESTS
static int DetectTransformFromBase64Test01(void)
{
    const uint8_t *input = (const uint8_t *)"VGhpcyBpcyBTdXJpY2F0YQo=";
    uint32_t input_len = strlen((char *)input);
    const char *result = "This is Suricata\n";
    uint32_t result_len = strlen((char *)result);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformFromBase64(&buffer, NULL);
    FAIL_IF_NOT(buffer.inspect_len == result_len);
    FAIL_IF_NOT(strncmp(result, (const char *)buffer.inspect, result_len) == 0);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformFromBase64Test02(void)
{
    const uint8_t *input = (const uint8_t *)"This is Suricata\n";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBuffer buffer_orig;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    buffer_orig = buffer;
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformFromBase64(&buffer, NULL);
    FAIL_IF_NOT(buffer.inspect_offset == buffer_orig.inspect_offset);
    FAIL_IF_NOT(buffer.inspect_len == buffer_orig.inspect_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    InspectionBufferFree(&buffer);
    PASS;
}

static void DetectTransformFromBase64RegisterTests(void)
{
    UtRegisterTest("DetectTransformFromBase64Test01", DetectTransformFromBase64Test01);
    UtRegisterTest("DetectTransformFromBase64Test02", DetectTransformFromBase64Test02);
}
#endif
