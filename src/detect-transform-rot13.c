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
 * \author Sascha Steinbiss <sascha@steinbiss.name>
 *
 * Implements the rot13 keyword
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-parse.h"
#include "detect-transform-rot13.h"

#include "util-unittest.h"
#include "util-print.h"

static int DetectTransformROT13Setup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectTransformROT13RegisterTests(void);
#endif
static void TransformROT13(InspectionBuffer *buffer, void *options);

void DetectTransformROT13Register(void)
{
    sigmatch_table[DETECT_TRANSFORM_ROT13].name = "rot13";
    sigmatch_table[DETECT_TRANSFORM_ROT13].desc =
        "apply ROT13 to alpha characters in buffer";
    sigmatch_table[DETECT_TRANSFORM_ROT13].url =
        "/rules/transforms.html#rot13";
    sigmatch_table[DETECT_TRANSFORM_ROT13].Transform =
        TransformROT13;
    sigmatch_table[DETECT_TRANSFORM_ROT13].Setup =
        DetectTransformROT13Setup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TRANSFORM_ROT13].RegisterTests =
        DetectTransformROT13RegisterTests;
#endif
    sigmatch_table[DETECT_TRANSFORM_ROT13].flags |= SIGMATCH_NOOPT;
}

/**
 *  \internal
 *  \brief Apply the rot13 keyword to the last pattern match, either content or uricontent
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param nullstr should be null
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformROT13Setup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_ROT13, NULL);
    SCReturnInt(r);
}

static void TransformROT13(InspectionBuffer *buffer, void *options)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    uint8_t output[input_len]; // length stays the same
    uint8_t *oi = output, *os = output;

    for (uint32_t i = 0; i < input_len; i++) {
        if (likely(isalpha(*input))) {
            char c = tolower(*input);
           if (c >= 'a' && c <= 'm') {
               *oi++ = *input + 13;
           } else if (c >= 'n' && c <= 'z') {
               *oi++ = *input - 13;
           }
        } else {
            *oi++ = *input;
        }
        input++;
    }
    uint32_t output_size = oi - os;

    InspectionBufferCopy(buffer, os, output_size);
}

#ifdef UNITTESTS
static int DetectTransformROT13Test01(void)
{
    const uint8_t *input = (const uint8_t *)"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const uint8_t *exp = (const uint8_t *)"NOPQRSTUVWXYZABCDEFGHIJKLM";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 8);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformROT13(&buffer, NULL);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF(memcmp(buffer.inspect, exp, input_len) != 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformROT13Test02(void)
{
    const uint8_t *input = (const uint8_t *)"abcdefghijklmnopqrstuvwxyz";
    const uint8_t *exp = (const uint8_t *)"nopqrstuvwxyzabcdefghijklm";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 8);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformROT13(&buffer, NULL);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF(memcmp(buffer.inspect, exp, input_len) != 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformROT13Test03(void)
{
    const char rule[] = "alert http any any -> any any (http_request_line; rot13; content:\"GET/HTTP\"; sid:1;)";
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

static int DetectTransformROT13Test04(void)
{
    const uint8_t *input = (const uint8_t *)"\b\n112WHATever789\n\n";
    const uint8_t *exp = (const uint8_t *)"\b\n112JUNGrire789\n\n";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 8);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformROT13(&buffer, NULL);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF(memcmp(buffer.inspect, exp, input_len) != 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static void DetectTransformROT13RegisterTests(void)
{
    UtRegisterTest("DetectTransformROT13Test01",
            DetectTransformROT13Test01);
    UtRegisterTest("DetectTransformROT13Test02",
            DetectTransformROT13Test02);
    UtRegisterTest("DetectTransformROT13Test03",
            DetectTransformROT13Test03);
    UtRegisterTest("DetectTransformROT13Test04",
            DetectTransformROT13Test04);
}
#endif
