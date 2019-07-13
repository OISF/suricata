/* Copyright (C) 2019 Open Information Security Foundation
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
 * Implements the tld transformation
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-parse.h"
#include "detect-transform-tld.h"

#include "util-unittest.h"
#include "util-print.h"
#include "util-memrchr.h"
#include "util-memcpy.h"

static int DetectTransformTLDSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectTransformTLDRegisterTests(void);

static void TransformTLD(InspectionBuffer *buffer);

void DetectTransformTLDRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_TLD].name = "tld";
    sigmatch_table[DETECT_TRANSFORM_TLD].desc =
        "modify buffer to extract the tld";
    sigmatch_table[DETECT_TRANSFORM_TLD].url =
        DOC_URL DOC_VERSION "/rules/transforms.html#tld";
    sigmatch_table[DETECT_TRANSFORM_TLD].Transform =
        TransformTLD;
    sigmatch_table[DETECT_TRANSFORM_TLD].Setup =
        DetectTransformTLDSetup;
    sigmatch_table[DETECT_TRANSFORM_TLD].RegisterTests =
        DetectTransformTLDRegisterTests;

    sigmatch_table[DETECT_TRANSFORM_TLD].flags |= SIGMATCH_NOOPT;
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
static int DetectTransformTLDSetup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_TLD);
    SCReturnInt(r);
}

static void TransformTLD(InspectionBuffer *buffer)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    uint8_t output[input_len]; // we can only shrink
    uint8_t *os = output;

    /* from end, scan back for dot */
    uint8_t *dot = memrchr(input, '.', input_len);

    /* no dot found */
    if (!dot) {
        return;
    }

    uint32_t output_size = input_len - (dot - input) - 1;
    /* no chars following dot */
    if (!output_size) {
        return;
    }

    dot++;
    memcpy(os, dot, output_size);

    InspectionBufferCopy(buffer, os, output_size);
}

#ifdef UNITTESTS
static int DetectTransformTLDTest01(void)
{
    const uint8_t *input = (const uint8_t *)"example.com";
    uint32_t input_len = strlen((char *)input);

    const char *result = "com";
    uint32_t result_len = strlen((char *)result);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformTLD(&buffer);
    FAIL_IF_NOT(buffer.inspect_len == result_len);
    FAIL_IF_NOT(strncmp(result, (const char *)buffer.inspect, result_len) == 0);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformTLDTest02(void)
{
    const uint8_t *input = (const uint8_t *)"suricon.conference.net";
    uint32_t input_len = strlen((char *)input);

    const char *result = "net";
    uint32_t result_len = strlen((char *)result);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformTLD(&buffer);
    FAIL_IF_NOT(buffer.inspect_len == result_len);
    FAIL_IF_NOT(strncmp(result, (const char *)buffer.inspect, result_len) == 0);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    PASS;
}

static int DetectTransformTLDTest03(void)
{
    const uint8_t *input = (const uint8_t *)"suricon-conference-net";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformTLD(&buffer);
    /* expect unchanged */
    FAIL_IF_NOT(buffer.inspect_len == input_len);
    FAIL_IF_NOT(strncmp((const char *)input, (const char *)buffer.inspect, input_len) == 0);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    PASS;
}

static int DetectTransformTLDTest04(void)
{
    const uint8_t *input = (const uint8_t *)"suricon.conference.";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformTLD(&buffer);
    /* expect unchanged */
    FAIL_IF_NOT(buffer.inspect_len == input_len);
    FAIL_IF_NOT(strncmp((const char *)input, (const char *)buffer.inspect, input_len) == 0);
    PASS;
}

static int DetectTransformTLDTest05(void)
{
    const char rule[] = "alert dns any any -> any any (dns.query; tld; content:\"org\"; sid:1;)";
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

static void DetectTransformTLDRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectTransformTLDTest01", DetectTransformTLDTest01);
    UtRegisterTest("DetectTransformTLDTest02", DetectTransformTLDTest02);
    UtRegisterTest("DetectTransformTLDTest03", DetectTransformTLDTest03);
    UtRegisterTest("DetectTransformTLDTest04", DetectTransformTLDTest04);
    UtRegisterTest("DetectTransformTLDTest05", DetectTransformTLDTest05);
#endif
}
