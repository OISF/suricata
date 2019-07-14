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
 * Implements the domain transformation
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-parse.h"
#include "detect-transform-domain.h"

#include "util-unittest.h"
#include "util-print.h"
#include "util-memrchr.h"
#include "util-memcpy.h"

static int DetectTransformDomainSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectTransformDomainRegisterTests(void);

static void TransformDomain(InspectionBuffer *buffer);

void DetectTransformDomainRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].name = "domain";
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].desc =
        "modify buffer to extract the domain";
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].url =
        DOC_URL DOC_VERSION "/rules/transforms.html#domain";
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].Transform = TransformDomain;
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].Setup = DetectTransformDomainSetup;
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].RegisterTests =
        DetectTransformDomainRegisterTests;

    sigmatch_table[DETECT_TRANSFORM_DOMAIN].flags |= SIGMATCH_NOOPT;
}

/**
 *  \internal
 *  \brief Extract the domain, if any, the last pattern match, either content or uricontent
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param nullstr should be null
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformDomainSetup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_DOMAIN);
    SCReturnInt(r);
}

static void TransformDomain(InspectionBuffer *buffer)
/**
 * \brief Reeturn the domain, if any, in the last pattern match.
 *
 * Given a string, "foo.bar.com", return the domain "bar.com".
 *
 * The inspection buffer is unaltered when:
 * - The buffer contains a string without dots: "foo-bar-com",  ""
 * - The buffer contains less than 2 characters for a TLD: g. foo.c
 * - The buffer contains 0 characters to the left of the TLD: .com
 */
{
    const uint8_t *input = buffer->inspect;
    const size_t input_len = buffer->inspect_len;
    uint8_t *end = (void *)input + input_len;

    /* find rightmost dot */
    uint8_t *dot = memrchr(input, '.', input_len);

    /* dot not found,less than 2 characters follow dot, no more to left */
    if (!dot || ((end - dot) < 3) || dot == input) {
        return;
    }

    dot--; /* move left */
    /* check for next 2nd most rightmost dot */
    dot = memrchr(input, '.', dot - input);
    uint8_t *begin;
    if (dot) {
        begin = dot + 1;
    } else {
        begin = (uint8_t *)input;
    }

    size_t output_size = end - begin;
    if (output_size) {
        uint8_t output[input_len]; // we can only shrink
        memcpy(output, begin, output_size);
        InspectionBufferCopy(buffer, output, output_size);
    }
}

#ifdef UNITTESTS
static int DetectTransformDomainTest01(void)
{
    const uint8_t *input = (const uint8_t *)"example.com";
    uint32_t input_len = strlen((char *)input);

    const char *result = "example.com";
    uint32_t result_len = strlen((char *)result);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDomain(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF_NOT(buffer.inspect_len == result_len);
    FAIL_IF_NOT(strncmp(result, (const char *)buffer.inspect, result_len) == 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformDomainTest02(void)
{
    const uint8_t *input = (const uint8_t *)"suricon.conference.net";
    uint32_t input_len = strlen((char *)input);

    const char *result = "conference.net";
    uint32_t result_len = strlen((char *)result);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDomain(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF_NOT(buffer.inspect_len == result_len);
    FAIL_IF_NOT(strncmp(result, (const char *)buffer.inspect, result_len) == 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformDomainTest03(void)
{
    const uint8_t *input = (const uint8_t *)"suricon-conference-net";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDomain(&buffer);
    /* expect unchanged */
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF_NOT(buffer.inspect_len == input_len);
    FAIL_IF_NOT(strncmp((const char *)input, (const char *)buffer.inspect, input_len) == 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformDomainTest04(void)
{
    const uint8_t *input = (const uint8_t *)"suricon.";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDomain(&buffer);
    /* expect unchanged */
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF_NOT(buffer.inspect_len == input_len);
    FAIL_IF_NOT(strncmp((const char *)input, (const char *)buffer.inspect, input_len) == 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformDomainTest05(void)
{
    const uint8_t *input = (const uint8_t *)"suricon.c";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDomain(&buffer);
    /* expect unchanged */
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF_NOT(buffer.inspect_len == input_len);
    FAIL_IF_NOT(strncmp((const char *)input, (const char *)buffer.inspect, input_len) == 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformDomainTest06(void)
{
    const uint8_t *input = (const uint8_t *)"suricon.nl";
    uint32_t input_len = strlen((char *)input);

    const char *result = "suricon.nl";
    uint32_t result_len = strlen((char *)result);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDomain(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF_NOT(buffer.inspect_len == result_len);
    FAIL_IF_NOT(strncmp(result, (const char *)buffer.inspect, result_len) == 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformDomainTest07(void)
{
    const uint8_t *input = (const uint8_t *)".suricon";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDomain(&buffer);
    /* expect unchanged */
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF_NOT(buffer.inspect_len == input_len);
    FAIL_IF_NOT(strncmp((const char *)input, (const char *)buffer.inspect, input_len) == 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformDomainTest08(void)
{
    const uint8_t *input = (const uint8_t *)"windows.update.microsoft.com";
    uint32_t input_len = strlen((char *)input);

    const char *result = "microsoft.com";
    uint32_t result_len = strlen((char *)result);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDomain(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF_NOT(buffer.inspect_len == result_len);
    FAIL_IF_NOT(strncmp(result, (const char *)buffer.inspect, result_len) == 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformDomainTest09(void)
{
    const uint8_t *input = (const uint8_t *)"";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDomain(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF_NOT(buffer.inspect_len == input_len);
    FAIL_IF_NOT(strncmp((const char *)input, (const char *)buffer.inspect, input_len) == 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformDomainTest10(void)
{
    const uint8_t *input = NULL;
    uint32_t input_len = 0;

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDomain(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF_NOT(buffer.inspect_len == input_len);
    FAIL_IF_NOT(strncmp((const char *)input, (const char *)buffer.inspect, input_len) == 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformDomainTest11(void)
{
    const char rule[] = "alert dns any any -> any any (dns.query; domain; content:\"org\"; sid:1;)";
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

static void DetectTransformDomainRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectTransformDomainTest01", DetectTransformDomainTest01);
    UtRegisterTest("DetectTransformDomainTest02", DetectTransformDomainTest02);
    UtRegisterTest("DetectTransformDomainTest03", DetectTransformDomainTest03);
    UtRegisterTest("DetectTransformDomainTest04", DetectTransformDomainTest04);
    UtRegisterTest("DetectTransformDomainTest05", DetectTransformDomainTest05);
    UtRegisterTest("DetectTransformDomainTest06", DetectTransformDomainTest06);
    UtRegisterTest("DetectTransformDomainTest07", DetectTransformDomainTest07);
    UtRegisterTest("DetectTransformDomainTest08", DetectTransformDomainTest08);
    UtRegisterTest("DetectTransformDomainTest09", DetectTransformDomainTest09);
    UtRegisterTest("DetectTransformDomainTest10", DetectTransformDomainTest10);
    UtRegisterTest("DetectTransformDomainTest11", DetectTransformDomainTest11);
#endif
}
