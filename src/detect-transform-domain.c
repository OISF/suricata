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
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].Transform =
        TransformDomain;
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].Setup =
        DetectTransformDomainSetup;
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].RegisterTests =
        DetectTransformDomainRegisterTests;

    sigmatch_table[DETECT_TRANSFORM_DOMAIN].flags |= SIGMATCH_NOOPT;
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
static int DetectTransformDomainSetup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_DOMAIN);
    SCReturnInt(r);
}

static void TransformDomain(InspectionBuffer *buffer)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    uint8_t output[input_len]; // we can only shrink
    uint8_t *os = output;

    SCLogDebug("Transforming %.*s", input_len, input);

    uint8_t *dot = memchr(input, '.', input_len);
    if (!dot) {
        return;
    }

    uint32_t rem = input_len - (dot - input) - 1;
    if (!rem) {
        return;
    }

    memcpy(os, dot + 1, rem);
    SCLogDebug("Domain is %.*s", rem, os);

    InspectionBufferCopy(buffer, os, rem);
}

#ifdef UNITTESTS
static int DetectTransformDomainTest01(void)
{
    const uint8_t *input = (const uint8_t *)"example.com";
    uint32_t input_len = strlen((char *)input);

    const char *result = "com";
    uint32_t result_len = strlen((char *)result);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDomain(&buffer);
    FAIL_IF_NOT(buffer.inspect_len == result_len);
    FAIL_IF_NOT(strncmp(result, (const char *)buffer.inspect, result_len) == 0);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
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
    FAIL_IF_NOT(buffer.inspect_len == result_len);
    FAIL_IF_NOT(strncmp(result, (const char *)buffer.inspect, result_len) == 0);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
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
    FAIL_IF_NOT(buffer.inspect_len == input_len);
    FAIL_IF_NOT(strncmp((const char *)input, (const char *)buffer.inspect, input_len) == 0);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
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
    FAIL_IF_NOT(buffer.inspect_len == input_len);
    FAIL_IF_NOT(strncmp((const char *)input, (const char *)buffer.inspect, input_len) == 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformDomainTest05(void)
{
    const uint8_t *input = (const uint8_t *)"windows.update.microsoft.com";
    uint32_t input_len = strlen((char *)input);

    const char *result = "update.microsoft.com";
    uint32_t result_len = strlen((char *)result);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDomain(&buffer);
    FAIL_IF_NOT(buffer.inspect_len == result_len);
    FAIL_IF_NOT(strncmp(result, (const char *)buffer.inspect, result_len) == 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformDomainTest06(void)
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
#endif
}
