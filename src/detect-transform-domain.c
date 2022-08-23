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
 * \author Eric Leblond <el@stamus-networks.com>
 *
 * Implements the domain extraction transformation
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-parse.h"
#include "detect-transform-domain.h"
#include "detect-engine-build.h"

#include "util-unittest.h"
#include "util-print.h"
#include "util-memrchr.h"
#include "util-memcpy.h"
#include "rust.h"

static int DetectTransformDomainSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectTransformDomainRegisterTests(void);
#endif
static void TransformDomain(InspectionBuffer *buffer, void *options);

void DetectTransformDomainRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].name = "domain";
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].desc =
        "modify buffer to extract the domain";
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].url =
        "/rules/transforms.html#domain";
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].Transform = TransformDomain;
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].Setup = DetectTransformDomainSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].RegisterTests =
        DetectTransformDomainRegisterTests;
#endif
    sigmatch_table[DETECT_TRANSFORM_DOMAIN].flags |= SIGMATCH_NOOPT;
}

/**
 *  \internal
 *  \brief Extract the dotprefix, if any, the last pattern match, either content or uricontent
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param nullstr should be null
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformDomainSetup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_DOMAIN, NULL);
    SCReturnInt(r);
}

/**
 * \brief Return the domain, if any, in the last pattern match.
 *
 */
static void TransformDomain(InspectionBuffer *buffer, void *options)
{
    const size_t input_len = buffer->inspect_len;
    size_t output_len = 0;

    if (input_len) {
        uint8_t output[input_len];

        bool res = rs_get_domain(buffer->inspect, input_len, output, &output_len);
        if (res == true) {
            InspectionBufferCopy(buffer, output, output_len);
        }
    }
}

#ifdef UNITTESTS
static int DetectTransformDomainTest01(void)
{
    const uint8_t *input = (const uint8_t *)"www.example.com";
    uint32_t input_len = strlen((char *)input);

    const char *result = "example.com";
    uint32_t result_len = strlen((char *)result);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDomain(&buffer, NULL);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF_NOT(buffer.inspect_len == result_len);
    FAIL_IF_NOT(strncmp(result, (const char *)buffer.inspect, result_len) == 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformDomainTest02(void)
{
    const uint8_t *input = (const uint8_t *)"hello.example.co.uk";
    uint32_t input_len = strlen((char *)input);

    const char *result = "example.co.uk";
    uint32_t result_len = strlen((char *)result);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, input_len);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformDomain(&buffer, NULL);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF_NOT(buffer.inspect_len == result_len);
    FAIL_IF_NOT(strncmp(result, (const char *)buffer.inspect, result_len) == 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformDomainTest03(void)
{
    const char rule[] = "alert dns any any -> any any (dns.query; domain; content:\"google.com\"; sid:1;)";
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

static void DetectTransformDomainRegisterTests(void)
{
    UtRegisterTest("DetectTransformDomainTest01", DetectTransformDomainTest01);
    UtRegisterTest("DetectTransformDomainTest02", DetectTransformDomainTest02);
    UtRegisterTest("DetectTransformDomainTest03", DetectTransformDomainTest03);
}
#endif
