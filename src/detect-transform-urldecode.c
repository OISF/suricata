/* Copyright (C) 2020 Open Information Security Foundation
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
 * \author Philippe Antoine <p.antoine@catenacyber.fr>
 *
 * Implements the url_decode transform keyword
 */

#include "suricata-common.h"

#include "detect-engine.h"
#include "detect-engine-build.h"
#include "detect-parse.h"
#include "detect-transform-urldecode.h"

#include "util-unittest.h"
#include "util-print.h"

static int DetectTransformUrlDecodeSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectTransformUrlDecodeRegisterTests(void);
#endif

static void TransformUrlDecode(InspectionBuffer *buffer, void *options);

void DetectTransformUrlDecodeRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_URL_DECODE].name = "url_decode";
    sigmatch_table[DETECT_TRANSFORM_URL_DECODE].desc =
        "modify buffer to decode urlencoded data before inspection";
    sigmatch_table[DETECT_TRANSFORM_URL_DECODE].url = "/rules/transforms.html#url-decode";
    sigmatch_table[DETECT_TRANSFORM_URL_DECODE].Transform =
        TransformUrlDecode;
    sigmatch_table[DETECT_TRANSFORM_URL_DECODE].Setup =
        DetectTransformUrlDecodeSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TRANSFORM_URL_DECODE].RegisterTests =
        DetectTransformUrlDecodeRegisterTests;
#endif

    sigmatch_table[DETECT_TRANSFORM_URL_DECODE].flags |= SIGMATCH_NOOPT;
}

/**
 *  \internal
 *  \brief Apply the transform keyword to the last pattern match
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param nullstr should be null
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformUrlDecodeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_URL_DECODE, NULL);
    SCReturnInt(r);
}

// util function so as to ease reuse sometimes
static bool BufferUrlDecode(const uint8_t *input, const uint32_t input_len, uint8_t *output, uint32_t *output_size)
{
    bool changed = false;
    uint8_t *oi = output;
    //PrintRawDataFp(stdout, input, input_len);
    for (uint32_t i = 0; i < input_len; i++) {
        if (input[i] == '%') {
            if (i + 2 < input_len) {
                if ((isxdigit(input[i+1])) && (isxdigit(input[i+2]))) {
                    // Decode %HH encoding.
                    *oi = (uint8_t)((input[i + 1] >= 'A' ? ((input[i + 1] & 0xdf) - 'A') + 10
                                                         : (input[i + 1] - '0'))
                                    << 4);
                    *oi |= (input[i+2] >= 'A' ? ((input[i+2] & 0xdf) - 'A') + 10 : (input[i+2] - '0'));
                    oi++;
                    // one more increment before looping
                    i += 2;
                    changed = true;
                } else {
                    // leaves incorrect percent
                    // does not handle unicode %u encoding
                    *oi++ = input[i];
                }
            } else {
                // leaves trailing incomplete percent
                *oi++ = input[i];
            }
        } else if (input[i] == '+') {
            *oi++ = ' ';
            changed = true;
        } else {
            *oi++ = input[i];
        }
    }
    *output_size = oi - output;
    return changed;
}

static void TransformUrlDecode(InspectionBuffer *buffer, void *options)
{
    uint32_t output_size;
    bool changed;

    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    if (input_len == 0) {
        return;
    }
    uint8_t output[input_len]; // we can only shrink

    changed = BufferUrlDecode(input, input_len, output, &output_size);

    if (changed) {
        InspectionBufferCopy(buffer, output, output_size);
    }
}

#ifdef UNITTESTS
static int DetectTransformUrlDecodeTest01(void)
{
    const uint8_t *input = (const uint8_t *)"Suricata%20is+%27%61wesome%21%27%25%30%30%ZZ%4";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 8);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformUrlDecode(&buffer, NULL);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    FAIL_IF (buffer.inspect_len != strlen("Suricata is 'awesome!'%00%ZZ%4"));
    FAIL_IF (memcmp(buffer.inspect, "Suricata is 'awesome!'%00%ZZ%4", buffer.inspect_len) != 0);
    InspectionBufferFree(&buffer);
    PASS;
}

static int DetectTransformUrlDecodeTest02(void)
{
    const char rule[] = "alert http any any -> any any (http.request_body; url_decode; content:\"mail=test@oisf.net\"; sid:1;)";
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

static void DetectTransformUrlDecodeRegisterTests(void)
{
    UtRegisterTest("DetectTransformUrlDecodeTest01",
            DetectTransformUrlDecodeTest01);
    UtRegisterTest("DetectTransformUrlDecodeTest02",
            DetectTransformUrlDecodeTest02);
}
#endif
