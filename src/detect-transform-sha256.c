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
#include "detect-transform-sha256.h"

#include "util-unittest.h"
#include "util-print.h"

static int DetectTransformToSha256Setup (DetectEngineCtx *, Signature *, const char *);
#ifdef HAVE_NSS
static void DetectTransformToSha256RegisterTests(void);
static void TransformToSha256(InspectionBuffer *buffer);
#endif

void DetectTransformSha256Register(void)
{
    sigmatch_table[DETECT_TRANSFORM_SHA256].name = "to_sha256";
    sigmatch_table[DETECT_TRANSFORM_SHA256].desc =
        "convert to sha256 hash of the buffer";
    sigmatch_table[DETECT_TRANSFORM_SHA256].url =
        DOC_URL DOC_VERSION "/rules/transforms.html#to-sha256";
    sigmatch_table[DETECT_TRANSFORM_SHA256].Setup =
        DetectTransformToSha256Setup;
#ifdef HAVE_NSS
    sigmatch_table[DETECT_TRANSFORM_SHA256].Transform =
        TransformToSha256;
    sigmatch_table[DETECT_TRANSFORM_SHA256].RegisterTests =
        DetectTransformToSha256RegisterTests;
#endif
    sigmatch_table[DETECT_TRANSFORM_SHA256].flags |= SIGMATCH_NOOPT;
}

#ifndef HAVE_NSS
static int DetectTransformToSha256Setup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCLogError(SC_ERR_NO_SHA256_SUPPORT, "no SHA-256 calculation support built in, "
            "needed for to_sha256 keyword");
    return -1;
}
#else
/**
 *  \internal
 *  \brief Apply the nocase keyword to the last pattern match, either content or uricontent
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param nullstr should be null
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformToSha256Setup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_SHA256);
    SCReturnInt(r);
}

static void TransformToSha256(InspectionBuffer *buffer)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    uint8_t output[SHA256_LENGTH];

    //PrintRawDataFp(stdout, input, input_len);

    HASHContext *sha256_ctx = HASH_Create(HASH_AlgSHA256);
    if (sha256_ctx) {
        HASH_Begin(sha256_ctx);
        HASH_Update(sha256_ctx, input, input_len);
        unsigned int len = 0;
        HASH_End(sha256_ctx, output, &len, sizeof(output));
        HASH_Destroy(sha256_ctx);

        InspectionBufferCopy(buffer, output, sizeof(output));
    }
}

#ifdef UNITTESTS
static int DetectTransformToSha256Test01(void)
{
    const uint8_t *input = (const uint8_t *)" A B C D ";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 8);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformToSha256(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    InspectionBufferFree(&buffer);
    PASS;
}

#endif

static void DetectTransformToSha256RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectTransformToSha256Test01",
            DetectTransformToSha256Test01);
#endif
}
#endif
