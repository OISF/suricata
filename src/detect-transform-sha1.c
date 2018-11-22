/* Copyright (C) 2007-2018 Open Information Security Foundation
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
 * Implements the sha1 transformation keyword
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-parse.h"
#include "detect-transform-sha1.h"

#include "util-unittest.h"
#include "util-print.h"

static int DetectTransformToSha1Setup (DetectEngineCtx *, Signature *, const char *);
#ifdef HAVE_NSS
static void DetectTransformToSha1RegisterTests(void);
static void TransformToSha1(InspectionBuffer *buffer);
#endif

void DetectTransformSha1Register(void)
{
    sigmatch_table[DETECT_TRANSFORM_SHA1].name = "to_sha1";
    sigmatch_table[DETECT_TRANSFORM_SHA1].desc =
        "convert to sha1 hash of the buffer";
    sigmatch_table[DETECT_TRANSFORM_SHA1].url =
        DOC_URL DOC_VERSION "/rules/transforms.html#to_sha1";
    sigmatch_table[DETECT_TRANSFORM_SHA1].Setup =
        DetectTransformToSha1Setup;
#ifdef HAVE_NSS
    sigmatch_table[DETECT_TRANSFORM_SHA1].Transform =
        TransformToSha1;
    sigmatch_table[DETECT_TRANSFORM_SHA1].RegisterTests =
        DetectTransformToSha1RegisterTests;
#endif
    sigmatch_table[DETECT_TRANSFORM_SHA1].flags |= SIGMATCH_NOOPT;
}

#ifndef HAVE_NSS
static int DetectTransformToSha1Setup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCLogError(SC_ERR_NO_SHA1_SUPPORT, "no SHA-1 calculation support built in, "
            "needed for to_sha1 keyword");
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
static int DetectTransformToSha1Setup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_SHA1);
    SCReturnInt(r);
}

static void TransformToSha1(InspectionBuffer *buffer)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    uint8_t output[SHA1_LENGTH];

    //PrintRawDataFp(stdout, input, input_len);

    HASHContext *sha1_ctx = HASH_Create(HASH_AlgSHA1);
    if (sha1_ctx) {
        HASH_Begin(sha1_ctx);
        HASH_Update(sha1_ctx, input, input_len);
        unsigned int len = 0;
        HASH_End(sha1_ctx, output, &len, sizeof(output));
        HASH_Destroy(sha1_ctx);

        InspectionBufferCopy(buffer, output, sizeof(output));
    }
}

#ifdef UNITTESTS
static int DetectTransformToSha1Test01(void)
{
    const uint8_t *input = (const uint8_t *)" A B C D ";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 8);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformToSha1(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    InspectionBufferFree(&buffer);
    PASS;
}

#endif

static void DetectTransformToSha1RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectTransformToSha1Test01",
            DetectTransformToSha1Test01);
#endif
}
#endif
