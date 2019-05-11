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
 * Implements the to_md5 transformation keyword
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-parse.h"
#include "detect-transform-md5.h"

#include "util-unittest.h"
#include "util-print.h"

static int DetectTransformToMd5Setup (DetectEngineCtx *, Signature *, const char *);
#ifdef HAVE_NSS
static void DetectTransformToMd5RegisterTests(void);
static void TransformToMd5(InspectionBuffer *buffer);
#endif

void DetectTransformMd5Register(void)
{
    sigmatch_table[DETECT_TRANSFORM_MD5].name = "to_md5";
    sigmatch_table[DETECT_TRANSFORM_MD5].desc =
        "convert to md5 hash of the buffer";
    sigmatch_table[DETECT_TRANSFORM_MD5].url =
        DOC_URL DOC_VERSION "/rules/transforms.html#to_sha256";
    sigmatch_table[DETECT_TRANSFORM_MD5].Setup =
        DetectTransformToMd5Setup;
#ifdef HAVE_NSS
    sigmatch_table[DETECT_TRANSFORM_MD5].Transform =
        TransformToMd5;
    sigmatch_table[DETECT_TRANSFORM_MD5].RegisterTests =
        DetectTransformToMd5RegisterTests;
#endif
    sigmatch_table[DETECT_TRANSFORM_MD5].flags |= SIGMATCH_NOOPT;
}

#ifndef HAVE_NSS
static int DetectTransformToMd5Setup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCLogError(SC_ERR_NO_MD5_SUPPORT, "no MD5 calculation support built in, "
            "needed for to_md5 keyword");
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
static int DetectTransformToMd5Setup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_MD5);
    SCReturnInt(r);
}

static void TransformToMd5(InspectionBuffer *buffer)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    uint8_t output[MD5_LENGTH];

    //PrintRawDataFp(stdout, input, input_len);

    HASHContext *ctx = HASH_Create(HASH_AlgMD5);
    if (ctx) {
        HASH_Begin(ctx);
        HASH_Update(ctx, input, input_len);
        unsigned int len = 0;
        HASH_End(ctx, output, &len, sizeof(output));
        HASH_Destroy(ctx);

        InspectionBufferCopy(buffer, output, sizeof(output));
    }
}

#ifdef UNITTESTS
static int DetectTransformToMd5Test01(void)
{
    const uint8_t *input = (const uint8_t *)" A B C D ";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 8);
    InspectionBufferSetup(&buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformToMd5(&buffer);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    InspectionBufferFree(&buffer);
    PASS;
}

#endif

static void DetectTransformToMd5RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectTransformToMd5Test01",
            DetectTransformToMd5Test01);
#endif
}
#endif
