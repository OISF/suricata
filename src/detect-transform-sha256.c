/* Copyright (C) 2007-2020 Open Information Security Foundation
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

#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-transform-sha256.h"

#include "util-unittest.h"
#include "util-print.h"

#include "rust.h"

static int DetectTransformToSha256Setup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectTransformToSha256RegisterTests(void);
#endif
static void TransformToSha256(InspectionBuffer *buffer, void *options);

void DetectTransformSha256Register(void)
{
    sigmatch_table[DETECT_TRANSFORM_SHA256].name = "to_sha256";
    sigmatch_table[DETECT_TRANSFORM_SHA256].desc =
        "convert to sha256 hash of the buffer";
    sigmatch_table[DETECT_TRANSFORM_SHA256].url =
        "/rules/transforms.html#to-sha256";
    sigmatch_table[DETECT_TRANSFORM_SHA256].Setup =
        DetectTransformToSha256Setup;
    sigmatch_table[DETECT_TRANSFORM_SHA256].Transform =
        TransformToSha256;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TRANSFORM_SHA256].RegisterTests =
        DetectTransformToSha256RegisterTests;
#endif
    sigmatch_table[DETECT_TRANSFORM_SHA256].flags |= SIGMATCH_NOOPT;
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
static int DetectTransformToSha256Setup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SCEnter();
    if (g_disable_hashing) {
        SCLogError(SC_ERR_HASHING_DISABLED, "SHA256 hashing has been disabled, "
                                            "needed for to_sha256 keyword");
        SCReturnInt(-1);
    }
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_SHA256, NULL);
    SCReturnInt(r);
}

static void TransformToSha256(InspectionBuffer *buffer, void *options)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    uint8_t output[SC_SHA256_LEN];

    //PrintRawDataFp(stdout, input, input_len);
    SCSha256HashBuffer(input, input_len, output, sizeof(output));
    InspectionBufferCopy(buffer, output, sizeof(output));
}

#ifdef UNITTESTS
static int DetectTransformToSha256Test01(void)
{
    const uint8_t *input = (const uint8_t *)" A B C D ";
    uint32_t input_len = strlen((char *)input);

    InspectionBuffer buffer;
    InspectionBufferInit(&buffer, 8);
    InspectionBufferSetup(NULL, -1, &buffer, input, input_len);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    TransformToSha256(&buffer, NULL);
    PrintRawDataFp(stdout, buffer.inspect, buffer.inspect_len);
    InspectionBufferFree(&buffer);
    PASS;
}

static void DetectTransformToSha256RegisterTests(void)
{
    UtRegisterTest("DetectTransformToSha256Test01",
            DetectTransformToSha256Test01);
}
#endif
