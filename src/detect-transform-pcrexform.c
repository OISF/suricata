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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 *
 * Implements the pcrexform transform keyword with option support
 */

#include "suricata-common.h"

#include "detect-engine.h"
#include "detect-transform-pcrexform.h"
#include "detect-pcre.h"

#ifdef UNITTESTS
#endif
typedef struct DetectTransformPcrexformData {
    pcre2_code *regex;
    pcre2_match_context *context;
} DetectTransformPcrexformData;

static int DetectTransformPcrexformSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectTransformPcrexformFree(DetectEngineCtx *, void *);
static void DetectTransformPcrexform(InspectionBuffer *buffer, void *options);
#ifdef UNITTESTS
void DetectTransformPcrexformRegisterTests (void);
#endif

void DetectTransformPcrexformRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_PCREXFORM].name = "pcrexform";
    sigmatch_table[DETECT_TRANSFORM_PCREXFORM].desc =
        "modify buffer via PCRE before inspection";
    sigmatch_table[DETECT_TRANSFORM_PCREXFORM].url = "/rules/transforms.html#pcre-xform";
    sigmatch_table[DETECT_TRANSFORM_PCREXFORM].Transform =
        DetectTransformPcrexform;
    sigmatch_table[DETECT_TRANSFORM_PCREXFORM].Free =
        DetectTransformPcrexformFree;
    sigmatch_table[DETECT_TRANSFORM_PCREXFORM].Setup =
        DetectTransformPcrexformSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TRANSFORM_PCREXFORM].RegisterTests = DetectTransformPcrexformRegisterTests;
#endif
    sigmatch_table[DETECT_TRANSFORM_PCREXFORM].flags |= SIGMATCH_QUOTES_MANDATORY;
}

static void DetectTransformPcrexformFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL) {
        DetectTransformPcrexformData *pxd = (DetectTransformPcrexformData *) ptr;
        pcre2_match_context_free(pxd->context);
        pcre2_code_free(pxd->regex);
        SCFree(pxd);
    }
}

/**
 *  \internal
 *  \brief Apply the pcrexform keyword to the last pattern match
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param regexstr options string
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformPcrexformSetup (DetectEngineCtx *de_ctx, Signature *s, const char *regexstr)
{
    SCEnter();

    // Create pxd from regexstr
    DetectTransformPcrexformData *pxd = SCCalloc(1, sizeof(*pxd));
    if (pxd == NULL) {
        SCLogDebug("pxd allocation failed");
        SCReturnInt(-1);
    }

    pxd->context = pcre2_match_context_create(NULL);
    if (pxd->context == NULL) {
        SCFree(pxd);
        SCReturnInt(-1);
    }
    pcre2_set_match_limit(pxd->context, SC_MATCH_LIMIT_DEFAULT);
    pcre2_set_recursion_limit(pxd->context, SC_MATCH_LIMIT_RECURSION_DEFAULT);
    int en;
    PCRE2_SIZE eo;
    pxd->regex = pcre2_compile((PCRE2_SPTR8)regexstr, PCRE2_ZERO_TERMINATED, 0, &en, &eo, NULL);
    if (pxd->regex == NULL) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(en, buffer, sizeof(buffer));
        SCLogError(SC_ERR_PCRE_COMPILE,
                "pcre2 compile of \"%s\" failed at "
                "offset %d: %s",
                regexstr, (int)eo, buffer);
        pcre2_match_context_free(pxd->context);
        SCFree(pxd);
        SCReturnInt(-1);
    }
    // check pcd->regex has exactly one capture expression
    uint32_t nb;
    if (pcre2_pattern_info(pxd->regex, PCRE2_INFO_CAPTURECOUNT, &nb) < 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "pcrexform failed getting info about capturecount");
        DetectTransformPcrexformFree(de_ctx, pxd);
        SCReturnInt(-1);
    }
    if (nb != 1) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                "pcrexform needs exactly one substring capture, found %" PRIu32, nb);
        DetectTransformPcrexformFree(de_ctx, pxd);
        SCReturnInt(-1);
    }

    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_PCREXFORM, pxd);
    if (r != 0) {
        DetectTransformPcrexformFree(de_ctx, pxd);
    }

    SCReturnInt(r);
}

static void DetectTransformPcrexform(InspectionBuffer *buffer, void *options)
{
    const char *input = (const char *)buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    DetectTransformPcrexformData *pxd = options;

    pcre2_match_data *match = pcre2_match_data_create_from_pattern(pxd->regex, NULL);
    int ret = pcre2_match(pxd->regex, (PCRE2_SPTR8)input, input_len, 0, 0, match, pxd->context);

    if (ret > 0) {
        const char *str;
        PCRE2_SIZE caplen;
        ret = pcre2_substring_get_bynumber(match, 1, (PCRE2_UCHAR8 **)&str, &caplen);

        if (ret >= 0) {
            InspectionBufferCopy(buffer, (uint8_t *)str, (uint32_t)caplen);
            pcre2_substring_free((PCRE2_UCHAR8 *)str);
        }
    }
    pcre2_match_data_free(match);
}

#ifdef UNITTESTS
#include "tests/detect-transform-pcrexform.c"
#endif
