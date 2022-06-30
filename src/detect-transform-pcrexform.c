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

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-pcre.h"
#include "detect-transform-pcrexform.h"

typedef DetectParseRegex DetectTransformPcrexformData;

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
    DetectTransformPcrexformData *pxd = SCCalloc(sizeof(*pxd), 1);
    if (pxd == NULL) {
        SCLogDebug("pxd allocation failed");
        SCReturnInt(-1);
    }

    if (!DetectSetupParseRegexesOpts(regexstr, pxd, 0)) {
        SCFree(pxd);
        SCReturnInt(-1);
    }

    if (pxd->study != NULL) {
        pxd->study->match_limit = SC_MATCH_LIMIT_DEFAULT;
        pxd->study->flags |= PCRE_EXTRA_MATCH_LIMIT;
#ifndef NO_PCRE_MATCH_RLIMIT
        pxd->study->match_limit_recursion = SC_MATCH_LIMIT_RECURSION_DEFAULT;
        pxd->study->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
#endif
    }

    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_PCREXFORM, pxd);
    if (r != 0) {
        SCFree(pxd);
    }

    SCReturnInt(r);
}

static void DetectTransformPcrexform(InspectionBuffer *buffer, void *options)
{
    const char *input = (const char *)buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    DetectTransformPcrexformData *pxd = options;

    int ov[MAX_SUBSTRINGS];
    int ret = DetectParsePcreExecLen(pxd, input, input_len, 0, 0, ov, MAX_SUBSTRINGS);

    if (ret > 0) {
        const char *str;
        ret = pcre_get_substring((char *) buffer->inspect, ov,
                                  MAX_SUBSTRINGS, ret - 1, &str);

        if (ret >= 0) {
            InspectionBufferCopy(buffer, (uint8_t *)str, (uint32_t) ret);
            pcre_free_substring(str);
        }
    }
}

#ifdef UNITTESTS
#include "tests/detect-transform-pcrexform.c"
#endif
