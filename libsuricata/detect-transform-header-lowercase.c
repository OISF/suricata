/* Copyright (C) 2023 Open Information Security Foundation
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
 * \author Philippe Antoine <contact@catenacyber.fr>
 *
 * Implements the header_lowercase transform keyword with option support
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-transform-header-lowercase.h"

/**
 *  \internal
 *  \brief Apply the header_lowercase keyword to the last pattern match
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param optstr options string
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformHeaderLowercaseSetup(
        DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_HEADER_LOWERCASE, NULL);
    SCReturnInt(r);
}

static void DetectTransformHeaderLowercase(InspectionBuffer *buffer, void *options)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    if (input_len == 0) {
        return;
    }
    uint8_t output[input_len];

    // state 0 is header name, 1 is header value
    int state = 0;
    for (uint32_t i = 0; i < input_len; i++) {
        if (state == 0) {
            if (input[i] == ':') {
                output[i] = input[i];
                state = 1;
            } else {
                output[i] = u8_tolower(input[i]);
            }
        } else {
            output[i] = input[i];
            if (input[i] == '\n') {
                state = 0;
            }
        }
    }
    InspectionBufferCopy(buffer, output, input_len);
}

void DetectTransformHeaderLowercaseRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_HEADER_LOWERCASE].name = "header_lowercase";
    sigmatch_table[DETECT_TRANSFORM_HEADER_LOWERCASE].desc =
            "modify buffer via lowercaseing header names";
    sigmatch_table[DETECT_TRANSFORM_HEADER_LOWERCASE].url =
            "/rules/transforms.html#header_lowercase";
    sigmatch_table[DETECT_TRANSFORM_HEADER_LOWERCASE].Transform = DetectTransformHeaderLowercase;
    sigmatch_table[DETECT_TRANSFORM_HEADER_LOWERCASE].Setup = DetectTransformHeaderLowercaseSetup;
    sigmatch_table[DETECT_TRANSFORM_HEADER_LOWERCASE].flags |= SIGMATCH_NOOPT;
}
