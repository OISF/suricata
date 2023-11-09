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
 * \author Jeff Lucovsky <jlucovsky@oisf.net>
 *
 * Implements case changing transforms
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-transform-casechange.h"

/**
 *  \internal
 *  \brief Register the to_lowercase transform
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param optstr options string
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformToLowerSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    SCEnter();

    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_TOLOWER, NULL);

    SCReturnInt(r);
}

/**
 *  \internal
 *  \brief Apply the to_lowercase keyword to the last pattern match
 *  \param buffer Inspection buffer
 *  \param optstr options string
 */
static void DetectTransformToLower(InspectionBuffer *buffer, void *options)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;

    if (input_len == 0) {
        return;
    }

    uint8_t output[input_len];
    for (uint32_t i = 0; i < input_len; i++) {
        output[i] = u8_tolower(input[i]);
    }

    InspectionBufferCopy(buffer, output, input_len);
}
/**
 *  \internal
 *  \brief Register the to_upperrcase transform
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param optstr options string
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformToUpperSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    SCEnter();

    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_TOUPPER, NULL);

    SCReturnInt(r);
}

/**
 *  \internal
 *  \brief Apply the to_uppercase keyword to the last pattern match
 *  \param buffer Inspection buffer
 *  \param optstr options string
 */
static void DetectTransformToUpper(InspectionBuffer *buffer, void *options)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;

    if (input_len == 0) {
        return;
    }

    uint8_t output[input_len];
    for (uint32_t i = 0; i < input_len; i++) {
        output[i] = u8_toupper(input[i]);
    }

    InspectionBufferCopy(buffer, output, input_len);
}

/*
 * \internal
 * \brief Check if content is compatible with transform
 *
 * If the content contains any lowercase characters, than it is not compatible.
 */
static bool TransformToUpperValidate(const uint8_t *content, uint16_t content_len, void *options)
{
    if (content) {
        for (uint32_t i = 0; i < content_len; i++) {
            if (islower(*content++)) {
                return false;
            }
        }
    }
    return true;
}

/*
 * \internal
 * \brief Check if content is compatible with transform
 *
 * If the content contains any uppercase characters, than it is not compatible.
 */
static bool TransformToLowerValidate(const uint8_t *content, uint16_t content_len, void *options)
{
    if (content) {
        for (uint32_t i = 0; i < content_len; i++) {
            if (isupper(*content++)) {
                return false;
            }
        }
    }
    return true;
}

void DetectTransformToUpperRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_TOUPPER].name = "to_uppercase";
    sigmatch_table[DETECT_TRANSFORM_TOUPPER].desc = "convert buffer to uppercase";
    sigmatch_table[DETECT_TRANSFORM_TOUPPER].url = "/rules/transforms.html#to_uppercase";
    sigmatch_table[DETECT_TRANSFORM_TOUPPER].Transform = DetectTransformToUpper;
    sigmatch_table[DETECT_TRANSFORM_TOUPPER].TransformValidate = TransformToUpperValidate;
    sigmatch_table[DETECT_TRANSFORM_TOUPPER].Setup = DetectTransformToUpperSetup;
    sigmatch_table[DETECT_TRANSFORM_TOUPPER].flags |= SIGMATCH_NOOPT;
}

void DetectTransformToLowerRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_TOLOWER].name = "to_lowercase";
    sigmatch_table[DETECT_TRANSFORM_TOLOWER].desc = "convert buffer to lowercase";
    sigmatch_table[DETECT_TRANSFORM_TOLOWER].url = "/rules/transforms.html#to_lowercase";
    sigmatch_table[DETECT_TRANSFORM_TOLOWER].Transform = DetectTransformToLower;
    sigmatch_table[DETECT_TRANSFORM_TOLOWER].TransformValidate = TransformToLowerValidate;
    sigmatch_table[DETECT_TRANSFORM_TOLOWER].Setup = DetectTransformToLowerSetup;
    sigmatch_table[DETECT_TRANSFORM_TOLOWER].flags |= SIGMATCH_NOOPT;
}
