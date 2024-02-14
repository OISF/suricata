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
 * Implements the strip_pseudo_headers transform keyword with option support
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-transform-strip-pseudo-headers.h"

/**
 *  \internal
 *  \brief Apply the strip_pseudo_headers keyword to the last pattern match
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param optstr options string
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformStripPseudoHeadersSetup(
        DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    SCEnter();
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_STRIP_PSEUDO_HEADERS, NULL);
    SCReturnInt(r);
}

static void DetectTransformStripPseudoHeaders(InspectionBuffer *buffer, void *options)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    if (input_len == 0) {
        return;
    }
    uint8_t output[input_len];

    bool new_line = true;
    bool pseudo = false;
    uint32_t j = 0;
    for (uint32_t i = 0; i < input_len; i++) {
        if (new_line) {
            if (input[i] == ':') {
                pseudo = true;
            }
            if (input[i] != '\r' && input[i] != '\n') {
                new_line = false;
            }
        } else {
            if (input[i] == '\n') {
                new_line = true;
                if (!pseudo) {
                    output[j] = input[i];
                    j++;
                }
                pseudo = false;
                continue;
            }
        }
        if (!pseudo) {
            output[j] = input[i];
            j++;
        }
    }
    InspectionBufferCopy(buffer, output, j);
}

void DetectTransformStripPseudoHeadersRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_STRIP_PSEUDO_HEADERS].name = "strip_pseudo_headers";
    sigmatch_table[DETECT_TRANSFORM_STRIP_PSEUDO_HEADERS].desc =
            "modify buffer via stripping pseudo headers";
    sigmatch_table[DETECT_TRANSFORM_STRIP_PSEUDO_HEADERS].url =
            "/rules/transforms.html#strip_pseudo_headers";
    sigmatch_table[DETECT_TRANSFORM_STRIP_PSEUDO_HEADERS].Transform =
            DetectTransformStripPseudoHeaders;
    sigmatch_table[DETECT_TRANSFORM_STRIP_PSEUDO_HEADERS].Setup =
            DetectTransformStripPseudoHeadersSetup;
    sigmatch_table[DETECT_TRANSFORM_STRIP_PSEUDO_HEADERS].flags |= SIGMATCH_NOOPT;
}
