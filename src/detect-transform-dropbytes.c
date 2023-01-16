/* Copyright (C) 2021 Open Information Security Foundation
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
 * \author Didier Stevens <didier.stevens@gmail.com>
 *
 * Implements the dropbytes transform keyword with option support
 * Layout of this C file mostly based on xor transform
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-transform-dropbytes.h"

#include "util-print.h"

typedef struct DetectTransformDropbytesData {
    uint8_t *bytes_to_drop;
    uint16_t cnt_bytes_to_drop;
    bool clear;
    bool negate;
} DetectTransformDropbytesData;

static int DetectTransformDropbytesSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectTransformDropbytesFree(DetectEngineCtx *, void *);
static void DetectTransformDropbytes(InspectionBuffer *buffer, void *options);
#ifdef UNITTESTS
void DetectTransformDropbytesRegisterTests(void);
#endif

void DetectTransformDropbytesRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_DROPBYTES].name = "dropbytes";
    sigmatch_table[DETECT_TRANSFORM_DROPBYTES].desc = "modify buffer by dropping bytes before inspection";
    sigmatch_table[DETECT_TRANSFORM_DROPBYTES].url = "/rules/transforms.html#dropbytes";
    sigmatch_table[DETECT_TRANSFORM_DROPBYTES].Transform = DetectTransformDropbytes;
    sigmatch_table[DETECT_TRANSFORM_DROPBYTES].Free = DetectTransformDropbytesFree;
    sigmatch_table[DETECT_TRANSFORM_DROPBYTES].Setup = DetectTransformDropbytesSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TRANSFORM_DROPBYTES].RegisterTests = DetectTransformDropbytesRegisterTests;
#endif
    sigmatch_table[DETECT_TRANSFORM_DROPBYTES].flags |= SIGMATCH_QUOTES_MANDATORY;
}

static void DetectTransformDropbytesFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL) {
        DetectTransformDropbytesData *pdd = (DetectTransformDropbytesData *)ptr;
        SCFree(pdd->bytes_to_drop);
        SCFree(pdd);
    }
}

/**
 *  \internal
 *  \brief Apply the dropbytes keyword to the last pattern match
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param optstr options string
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformDropbytesSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    SCEnter();

    // Create pdd from optstr
    DetectTransformDropbytesData *pdd = SCCalloc(1, sizeof(*pdd));
    if (pdd == NULL) {
        SCLogError("memory allocation failed");
        SCReturnInt(-1);
    }

    char *comma;
    int ret = 0;
    uint8_t *content = NULL;
    uint16_t len = 0;

    pdd->clear = false;
    pdd->negate = false;

    comma = strchr(optstr, ',');

    if (comma == NULL) {
        ret = DetectContentDataParse("dropbytes", optstr, &content, &len);
    } else {
        for (uint32_t i = 0; i < (comma - optstr); i++) {
            if (optstr[i] == 'c') {
                pdd->clear = true;
            } else if (optstr[i] == '!') {
                pdd->negate = true;
            } else {
                SCLogError("DROPBYTES unknown flag: %c", optstr[i]);
                DetectTransformDropbytesFree(de_ctx, pdd);
                SCReturnInt(-1);
            }
        }
        ret = DetectContentDataParse("dropbytes", comma + 1, &content, &len);
    }

    if (ret == -1 || content == NULL) {
        SCLogError("DROPBYTES option error");
        DetectTransformDropbytesFree(de_ctx, pdd);
        SCReturnInt(-1);
    }

    pdd->bytes_to_drop = content;
    pdd->cnt_bytes_to_drop = len;
    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_DROPBYTES, pdd);
    if (r != 0) {
        DetectTransformDropbytesFree(de_ctx, pdd);
    }

    SCReturnInt(r);
}

static void DetectTransformDropbytes(InspectionBuffer *buffer, void *options)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    uint32_t output_len = 0;
    DetectTransformDropbytesData *pdd = options;
    if (input_len == 0) {
        return;
    }
    uint8_t output[input_len];

#ifdef DEBUG
    uint8_t dump[10000];
    uint32_t offset = 0;
    PrintRawDataToBuffer(dump, &offset, 10000, input, input_len);
    SCLogDebug("Input:\n%s\n", (char *)dump);
#endif

    for (uint32_t i = 0; i < input_len; i++) {
        bool keep = !pdd->negate;
        for (uint32_t k = 0; k < pdd->cnt_bytes_to_drop; k++) {
            if (input[i] == pdd->bytes_to_drop[k]) {
                keep = pdd->negate;
                break;
            }
        }
        if (keep) {
            output[output_len++] = input[i];
        }
    }

    if (output_len == 0 || (pdd->clear && input_len == output_len))
        buffer->inspect_len = 0;
    else
        InspectionBufferCopy(buffer, output, output_len);

#ifdef DEBUG
    offset = 0;
    PrintRawDataToBuffer(dump, &offset, 10000, buffer->inspect, buffer->inspect_len);
    SCLogDebug("Output:\n%s\n", (char *)dump);
#endif
}

#ifdef UNITTESTS
#include "tests/detect-transform-dropbytes.c"
#endif
