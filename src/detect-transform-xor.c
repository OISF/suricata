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
 * \author Philippe Antoine <contact@catenacyber.fr>
 *
 * Implements the xor transform keyword with option support
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#endif
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-transform-xor.h"

typedef struct DetectTransformXorData {
    uint8_t *key;
    // limit the key length
    uint8_t length;
} DetectTransformXorData;

static int DetectTransformXorSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectTransformXorFree(DetectEngineCtx *, void *);
static void DetectTransformXor(InspectionBuffer *buffer, void *options);
#ifdef UNITTESTS
void DetectTransformXorRegisterTests(void);
#endif

void DetectTransformXorRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_XOR].name = "xor";
    sigmatch_table[DETECT_TRANSFORM_XOR].desc = "modify buffer via XOR decoding before inspection";
    sigmatch_table[DETECT_TRANSFORM_XOR].url = "/rules/transforms.html#xor";
    sigmatch_table[DETECT_TRANSFORM_XOR].Transform = DetectTransformXor;
    sigmatch_table[DETECT_TRANSFORM_XOR].Free = DetectTransformXorFree;
    sigmatch_table[DETECT_TRANSFORM_XOR].Setup = DetectTransformXorSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TRANSFORM_XOR].RegisterTests = DetectTransformXorRegisterTests;
#endif
    sigmatch_table[DETECT_TRANSFORM_XOR].flags |= SIGMATCH_QUOTES_MANDATORY;
}

static void DetectTransformXorFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL) {
        DetectTransformXorData *pxd = (DetectTransformXorData *)ptr;
        SCFree(pxd->key);
        SCFree(pxd);
    }
}

/**
 *  \internal
 *  \brief Apply the xor keyword to the last pattern match
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param optstr options string
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformXorSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    SCEnter();

    // Create pxd from optstr
    DetectTransformXorData *pxd = SCCalloc(1, sizeof(*pxd));
    if (pxd == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
        SCReturnInt(-1);
    }

    size_t keylen = strlen(optstr);
    if (keylen % 2 == 1) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "XOR transform key's length must be an even number");
        DetectTransformXorFree(de_ctx, pxd);
        SCReturnInt(-1);
    }
    if (keylen / 2 > UINT8_MAX) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Key length too big for XOR transform");
        DetectTransformXorFree(de_ctx, pxd);
        SCReturnInt(-1);
    }
    pxd->length = (uint8_t)(keylen / 2);
    pxd->key = SCMalloc(keylen / 2);
    if (pxd->key == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "memory allocation failed");
        DetectTransformXorFree(de_ctx, pxd);
        SCReturnInt(-1);
    }
    for (size_t i = 0; i < keylen / 2; i++) {
        if ((isxdigit(optstr[2 * i])) && (isxdigit(optstr[2 * i + 1]))) {
            pxd->key[i] = (uint8_t)((optstr[2 * i] >= 'A' ? ((optstr[2 * i] & 0xdf) - 'A') + 10
                                                          : (optstr[2 * i] - '0'))
                                    << 4);
            pxd->key[i] |= (optstr[2 * i + 1] >= 'A' ? ((optstr[2 * i + 1] & 0xdf) - 'A') + 10
                                                     : (optstr[2 * i + 1] - '0'));
        } else {
            SCLogError(SC_ERR_INVALID_SIGNATURE,
                    "XOR transform key must be hexadecimal characters only");
            DetectTransformXorFree(de_ctx, pxd);
            SCReturnInt(-1);
        }
    }

    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_XOR, pxd);
    if (r != 0) {
        DetectTransformXorFree(de_ctx, pxd);
    }

    SCReturnInt(r);
}

static void DetectTransformXor(InspectionBuffer *buffer, void *options)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    DetectTransformXorData *pxd = options;
    if (input_len == 0) {
        return;
    }
    uint8_t output[input_len];

    for (uint32_t i = 0; i < input_len; i++) {
        output[i] = input[i] ^ pxd->key[i % pxd->length];
    }
    InspectionBufferCopy(buffer, output, input_len);
}

#ifdef UNITTESTS
#include "tests/detect-transform-xor.c"
#endif
