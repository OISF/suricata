/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements the offset keyword.
 */

#include "suricata-common.h"

#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-byte-extract.h"
#include "detect-offset.h"

#include "flow-var.h"

#include "util-debug.h"

static int DetectOffsetSetup(DetectEngineCtx *, Signature *, const char *);

void DetectOffsetRegister (void)
{
    sigmatch_table[DETECT_OFFSET].name = "offset";
    sigmatch_table[DETECT_OFFSET].desc = "designate from which byte in the payload will be checked to find a match";
    sigmatch_table[DETECT_OFFSET].url = DOC_URL DOC_VERSION "/rules/payload-keywords.html#offset";
    sigmatch_table[DETECT_OFFSET].Match = NULL;
    sigmatch_table[DETECT_OFFSET].Setup = DetectOffsetSetup;
    sigmatch_table[DETECT_OFFSET].Free  = NULL;
    sigmatch_table[DETECT_OFFSET].RegisterTests = NULL;
}

int DetectOffsetSetup (DetectEngineCtx *de_ctx, Signature *s, const char *offsetstr)
{
    const char *str = offsetstr;
    SigMatch *pm = NULL;
    int ret = -1;

    /* retrive the sm to apply the offset against */
    pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, -1);
    if (pm == NULL) {
        SCLogError(SC_ERR_OFFSET_MISSING_CONTENT, "offset needs "
                   "preceding content option");
        goto end;
    }

    /* verify other conditions */
    DetectContentData *cd = (DetectContentData *)pm->ctx;

    if (cd->flags & DETECT_CONTENT_OFFSET) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use multiple offsets for the same content. ");
        goto end;
    }
    if ((cd->flags & DETECT_CONTENT_WITHIN) || (cd->flags & DETECT_CONTENT_DISTANCE)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use a relative "
                   "keyword like within/distance with a absolute "
                   "relative keyword like depth/offset for the same "
                   "content." );
        goto end;
    }
    if (cd->flags & DETECT_CONTENT_NEGATED && cd->flags & DETECT_CONTENT_FAST_PATTERN) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have a relative "
                   "negated keyword set along with a fast_pattern");
        goto end;
    }
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have a relative "
                   "keyword set along with a fast_pattern:only;");
        goto end;
    }
    if (str[0] != '-' && isalpha((unsigned char)str[0])) {
        SigMatch *bed_sm =
            DetectByteExtractRetrieveSMVar(str, s);
        if (bed_sm == NULL) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "unknown byte_extract var "
                       "seen in offset - %s\n", str);
            goto end;
        }
        cd->offset = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
        cd->flags |= DETECT_CONTENT_OFFSET_BE;
    } else {
        cd->offset = (uint32_t)atoi(str);
        if (cd->depth != 0) {
            if (cd->depth < cd->content_len) {
                SCLogDebug("depth increased to %"PRIu32" to match pattern len",
                           cd->content_len);
                cd->depth = cd->content_len;
            }
            /* Updating the depth as is relative to the offset */
            cd->depth += cd->offset;
        }
    }
    cd->flags |= DETECT_CONTENT_OFFSET;

    ret = 0;
 end:
    return ret;
}

