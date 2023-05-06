/* Copyright (C) 2007-2019 Open Information Security Foundation
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
#include "detect-byte.h"
#include "detect-byte-extract.h"
#include "detect-offset.h"

#include "flow-var.h"

#include "util-byte.h"
#include "util-debug.h"

static int DetectOffsetSetup(DetectEngineCtx *, Signature *, const char *);

void DetectOffsetRegister (void)
{
    sigmatch_table[DETECT_OFFSET].name = "offset";
    sigmatch_table[DETECT_OFFSET].desc = "designate from which byte in the payload will be checked to find a match";
    sigmatch_table[DETECT_OFFSET].url = "/rules/payload-keywords.html#offset";
    sigmatch_table[DETECT_OFFSET].Setup = DetectOffsetSetup;
}

int DetectOffsetSetup (DetectEngineCtx *de_ctx, Signature *s, const char *offsetstr)
{
    const char *str = offsetstr;

    /* retrieve the sm to apply the offset against */
    SigMatch *pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, -1);
    if (pm == NULL) {
        SCLogError("offset needs preceding content option.");
        return -1;
    }

    /* verify other conditions */
    DetectContentData *cd = (DetectContentData *)pm->ctx;

    if (cd->flags & DETECT_CONTENT_STARTS_WITH) {
        SCLogError("can't use offset with startswith.");
        return -1;
    }
    if (cd->flags & DETECT_CONTENT_OFFSET) {
        SCLogError("can't use multiple offsets for the same content.");
        return -1;
    }
    if (cd->flags & (DETECT_CONTENT_WITHIN | DETECT_CONTENT_DISTANCE)) {
        SCLogError("can't use a relative "
                   "keyword like within/distance with a absolute "
                   "relative keyword like depth/offset for the same "
                   "content.");
        return -1;
    }
    if (cd->flags & DETECT_CONTENT_NEGATED && cd->flags & DETECT_CONTENT_FAST_PATTERN) {
        SCLogError("can't have a relative "
                   "negated keyword set along with 'fast_pattern'.");
        return -1;
    }
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
        SCLogError("can't have a relative "
                   "keyword set along with 'fast_pattern:only;'.");
        return -1;
    }
    if (str[0] != '-' && isalpha((unsigned char)str[0])) {
        DetectByteIndexType index;
        if (!DetectByteRetrieveSMVar(str, s, &index)) {
            SCLogError("unknown byte_ keyword var "
                       "seen in offset - %s.",
                    str);
            return -1;
        }
        cd->offset = index;
        cd->flags |= DETECT_CONTENT_OFFSET_VAR;
    } else {
        if (StringParseUint16(&cd->offset, 0, 0, str) < 0)
        {
            SCLogError("invalid value for offset: %s.", str);
            return -1;
        }
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
    return 0;
}

