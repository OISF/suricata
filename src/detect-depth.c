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
 * Implements the depth keyword.
 */

#include "suricata-common.h"

#include "detect-parse.h"
#include "detect-content.h"
#include "detect-byte.h"
#include "detect-depth.h"

#include "util-byte.h"

static int DetectDepthSetup (DetectEngineCtx *, Signature *, const char *);
static int DetectStartsWithSetup (DetectEngineCtx *, Signature *, const char *);

void DetectDepthRegister (void)
{
    sigmatch_table[DETECT_DEPTH].name = "depth";
    sigmatch_table[DETECT_DEPTH].desc = "designate how many bytes from the beginning of the payload will be checked";
    sigmatch_table[DETECT_DEPTH].url = "/rules/payload-keywords.html#depth";
    sigmatch_table[DETECT_DEPTH].Match = NULL;
    sigmatch_table[DETECT_DEPTH].Setup = DetectDepthSetup;
    sigmatch_table[DETECT_DEPTH].Free  = NULL;

    sigmatch_table[DETECT_STARTS_WITH].name = "startswith";
    sigmatch_table[DETECT_STARTS_WITH].desc = "pattern must be at the start of a buffer (same as 'depth:<pattern len>')";
    sigmatch_table[DETECT_STARTS_WITH].url = "/rules/payload-keywords.html#startswith";
    sigmatch_table[DETECT_STARTS_WITH].Setup = DetectStartsWithSetup;
    sigmatch_table[DETECT_STARTS_WITH].flags |= SIGMATCH_NOOPT;
}

static int DetectDepthSetup (DetectEngineCtx *de_ctx, Signature *s, const char *depthstr)
{
    const char *str = depthstr;
    SigMatch *pm = NULL;
    int ret = -1;

    /* retrive the sm to apply the depth against */
    pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, -1);
    if (pm == NULL) {
        SCLogError(SC_ERR_DEPTH_MISSING_CONTENT, "depth needs "
                   "preceding content, uricontent option, http_client_body, "
                   "http_server_body, http_header option, http_raw_header option, "
                   "http_method option, http_cookie, http_raw_uri, "
                   "http_stat_msg, http_stat_code, http_user_agent, "
                   "http_host, http_raw_host or "
                   "file_data/dce_stub_data sticky buffer options.");
        goto end;
    }

    /* verify other conditions. */
    DetectContentData *cd = (DetectContentData *)pm->ctx;

    if (cd->flags & DETECT_CONTENT_DEPTH) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use multiple depths for the same content.");
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
                   "negated keyword set along with 'fast_pattern'.");
        goto end;
    }
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have a relative "
                   "keyword set along with 'fast_pattern:only;'.");
        goto end;
    }
    if (str[0] != '-' && isalpha((unsigned char)str[0])) {
        DetectByteIndexType index;
        if (!DetectByteRetrieveSMVar(str, s, &index)) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "unknown byte_ keyword var "
                       "seen in depth - %s.", str);
            goto end;
        }
        cd->depth = index;
        cd->flags |= DETECT_CONTENT_DEPTH_VAR;
    } else {
        if (StringParseUint16(&cd->depth, 0, 0, str) < 0)
        {
            SCLogError(SC_ERR_INVALID_SIGNATURE,
                      "invalid value for depth: %s.", str);
            goto end;
        }

        if (cd->depth < cd->content_len) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "depth:%u smaller than "
                   "content of len %u.", cd->depth, cd->content_len);
            return -1;
        }
        /* Now update the real limit, as depth is relative to the offset */
        cd->depth += cd->offset;
    }
    cd->flags |= DETECT_CONTENT_DEPTH;

    ret = 0;
 end:
    return ret;
}

static int DetectStartsWithSetup (DetectEngineCtx *de_ctx, Signature *s, const char *unused)
{
    SigMatch *pm = NULL;
    int ret = -1;

    /* retrieve the sm to apply the depth against */
    pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, -1);
    if (pm == NULL) {
        SCLogError(SC_ERR_DEPTH_MISSING_CONTENT, "startswith needs a "
                   "preceding content option.");
        goto end;
    }

    /* verify other conditions. */
    DetectContentData *cd = (DetectContentData *)pm->ctx;

    if (cd->flags & DETECT_CONTENT_DEPTH) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use multiple "
                "depth/startswith settings for the same content.");
        goto end;
    }
    if ((cd->flags & DETECT_CONTENT_WITHIN) || (cd->flags & DETECT_CONTENT_DISTANCE)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use a relative "
                   "keyword like within/distance with a absolute "
                   "relative keyword like depth/offset for the same "
                   "content.");
        goto end;
    }
    if (cd->flags & DETECT_CONTENT_NEGATED && cd->flags & DETECT_CONTENT_FAST_PATTERN) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have a relative "
                   "negated keyword set along with a 'fast_pattern'.");
        goto end;
    }
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have a relative "
                   "keyword set along with 'fast_pattern:only;'.");
        goto end;
    }
    if (cd->flags & DETECT_CONTENT_OFFSET) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't mix offset "
                   "with startswith.");
        goto end;
    }

    cd->depth = cd->content_len;
    cd->flags |= DETECT_CONTENT_DEPTH;
    cd->flags |= DETECT_CONTENT_STARTS_WITH;

    ret = 0;
 end:
    return ret;
}
