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
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
 *
 * Implements the depth keyword
 */

#include "suricata-common.h"

#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-parse.h"

#include "flow-var.h"
#include "app-layer.h"

#include "util-debug.h"

static int DetectDepthSetup (DetectEngineCtx *, Signature *, char *);

void DetectDepthRegister (void) {
    sigmatch_table[DETECT_DEPTH].name = "depth";
    sigmatch_table[DETECT_DEPTH].Match = NULL;
    sigmatch_table[DETECT_DEPTH].Setup = DetectDepthSetup;
    sigmatch_table[DETECT_DEPTH].Free  = NULL;
    sigmatch_table[DETECT_DEPTH].RegisterTests = NULL;

    sigmatch_table[DETECT_DEPTH].flags |= SIGMATCH_PAYLOAD;
}

static int DetectDepthSetup (DetectEngineCtx *de_ctx, Signature *s, char *depthstr)
{
    char *str = depthstr;
    char dubbed = 0;
    SigMatch *pm = NULL;
    DetectContentData *cd = NULL;
    DetectUricontentData *ud = NULL;

    /* strip "'s */
    if (depthstr[0] == '\"' && depthstr[strlen(depthstr)-1] == '\"') {
        str = SCStrdup(depthstr+1);
        str[strlen(depthstr)-2] = '\0';
        dubbed = 1;
    }

    switch (s->alproto) {
        case ALPROTO_DCERPC:
            /* add to the latest content keyword from either dmatch or pmatch */
            pm =  SigMatchGetLastSMFromLists(s, 4,
                                             DETECT_CONTENT, s->dmatch_tail,
                                             DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH]);
            if (pm == NULL) {
                SCLogError(SC_ERR_DEPTH_MISSING_CONTENT, "depth needs "
                           "preceeding content option for dcerpc sig");
                if (dubbed)
                    SCFree(str);
                return -1;
            }

            break;

        default:
            pm =  SigMatchGetLastSMFromLists(s, 4,
                                             DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                                             DETECT_URICONTENT, s->umatch_tail);
            if (pm == NULL) {
                SCLogError(SC_ERR_DEPTH_MISSING_CONTENT, "depth needs "
                           "preceeding content or uricontent option");
                if (dubbed)
                    SCFree(str);
                return -1;
            }

            break;
    }

    switch (pm->type) {
        case DETECT_URICONTENT:
            ud = (DetectUricontentData *)pm->ctx;
            if (ud == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid argument");
                if (dubbed)
                    SCFree(str);
                return -1;
            }

            if (ud->flags & DETECT_URICONTENT_NEGATED) {
                if (ud->flags & DETECT_URICONTENT_FAST_PATTERN) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "You can't have a relative "
                               "negated keyword set along with a fast_pattern");
                    goto error;
                }
            } else {
                if (ud->flags & DETECT_URICONTENT_FAST_PATTERN_ONLY) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "You can't have a relative "
                               "keyword set along with a fast_pattern:only;");
                    goto error;
                }
            }

            ud->depth = (uint32_t)atoi(str);
            if (ud->depth < ud->uricontent_len) {
                ud->depth = ud->uricontent_len;
                SCLogDebug("depth increased to %"PRIu32" to match pattern len ",
                           ud->depth);
            }
            /* Now update the real limit, as depth is relative to the offset */
            ud->depth += ud->offset;
            ud->flags |= DETECT_URICONTENT_DEPTH;

            break;

        case DETECT_CONTENT:
            cd = (DetectContentData *)pm->ctx;
            if (cd == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid argument");
                if (dubbed) SCFree(str);
                return -1;
            }

            if (cd->flags & DETECT_CONTENT_NEGATED) {
                if (cd->flags & DETECT_CONTENT_FAST_PATTERN) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "You can't have a relative "
                               "negated keyword set along with a fast_pattern");
                    goto error;
                }
            } else {
                if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "You can't have a relative "
                               "keyword set along with a fast_pattern:only;");
                    goto error;
                }
            }

            cd->depth = (uint32_t)atoi(str);
            if (cd->depth < cd->content_len) {
                cd->depth = cd->content_len;
                SCLogDebug("depth increased to %"PRIu32" to match pattern len ",
                           cd->depth);
            }
            /* Now update the real limit, as depth is relative to the offset */
            cd->depth += cd->offset;
            cd->flags |= DETECT_CONTENT_DEPTH;

            break;

        default:
            SCLogError(SC_ERR_DEPTH_MISSING_CONTENT, "depth needs a preceeding "
                    "content (or uricontent) option");
            if (dubbed) SCFree(str);
                return -1;
        break;
    }

    if (dubbed)
        SCFree(str);
    return 0;

error:
    if (dubbed)
        SCFree(str);
    return -1;
}
