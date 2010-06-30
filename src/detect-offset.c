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
 *
 * Implements the offset keyword
 */

#include "suricata-common.h"

#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "app-layer.h"

#include "flow-var.h"

#include "util-debug.h"

static int DetectOffsetSetup (DetectEngineCtx *, Signature *, char *);

void DetectOffsetRegister (void) {
    sigmatch_table[DETECT_OFFSET].name = "offset";
    sigmatch_table[DETECT_OFFSET].Match = NULL;
    sigmatch_table[DETECT_OFFSET].Setup = DetectOffsetSetup;
    sigmatch_table[DETECT_OFFSET].Free  = NULL;
    sigmatch_table[DETECT_OFFSET].RegisterTests = NULL;

    sigmatch_table[DETECT_OFFSET].flags |= SIGMATCH_PAYLOAD;
}

int DetectOffsetSetup (DetectEngineCtx *de_ctx, Signature *s, char *offsetstr)
{
    char *str = offsetstr;
    char dubbed = 0;
    SigMatch *pm = NULL;

    /* strip "'s */
    if (offsetstr[0] == '\"' && offsetstr[strlen(offsetstr)-1] == '\"') {
        str = SCStrdup(offsetstr+1);
        str[strlen(offsetstr)-2] = '\0';
        dubbed = 1;
    }

    switch (s->alproto) {
        case ALPROTO_DCERPC:
            /* add to the latest "content" keyword from either dmatch or pmatch */
            pm =  SigMatchGetLastSMFromLists(s, 4,
                                             DETECT_CONTENT, s->dmatch_tail,
                                             DETECT_CONTENT, s->pmatch_tail);
            if (pm == NULL) {
                SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "offset needs"
                           "preceeding content option for dcerpc sig");
                if (dubbed)
                    SCFree(str);
                return -1;
            }

            break;

        default:
            pm = SigMatchGetLastSMFromLists(s, 4,
                                            DETECT_CONTENT, s->pmatch_tail,
                                            DETECT_URICONTENT, s->umatch_tail);
            if (pm == NULL) {
                SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "distance needs"
                           "preceeding content or uricontent option");
                if (dubbed)
                    SCFree(str);
                return -1;
            }

            break;
    }

    DetectUricontentData *ud = NULL;
    DetectContentData *cd = NULL;
    switch (pm->type) {
        case DETECT_URICONTENT:
            ud = (DetectUricontentData *)pm->ctx;
            if (ud == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid argument");
                if (dubbed) SCFree(str);
                return -1;
            }
            ud->offset = (uint32_t)atoi(str);
            if (ud->depth != 0 && (ud->uricontent_len + ud->offset) > ud->depth) {
                if (ud->depth > ud->uricontent_len) {
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len"
                        " and offset", ud->depth + ud->offset);
                    ud->depth += ud->offset;
                } else {
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len"
                            " and offset", ud->uricontent_len + ud->offset);
                    ud->depth = ud->uricontent_len + ud->offset;
                }
            }
            break;

        case DETECT_CONTENT:
            cd = (DetectContentData *)pm->ctx;
            if (cd == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid argument");
                if (dubbed) SCFree(str);
                return -1;
            }
            cd->offset = (uint32_t)atoi(str);
            if (cd->depth != 0 && (cd->content_len + cd->offset) > cd->depth) {
                if (cd->depth > cd->content_len) {
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len"
                        " and offset", cd->depth + cd->offset);
                    cd->depth += cd->offset;
                } else {
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len"
                            " and offset", cd->content_len + cd->offset);
                    cd->depth = cd->content_len + cd->offset;
                }
            }
            break;

        default:
            SCLogError(SC_ERR_OFFSET_MISSING_CONTENT, "offset needs a preceeding"
                    " content or uricontent option");
            if (dubbed) SCFree(str);
                return -1;

            break;
    }

    if (dubbed)
        SCFree(str);
    return 0;
}

