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
        if (str == NULL)
            goto error;
        str[strlen(offsetstr)-2] = '\0';
        dubbed = 1;
    }

    switch (s->alproto) {
        case ALPROTO_DCERPC:
            /* add to the latest "content" keyword from either dmatch or pmatch */
            pm =  SigMatchGetLastSMFromLists(s, 4,
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_DMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH]);
            if (pm == NULL) {
                SCLogError(SC_ERR_OFFSET_MISSING_CONTENT, "offset needs "
                           "preceeding content option for dcerpc sig");
                if (dubbed)
                    SCFree(str);
                return -1;
            }

            break;

        default:
            pm = SigMatchGetLastSMFromLists(s, 22,
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_UMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HCBDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSBDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRHDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HMDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HCDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSCDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH]);
            if (pm == NULL) {
                SCLogError(SC_ERR_OFFSET_MISSING_CONTENT, "offset needs "
                           "preceeding content or uricontent option, http_client_body, "
                           "http_header, http_raw_header, http_method, "
                           "http_cookie, http_raw_uri, http_stat_msg or "
                           "http_stat_code option");
                if (dubbed)
                    SCFree(str);
                return -1;
            }

            break;
    }

    /* we can remove this switch now with the unified structure */
    DetectContentData *cd = NULL;
    switch (pm->type) {
        case DETECT_CONTENT:
            cd = (DetectContentData *)pm->ctx;
            if (cd == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid argument");
                if (dubbed)
                    SCFree(str);
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

            if (cd->flags & DETECT_CONTENT_WITHIN || cd->flags & DETECT_CONTENT_DISTANCE) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "You can't use a relative keyword "
                               "with a non-relative keyword for the same content." );
                goto error;
            }

            if (cd->flags & DETECT_CONTENT_OFFSET) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "You can't use multiple offsets for the same content. ");
                goto error;
            }

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                               "seen in offset - %s\n", str);
                    goto error;
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

            break;

        default:
            SCLogError(SC_ERR_OFFSET_MISSING_CONTENT, "offset needs a preceeding"
                    " content or uricontent option");
            goto error;
    }

    if (dubbed)
        SCFree(str);
    return 0;

error:
    if (dubbed)
        SCFree(str);
    return -1;
}

