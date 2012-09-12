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
 * Implements the depth keyword.
 */

#include "suricata-common.h"

#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-byte-extract.h"
#include "detect-parse.h"

#include "flow-var.h"
#include "app-layer.h"

#include "util-debug.h"

static int DetectDepthSetup (DetectEngineCtx *, Signature *, char *);

void DetectDepthRegister (void) {
    sigmatch_table[DETECT_DEPTH].name = "depth";
    sigmatch_table[DETECT_DEPTH].desc = "designate how many bytes from the beginning of the payload will be checked";
    sigmatch_table[DETECT_DEPTH].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Payload_keywords#Depth";
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

    /* strip "'s */
    if (depthstr[0] == '\"' && depthstr[strlen(depthstr) - 1] == '\"') {
        str = SCStrdup(depthstr + 1);
        if (unlikely(str == NULL))
            goto error;
        str[strlen(depthstr) - 2] = '\0';
        dubbed = 1;
    }

    switch (s->alproto) {
        case ALPROTO_DCERPC:
            /* add to the latest content keyword from either dmatch or pmatch */
            pm =  SigMatchGetLastSMFromLists(s, 4,
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_DMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH]);
            if (pm == NULL) {
                SCLogError(SC_ERR_DEPTH_MISSING_CONTENT, "depth needs "
                           "preceding content option for dcerpc sig");
                if (dubbed)
                    SCFree(str);
                return -1;
            }

            break;

        default:
            pm =  SigMatchGetLastSMFromLists(s, 24,
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_UMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HCBDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSBDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRHDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HMDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HCDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSCDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH],
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HUADMATCH]);
            if (pm == NULL) {
                SCLogError(SC_ERR_DEPTH_MISSING_CONTENT, "depth needs "
                        "preceding content, uricontent option, http_client_body, "
                        "http_server_body, http_header option, http_raw_header option, "
                        "http_method option, http_cookie, http_raw_uri, "
                        "http_stat_msg, http_stat_code or http_user_agent option");
                if (dubbed)
                    SCFree(str);
                return -1;
            }

            break;
    }

    /* i swear we will clean this up :).  Use a single version for all.  Using
     * separate versions for all now, to avoiding breaking any code */
    switch (pm->type) {
        case DETECT_CONTENT:
            cd = (DetectContentData *)pm->ctx;
            if (cd == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid argument");
                if (dubbed) SCFree(str);
                return -1;
            }

            if (cd->flags & DETECT_CONTENT_NEGATED) {
                if (cd->flags & DETECT_CONTENT_FAST_PATTERN) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have a relative "
                               "negated keyword set along with a fast_pattern");
                    goto error;
                }
            } else {
                if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have a relative "
                               "keyword set along with a fast_pattern:only;");
                    goto error;
                }
            }

            if ((cd->flags & DETECT_CONTENT_WITHIN) || (cd->flags & DETECT_CONTENT_DISTANCE)) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use a relative keyword "
                               "with a non-relative keyword for the same content." );
                goto error;
            }

            if (cd->flags & DETECT_CONTENT_DEPTH) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use multiple depths for the same content.");
                goto error;
            }

            if (str[0] != '-' && isalpha((unsigned char)str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "unknown byte_extract var "
                               "seen in depth - %s\n", str);
                    goto error;
                }
                cd->depth = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_DEPTH_BE;
            } else {
                cd->depth = (uint32_t)atoi(str);
                if (cd->depth < cd->content_len) {
                    uint32_t content_len = cd->content_len;
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "depth - %"PRIu16
                               " smaller than content length - %"PRIu32,
                               cd->depth, content_len);
                    goto error;
                }
                /* Now update the real limit, as depth is relative to the offset */
                cd->depth += cd->offset;
            }

            cd->flags |= DETECT_CONTENT_DEPTH;

            break;

        default:
            SCLogError(SC_ERR_DEPTH_MISSING_CONTENT, "depth needs a preceding "
                    "content (or uricontent) option");
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
