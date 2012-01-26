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
    DetectContentData *ud = NULL;

    /* strip "'s */
    if (depthstr[0] == '\"' && depthstr[strlen(depthstr) - 1] == '\"') {
        str = SCStrdup(depthstr + 1);
        if (str == NULL)
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
                           "preceeding content option for dcerpc sig");
                if (dubbed)
                    SCFree(str);
                return -1;
            }

            break;

        default:
            pm =  SigMatchGetLastSMFromLists(s, 22,
                    DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                    DETECT_URICONTENT, s->sm_lists_tail[DETECT_SM_LIST_UMATCH],
                    DETECT_AL_HTTP_RAW_URI, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH],
                    DETECT_AL_HTTP_CLIENT_BODY, s->sm_lists_tail[DETECT_SM_LIST_HCBDMATCH],
                    DETECT_AL_HTTP_SERVER_BODY, s->sm_lists_tail[DETECT_SM_LIST_HSBDMATCH],
                    DETECT_AL_HTTP_HEADER, s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH],
                    DETECT_AL_HTTP_RAW_HEADER, s->sm_lists_tail[DETECT_SM_LIST_HRHDMATCH],
                    DETECT_AL_HTTP_METHOD, s->sm_lists_tail[DETECT_SM_LIST_HMDMATCH],
                    DETECT_AL_HTTP_COOKIE, s->sm_lists_tail[DETECT_SM_LIST_HCDMATCH],
                    DETECT_AL_HTTP_STAT_CODE, s->sm_lists_tail[DETECT_SM_LIST_HSCDMATCH],
                    DETECT_AL_HTTP_STAT_MSG, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH]);
            if (pm == NULL) {
                SCLogError(SC_ERR_DEPTH_MISSING_CONTENT, "depth needs "
                        "preceeding content, uricontent option, http_client_body, "
                        "http_server_body, http_header option, http_raw_header option, "
                        "http_method option, http_cookie, http_raw_uri, "
                        "http_stat_msg or http_stat_code option");
                if (dubbed)
                    SCFree(str);
                return -1;
            }

            break;
    }

    /* i swear we will clean this up :).  Use a single version for all.  Using
     * separate versions for all now, to avoiding breaking any code */
    switch (pm->type) {
        case DETECT_URICONTENT:
            ud = (DetectContentData *)pm->ctx;
            if (ud == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid argument");
                if (dubbed)
                    SCFree(str);
                return -1;
            }

            if (ud->flags & DETECT_CONTENT_NEGATED) {
                if (ud->flags & DETECT_CONTENT_FAST_PATTERN) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "You can't have a relative "
                               "negated keyword set along with a fast_pattern");
                    goto error;
                }
            } else {
                if (ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "You can't have a relative "
                               "keyword set along with a fast_pattern:only;");
                    goto error;
                }
            }

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                               "seen in depth - %s\n", str);
                    goto error;
                }
                ud->depth = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                ud->flags |= DETECT_CONTENT_DEPTH_BE;
            } else {
                ud->depth = (uint32_t)atoi(str);
                if (ud->depth < ud->content_len) {
                    ud->depth = ud->content_len;
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len ",
                               ud->depth);
                }
                /* Now update the real limit, as depth is relative to the offset */
                ud->depth += ud->offset;
            }

            ud->flags |= DETECT_CONTENT_DEPTH;

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

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                               "seen in depth - %s\n", str);
                    goto error;
                }
                cd->depth = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_DEPTH_BE;
            } else {
                cd->depth = (uint32_t)atoi(str);
                if (cd->depth < cd->content_len) {
                    cd->depth = cd->content_len;
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len ",
                               cd->depth);
                }
                /* Now update the real limit, as depth is relative to the offset */
                cd->depth += cd->offset;
            }

            cd->flags |= DETECT_CONTENT_DEPTH;

            break;

        case DETECT_AL_HTTP_CLIENT_BODY:
            cd = (DetectContentData *)pm->ctx;
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

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                               "seen in depth - %s\n", str);
                    goto error;
                }
                cd->depth = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_DEPTH_BE;
            } else {
                cd->depth = (uint32_t)atoi(str);
                if (cd->depth < cd->content_len) {
                    cd->depth = cd->content_len;
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len ",
                               cd->depth);
                }
                /* Now update the real limit, as depth is relative to the offset */
                cd->depth += cd->offset;
            }

            cd->flags |= DETECT_CONTENT_DEPTH;

            break;

        case DETECT_AL_HTTP_SERVER_BODY:
            cd = (DetectContentData *)pm->ctx;
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

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                               "seen in depth - %s\n", str);
                    goto error;
                }
                cd->depth = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_DEPTH_BE;
            } else {
                cd->depth = (uint32_t)atoi(str);
                if (cd->depth < cd->content_len) {
                    cd->depth = cd->content_len;
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len ",
                               cd->depth);
                }
                /* Now update the real limit, as depth is relative to the offset */
                cd->depth += cd->offset;
            }

            cd->flags |= DETECT_CONTENT_DEPTH;

            break;

        case DETECT_AL_HTTP_HEADER:
            cd = (DetectContentData *)pm->ctx;
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

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                               "seen in depth - %s\n", str);
                    goto error;
                }
                cd->depth = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_DEPTH_BE;
            } else {
                cd->depth = (uint32_t)atoi(str);
                if (cd->depth < cd->content_len) {
                    cd->depth = cd->content_len;
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len ",
                               cd->depth);
                }
                /* Now update the real limit, as depth is relative to the offset */
                cd->depth += cd->offset;
            }

            cd->flags |= DETECT_CONTENT_DEPTH;

            break;

        case DETECT_AL_HTTP_RAW_HEADER:
            cd = (DetectContentData *)pm->ctx;
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

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                               "seen in depth - %s\n", str);
                    goto error;
                }
                cd->depth = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_DEPTH_BE;
            } else {
                cd->depth = (uint32_t)atoi(str);
                if (cd->depth < cd->content_len) {
                    cd->depth = cd->content_len;
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len ",
                               cd->depth);
                }
                /* Now update the real limit, as depth is relative to the offset */
                cd->depth += cd->offset;
            }

            cd->flags |= DETECT_CONTENT_DEPTH;

            break;

        case DETECT_AL_HTTP_METHOD:
            cd = (DetectContentData *)pm->ctx;
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

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                               "seen in depth - %s\n", str);
                    goto error;
                }
                cd->depth = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_DEPTH_BE;
            } else {
                cd->depth = (uint32_t)atoi(str);
                if (cd->depth < cd->content_len) {
                    cd->depth = cd->content_len;
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len ",
                               cd->depth);
                }
                /* Now update the real limit, as depth is relative to the offset */
                cd->depth += cd->offset;
            }

            cd->flags |= DETECT_CONTENT_DEPTH;

            break;

        case DETECT_AL_HTTP_COOKIE:
            cd = (DetectContentData *)pm->ctx;
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

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                               "seen in depth - %s\n", str);
                    goto error;
                }
                cd->depth = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_DEPTH_BE;
            } else {
                cd->depth = (uint32_t)atoi(str);
                if (cd->depth < cd->content_len) {
                    cd->depth = cd->content_len;
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len ",
                               cd->depth);
                }
                /* Now update the real limit, as depth is relative to the offset */
                cd->depth += cd->offset;
            }

            cd->flags |= DETECT_CONTENT_DEPTH;

            break;

        case DETECT_AL_HTTP_RAW_URI:
            cd = (DetectContentData *)pm->ctx;
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

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                               "seen in depth - %s\n", str);
                    goto error;
                }
                cd->depth = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_DEPTH_BE;
            } else {
                cd->depth = (uint32_t)atoi(str);
                if (cd->depth < cd->content_len) {
                    cd->depth = cd->content_len;
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len ",
                               cd->depth);
                }
                /* Now update the real limit, as depth is relative to the offset */
                cd->depth += cd->offset;
                cd->flags |= DETECT_CONTENT_DEPTH;
            }

            break;

        case DETECT_AL_HTTP_STAT_MSG:
            cd = (DetectContentData *)pm->ctx;
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

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                               "seen in depth - %s\n", str);
                    goto error;
                }
                cd->depth = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_DEPTH_BE;
            } else {
                cd->depth = (uint32_t)atoi(str);
                if (cd->depth < cd->content_len) {
                    cd->depth = cd->content_len;
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len ",
                               cd->depth);
                }
                /* Now update the real limit, as depth is relative to the offset */
                cd->depth += cd->offset;
                cd->flags |= DETECT_CONTENT_DEPTH;
            }

            break;

        case DETECT_AL_HTTP_STAT_CODE:
            cd = (DetectContentData *)pm->ctx;
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

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                               "seen in depth - %s\n", str);
                    goto error;
                }
                cd->depth = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_DEPTH_BE;
            } else {
                cd->depth = (uint32_t)atoi(str);
                if (cd->depth < cd->content_len) {
                    cd->depth = cd->content_len;
                    SCLogDebug("depth increased to %"PRIu32" to match pattern len ",
                               cd->depth);
                }
                /* Now update the real limit, as depth is relative to the offset */
                cd->depth += cd->offset;
                cd->flags |= DETECT_CONTENT_DEPTH;
            }

            break;

        default:
            SCLogError(SC_ERR_DEPTH_MISSING_CONTENT, "depth needs a preceeding "
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
