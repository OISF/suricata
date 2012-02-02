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
 * Implements the within keyword
 */

#include "suricata-common.h"

#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-bytejump.h"
#include "detect-byte-extract.h"
#include "app-layer.h"
#include "detect-parse.h"

#include "flow-var.h"

#include "util-debug.h"
#include "detect-pcre.h"
#include "util-unittest.h"

static int DetectWithinSetup (DetectEngineCtx *, Signature *, char *);
void DetectWithinRegisterTests(void);

void DetectWithinRegister (void) {
    sigmatch_table[DETECT_WITHIN].name = "within";
    sigmatch_table[DETECT_WITHIN].Match = NULL;
    sigmatch_table[DETECT_WITHIN].Setup = DetectWithinSetup;
    sigmatch_table[DETECT_WITHIN].Free  = NULL;
    sigmatch_table[DETECT_WITHIN].RegisterTests = DetectWithinRegisterTests;

    sigmatch_table[DETECT_WITHIN].flags |= SIGMATCH_PAYLOAD;
}

/** \brief Setup within pattern (content/uricontent) modifier.
 *
 *  \todo apply to uricontent
 *
 *  \retval 0 ok
 *  \retval -1 error, sig needs to be invalidated
 */
static int DetectWithinSetup (DetectEngineCtx *de_ctx, Signature *s, char *withinstr)
{
    char *str = withinstr;
    char dubbed = 0;
    SigMatch *pm = NULL;

    /* strip "'s */
    if (withinstr[0] == '\"' && withinstr[strlen(withinstr)-1] == '\"') {
        str = SCStrdup(withinstr+1);
        if (str == NULL)
            goto error;
        str[strlen(withinstr)-2] = '\0';
        dubbed = 1;
    }

    /* if we still haven't found that the sig is related to DCERPC,
     * it's a direct entry into Signature->[DETECT_SM_LIST_PMATCH] */
    if (s->alproto == ALPROTO_DCERPC) {
        SigMatch *dcem = NULL;
        SigMatch *dm = NULL;
        SigMatch *pm1 = NULL;

        SigMatch *pm1_ots = NULL;
        SigMatch *pm2_ots = NULL;

        dcem = SigMatchGetLastSMFromLists(s, 6,
                DETECT_DCE_IFACE, s->sm_lists_tail[DETECT_SM_LIST_AMATCH],
                DETECT_DCE_OPNUM, s->sm_lists_tail[DETECT_SM_LIST_AMATCH],
                DETECT_DCE_STUB_DATA, s->sm_lists_tail[DETECT_SM_LIST_AMATCH]);

        pm1_ots = SigMatchGetLastSMFromLists(s, 6,
                DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_PMATCH]);
        if (pm1_ots != NULL && pm1_ots->prev != NULL) {
            pm2_ots = SigMatchGetLastSMFromLists(s, 6,
                    DETECT_CONTENT, pm1_ots->prev,
                    DETECT_PCRE, pm1_ots->prev,
                    DETECT_BYTEJUMP, pm1_ots->prev);
        }

        dm = SigMatchGetLastSMFromLists(s, 2, DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_DMATCH]);
        pm1 = SigMatchGetLastSMFromLists(s, 2, DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH]);

        if (dm == NULL && pm1 == NULL) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid signature.  within "
                       "needs a preceding content keyword");
            goto error;
        }

        if (dm == NULL) {
            if (pm2_ots == NULL) {
                if (pm1->idx > dcem->idx) {
                    /* transfer pm1 to dmatch list and within is against this */
                    SigMatchTransferSigMatchAcrossLists(pm1,
                            &s->sm_lists[DETECT_SM_LIST_PMATCH],
                            &s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                            &s->sm_lists[DETECT_SM_LIST_DMATCH],
                            &s->sm_lists_tail[DETECT_SM_LIST_DMATCH]);
                    pm = pm1;
                } else {
                    /* within is against pm1 and we continue this way */
                    pm = pm1;
                }
            } else if (pm2_ots->idx > dcem->idx) {
                /* within is against pm1, pm = pm1; */
                pm = pm1;
            } else if (pm1->idx > dcem->idx) {
                /* transfer pm1 to dmatch list and within is against this */
                SigMatchTransferSigMatchAcrossLists(pm1,
                        &s->sm_lists[DETECT_SM_LIST_PMATCH],
                        &s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                        &s->sm_lists[DETECT_SM_LIST_DMATCH],
                                                    &s->sm_lists_tail[DETECT_SM_LIST_DMATCH]);
                pm = pm1;
            } else {
                /* within is against pm1 and we continue this way */
                pm = pm1;
            }
        } else {
            if (pm1 == NULL) {
                /* within is against dm and continue this way */
                pm = dm;
            } else if (dm->idx > pm1->idx) {
                /* within is against dm */
                pm = dm;
            } else if (pm2_ots == NULL || pm2_ots->idx < dcem->idx) {
                /* trasnfer pm1 to dmatch list and pm = pm1 */
                SigMatchTransferSigMatchAcrossLists(pm1,
                        &s->sm_lists[DETECT_SM_LIST_PMATCH],
                        &s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                        &s->sm_lists[DETECT_SM_LIST_DMATCH],
                        &s->sm_lists_tail[DETECT_SM_LIST_DMATCH]);
                pm = pm1;
            } else {
                /* within is against pm1, pm = pm1 */
                pm = pm1;
            }
        }
    } else {
        pm = SigMatchGetLastSMFromLists(s, 18,
                DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                DETECT_URICONTENT, s->sm_lists_tail[DETECT_SM_LIST_UMATCH],
                DETECT_AL_HTTP_CLIENT_BODY, s->sm_lists_tail[DETECT_SM_LIST_HCBDMATCH],
                DETECT_AL_HTTP_SERVER_BODY, s->sm_lists_tail[DETECT_SM_LIST_HSBDMATCH],
                DETECT_AL_HTTP_HEADER, s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH],
                DETECT_AL_HTTP_RAW_HEADER, s->sm_lists_tail[DETECT_SM_LIST_HRHDMATCH],
                DETECT_AL_HTTP_METHOD, s->sm_lists_tail[DETECT_SM_LIST_HMDMATCH],
                DETECT_AL_HTTP_COOKIE, s->sm_lists_tail[DETECT_SM_LIST_HCDMATCH],
                DETECT_AL_HTTP_RAW_URI, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH]);
        if (pm == NULL) {
            SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs"
                       "preceeding content, uricontent, http_client_body, "
                       "http_server_body, http_header, http_raw_header, "
                        "http_method, http_cookie or http_raw_uri option");
            if (dubbed)
                SCFree(str);
            return -1;
        }
    }

    DetectContentData *ud = NULL;
    DetectContentData *cd = NULL;
    DetectPcreData *pe = NULL;

    switch (pm->type) {
        case DETECT_URICONTENT:
            ud = (DetectContentData *)pm->ctx;
            if (ud == NULL) {
                SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "Unknown previous keyword!\n");
                goto error;
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
                               "seen in within - %s\n", str);
                    goto error;
                }
                ud->within = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                ud->flags |= DETECT_CONTENT_WITHIN_BE;
            } else {
                ud->within = strtol(str, NULL, 10);
                if (ud->within < (int32_t)ud->content_len) {
                    SCLogError(SC_ERR_WITHIN_INVALID, "within argument \"%"PRIi32"\" is "
                               "less than the content length \"%"PRIu32"\" which is invalid, since "
                               "this will never match.  Invalidating signature", ud->within,
                               ud->content_len);
                    goto error;
                }
            }

            ud->flags |= DETECT_CONTENT_WITHIN;

            pm = SigMatchGetLastSMFromLists(s, 6,
                                            DETECT_URICONTENT, pm->prev,
                                            DETECT_PCRE, pm->prev,
                                            DETECT_BYTEJUMP, pm->prev);
            if (pm == NULL) {
                SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs two "
                           "preceeding content or uricontent options");
                goto error;
            }

            switch (pm->type) {
                case DETECT_URICONTENT:
                    /* Set the relative next flag on the prev sigmatch */
                    ud = (DetectContentData *)pm->ctx;
                    if (ud == NULL) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous-"
                                   "previous keyword!");
                        goto error;
                    }
                    ud->flags |= DETECT_CONTENT_RELATIVE_NEXT;

                    if (ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "Previous keyword "
                                   "has a fast_pattern:only; set.  You can't "
                                   "have relative keywords around a fast_pattern "
                                   "only content");
                        goto error;
                    }

                    break;

                case DETECT_PCRE:
                    pe = (DetectPcreData *) pm->ctx;
                    if (pe == NULL) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous-"
                                   "previous keyword!");
                        goto error;
                    }
                    pe->flags |= DETECT_PCRE_RELATIVE_NEXT;

                    break;

                case DETECT_BYTEJUMP:
                    SCLogDebug("No setting relative_next for bytejump.  We "
                               "have no use for it");

                    break;

                default:
                    /* this will never hit */
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous-"
                                   "previous keyword!");
                    break;
            }

            DetectUricontentPrint(ud);

            break;

        case DETECT_CONTENT:
            cd = (DetectContentData *)pm->ctx;
            if (cd == NULL) {
                SCLogError(SC_ERR_RULE_KEYWORD_UNKNOWN, "Unknown previous keyword!\n");
                goto error;
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
                               "seen in within - %s\n", str);
                    goto error;
                }
                cd->within = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_WITHIN_BE;
            } else {
                cd->within = strtol(str, NULL, 10);
                if (cd->within < (int32_t)cd->content_len) {
                    SCLogError(SC_ERR_WITHIN_INVALID, "within argument \"%"PRIi32"\" is "
                               "less than the content length \"%"PRIu32"\" which is invalid, since "
                               "this will never match.  Invalidating signature", cd->within,
                               cd->content_len);
                    goto error;
                }
            }

            cd->flags |= DETECT_CONTENT_WITHIN;

            pm = SigMatchGetLastSMFromLists(s, 6,
                                            DETECT_CONTENT, pm->prev,
                                            DETECT_PCRE, pm->prev,
                                            DETECT_BYTEJUMP, pm->prev);
            if (pm == NULL) {
                if (s->alproto == ALPROTO_DCERPC) {
                    SCLogDebug("content relative without a previous content based "
                               "keyword.  Holds good only in the case of DCERPC "
                               "alproto like now.");
                } else {
                    //SCLogError(SC_ERR_INVALID_SIGNATURE, "No related "
                    //           "previous-previous content or pcre keyword");
                    //goto error;
                    ;
                }
            } else {
                switch (pm->type) {
                    case DETECT_CONTENT:
                        /* Set the relative next flag on the prev sigmatch */
                        cd = (DetectContentData *)pm->ctx;
                        if (cd == NULL) {
                            SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous-"
                                       "previous keyword!");
                            goto error;
                        }
                        cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;

                        if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                            SCLogError(SC_ERR_INVALID_SIGNATURE, "Previous keyword "
                                       "has a fast_pattern:only; set.  You can't "
                                       "have relative keywords around a fast_pattern "
                                       "only content");
                            goto error;
                        }

                        break;

                    case DETECT_PCRE:
                        pe = (DetectPcreData *) pm->ctx;
                        if (pe == NULL) {
                            SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous-"
                                       "previous keyword!");
                            goto error;
                        }
                        pe->flags |= DETECT_PCRE_RELATIVE_NEXT;

                        break;

                    case DETECT_BYTEJUMP:
                        SCLogDebug("No setting relative_next for bytejump.  We "
                                   "have no use for it");

                        break;

                    default:
                        /* this will never hit */
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous-"
                                       "previous keyword!");
                        break;
                }
            }

            break;

        case DETECT_AL_HTTP_CLIENT_BODY:
            cd = (DetectContentData *)pm->ctx;

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                               "seen in within - %s\n", str);
                    goto error;
                }
                cd->within = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_WITHIN_BE;
            } else {
                cd->within = strtol(str, NULL, 10);
                if (cd->within < (int32_t)cd->content_len) {
                    SCLogError(SC_ERR_WITHIN_INVALID, "within argument \"%"PRIi32"\" is "
                               "less than the content length \"%"PRIu32"\" which is invalid, since "
                               "this will never match.  Invalidating signature", cd->within,
                               cd->content_len);
                    goto error;
                }
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

            cd->flags |= DETECT_CONTENT_WITHIN;

            /* reassigning pm */
            pm = SigMatchGetLastSMFromLists(s, 4,
                                            DETECT_AL_HTTP_CLIENT_BODY, pm->prev,
                                            DETECT_PCRE, pm->prev);
            if (pm == NULL) {
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance for http_client_body "
                           "needs preceeding http_client_body content");
                goto error;
            }

            if (pm->type == DETECT_PCRE) {
                DetectPcreData *tmp_pd = (DetectPcreData *)pm->ctx;
                tmp_pd->flags |=  DETECT_PCRE_RELATIVE_NEXT;
            } else {
                /* reassigning cd */
                cd = (DetectContentData *)pm->ctx;
                if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Previous keyword "
                               "has a fast_pattern:only; set.  You can't "
                               "have relative keywords around a fast_pattern "
                               "only content");
                    goto error;
                }
                cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
            }

            break;

        case DETECT_AL_HTTP_SERVER_BODY:
            cd = (DetectContentData *)pm->ctx;

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                               "seen in within - %s\n", str);
                    goto error;
                }
                cd->within = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_WITHIN_BE;
            } else {
                cd->within = strtol(str, NULL, 10);
                if (cd->within < (int32_t)cd->content_len) {
                    SCLogError(SC_ERR_WITHIN_INVALID, "within argument \"%"PRIi32"\" is "
                               "less than the content length \"%"PRIu32"\" which is invalid, since "
                               "this will never match.  Invalidating signature", cd->within,
                               cd->content_len);
                    goto error;
                }
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

            cd->flags |= DETECT_CONTENT_WITHIN;

            /* reassigning pm */
            pm = SigMatchGetLastSMFromLists(s, 4,
                                            DETECT_AL_HTTP_SERVER_BODY, pm->prev,
                                            DETECT_PCRE, pm->prev);
            if (pm == NULL) {
                if (s->init_flags & SIG_FLAG_INIT_FILE_DATA) {
                    /* file_data; content:"abc"; within:3; is valid, in this case
                     * there will be no previous pm. We convert to depth in this case */
                    cd->flags &= ~DETECT_CONTENT_WITHIN;

                    SCLogDebug("converted within to depth for content relative to file_data");
                    cd->depth = cd->within;
                } else {
                    SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "within for http_server_body "
                            "needs preceeding http_server_body content");
                    goto error;
                }
            } else {
                if (pm->type == DETECT_PCRE) {
                    DetectPcreData *tmp_pd = (DetectPcreData *)pm->ctx;
                    tmp_pd->flags |=  DETECT_PCRE_RELATIVE_NEXT;
                } else {
                    /* reassigning cd */
                    cd = (DetectContentData *)pm->ctx;
                    if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "Previous keyword "
                                "has a fast_pattern:only; set.  You can't "
                                "have relative keywords around a fast_pattern "
                                "only content");
                        goto error;
                    }
                    cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
                }
            }
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
                               "seen in within - %s\n", str);
                    goto error;
                }
                cd->within = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_WITHIN_BE;
            } else {
                cd->within = strtol(str, NULL, 10);
                if (cd->within < (int32_t)cd->content_len) {
                    SCLogError(SC_ERR_WITHIN_INVALID, "within argument \"%"PRIi32"\" is "
                               "less than the content length \"%"PRIu32"\" which is invalid, since "
                               "this will never match.  Invalidating signature", cd->within,
                               cd->content_len);
                    goto error;
                }
            }

            cd->flags |= DETECT_CONTENT_WITHIN;

            /* reassigning pm */
            pm = SigMatchGetLastSMFromLists(s, 4,
                                            DETECT_AL_HTTP_HEADER, pm->prev,
                                            DETECT_PCRE, pm->prev);
            if (pm == NULL) {
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance for http_header "
                           "needs preceeding http_header content");
                goto error;
            }

            if (pm->type == DETECT_PCRE) {
                DetectPcreData *tmp_pd = (DetectPcreData *)pm->ctx;
                tmp_pd->flags |=  DETECT_PCRE_RELATIVE_NEXT;
            } else {
                /* reassigning cd */
                cd = (DetectContentData *)pm->ctx;
                if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Previous keyword "
                               "has a fast_pattern:only; set.  You can't "
                               "have relative keywords around a fast_pattern "
                               "only content");
                    goto error;
                }
                cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
            }

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
                               "seen in within - %s\n", str);
                    goto error;
                }
                cd->within = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_WITHIN_BE;
            } else {
                cd->within = strtol(str, NULL, 10);
                if (cd->within < (int32_t)cd->content_len) {
                    SCLogError(SC_ERR_WITHIN_INVALID, "within argument \"%"PRIi32"\" is "
                               "less than the content length \"%"PRIu32"\" which is invalid, since "
                               "this will never match.  Invalidating signature", cd->within,
                               cd->content_len);
                    goto error;
                }
            }

            cd->flags |= DETECT_CONTENT_WITHIN;

            /* reassigning pm */
            pm = SigMatchGetLastSMFromLists(s, 4,
                                            DETECT_AL_HTTP_RAW_HEADER, pm->prev,
                                            DETECT_PCRE, pm->prev);
            if (pm == NULL) {
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance for http_raw_header "
                           "needs preceeding http_raw_header content");
                goto error;
            }

            if (pm->type == DETECT_PCRE) {
                DetectPcreData *tmp_pd = (DetectPcreData *)pm->ctx;
                tmp_pd->flags |=  DETECT_PCRE_RELATIVE_NEXT;
            } else {
                /* reassigning cd */
                cd = (DetectContentData *)pm->ctx;
                if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Previous keyword "
                               "has a fast_pattern:only; set.  You can't "
                               "have relative keywords around a fast_pattern "
                               "only content");
                    goto error;
                }
                cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
            }

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
                               "seen in within - %s\n", str);
                    goto error;
                }
                cd->within = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_WITHIN_BE;
            } else {
                cd->within = strtol(str, NULL, 10);
                if (cd->within < (int32_t)cd->content_len) {
                    SCLogError(SC_ERR_WITHIN_INVALID, "within argument \"%"PRIi32"\" is "
                               "less than the content length \"%"PRIu32"\" which is invalid, since "
                               "this will never match.  Invalidating signature", cd->within,
                               cd->content_len);
                    goto error;
                }
            }

            cd->flags |= DETECT_CONTENT_WITHIN;

            /* reassigning pm */
            pm = SigMatchGetLastSMFromLists(s, 4,
                                            DETECT_AL_HTTP_METHOD, pm->prev,
                                            DETECT_PCRE_HTTPMETHOD, pm->prev);
            if (pm == NULL) {
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance for http_method "
                           "needs preceeding http_method content");
                goto error;
            }

            if (pm->type == DETECT_PCRE_HTTPMETHOD) {
                DetectPcreData *tmp_pd = (DetectPcreData *)pm->ctx;
                tmp_pd->flags |=  DETECT_PCRE_RELATIVE_NEXT;
            } else {
                /* reassigning cd */
                cd = (DetectContentData *)pm->ctx;
                if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Previous keyword "
                               "has a fast_pattern:only; set.  You can't "
                               "have relative keywords around a fast_pattern "
                               "only content");
                    goto error;
                }
                cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
            }

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
                               "seen in within - %s\n", str);
                    goto error;
                }
                cd->within = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_WITHIN_BE;
            } else {
                cd->within = strtol(str, NULL, 10);
                if (cd->within < (int32_t)cd->content_len) {
                    SCLogError(SC_ERR_WITHIN_INVALID, "within argument \"%"PRIi32"\" is "
                               "less than the content length \"%"PRIu32"\" which is invalid, since "
                               "this will never match.  Invalidating signature", cd->within,
                               cd->content_len);
                    goto error;
                }
            }

            cd->flags |= DETECT_CONTENT_WITHIN;

            /* reassigning pm */
            pm = SigMatchGetLastSMFromLists(s, 4,
                                            DETECT_AL_HTTP_COOKIE, pm->prev,
                                            DETECT_PCRE_HTTPCOOKIE, pm->prev);
            if (pm == NULL) {
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance for http_cookie "
                           "needs preceeding http_cookie content");
                goto error;
            }

            if (pm->type == DETECT_PCRE_HTTPCOOKIE) {
                DetectPcreData *tmp_pd = (DetectPcreData *)pm->ctx;
                tmp_pd->flags |=  DETECT_PCRE_RELATIVE_NEXT;
            } else {
                /* reassigning cd */
                cd = (DetectContentData *)pm->ctx;
                if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Previous keyword "
                               "has a fast_pattern:only; set.  You can't "
                               "have relative keywords around a fast_pattern "
                               "only content");
                    goto error;
                }
                cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
            }

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
                               "seen in within - %s\n", str);
                    goto error;
                }
                cd->within = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_WITHIN_BE;
            } else {
                cd->within = strtol(str, NULL, 10);
                if (cd->within < (int32_t)cd->content_len) {
                    SCLogError(SC_ERR_WITHIN_INVALID, "within argument \"%"PRIi32"\" is "
                               "less than the content length \"%"PRIu32"\" which is invalid, since "
                               "this will never match.  Invalidating signature", cd->within,
                               cd->content_len);
                    goto error;
                }
            }

            cd->flags |= DETECT_CONTENT_WITHIN;

            /* reassigning pm */
            pm = SigMatchGetLastSMFromLists(s, 4,
                                            DETECT_AL_HTTP_RAW_URI, pm->prev,
                                            DETECT_PCRE, pm->prev);
            if (pm == NULL) {
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance for http_raw_uri "
                           "needs preceeding http_raw_uri content");
                goto error;
            }

            if (pm->type == DETECT_PCRE) {
                DetectPcreData *tmp_pd = (DetectPcreData *)pm->ctx;
                tmp_pd->flags |=  DETECT_PCRE_RELATIVE_NEXT;
            } else {
                /* reassigning cd */
                cd = (DetectContentData *)pm->ctx;
                if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Previous keyword "
                               "has a fast_pattern:only; set.  You can't "
                               "have relative keywords around a fast_pattern "
                               "only content");
                    goto error;
                }
                cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
            }

            break;

        default:
            SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs two "
                       "preceeding content or uricontent options");
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

/***********************************Unittests**********************************/

#ifdef UNITTESTS
#include "util-unittest-helper.h"
 /**
 * \test DetectWithinTestPacket01 is a test to check matches of
 * within, if the previous keyword is pcre (bug 145)
 */
int DetectWithinTestPacket01 (void) {
    int result = 0;
    uint8_t *buf = (uint8_t *)"GET /AllWorkAndNoPlayMakesWillADullBoy HTTP/1.0"
                    "User-Agent: Wget/1.11.4"
                    "Accept: */*"
                    "Host: www.google.com"
                    "Connection: Keep-Alive"
                    "Date: Mon, 04 Jan 2010 17:29:39 GMT";
    uint16_t buflen = strlen((char *)buf);
    Packet *p;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    if (p == NULL)
        goto end;

    char sig[] = "alert tcp any any -> any any (msg:\"pcre with within "
                 "modifier\"; pcre:\"/AllWorkAndNoPlayMakesWillADullBoy/\";"
                 " content:\"HTTP\"; within:5; sid:49; rev:1;)";

    result = UTHPacketMatchSig(p, sig);

    UTHFreePacket(p);
end:
    return result;
}


int DetectWithinTestPacket02 (void) {
    int result = 0;
    uint8_t *buf = (uint8_t *)"Zero Five Ten Fourteen";
    uint16_t buflen = strlen((char *)buf);
    Packet *p;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    if (p == NULL)
        goto end;

    char sig[] = "alert tcp any any -> any any (msg:\"pcre with within "
                 "modifier\"; content:\"Five\"; content:\"Ten\"; within:3; distance:1; sid:1;)";

    result = UTHPacketMatchSig(p, sig);

    UTHFreePacket(p);
end:
    return result;
}


#endif /* UNITTESTS */

void DetectWithinRegisterTests(void) {
    #ifdef UNITTESTS
    UtRegisterTest("DetectWithinTestPacket01", DetectWithinTestPacket01, 1);
    UtRegisterTest("DetectWithinTestPacket02", DetectWithinTestPacket02, 1);
    #endif /* UNITTESTS */
}
