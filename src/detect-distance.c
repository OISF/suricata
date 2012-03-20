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
 * Implements the distance keyword
 */

#include "suricata-common.h"

#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "app-layer.h"
#include "detect-parse.h"

#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"
#include "detect-byte-extract.h"

#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "detect-bytejump.h"
#include "util-unittest-helper.h"

static int DetectDistanceSetup(DetectEngineCtx *, Signature *, char *);
void DetectDistanceRegisterTests(void);

void DetectDistanceRegister (void) {
    sigmatch_table[DETECT_DISTANCE].name = "distance";
    sigmatch_table[DETECT_DISTANCE].Match = NULL;
    sigmatch_table[DETECT_DISTANCE].Setup = DetectDistanceSetup;
    sigmatch_table[DETECT_DISTANCE].Free  = NULL;
    sigmatch_table[DETECT_DISTANCE].RegisterTests = DetectDistanceRegisterTests;

    sigmatch_table[DETECT_DISTANCE].flags |= SIGMATCH_PAYLOAD;
}

static int DetectDistanceSetup (DetectEngineCtx *de_ctx, Signature *s,
        char *distancestr)
{
    char *str = distancestr;
    char dubbed = 0;
    SigMatch *pm = NULL;

    /* strip "'s */
    if (distancestr[0] == '\"' && distancestr[strlen(distancestr) - 1] == '\"') {
        str = SCStrdup(distancestr + 1);
        if (str == NULL)
            goto error;
        str[strlen(distancestr) - 2] = '\0';
        dubbed = 1;
    }

    /* if we still haven't found that the sig is related to DCERPC,
     * it's a direct entry into Signature->sm_lists[DETECT_SM_LIST_PMATCH] */
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
        pm = SigMatchGetLastSMFromLists(s, 22,
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
                DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH]);
        if (pm == NULL) {
            SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs "
                       "preceeding content, uricontent option, http_client_body, "
                       "http_server_body, http_header, http_raw_header, http_method, "
                       "http_cookie, http_raw_uri, http_stat_msg or http_stat_code "
                       "option");
            if (dubbed)
                SCFree(str);
            return -1;
        }
    }

    DetectContentData *cd = NULL;
    DetectPcreData *pe = NULL;

    switch (pm->type) {
        case DETECT_CONTENT:
            cd = (DetectContentData *)pm->ctx;
            if (cd == NULL) {
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance needs two "
                "preceeding content or uricontent options");
                goto error;
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

            if (cd->flags & DETECT_CONTENT_DEPTH || cd->flags & DETECT_CONTENT_OFFSET) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use a relative keyword "
                               "with a non-relative keyword for the same content." );
                goto error;
            }

            if (cd->flags & DETECT_CONTENT_DISTANCE) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use multiple distances with the same content. ");
                goto error;
            }

            if (str[0] != '-' && isalpha(str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "unknown byte_extract var "
                               "seen in distance - %s\n", str);
                    goto error;
                }
                cd->distance = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
                cd->flags |= DETECT_CONTENT_DISTANCE_BE;
            } else {
                cd->distance = strtol(str, NULL, 10);
            }

            cd->flags |= DETECT_CONTENT_DISTANCE;

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
                    //"previous-previous content or pcre keyword");
                    //goto error;
                    ;
                }
            } else {
                switch (pm->type) {
                    case DETECT_CONTENT:
                        /* Set the relative next flag on the prev sigmatch */
                        cd = (DetectContentData *)pm->ctx;
                        if (cd == NULL) {
                            SCLogError(SC_ERR_INVALID_SIGNATURE, "unknown previous-"
                                       "previous keyword!");
                            goto error;
                        }
                        cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;

                        if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                            SCLogError(SC_ERR_INVALID_SIGNATURE, "previous keyword "
                                       "has a fast_pattern:only; set. Can't have "
                                       "relative keywords around a fast_pattern "
                                       "only content");
                            goto error;
                        }

                        break;

                    case DETECT_PCRE:
                        pe = (DetectPcreData *) pm->ctx;
                        if (pe == NULL) {
                            SCLogError(SC_ERR_INVALID_SIGNATURE, "unknown previous-"
                                       "previous keyword!");
                            goto error;
                        }
                        pe->flags |= DETECT_PCRE_RELATIVE_NEXT;

                        break;

                    case DETECT_BYTEJUMP:
                        SCLogDebug("no setting relative_next for bytejump.  We "
                                   "have no use for it");

                        break;

                    default:
                        /* this will never hit */
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "unknown previous-"
                                       "previous keyword!");
                        break;
                }
            }

            break;

        default:
            SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance needs two "
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

#ifdef UNITTESTS

static int DetectDistanceTest01(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        printf("no de_ctx: ");
        goto end;
    }

    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (content:\"|AA BB|\"; content:\"|CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE|\"; distance: 4; within: 19; sid:1; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigMatch *sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm == NULL) {
        printf("sm NULL: ");
        goto end;
    }

    sm = sm->next;
    if (sm == NULL) {
        printf("sm2 NULL: ");
        goto end;
    }

    DetectContentData *co = (DetectContentData *)sm->ctx;
    if (co == NULL) {
        printf("co == NULL: ");
        goto end;
    }

    if (co->distance != 4) {
        printf("distance %"PRIi32", expected 4: ", co->distance);
        goto end;
    }

    /* within needs to be 23: distance + content_len as Snort auto fixes this */
    if (co->within != 19) {
        printf("within %"PRIi32", expected 23: ", co->within);
        goto end;
    }

    result = 1;
end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test DetectDistanceTestPacket01 is a test to check matches of
 * distance works, if the previous keyword is byte_jump and content
 * (bug 163)
 */
int DetectDistanceTestPacket01 (void) {
    int result = 0;
    uint8_t buf[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint16_t buflen = sizeof(buf);
    Packet *p;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    if (p == NULL)
        goto end;

    char sig[] = "alert tcp any any -> any any (msg:\"suricata test\"; "
                    "byte_jump:1,2; content:\"|00|\"; "
                    "within:1; distance:2; sid:98711212; rev:1;)";

    p->flowflags = FLOW_PKT_ESTABLISHED | FLOW_PKT_TOCLIENT;
    result = UTHPacketMatchSig(p, sig);

    UTHFreePacket(p);
end:
    return result;
}
#endif /* UNITTESTS */

void DetectDistanceRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectDistanceTest01 -- distance / within mix", DetectDistanceTest01, 1);
    UtRegisterTest("DetectDistanceTestPacket01", DetectDistanceTestPacket01, 1);
#endif /* UNITTESTS */
}

