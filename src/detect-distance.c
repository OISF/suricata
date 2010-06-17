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
    SigMatch *match_tail = NULL;

    /* strip "'s */
    if (distancestr[0] == '\"' && distancestr[strlen(distancestr)-1] == '\"') {
        str = SCStrdup(distancestr+1);
        str[strlen(distancestr)-2] = '\0';
        dubbed = 1;
    }

    switch (s->alproto) {
        case ALPROTO_DCERPC:
            /* If we have a signature that is related to dcerpc, then we add the
             * sm to Signature->dmatch.  All content inspections for a dce rpc
             * alproto is done inside detect-engine-dcepayload.c */
            pm =  SigMatchGetLastSMFromLists(s, 2, DETECT_CONTENT, s->dmatch_tail);
            if (pm == NULL) {
                SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "distance needs"
                           "preceeding content option for dcerpc sig");
                if (dubbed)
                    SCFree(str);
                return -1;
            }

            break;

        default:
            pm =  SigMatchGetLastSMFromLists(s, 4,
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
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance needs two "
                "preceeding content or uricontent options");
                goto error;
            }

            ud->distance = strtol(str, NULL, 10);
            ud->flags |= DETECT_URICONTENT_DISTANCE;
            if (ud->flags & DETECT_URICONTENT_WITHIN) {
                if ((ud->distance + ud->uricontent_len) > ud->within) {
                    ud->within = ud->distance + ud->uricontent_len;
                }
            }

            pm = DetectUricontentGetLastPattern(s->umatch_tail->prev);
            if (pm == NULL) {
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance needs two"
                        " preceeding content or  uricontent options");
                goto error;
            }

            if (pm->type == DETECT_URICONTENT) {
                ud = (DetectUricontentData *)pm->ctx;
                ud->flags |= DETECT_URICONTENT_RELATIVE_NEXT;
            } else {
                SCLogError(SC_ERR_RULE_KEYWORD_UNKNOWN, "Unknown previous"
                        " keyword!");
                goto error;
            }
        break;

        case DETECT_CONTENT:
            cd = (DetectContentData *)pm->ctx;
            if (cd == NULL) {
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance needs two "
                "preceeding content or uricontent options");
                goto error;
            }

            cd->distance = strtol(str, NULL, 10);
            cd->flags |= DETECT_CONTENT_DISTANCE;
            if (cd->flags & DETECT_CONTENT_WITHIN) {
                if ((cd->distance + cd->content_len) > cd->within) {
                    cd->within = cd->distance + cd->content_len;
                }
            }

            switch (s->alproto) {
                case ALPROTO_DCERPC:
                    match_tail = s->dmatch_tail;
                    break;

                default:
                    match_tail = s->pmatch_tail;
                    break;
            }

            if ( (pm = SigMatchGetLastSM(match_tail->prev, DETECT_CONTENT)) != NULL) {
                /* Set the relative next flag on the prev sigmatch */
                cd = (DetectContentData *)pm->ctx;
                if (cd == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous-"
                            "previous keyword!");
                    goto error;
                }
                cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;

            } else if ( (pm = SigMatchGetLastSM(match_tail, DETECT_BYTEJUMP)) != NULL) {
                DetectBytejumpData *data = NULL;
                data = (DetectBytejumpData *) pm->ctx;
                if (data == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous keyword!");
                    goto error;
                }
                data->flags |= DETECT_BYTEJUMP_RELATIVE;

            } else {
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance needs two "
                           "preceeding content or uricontent options");
                goto error;
            }

            break;

        default:
            SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance needs two "
                       "preceeding content or uricontent options");
            if (dubbed) SCFree(str);
                return -1;
        break;
    }

    if (dubbed) SCFree(str);
    return 0;
error:
    if (dubbed) SCFree(str);
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

    SigMatch *sm = de_ctx->sig_list->pmatch;
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
    if (co->within != 23) {
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

