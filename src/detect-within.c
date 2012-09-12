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
    sigmatch_table[DETECT_WITHIN].desc = "indicate that this content match has to be within a certain distance of the previous content keyword match";
    sigmatch_table[DETECT_WITHIN].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Payload_keywords#Within";
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
        if (unlikely(str == NULL))
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
            SCLogError(SC_ERR_INVALID_SIGNATURE, "\"within\" requires a "
                    "preceding content keyword");
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
        pm = SigMatchGetLastSMFromLists(s, 24,
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
                DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH],
                DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HUADMATCH]);
        if (pm == NULL) {
            SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "\"within\" requires "
                       "preceding content, uricontent, http_client_body, "
                       "http_server_body, http_header, http_raw_header, "
                       "http_method, http_cookie, http_raw_uri, "
                       "http_stat_msg, http_stat_code or http_user_agent "
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
                SCLogError(SC_ERR_INVALID_SIGNATURE, "content error");
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
                               "keyword set along with a fast_pattern:only");
                    goto error;
                }
            }

            if ((cd->flags & DETECT_CONTENT_DEPTH) || (cd->flags & DETECT_CONTENT_OFFSET)) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use a relative keyword "
                               "with a non-relative keyword for the same content" );
                goto error;
            }

            if (str[0] != '-' && isalpha((unsigned char)str[0])) {
                SigMatch *bed_sm =
                    DetectByteExtractRetrieveSMVar(str, s,
                                                   SigMatchListSMBelongsTo(s, pm));
                if (bed_sm == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "unknown byte_extract var "
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
                               "keyword. Holds good only in the case of DCERPC "
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
                            SCLogError(SC_ERR_INVALID_SIGNATURE, "content error");
                            goto error;
                        }
                        cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;

                        if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                            SCLogError(SC_ERR_INVALID_SIGNATURE, "previous keyword "
                                       "has a fast_pattern:only; set. Can't "
                                       "have relative keywords around a fast_pattern "
                                       "only content");
                            goto error;
                        }

                        break;

                    case DETECT_PCRE:
                        pe = (DetectPcreData *) pm->ctx;
                        if (pe == NULL) {
                            SCLogError(SC_ERR_INVALID_SIGNATURE, "pcre error");
                            goto error;
                        }
                        pe->flags |= DETECT_PCRE_RELATIVE_NEXT;

                        break;

                    case DETECT_BYTEJUMP:
                        SCLogDebug("no setting relative_next for bytejump. We "
                                   "have no use for it");

                        break;

                    default:
                        /* this will never hit */
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "unsupported type %d", pm->type);
                        break;
                }
            }

            break;

        default:
            SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs two "
                       "preceding content or uricontent options");
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
