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
 * Implements the within keyword
 */

#include "suricata-common.h"

#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-bytejump.h"

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

    /* strip "'s */
    if (withinstr[0] == '\"' && withinstr[strlen(withinstr)-1] == '\"') {
        str = SCStrdup(withinstr+1);
        str[strlen(withinstr)-2] = '\0';
        dubbed = 1;
    }

    /** Search for the first previous DetectContent
     * SigMatch (it can be the same as this one) */
    SigMatch *pm = SigMatchGetLastPattern(s);
    if (pm == NULL) {
        SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "depth needs"
                   "two preceeding content or uricontent options");
        if (dubbed) SCFree(str);
        return -1;
    }

    DetectUricontentData *ud = NULL;
    DetectContentData *cd = NULL;

    switch (pm->type) {
        case DETECT_URICONTENT:
            ud = (DetectUricontentData *)pm->ctx;
            if (ud == NULL) {
                SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "Unknown previous keyword!\n");
                goto error;
            }

            ud->within = strtol(str, NULL, 10);
            if (ud->within < (int32_t)ud->uricontent_len) {
                SCLogError(SC_ERR_WITHIN_INVALID, "within argument \"%"PRIi32"\" is "
                        "less than the content length \"%"PRIu32"\" which is invalid, since "
                        "this will never match.  Invalidating signature", ud->within,
                        ud->uricontent_len);
                goto error;
            }

            ud->flags |= DETECT_URICONTENT_WITHIN;

            if (ud->flags & DETECT_URICONTENT_DISTANCE) {
                if ((ud->distance + ud->uricontent_len) > ud->within) {
                    ud->within = ud->distance + ud->uricontent_len;
                }
            }

            pm = DetectUricontentGetLastPattern(s->umatch_tail->prev);
            if (pm == NULL) {
                SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs two"
                           " preceeding content or uricontent options");
                goto error;
            }

            /* Set the relative next flag on the prev sigmatch */
            if (pm->type == DETECT_URICONTENT) {
                ud = (DetectUricontentData *)pm->ctx;
                ud->flags |= DETECT_URICONTENT_RELATIVE_NEXT;
            } else {
                SCLogError(SC_ERR_RULE_KEYWORD_UNKNOWN, "Unknown previous-previous keyword!\n");
                goto error;
            }
            DetectUricontentPrint(ud);

        break;

        case DETECT_CONTENT:
            cd = (DetectContentData *)pm->ctx;
            if (cd == NULL) {
                SCLogError(SC_ERR_RULE_KEYWORD_UNKNOWN, "Unknown previous keyword!\n");
                goto error;
            }

            cd->within = strtol(str, NULL, 10);
            if (cd->within < (int32_t)cd->content_len) {
                SCLogError(SC_ERR_WITHIN_INVALID, "within argument \"%"PRIi32"\" is "
                        "less than the content length \"%"PRIu32"\" which is invalid, since "
                        "this will never match.  Invalidating signature", cd->within,
                        cd->content_len);
                goto error;
            }

            cd->flags |= DETECT_CONTENT_WITHIN;

            if (cd->flags & DETECT_CONTENT_DISTANCE) {
                if ((cd->distance + cd->content_len) > cd->within) {
                    cd->within = cd->distance + cd->content_len;
                }
            }

            pm = SigMatchGetLastSM(s->pmatch_tail->prev, DETECT_CONTENT);
            if (pm != NULL) {
                /* Set the relative next flag on the prev sigmatch */
                cd = (DetectContentData *)pm->ctx;
                if (cd == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous-"
                            "previous keyword!");
                    goto error;
                }
                cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
            } else if ((pm = SigMatchGetLastSM(s->pmatch_tail, DETECT_PCRE)) != NULL) {
                DetectPcreData *pe = NULL;
                pe = (DetectPcreData *) pm->ctx;
                if (pe == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous keyword!");
                    goto error;
                }
                pe->flags |= DETECT_PCRE_RELATIVE;
            } else if ((pm = SigMatchGetLastSM(s->pmatch_tail, DETECT_BYTEJUMP))
                                != NULL)
            {
                DetectBytejumpData *data = NULL;
                data = (DetectBytejumpData *) pm->ctx;
                if (data == NULL) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous keyword!");
                    goto error;
                }
                data->flags |= DETECT_BYTEJUMP_RELATIVE;
            } else {
                SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs two"
                        " preceeding content or uricontent options");
                goto error;
            }

        break;

        default:
            SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs two preceeding content or uricontent options");
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

#endif /* UNITTESTS */

void DetectWithinRegisterTests(void) {
    #ifdef UNITTESTS
    UtRegisterTest("DetectWithinTestPacket01", DetectWithinTestPacket01, 1);
    #endif /* UNITTESTS */
}