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
#include "detect-engine.h"
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

static int DetectWithinSetup(DetectEngineCtx *, Signature *, char *);
void DetectWithinRegisterTests(void);

void DetectWithinRegister(void)
{
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
static int DetectWithinSetup(DetectEngineCtx *de_ctx, Signature *s, char *withinstr)
{
    char *str = withinstr;
    char dubbed = 0;
    SigMatch *pm = NULL;
    int ret = -1;

    /* strip "'s */
    if (withinstr[0] == '\"' && withinstr[strlen(withinstr)-1] == '\"') {
        str = SCStrdup(withinstr+1);
        if (unlikely(str == NULL))
            goto end;
        str[strlen(withinstr) - 2] = '\0';
        dubbed = 1;
    }

    /* retrive the sm to apply the depth against */
    if (s->list != DETECT_SM_LIST_NOTSET) {
        pm = SigMatchGetLastSMFromLists(s, 2, DETECT_CONTENT, s->sm_lists_tail[s->list]);
    } else {
        pm =  SigMatchGetLastSMFromLists(s, 28,
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_UMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HCBDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_FILEDATA],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRHDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HMDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HCDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSCDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HUADMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HHHDMATCH],
                                         DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRHHDMATCH]);
    }
    if (pm == NULL) {
        SCLogError(SC_ERR_OFFSET_MISSING_CONTENT, "within needs "
                   "preceding content, uricontent option, http_client_body, "
                   "http_server_body, http_header option, http_raw_header option, "
                   "http_method option, http_cookie, http_raw_uri, "
                   "http_stat_msg, http_stat_code, http_user_agent or "
                   "file_data/dce_stub_data sticky buffer option");
        goto end;
    }


    /* verify other conditions */
    DetectContentData *cd = (DetectContentData *)pm->ctx;
    if (cd->flags & DETECT_CONTENT_WITHIN) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use multiple withins for the same content.");
        goto end;
    }
    if ((cd->flags & DETECT_CONTENT_DEPTH) || (cd->flags & DETECT_CONTENT_OFFSET)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use a relative "
                   "keyword like within/distance with a absolute "
                   "relative keyword like depth/offset for the same "
                   "content." );
        goto end;
    }
    if (cd->flags & DETECT_CONTENT_NEGATED && cd->flags & DETECT_CONTENT_FAST_PATTERN) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have a relative "
                   "negated keyword set along with a fast_pattern");
        goto end;
    }
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have a relative "
                   "keyword set along with a fast_pattern:only;");
        goto end;
    }
    if (str[0] != '-' && isalpha((unsigned char)str[0])) {
        SigMatch *bed_sm = DetectByteExtractRetrieveSMVar(str, s);
        if (bed_sm == NULL) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "unknown byte_extract var "
                       "seen in within - %s\n", str);
            goto end;
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
            goto end;
        }
    }
    cd->flags |= DETECT_CONTENT_WITHIN;

    /* these are the only ones against which we set a flag.  We have other
     * relative keywords like byttest, isdataat, bytejump, but we don't
     * set a flag against them */
    SigMatch *prev_pm = SigMatchGetLastSMFromLists(s, 4,
                                                   DETECT_CONTENT, pm->prev,
                                                   DETECT_PCRE, pm->prev);
    if (prev_pm == NULL) {
        ret = 0;
        goto end;
    }
    if (prev_pm->type == DETECT_CONTENT) {
        DetectContentData *cd = (DetectContentData *)prev_pm->ctx;
        if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "previous keyword "
                       "has a fast_pattern:only; set. Can't "
                       "have relative keywords around a fast_pattern "
                       "only content");
            goto end;
        }
        cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
    } else if (prev_pm->type == DETECT_PCRE) {
        DetectPcreData *pd = (DetectPcreData *)prev_pm->ctx;
        pd->flags |= DETECT_PCRE_RELATIVE_NEXT;
    }

    ret = 0;
 end:
    if (dubbed)
        SCFree(str);
    return ret;
}

/***********************************Unittests**********************************/

#ifdef UNITTESTS
#include "util-unittest-helper.h"
 /**
 * \test DetectWithinTestPacket01 is a test to check matches of
 * within, if the previous keyword is pcre (bug 145)
 */
int DetectWithinTestPacket01 (void)
{
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


int DetectWithinTestPacket02 (void)
{
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

static int DetectWithinTestVarSetup(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    char sig[] = "alert tcp any any -> any any ( "
        "msg:\"test rule\"; "
        "content:\"abc\"; "
        "http_client_body; "
        "byte_extract:2,0,somevar,relative; "
        "content:\"def\"; "
        "within:somevar; "
        "http_client_body; "
        "sid:4; rev:1;)";

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->sig_list = SigInit(de_ctx, sig);
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    result = 1;

end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

#endif /* UNITTESTS */

void DetectWithinRegisterTests(void)
{
    #ifdef UNITTESTS
    UtRegisterTest("DetectWithinTestPacket01", DetectWithinTestPacket01, 1);
    UtRegisterTest("DetectWithinTestPacket02", DetectWithinTestPacket02, 1);
    UtRegisterTest("DetectWithinTestVarSetup", DetectWithinTestVarSetup, 1);
    #endif /* UNITTESTS */
}
