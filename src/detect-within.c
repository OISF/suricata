/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#include "detect-byte.h"
#include "app-layer.h"

#include "flow-var.h"

#include "util-byte.h"
#include "util-debug.h"
#include "detect-pcre.h"
#include "detect-within.h"
#include "util-unittest.h"

static int DetectWithinSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectWithinRegisterTests(void);
#endif

void DetectWithinRegister(void)
{
    sigmatch_table[DETECT_WITHIN].name = "within";
    sigmatch_table[DETECT_WITHIN].desc = "indicate that this content match has to be within a certain distance of the previous content keyword match";
    sigmatch_table[DETECT_WITHIN].url = "/rules/payload-keywords.html#within";
    sigmatch_table[DETECT_WITHIN].Match = NULL;
    sigmatch_table[DETECT_WITHIN].Setup = DetectWithinSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_WITHIN].RegisterTests = DetectWithinRegisterTests;
#endif
}

/** \brief Setup within pattern (content/uricontent) modifier.
 *
 *  \todo apply to uricontent
 *
 *  \retval 0 ok
 *  \retval -1 error, sig needs to be invalidated
 */
static int DetectWithinSetup(DetectEngineCtx *de_ctx, Signature *s, const char *withinstr)
{
    const char *str = withinstr;
    SigMatch *pm = NULL;
    int ret = -1;

    /* retrieve the sm to apply the within against */
    pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, -1);
    if (pm == NULL) {
        SCLogError(SC_ERR_OFFSET_MISSING_CONTENT, "within needs "
                   "preceding content option");
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
        DetectByteIndexType index;
        if (!DetectByteRetrieveSMVar(str, s, &index)) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "unknown byte_ keyword var "
                       "seen in within - %s\n", str);
            goto end;
        }
        cd->within = index;
        cd->flags |= DETECT_CONTENT_WITHIN_VAR;
    } else {
        if (StringParseInt32(&cd->within, 0, 0, str) < 0) {
            SCLogError(SC_ERR_INVALID_SIGNATURE,
                      "invalid value for within: %s", str);
            goto end;
        }

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
    SigMatch *prev_pm = DetectGetLastSMByListPtr(s, pm->prev,
            DETECT_CONTENT, DETECT_PCRE, -1);
    if (prev_pm == NULL) {
        ret = 0;
        goto end;
    }
    if (prev_pm->type == DETECT_CONTENT) {
        DetectContentData *prev_cd = (DetectContentData *)prev_pm->ctx;
        if (prev_cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "previous keyword "
                       "has a fast_pattern:only; set. Can't "
                       "have relative keywords around a fast_pattern "
                       "only content");
            goto end;
        }
        prev_cd->flags |= DETECT_CONTENT_WITHIN_NEXT;
    } else if (prev_pm->type == DETECT_PCRE) {
        DetectPcreData *pd = (DetectPcreData *)prev_pm->ctx;
        pd->flags |= DETECT_PCRE_RELATIVE_NEXT;
    }

    ret = 0;
 end:
    return ret;
}

/***********************************Unittests**********************************/

#ifdef UNITTESTS
#include "util-unittest-helper.h"
 /**
 * \test DetectWithinTestPacket01 is a test to check matches of
 * within, if the previous keyword is pcre (bug 145)
 */
static int DetectWithinTestPacket01 (void)
{
    uint8_t *buf = (uint8_t *)"GET /AllWorkAndNoPlayMakesWillADullBoy HTTP/1.0"
                    "User-Agent: Wget/1.11.4"
                    "Accept: */*"
                    "Host: www.google.com"
                    "Connection: Keep-Alive"
                    "Date: Mon, 04 Jan 2010 17:29:39 GMT";
    uint16_t buflen = strlen((char *)buf);

    Packet *p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"pcre with within "
                 "modifier\"; pcre:\"/AllWorkAndNoPlayMakesWillADullBoy/\";"
                 " content:\"HTTP\"; within:5; sid:49; rev:1;)";
    int result = UTHPacketMatchSig(p, sig);
    FAIL_IF_NOT(result == 1);

    UTHFreePacket(p);
    PASS;
}


static int DetectWithinTestPacket02 (void)
{
    uint8_t *buf = (uint8_t *)"Zero Five Ten Fourteen";
    uint16_t buflen = strlen((char *)buf);

    Packet *p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"pcre with within "
                 "modifier\"; content:\"Five\"; content:\"Ten\"; within:3; distance:1; sid:1;)";

    int result = UTHPacketMatchSig(p, sig);
    FAIL_IF_NOT(result == 1);

    UTHFreePacket(p);
    PASS;
}

static int DetectWithinTestVarSetup(void)
{
    char sig[] = "alert tcp any any -> any any ( "
        "msg:\"test rule\"; "
        "content:\"abc\"; "
        "http_client_body; "
        "byte_extract:2,0,somevar,relative; "
        "content:\"def\"; "
        "within:somevar; "
        "http_client_body; "
        "sid:4; rev:1;)";

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    FAIL_IF_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

void DetectWithinRegisterTests(void)
{
    UtRegisterTest("DetectWithinTestPacket01", DetectWithinTestPacket01);
    UtRegisterTest("DetectWithinTestPacket02", DetectWithinTestPacket02);
    UtRegisterTest("DetectWithinTestVarSetup", DetectWithinTestVarSetup);
}
#endif /* UNITTESTS */