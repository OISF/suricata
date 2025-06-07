/* Copyright (C) 2007-2023 Open Information Security Foundation
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

#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"
#include "detect-byte.h"
#include "detect-byte-extract.h"
#include "detect-distance.h"

#include "flow-var.h"

#include "util-byte.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "detect-bytejump.h"
#include "util-unittest-helper.h"

static int DetectDistanceSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectDistanceRegisterTests(void);
#endif

void DetectDistanceRegister(void)
{
    sigmatch_table[DETECT_DISTANCE].name = "distance";
    sigmatch_table[DETECT_DISTANCE].desc = "indicates a relation between this content keyword and the content preceding it";
    sigmatch_table[DETECT_DISTANCE].url = "/rules/payload-keywords.html#distance";
    sigmatch_table[DETECT_DISTANCE].Match = NULL;
    sigmatch_table[DETECT_DISTANCE].Setup = DetectDistanceSetup;
    sigmatch_table[DETECT_DISTANCE].Free  = NULL;
#ifdef UNITTESTS
    sigmatch_table[DETECT_DISTANCE].RegisterTests = DetectDistanceRegisterTests;
#endif
}

static int DetectDistanceSetup (DetectEngineCtx *de_ctx, Signature *s,
        const char *distancestr)
{
    const char *str = distancestr;

    /* retrieve the sm to apply the distance against */
    SigMatch *pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, -1);
    if (pm == NULL) {
        SCLogError("distance needs "
                   "preceding content, uricontent option, http_client_body, "
                   "http_server_body, http_header option, http_raw_header option, "
                   "http_method option, http_cookie, http_raw_uri, "
                   "http_stat_msg, http_stat_code, http_user_agent or "
                   "file_data/dce_stub_data sticky buffer option");
        return -1;
    }

    /* verify other conditions */
    DetectContentData *cd = (DetectContentData *)pm->ctx;
    if (cd->flags & DETECT_CONTENT_DISTANCE) {
        SCLogError("can't use multiple distances for the same content.");
        return -1;
    }
    if ((cd->flags & DETECT_CONTENT_DEPTH) || (cd->flags & DETECT_CONTENT_OFFSET)) {
        SCLogError("can't use a relative "
                   "keyword like within/distance with a absolute "
                   "relative keyword like depth/offset for the same "
                   "content.");
        return -1;
    }
    if (cd->flags & DETECT_CONTENT_NEGATED && cd->flags & DETECT_CONTENT_FAST_PATTERN) {
        SCLogError("can't have a relative "
                   "negated keyword set along with a fast_pattern");
        return -1;
    }
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
        SCLogError("can't have a relative "
                   "keyword set along with a fast_pattern:only;");
        return -1;
    }
    if (str[0] != '-' && isalpha((unsigned char)str[0])) {
        DetectByteIndexType index;
        if (!DetectByteRetrieveSMVar(str, s, -1, &index)) {
            SCLogError("unknown byte_ keyword var "
                       "seen in distance - %s",
                    str);
            return -1;
        }
        cd->distance = index;
        cd->flags |= DETECT_CONTENT_DISTANCE_VAR;
    } else {
        if ((StringParseI32RangeCheck(&cd->distance, 0, 0, str, -DETECT_CONTENT_VALUE_MAX,
                     DETECT_CONTENT_VALUE_MAX) < 0)) {
            SCLogError("invalid value for distance: %s", str);
            return -1;
        }
    }
    cd->flags |= DETECT_CONTENT_DISTANCE;

    SigMatch *prev_pm = DetectGetLastSMByListPtr(s, pm->prev,
            DETECT_CONTENT, DETECT_PCRE, -1);
    if (prev_pm == NULL) {
        return 0;
    }

    if (prev_pm->type == DETECT_CONTENT) {
        DetectContentData *prev_cd = (DetectContentData *)prev_pm->ctx;
        if (prev_cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
            SCLogError("previous keyword "
                       "has a fast_pattern:only; set. Can't "
                       "have relative keywords around a fast_pattern "
                       "only content");
            return -1;
        }
        if ((cd->flags & DETECT_CONTENT_NEGATED) == 0) {
            prev_cd->flags |= DETECT_CONTENT_DISTANCE_NEXT;
        } else {
            prev_cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
        }
    } else if (prev_pm->type == DETECT_PCRE) {
        DetectPcreData *pd = (DetectPcreData *)prev_pm->ctx;
        pd->flags |= DETECT_PCRE_RELATIVE_NEXT;
    }

    return 0;
}

#ifdef UNITTESTS

static int DetectDistanceTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (content:\"|AA BB|\"; content:\"|CC DD EE FF 00 11 22 33 "
            "44 55 66 77 88 99 AA BB CC DD EE|\"; distance: 4; within: 19; sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    SigMatch *sm = de_ctx->sig_list->init_data->smlists[DETECT_SM_LIST_PMATCH];
    FAIL_IF_NULL(sm);

    sm = sm->next;
    FAIL_IF_NULL(sm);

    DetectContentData *co = (DetectContentData *)sm->ctx;
    FAIL_IF_NULL(co);

    FAIL_IF_NOT(co->distance = 4);

    /* within needs to be 23: distance + content_len as Snort auto fixes this */
    FAIL_IF_NOT(co->within = 19);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test DetectDistanceTestPacket01 is a test to check matches of
 * distance works, if the previous keyword is byte_jump and content
 * (bug 163)
 */
static int DetectDistanceTestPacket01 (void)
{
    uint8_t buf[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);
    char sig[] = "alert tcp any any -> any any (msg:\"suricata test\"; "
                    "byte_jump:1,2; content:\"|00|\"; "
                    "within:1; distance:2; sid:98711212; rev:1;)";

    p->flowflags = FLOW_PKT_ESTABLISHED | FLOW_PKT_TOCLIENT;
    FAIL_IF_NOT(UTHPacketMatchSig(p, sig));

    UTHFreePacket(p);

    PASS;
}

static void DetectDistanceRegisterTests(void)
{
    UtRegisterTest("DetectDistanceTest01 -- distance / within mix",
                   DetectDistanceTest01);
    UtRegisterTest("DetectDistanceTestPacket01", DetectDistanceTestPacket01);
}
#endif /* UNITTESTS */
