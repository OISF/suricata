/* Copyright (C) 2007-2018 Open Information Security Foundation
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
 * \author Gurvinder Singh <gurvindersighdahiya@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements the ttl keyword including prefilter support.
 */

#include "suricata-common.h"
#include "stream-tcp.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"

#include "detect-ttl.h"
#include "util-debug.h"

/**
 * \brief Regex for parsing our ttl options
 */
#define PARSE_REGEX  "^\\s*([0-9]*)?\\s*([<>=-]+)?\\s*([0-9]+)?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* prototypes */
static int DetectTtlMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectTtlSetup (DetectEngineCtx *, Signature *, const char *);
void DetectTtlFree (void *);
#ifdef UNITTESTS
void DetectTtlRegisterTests (void);
#endif
static int PrefilterSetupTtl(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static _Bool PrefilterTtlIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for ttl: keyword
 */

void DetectTtlRegister(void)
{
    sigmatch_table[DETECT_TTL].name = "ttl";
    sigmatch_table[DETECT_TTL].desc = "check for a specific IP time-to-live value";
    sigmatch_table[DETECT_TTL].url = DOC_URL DOC_VERSION "/rules/header-keywords.html#ttl";
    sigmatch_table[DETECT_TTL].Match = DetectTtlMatch;
    sigmatch_table[DETECT_TTL].Setup = DetectTtlSetup;
    sigmatch_table[DETECT_TTL].Free = DetectTtlFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TTL].RegisterTests = DetectTtlRegisterTests;
#endif
    sigmatch_table[DETECT_TTL].SupportsPrefilter = PrefilterTtlIsPrefilterable;
    sigmatch_table[DETECT_TTL].SetupPrefilter = PrefilterSetupTtl;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
    return;
}

static inline int TtlMatch(const uint8_t pttl, const uint8_t mode,
                           const uint8_t dttl1, const uint8_t dttl2)
{
    if (mode == DETECT_TTL_EQ && pttl == dttl1)
        return 1;
    else if (mode == DETECT_TTL_LT && pttl < dttl1)
        return 1;
    else if (mode == DETECT_TTL_GT && pttl > dttl1)
        return 1;
    else if (mode == DETECT_TTL_RA && (pttl > dttl1 && pttl < dttl2))
        return 1;

    return 0;
}

/**
 * \brief This function is used to match TTL rule option on a packet with
 *        those passed via ttl
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectTtlData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTtlMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    uint8_t pttl;
    if (PKT_IS_IPV4(p)) {
        pttl = IPV4_GET_IPTTL(p);
    } else if (PKT_IS_IPV6(p)) {
        pttl = IPV6_GET_HLIM(p);
    } else {
        SCLogDebug("Packet is of not IPv4 or IPv6");
        return 0;
    }

    const DetectTtlData *ttld = (const DetectTtlData *)ctx;
    return TtlMatch(pttl, ttld->mode, ttld->ttl1, ttld->ttl2);
}

/**
 * \brief This function is used to parse ttl options passed via ttl: keyword
 *
 * \param ttlstr Pointer to the user provided ttl options
 *
 * \retval ttld pointer to DetectTtlData on success
 * \retval NULL on failure
 */

static DetectTtlData *DetectTtlParse (const char *ttlstr)
{
#define MAX_SUBSTRINGS 30
    int ov[MAX_SUBSTRINGS];
    char arg1[6] = "";
    char arg2[6] = "";
    char arg3[6] = "";

    int ret = pcre_exec(parse_regex, parse_regex_study, ttlstr, strlen(ttlstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        return NULL;
    }

    int res = pcre_copy_substring((char *) ttlstr, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        return NULL;
    }
    SCLogDebug("arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_copy_substring((char *) ttlstr, ov, MAX_SUBSTRINGS, 2, arg2, sizeof(arg2));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            return NULL;
        }
        SCLogDebug("arg2 \"%s\"", arg2);

        if (ret >= 4) {
            res = pcre_copy_substring((char *) ttlstr, ov, MAX_SUBSTRINGS, 3, arg3, sizeof(arg3));
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
                return NULL;
            }
            SCLogDebug("arg3 \"%s\"", arg3);
        }
    }

    int ttl1 = 0;
    int ttl2 = 0;
    int mode = 0;

    if (strlen(arg2) > 0) {
        switch (arg2[0]) {
            case '<':
                if (strlen(arg3) == 0)
                    return NULL;

                mode = DETECT_TTL_LT;
                ttl1 = atoi(arg3);

                SCLogDebug("ttl is %d",ttl1);
                if (strlen(arg1) > 0)
                    return NULL;

                break;
            case '>':
                if (strlen(arg3) == 0)
                    return NULL;

                mode = DETECT_TTL_GT;
                ttl1 = atoi(arg3);

                SCLogDebug("ttl is %d",ttl1);
                if (strlen(arg1) > 0)
                    return NULL;

                break;
            case '-':
                if (strlen(arg1) == 0 || strlen(arg3) == 0)
                    return NULL;

                mode = DETECT_TTL_RA;
                ttl1 = atoi(arg1);
                ttl2 = atoi(arg3);

                SCLogDebug("ttl is %d to %d",ttl1, ttl2);
                if (ttl1 >= ttl2) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid ttl range");
                    return NULL;
                }
                break;
            default:
                mode = DETECT_TTL_EQ;

                if ((strlen(arg2) > 0) ||
                    (strlen(arg3) > 0) ||
                    (strlen(arg1) == 0))
                    return NULL;

                ttl1 = atoi(arg1);
                break;
        }
    } else {
        mode = DETECT_TTL_EQ;

        if ((strlen(arg3) > 0) ||
            (strlen(arg1) == 0))
            return NULL;

        ttl1 = atoi(arg1);
    }

    if (ttl1 < 0 || ttl1 > UCHAR_MAX ||
        ttl2 < 0 || ttl2 > UCHAR_MAX) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid ttl value(s)");
        return NULL;
    }

    DetectTtlData *ttld = SCMalloc(sizeof(DetectTtlData));
    if (unlikely(ttld == NULL))
        return NULL;
    ttld->ttl1 = (uint8_t)ttl1;
    ttld->ttl2 = (uint8_t)ttl2;
    ttld->mode = mode;

    return ttld;
}

/**
 * \brief this function is used to attld the parsed ttl data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param ttlstr pointer to the user provided ttl options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTtlSetup (DetectEngineCtx *de_ctx, Signature *s, const char *ttlstr)
{
    DetectTtlData *ttld = DetectTtlParse(ttlstr);
    if (ttld == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectTtlFree(ttld);
        return -1;
    }

    sm->type = DETECT_TTL;
    sm->ctx = (SigMatchCtx *)ttld;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;
    return 0;
}

/**
 * \brief this function will free memory associated with DetectTtlData
 *
 * \param ptr pointer to DetectTtlData
 */
void DetectTtlFree(void *ptr)
{
    DetectTtlData *ttld = (DetectTtlData *)ptr;
    SCFree(ttld);
}

/* prefilter code */

static void
PrefilterPacketTtlMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturn;
    }

    uint8_t pttl;
    if (PKT_IS_IPV4(p)) {
        pttl = IPV4_GET_IPTTL(p);
    } else if (PKT_IS_IPV6(p)) {
        pttl = IPV6_GET_HLIM(p);
    } else {
        SCLogDebug("Packet is of not IPv4 or IPv6");
        return;
    }

    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (PrefilterPacketHeaderExtraMatch(ctx, p) == FALSE)
        return;

    if (TtlMatch(pttl, ctx->v1.u8[0], ctx->v1.u8[1], ctx->v1.u8[2]))
    {
        SCLogDebug("packet matches ttl/hl %u", pttl);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketTtlSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectTtlData *a = smctx;
    v->u8[0] = a->mode;
    v->u8[1] = a->ttl1;
    v->u8[2] = a->ttl2;
}

static _Bool
PrefilterPacketTtlCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectTtlData *a = smctx;
    if (v.u8[0] == a->mode &&
        v.u8[1] == a->ttl1 &&
        v.u8[2] == a->ttl2)
        return TRUE;
    return FALSE;
}

static int PrefilterSetupTtl(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_TTL,
            PrefilterPacketTtlSet,
            PrefilterPacketTtlCompare,
            PrefilterPacketTtlMatch);
}

static _Bool PrefilterTtlIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_TTL:
                return TRUE;
        }
    }
    return FALSE;
}

#ifdef UNITTESTS
#include "tests/detect-ttl.c"
#endif
