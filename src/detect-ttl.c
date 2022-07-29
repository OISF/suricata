/* Copyright (C) 2007-2020 Open Information Security Foundation
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

#include "detect-parse.h"
#include "detect-engine-uint.h"

#include "detect-ttl.h"

/* prototypes */
static int DetectTtlMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectTtlSetup (DetectEngineCtx *, Signature *, const char *);
void DetectTtlFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
void DetectTtlRegisterTests (void);
#endif
static int PrefilterSetupTtl(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterTtlIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for ttl: keyword
 */

void DetectTtlRegister(void)
{
    sigmatch_table[DETECT_TTL].name = "ttl";
    sigmatch_table[DETECT_TTL].desc = "check for a specific IP time-to-live value";
    sigmatch_table[DETECT_TTL].url = "/rules/header-keywords.html#ttl";
    sigmatch_table[DETECT_TTL].Match = DetectTtlMatch;
    sigmatch_table[DETECT_TTL].Setup = DetectTtlSetup;
    sigmatch_table[DETECT_TTL].Free = DetectTtlFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TTL].RegisterTests = DetectTtlRegisterTests;
#endif
    sigmatch_table[DETECT_TTL].SupportsPrefilter = PrefilterTtlIsPrefilterable;
    sigmatch_table[DETECT_TTL].SetupPrefilter = PrefilterSetupTtl;

    return;
}

/**
 * \brief This function is used to match TTL rule option on a packet with
 *        those passed via ttl
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectU8Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTtlMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
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

    const DetectU8Data *ttld = (const DetectU8Data *)ctx;
    return DetectU8Match(pttl, ttld);
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
    DetectU8Data *ttld = DetectU8Parse(ttlstr);
    if (ttld == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectTtlFree(de_ctx, ttld);
        return -1;
    }

    sm->type = DETECT_TTL;
    sm->ctx = (SigMatchCtx *)ttld;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;
    return 0;
}

/**
 * \brief this function will free memory associated with DetectU8Data
 *
 * \param ptr pointer to DetectU8Data
 */
void DetectTtlFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u8_free(ptr);
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
    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    DetectU8Data du8;
    du8.mode = ctx->v1.u8[0];
    du8.arg1 = ctx->v1.u8[1];
    du8.arg2 = ctx->v1.u8[2];
    if (DetectU8Match(pttl, &du8)) {
        SCLogDebug("packet matches ttl/hl %u", pttl);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupTtl(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_TTL, PrefilterPacketU8Set,
            PrefilterPacketU8Compare, PrefilterPacketTtlMatch);
}

static bool PrefilterTtlIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_TTL:
                return true;
        }
    }
    return false;
}

#ifdef UNITTESTS
#include "tests/detect-ttl.c"
#endif
