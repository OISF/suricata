/* Copyright (C) 2020 Open Information Security Foundation
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
 * \author Philippe Antoine <p.antoine@catenacyber.fr>
 *
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "detect.h"
#endif

#include "detect-parse.h"

#include "detect-icmpv6-mtu.h"
#include "detect-engine-uint.h"

/* prototypes */
static int DetectICMPv6mtuMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectICMPv6mtuSetup (DetectEngineCtx *, Signature *, const char *);
void DetectICMPv6mtuFree (DetectEngineCtx *de_ctx, void *);
#ifdef UNITTESTS
void DetectICMPv6mtuRegisterTests (void);
#endif
static int PrefilterSetupIcmpv6mtu(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterIcmpv6mtuIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for icmpv6.mtu: keyword
 */

void DetectICMPv6mtuRegister(void)
{
    sigmatch_table[DETECT_ICMPV6MTU].name = "icmpv6.mtu";
    sigmatch_table[DETECT_ICMPV6MTU].desc = "match on ICMPv6 MTU field";
    sigmatch_table[DETECT_ICMPV6MTU].url = "/rules/header-keywords.html#icmpv6mtu";
    sigmatch_table[DETECT_ICMPV6MTU].Match = DetectICMPv6mtuMatch;
    sigmatch_table[DETECT_ICMPV6MTU].Setup = DetectICMPv6mtuSetup;
    sigmatch_table[DETECT_ICMPV6MTU].Free = DetectICMPv6mtuFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ICMPV6MTU].RegisterTests = DetectICMPv6mtuRegisterTests;
#endif
    sigmatch_table[DETECT_ICMPV6MTU].SupportsPrefilter = PrefilterIcmpv6mtuIsPrefilterable;
    sigmatch_table[DETECT_ICMPV6MTU].SetupPrefilter = PrefilterSetupIcmpv6mtu;
    return;
}

// returns 0 on no mtu, and 1 if mtu
static inline int DetectICMPv6mtuGetValue(Packet *p, uint32_t *picmpv6mtu)
{
    if (!(PKT_IS_ICMPV6(p)) || PKT_IS_PSEUDOPKT(p))
        return 0;
    if (ICMPV6_GET_CODE(p) != 0)
        return 0;
    if (!(ICMPV6_HAS_MTU(p)))
        return 0;

    *picmpv6mtu = ICMPV6_GET_MTU(p);
    return 1;
}

/**
 * \brief This function is used to match ICMPV6 MTU rule option on a packet with those passed via icmpv6.mtu:
 *
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param s pointer to the signature unused
 * \param ctx pointer to the signature match context
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectICMPv6mtuMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    uint32_t picmpv6mtu;
    if (DetectICMPv6mtuGetValue(p, &picmpv6mtu) == 0) {
        return 0;
    }

    const DetectU32Data *du32 = (const DetectU32Data *)ctx;
    return DetectU32Match(picmpv6mtu, du32);
}

/**
 * \brief this function is used to attach the parsed icmpv6.mtu data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param icmpv6mtustr pointer to the user provided icmpv6.mtu options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectICMPv6mtuSetup (DetectEngineCtx *de_ctx, Signature *s, const char *icmpv6mtustr)
{
    DetectU32Data *icmpv6mtud = DetectU32Parse(icmpv6mtustr);
    if (icmpv6mtud == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectICMPv6mtuFree(de_ctx, icmpv6mtud);
        return -1;
    }

    sm->type = DETECT_ICMPV6MTU;
    sm->ctx = (SigMatchCtx *)icmpv6mtud;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;
    s->proto.flags |= DETECT_PROTO_IPV6;

    return 0;
}

/**
 * \brief this function will free memory associated with DetectU32Data
 *
 * \param ptr pointer to DetectU32Data
 */
void DetectICMPv6mtuFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u32_free(ptr);
}

/* prefilter code */

static void
PrefilterPacketIcmpv6mtuMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    uint32_t picmpv6mtu;
    if (DetectICMPv6mtuGetValue(p, &picmpv6mtu) == 0) {
        return;
    }

    /* during setup Suricata will automatically see if there is another
     * check that can be added: alproto, sport or dport */
    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    /* if we match, add all the sigs that use this prefilter. This means
     * that these will be inspected further */
    DetectU32Data du32;
    du32.mode = ctx->v1.u8[0];
    du32.arg1 = ctx->v1.u32[1];
    du32.arg2 = ctx->v1.u32[2];
    if (DetectU32Match(picmpv6mtu, &du32))
    {
        SCLogDebug("packet matches icmpv6.mtu/hl %u", picmpv6mtu);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupIcmpv6mtu(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_ICMPV6MTU,
            PrefilterPacketU32Set,
            PrefilterPacketU32Compare,
            PrefilterPacketIcmpv6mtuMatch);
}

static bool PrefilterIcmpv6mtuIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_ICMPV6MTU);
}

#ifdef UNITTESTS
#include "tests/detect-icmpv6-mtu.c"
#endif
