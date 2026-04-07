/* Copyright (C) 2007-2026 Open Information Security Foundation
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
 * \author XXX
 *
 * XXX Short description of the purpose of this keyword
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-uint.h"

#include "detect-template.h"

#ifdef UNITTESTS
static void DetectTemplateRegisterTests (void);
#endif

/**
 * \brief This function is used to match TEMPLATE rule option on a packet with those passed via
 * template:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectU8Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTemplateMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* TODO replace this */
    uint8_t ptemplate;
    if (PacketIsIPv4(p)) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        ptemplate = IPV4_GET_RAW_IPTTL(ip4h);
    } else if (PacketIsIPv6(p)) {
        const IPV6Hdr *ip6h = PacketGetIPv6(p);
        ptemplate = IPV6_GET_RAW_HLIM(ip6h);
    } else {
        SCLogDebug("Packet is of not IPv4 or IPv6");
        return 0;
    }

    const DetectU8Data *templated = (const DetectU8Data *)ctx;
    return DetectU8Match(ptemplate, templated);
}

/**
 * \brief this function will free memory associated with DetectU8Data
 *
 * \param ptr pointer to DetectU8Data
 */
static void DetectTemplateFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU8Free(ptr);
}

/**
 * \brief this function is used to add the parsed template data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param templatestr pointer to the user provided template options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTemplateSetup (DetectEngineCtx *de_ctx, Signature *s, const char *templatestr)
{
    DetectU8Data *templated = DetectU8Parse(templatestr);
    if (templated == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_TEMPLATE, (SigMatchCtx *)templated,
                DETECT_SM_LIST_MATCH) == NULL) {
        DetectTemplateFree(de_ctx, templated);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

/* prefilter code */

static void PrefilterPacketTemplateMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    uint8_t ptemplate;
    /* TODO update */
    if (PacketIsIPv4(p)) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        ptemplate = IPV4_GET_RAW_IPTTL(ip4h);
    } else if (PacketIsIPv6(p)) {
        const IPV6Hdr *ip6h = PacketGetIPv6(p);
        ptemplate = IPV6_GET_RAW_HLIM(ip6h);
    } else {
        SCLogDebug("Packet is of not IPv4 or IPv6");
        return;
    }

    /* during setup Suricata will automatically see if there is another
     * check that can be added: alproto, sport or dport */
    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    DetectU8Data du8;
    du8.mode = ctx->v1.u8[0];
    du8.arg1 = ctx->v1.u8[1];
    du8.arg2 = ctx->v1.u8[2];
    /* if we match, add all the sigs that use this prefilter. This means
     * that these will be inspected further */
    if (DetectU8Match(ptemplate, &du8)) {
        SCLogDebug("packet matches template/hl %u", ptemplate);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupTemplate(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_TEMPLATE, SIG_MASK_REQUIRE_REAL_PKT,
            PrefilterPacketU8Set, PrefilterPacketU8Compare, PrefilterPacketTemplateMatch);
}

static bool PrefilterTemplateIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_TEMPLATE);
}

/**
 * \brief Registration function for template: keyword
 */

void DetectTemplateRegister(void)
{
    /* keyword name: this is how the keyword is used in a rule */
    sigmatch_table[DETECT_TEMPLATE].name = "template";
    /* description: listed in "suricata --list-keywords=all" */
    sigmatch_table[DETECT_TEMPLATE].desc = "TODO describe the keyword";
    /* link to further documentation of the keyword. */
    sigmatch_table[DETECT_TEMPLATE].url = "/rules/header-keywords.html#template";
    /* match function is called when the signature is inspected on a packet */
    sigmatch_table[DETECT_TEMPLATE].Match = DetectTemplateMatch;
    /* setup function is called during signature parsing, when the template
     * keyword is encountered in the rule */
    sigmatch_table[DETECT_TEMPLATE].Setup = DetectTemplateSetup;
    /* free function is called when the detect engine is freed. Normally at
     * shutdown, but also during rule reloads. */
    sigmatch_table[DETECT_TEMPLATE].Free = DetectTemplateFree;
    sigmatch_table[DETECT_TEMPLATE].SupportsPrefilter = PrefilterTemplateIsPrefilterable;
    sigmatch_table[DETECT_TEMPLATE].SetupPrefilter = PrefilterSetupTemplate;
    sigmatch_table[DETECT_TEMPLATE].flags = SIGMATCH_INFO_UINT8;
#ifdef UNITTESTS
    /* registers unittests into the system */
    sigmatch_table[DETECT_TEMPLATE].RegisterTests = DetectTemplateRegisterTests;
#endif
}

#ifdef UNITTESTS
#include "tests/detect-template.c"
#endif
