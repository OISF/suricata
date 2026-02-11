/* Copyright (C) 2026 Open Information Security Foundation
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
 * Implements igmp.type keyword support
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-build.h"

#include "detect-igmp-type.h"
#include "detect-engine-uint.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

static int DetectIGMPTypeMatch(
        DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
static int DetectIGMPTypeSetup(DetectEngineCtx *, Signature *, const char *);
void DetectIGMPTypeFree(DetectEngineCtx *, void *);

static int PrefilterSetupIGMPType(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterIGMPTypeIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for igmp.type keyword
 */
void DetectIGMPTypeRegister(void)
{
    sigmatch_table[DETECT_IGMP_TYPE].name = "igmp.type";
    sigmatch_table[DETECT_IGMP_TYPE].desc = "match on a specific IGMP type";
    sigmatch_table[DETECT_IGMP_TYPE].url = "/rules/header-keywords.html#igmp.type";
    sigmatch_table[DETECT_IGMP_TYPE].Match = DetectIGMPTypeMatch;
    sigmatch_table[DETECT_IGMP_TYPE].Setup = DetectIGMPTypeSetup;
    sigmatch_table[DETECT_IGMP_TYPE].Free = DetectIGMPTypeFree;
    sigmatch_table[DETECT_IGMP_TYPE].flags = SIGMATCH_INFO_UINT8;
    sigmatch_table[DETECT_IGMP_TYPE].SupportsPrefilter = PrefilterIGMPTypeIsPrefilterable;
    sigmatch_table[DETECT_IGMP_TYPE].SetupPrefilter = PrefilterSetupIGMPType;
}

/**
 * \brief This function is used to match igmp.type rule option
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectU8Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectIGMPTypeMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    if (!PacketIsIGMP(p)) {
        /* Packet not IGMP */
        return 0;
    }

    const IGMPHdr *igmph = PacketGetIGMP(p);
    uint8_t type = igmph->type;
    const DetectU8Data *itd = (const DetectU8Data *)ctx;
    return DetectU8Match(type, itd);
}

/**
 * \brief this function is used to add the parsed igmp.type data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided igmp.type options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectIGMPTypeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (!(DetectProtoContainsProto(&s->proto, IPPROTO_IGMP)))
        return -1;

    DetectU8Data *itd = DetectU8Parse(str);
    if (itd == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_IGMP_TYPE, (SigMatchCtx *)itd, DETECT_SM_LIST_MATCH) == NULL) {
        DetectIGMPTypeFree(de_ctx, itd);
        return -1;
    }
    s->proto.flags |= DETECT_PROTO_IPV4;
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

/**
 * \brief this function will free memory associated with DetectU8Data
 *
 * \param ptr pointer to DetectU8Data
 */
void DetectIGMPTypeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectU8Data *itd = (DetectU8Data *)ptr;
    SCDetectU8Free(itd);
}

/* prefilter code
 *
 * Prefilter uses the U8Hash logic, where we setup a 256 entry array
 * for each IGMP type. Each array element has the list of signatures
 * that need to be inspected. */

static void PrefilterPacketIGMPTypeMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    if (PacketIsIGMP(p)) {
        const IGMPHdr *igmph = PacketGetIGMP(p);
        uint8_t type = igmph->type;
        const PrefilterPacketU8HashCtx *h = pectx;
        const SigsArray *sa = h->array[type];
        if (sa) {
            PrefilterAddSids(&det_ctx->pmq, sa->sigs, sa->cnt);
        }
    }
}

static int PrefilterSetupIGMPType(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeaderU8Hash(de_ctx, sgh, DETECT_IGMP_TYPE,
            SIG_MASK_REQUIRE_REAL_PKT, PrefilterPacketU8Set, PrefilterPacketU8Compare,
            PrefilterPacketIGMPTypeMatch);
}

static bool PrefilterIGMPTypeIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_IGMP_TYPE);
}
