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
 * \author XXX
 *
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#endif

#include "detect-parse.h"
#include "detect-engine-uint.h"

#include "detect-template2.h"


/* prototypes */
static int DetectTemplate2Match (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectTemplate2Setup (DetectEngineCtx *, Signature *, const char *);
void DetectTemplate2Free (DetectEngineCtx *, void *);
#ifdef UNITTESTS
void DetectTemplate2RegisterTests (void);
#endif
static int PrefilterSetupTemplate2(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterTemplate2IsPrefilterable(const Signature *s);

/**
 * \brief Registration function for template2: keyword
 */

void DetectTemplate2Register(void)
{
    sigmatch_table[DETECT_TEMPLATE2].name = "template2";
    sigmatch_table[DETECT_TEMPLATE2].desc = "TODO describe the keyword";
    sigmatch_table[DETECT_TEMPLATE2].url = "/rules/header-keywords.html#template2";
    sigmatch_table[DETECT_TEMPLATE2].Match = DetectTemplate2Match;
    sigmatch_table[DETECT_TEMPLATE2].Setup = DetectTemplate2Setup;
    sigmatch_table[DETECT_TEMPLATE2].Free = DetectTemplate2Free;
    sigmatch_table[DETECT_TEMPLATE2].SupportsPrefilter = PrefilterTemplate2IsPrefilterable;
    sigmatch_table[DETECT_TEMPLATE2].SetupPrefilter = PrefilterSetupTemplate2;

    return;
}

/**
 * \brief This function is used to match TEMPLATE2 rule option on a packet with those passed via
 * template2:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectU8Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTemplate2Match (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{

    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    /* TODO replace this */
    uint8_t ptemplate2;
    if (PKT_IS_IPV4(p)) {
        ptemplate2 = IPV4_GET_IPTTL(p);
    } else if (PKT_IS_IPV6(p)) {
        ptemplate2 = IPV6_GET_HLIM(p);
    } else {
        SCLogDebug("Packet is of not IPv4 or IPv6");
        return 0;
    }

    const DetectU8Data *template2d = (const DetectU8Data *)ctx;
    return DetectU8Match(ptemplate2, template2d);
}

/**
 * \brief this function is used to add the parsed template2 data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param template2str pointer to the user provided template2 options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTemplate2Setup (DetectEngineCtx *de_ctx, Signature *s, const char *template2str)
{
    DetectU8Data *template2d = DetectU8Parse(template2str);
    if (template2d == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectTemplate2Free(de_ctx, template2d);
        return -1;
    }

    sm->type = DETECT_TEMPLATE2;
    sm->ctx = (SigMatchCtx *)template2d;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

/**
 * \brief this function will free memory associated with DetectU8Data
 *
 * \param ptr pointer to DetectU8Data
 */
void DetectTemplate2Free(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u8_free(ptr);
}

/* prefilter code */

static void
PrefilterPacketTemplate2Match(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturn;
    }

    uint8_t ptemplate2;
/* TODO update */
    if (PKT_IS_IPV4(p)) {
        ptemplate2 = IPV4_GET_IPTTL(p);
    } else if (PKT_IS_IPV6(p)) {
        ptemplate2 = IPV6_GET_HLIM(p);
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
    if (DetectU8Match(ptemplate2, &du8)) {
        SCLogDebug("packet matches template2/hl %u", ptemplate2);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupTemplate2(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_TEMPLATE2, PrefilterPacketU8Set,
            PrefilterPacketU8Compare, PrefilterPacketTemplate2Match);
}

static bool PrefilterTemplate2IsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_TEMPLATE2:
                return true;
        }
    }
    return false;
}
