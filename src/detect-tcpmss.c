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
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#include "suricata-common.h"

#include "detect-parse.h"
#include "detect-engine-uint.h"

#include "detect-tcpmss.h"


/* prototypes */
static int DetectTcpmssMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectTcpmssSetup (DetectEngineCtx *, Signature *, const char *);
void DetectTcpmssFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
void DetectTcpmssRegisterTests (void);
#endif
static int PrefilterSetupTcpmss(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterTcpmssIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for tcpmss: keyword
 */

void DetectTcpmssRegister(void)
{
    sigmatch_table[DETECT_TCPMSS].name = "tcp.mss";
    sigmatch_table[DETECT_TCPMSS].desc = "match on TCP MSS option field";
    sigmatch_table[DETECT_TCPMSS].url = "/rules/header-keywords.html#tcpmss";
    sigmatch_table[DETECT_TCPMSS].Match = DetectTcpmssMatch;
    sigmatch_table[DETECT_TCPMSS].Setup = DetectTcpmssSetup;
    sigmatch_table[DETECT_TCPMSS].Free = DetectTcpmssFree;
    sigmatch_table[DETECT_TCPMSS].SupportsPrefilter = PrefilterTcpmssIsPrefilterable;
    sigmatch_table[DETECT_TCPMSS].SetupPrefilter = PrefilterSetupTcpmss;

    return;
}

/**
 * \brief This function is used to match TCPMSS rule option on a packet with those passed via
 * tcpmss:
 *
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param ctx pointer to the sigmatch that we will cast into DetectU16Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTcpmssMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{

    if (!(PKT_IS_TCP(p)) || PKT_IS_PSEUDOPKT(p))
        return 0;

    if (!(TCP_HAS_MSS(p)))
        return 0;

    uint16_t ptcpmss = TCP_GET_MSS(p);

    const DetectU16Data *tcpmssd = (const DetectU16Data *)ctx;
    return DetectU16Match(ptcpmss, tcpmssd);
}

/**
 * \brief this function is used to attach the parsed tcpmss data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param tcpmssstr pointer to the user provided tcpmss options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTcpmssSetup (DetectEngineCtx *de_ctx, Signature *s, const char *tcpmssstr)
{
    DetectU16Data *tcpmssd = DetectU16Parse(tcpmssstr);
    if (tcpmssd == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectTcpmssFree(de_ctx, tcpmssd);
        return -1;
    }

    sm->type = DETECT_TCPMSS;
    sm->ctx = (SigMatchCtx *)tcpmssd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

/**
 * \brief this function will free memory associated with DetectU16Data
 *
 * \param ptr pointer to DetectU16Data
 */
void DetectTcpmssFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u16_free(ptr);
}

/* prefilter code */

static void
PrefilterPacketTcpmssMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (!(PKT_IS_TCP(p)) || PKT_IS_PSEUDOPKT(p))
        return;

    if (!(TCP_HAS_MSS(p)))
        return;

    uint16_t ptcpmss = TCP_GET_MSS(p);

    /* during setup Suricata will automatically see if there is another
     * check that can be added: alproto, sport or dport */
    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    DetectU16Data du16;
    du16.mode = ctx->v1.u8[0];
    du16.arg1 = ctx->v1.u16[1];
    du16.arg2 = ctx->v1.u16[2];
    /* if we match, add all the sigs that use this prefilter. This means
     * that these will be inspected further */
    if (DetectU16Match(ptcpmss, &du16)) {
        SCLogDebug("packet matches tcpmss/hl %u", ptcpmss);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupTcpmss(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_TCPMSS, PrefilterPacketU16Set,
            PrefilterPacketU16Compare, PrefilterPacketTcpmssMatch);
}

static bool PrefilterTcpmssIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_TCPMSS:
                return true;
        }
    }
    return false;
}
