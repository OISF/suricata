/* Copyright (C) 2007-2025 Open Information Security Foundation
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
 * \author Victor Julien <vjulien@oisf.net>
 *
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-uint.h"
#include "util-byte.h"

#include "detect-tcp-wscale.h"

/* prototypes */
static int DetectTcpWscaleMatch(
        DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
static int DetectTcpWscaleSetup(DetectEngineCtx *, Signature *, const char *);
void DetectTcpWscaleFree(DetectEngineCtx *, void *);
static int PrefilterSetupTcpWscale(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterTcpWscaleIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for tcp.wscale keyword
 */

void DetectTcpWscaleRegister(void)
{
    sigmatch_table[DETECT_TCP_WSCALE].name = "tcp.wscale";
    sigmatch_table[DETECT_TCP_WSCALE].desc = "match on TCP WSCALE option field";
    sigmatch_table[DETECT_TCP_WSCALE].url = "/rules/header-keywords.html#tcpwscale";
    sigmatch_table[DETECT_TCP_WSCALE].Match = DetectTcpWscaleMatch;
    sigmatch_table[DETECT_TCP_WSCALE].Setup = DetectTcpWscaleSetup;
    sigmatch_table[DETECT_TCP_WSCALE].Free = DetectTcpWscaleFree;
    sigmatch_table[DETECT_TCP_WSCALE].SupportsPrefilter = PrefilterTcpWscaleIsPrefilterable;
    sigmatch_table[DETECT_TCP_WSCALE].SetupPrefilter = PrefilterSetupTcpWscale;
    sigmatch_table[DETECT_TCP_WSCALE].flags = SIGMATCH_SUPPORT_FIREWALL | SIGMATCH_INFO_UINT8;
    sigmatch_table[DETECT_TCP_WSCALE].tables =
            (DETECT_TABLE_PACKET_PRE_FLOW_FLAG | DETECT_TABLE_PACKET_PRE_STREAM_FLAG |
                    DETECT_TABLE_PACKET_FILTER_FLAG | DETECT_TABLE_PACKET_TD_FLAG);
}

/**
 * \brief This function is used to match WSCALE rule option on a packet with those passed via
 * tcp.wscale:
 *
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param ctx pointer to the sigmatch that we will cast into DetectU8Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTcpWscaleMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    if (!(PacketIsTCP(p)))
        return 0;

    if (!(TCP_HAS_WSCALE(p)))
        return 0;

    uint8_t v = TCP_GET_WSCALE(p);

    const DetectU8Data *ws = (const DetectU8Data *)ctx;
    return DetectU8Match(v, ws);
}

/**
 * \brief this function is used to attach the parsed tcp.wscale data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTcpWscaleSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectU8Data *ws = DetectU8Parse(str);
    if (ws == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_TCP_WSCALE, (SigMatchCtx *)ws, DETECT_SM_LIST_MATCH) == NULL) {
        DetectTcpWscaleFree(de_ctx, ws);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

/**
 * \brief this function will free memory associated with DetectU8Data
 *
 * \param ptr pointer to DetectU8Data
 */
void DetectTcpWscaleFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU8Free(ptr);
}

/* prefilter code */

static void PrefilterPacketTcpWscaleMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));
    if (!(PacketIsTCP(p)))
        return;

    if (!(TCP_HAS_WSCALE(p)))
        return;

    const uint8_t v = TCP_GET_WSCALE(p);

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
    if (DetectU8Match(v, &du8)) {
        SCLogDebug("packet matches wscale %u", v);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupTcpWscale(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_TCP_WSCALE, SIG_MASK_REQUIRE_REAL_PKT,
            PrefilterPacketU8Set, PrefilterPacketU8Compare, PrefilterPacketTcpWscaleMatch);
}

static bool PrefilterTcpWscaleIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH]; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_TCP_WSCALE:
                return true;
        }
    }
    return false;
}
