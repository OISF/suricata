/* Copyright (C) 2007-2019 Open Information Security Foundation
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

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-fast-pattern.h"
#include "detect-tcphdr.h"

/* prototypes */
static int DetectTcphdrSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
void DetectTcphdrRegisterTests (void);
#endif

/**
 * \brief Registration function for tcphdr: keyword
 */

void DetectTcphdrRegister(void)
{
    sigmatch_table[DETECT_TCPHDR].name = "tcp.hdr";
    sigmatch_table[DETECT_TCPHDR].desc = "sticky buffer to match on the TCP header";
    sigmatch_table[DETECT_TCPHDR].url = DOC_URL DOC_VERSION "/rules/header-keywords.html#tcphdr";
    sigmatch_table[DETECT_TCPHDR].Setup = DetectTcphdrSetup;
    sigmatch_table[DETECT_TCPHDR].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TCPHDR].RegisterTests = DetectTcphdrRegisterTests;
#endif
    SupportFastPatternForSigMatchList(DETECT_SM_LIST_L4HDR, 2);
    return;
}

/**
 * \brief this function is used to atcphdrd the parsed tcphdr data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param tcphdrstr pointer to the user provided tcphdr options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTcphdrSetup (DetectEngineCtx *de_ctx, Signature *s, const char *tcphdrstr)
{
    if (!(DetectProtoContainsProto(&s->proto, IPPROTO_TCP)))
        return -1;

    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    if (DetectBufferSetActiveList(s, DETECT_SM_LIST_L4HDR) < 0)
        return -1;

    return 0;
}

static void PrefilterTcpHeader(DetectEngineThreadCtx *det_ctx,
        Packet *p, const void *pectx)
{
    SCEnter();

    uint32_t hlen = TCP_GET_HLEN(p);
    if (((uint8_t *)p->tcph + (ptrdiff_t)hlen) >
            ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)))
    {
        SCLogDebug("data out of range: %p > %p",
                ((uint8_t *)p->tcph + (ptrdiff_t)hlen),
                ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)));
        SCReturn;
    }

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    if (hlen < mpm_ctx->minlen)
        SCReturn;

    (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
            &det_ctx->mtc, &det_ctx->pmq,
            (uint8_t *)p->tcph, hlen);
}

int PrefilterTcpHeaderRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    return PrefilterAppendEngine(de_ctx, sgh,
            PrefilterTcpHeader, mpm_ctx, NULL, "tcp.hdr");
}

/**
 *  \brief Do the content inspection & validation for a signature
 *
 *  \param det_ctx Detection engine thread context
 *  \param s Signature to inspect
 *  \param p Packet
 *
 *  \retval false no match
 *  \retval true match
 */
bool DetectEngineInspectRuleTcpHeaderMatches(
     ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
     const Signature *s, const SigMatchData *sm_data,
     Flow *f, Packet *p,
     uint8_t *alert_flags)
{
    SCEnter();

    BUG_ON(sm_data == NULL);
    BUG_ON(sm_data != s->sm_arrays[DETECT_SM_LIST_L4HDR]);

    if (!(PKT_IS_TCP(p))) {
        SCReturnInt(false);
    }
    uint32_t hlen = TCP_GET_HLEN(p);
    if (((uint8_t *)p->tcph + (ptrdiff_t)hlen) >
            ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)))
    {
        SCLogDebug("data out of range: %p > %p",
                ((uint8_t *)p->tcph + (ptrdiff_t)hlen),
                ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)));
        SCReturnInt(false);
    }

#ifdef DEBUG
    det_ctx->payload_persig_cnt++;
    det_ctx->payload_persig_size += hlen;
#endif
    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    det_ctx->replist = NULL;

    int r = DetectEngineContentInspection(det_ctx->de_ctx, det_ctx,
            s, sm_data,
            p, NULL, (uint8_t *)p->tcph, hlen, 0,
            DETECT_CI_FLAGS_SINGLE, DETECT_ENGINE_CONTENT_INSPECTION_MODE_HEADER);
    if (r == 1) {
        SCReturnInt(true);
    }
    SCReturnInt(false);
}

#ifdef UNITTESTS
#include "tests/detect-tcphdr.c"
#endif
