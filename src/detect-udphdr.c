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
#include "detect-udphdr.h"

/* prototypes */
static int DetectUdphdrSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
void DetectUdphdrRegisterTests (void);
#endif

/**
 * \brief Registration function for tcphdr: keyword
 */

void DetectUdphdrRegister(void)
{
    sigmatch_table[DETECT_UDPHDR].name = "udp.hdr";
    sigmatch_table[DETECT_UDPHDR].desc = "sticky buffer to match on the UDP header";
    sigmatch_table[DETECT_UDPHDR].url = DOC_URL DOC_VERSION "/rules/header-keywords.html#udphdr";
    sigmatch_table[DETECT_UDPHDR].Setup = DetectUdphdrSetup;
    sigmatch_table[DETECT_UDPHDR].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_UDPHDR].RegisterTests = DetectUdphdrRegisterTests;
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
static int DetectUdphdrSetup (DetectEngineCtx *de_ctx, Signature *s, const char *tcphdrstr)
{
    if (!(DetectProtoContainsProto(&s->proto, IPPROTO_UDP)))
        return -1;

    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    if (DetectBufferSetActiveList(s, DETECT_SM_LIST_L4HDR) < 0)
        return -1;

    return 0;
}

static void PrefilterUdpHeader(DetectEngineThreadCtx *det_ctx,
        Packet *p, const void *pectx)
{
    SCEnter();

    if (((uint8_t *)p->udph + (ptrdiff_t)UDP_HEADER_LEN) >
            ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)))
    {
        SCLogDebug("data out of range: %p > %p",
                ((uint8_t *)p->udph + (ptrdiff_t)UDP_HEADER_LEN),
                ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)));
        SCReturn;
    }

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    if (UDP_HEADER_LEN < mpm_ctx->minlen)
        SCReturn;

    (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
            &det_ctx->mtc, &det_ctx->pmq,
            (uint8_t *)p->udph, UDP_HEADER_LEN);
}

int PrefilterUdpHeaderRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    return PrefilterAppendEngine(de_ctx, sgh,
            PrefilterUdpHeader, mpm_ctx, NULL, "udp.hdr");
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
bool DetectEngineInspectRuleUdpHeaderMatches(
     ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
     const Signature *s, const SigMatchData *sm_data,
     Flow *f, Packet *p,
     uint8_t *alert_flags)
{
    SCEnter();

    BUG_ON(sm_data == NULL);
    BUG_ON(sm_data != s->sm_arrays[DETECT_SM_LIST_L4HDR]);

    if (!(PKT_IS_UDP(p))) {
        SCReturnInt(false);
    }
    if (((uint8_t *)p->udph + (ptrdiff_t)UDP_HEADER_LEN) >
            ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)))
    {
        SCLogDebug("data out of range: %p > %p",
                ((uint8_t *)p->udph + (ptrdiff_t)UDP_HEADER_LEN),
                ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)));
        SCReturnInt(false);
    }

#ifdef DEBUG
    det_ctx->payload_persig_cnt++;
    det_ctx->payload_persig_size += UDP_HEADER_LEN;
#endif
    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    det_ctx->replist = NULL;

    int r = DetectEngineContentInspection(det_ctx->de_ctx, det_ctx,
            s, sm_data,
            p, NULL, (uint8_t *)p->udph, UDP_HEADER_LEN, 0,
            DETECT_CI_FLAGS_SINGLE, DETECT_ENGINE_CONTENT_INSPECTION_MODE_HEADER);
    if (r == 1) {
        SCReturnInt(true);
    }
    SCReturnInt(false);
}

#ifdef UNITTESTS
#include "tests/detect-udphdr.c"
#endif
