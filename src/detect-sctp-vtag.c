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
 * Implements sctp.vtag keyword
 *
 * Author: Giuseppe Longo <glongo@oisf.net>
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-build.h"
#include "detect-engine-uint.h"

#include "detect-sctp-vtag.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

static int DetectSCTPVtagSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectSCTPVtagMatch(
        DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
static void DetectSCTPVtagFree(DetectEngineCtx *, void *);
static int PrefilterSetupSCTPVtag(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterSCTPVtagIsPrefilterable(const Signature *s);

#ifdef UNITTESTS
void DetectSCTPVtagRegisterTests(void);
#endif

void DetectSCTPVtagRegister(void)
{
    sigmatch_table[DETECT_SCTP_VTAG].name = "sctp.vtag";
    sigmatch_table[DETECT_SCTP_VTAG].desc = "match on the SCTP verification tag";
    sigmatch_table[DETECT_SCTP_VTAG].url = "/rules/header-keywords.html#sctp-vtag";
    sigmatch_table[DETECT_SCTP_VTAG].Match = DetectSCTPVtagMatch;
    sigmatch_table[DETECT_SCTP_VTAG].Setup = DetectSCTPVtagSetup;
    sigmatch_table[DETECT_SCTP_VTAG].Free = DetectSCTPVtagFree;
    sigmatch_table[DETECT_SCTP_VTAG].flags = SIGMATCH_INFO_UINT32;
    sigmatch_table[DETECT_SCTP_VTAG].SupportsPrefilter = PrefilterSCTPVtagIsPrefilterable;
    sigmatch_table[DETECT_SCTP_VTAG].SetupPrefilter = PrefilterSetupSCTPVtag;
#ifdef UNITTESTS
    sigmatch_table[DETECT_SCTP_VTAG].RegisterTests = DetectSCTPVtagRegisterTests;
#endif
}

static int DetectSCTPVtagMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectU32Data *data = (const DetectU32Data *)ctx;

    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    if (!(PacketIsSCTP(p))) {
        return 0;
    }

    return DetectU32Match(SCTP_GET_RAW_VTAG(PacketGetSCTP(p)), data);
}

static int DetectSCTPVtagSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    if (!(DetectProtoContainsProto(s->proto, IPPROTO_SCTP)))
        return -1;

    DetectU32Data *data = SCDetectU32Parse(optstr);
    if (data == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_SCTP_VTAG, (SigMatchCtx *)data, DETECT_SM_LIST_MATCH) == NULL) {
        DetectSCTPVtagFree(de_ctx, data);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;
    return 0;
}

static void DetectSCTPVtagFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU32Free(ptr);
}

static void PrefilterPacketSCTPVtagMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;

    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));
    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    if (p->proto == IPPROTO_SCTP && PacketIsSCTP(p)) {
        DetectU32Data du32;
        du32.mode = ctx->v1.u8[0];
        du32.arg1 = ctx->v1.u32[1];
        du32.arg2 = ctx->v1.u32[2];
        if (DetectU32Match(SCTP_GET_RAW_VTAG(PacketGetSCTP(p)), &du32)) {
            SCLogDebug("packet matches SCTP vtag %u", ctx->v1.u32[0]);
            PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
        }
    }
}

static int PrefilterSetupSCTPVtag(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_SCTP_VTAG, SIG_MASK_REQUIRE_REAL_PKT,
            PrefilterPacketU32Set, PrefilterPacketU32Compare, PrefilterPacketSCTPVtagMatch);
}

static bool PrefilterSCTPVtagIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_SCTP_VTAG);
}

#ifdef UNITTESTS
#include "tests/detect-sctp-vtag.c"
#endif
