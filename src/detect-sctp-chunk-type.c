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
 * Implements sctp.chunk_type keyword support
 *
 * Author: Giuseppe Longo <glongo@oisf.net>
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-build.h"

#include "detect-sctp-chunk-type.h"
#include "detect-engine-uint.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

static int DetectSCTPChunkTypeMatch(
        DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
static int DetectSCTPChunkTypeSetup(DetectEngineCtx *, Signature *, const char *);
void DetectSCTPChunkTypeFree(DetectEngineCtx *, void *);

static int PrefilterSetupSCTPChunkType(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterSCTPChunkTypeIsPrefilterable(const Signature *s);

#ifdef UNITTESTS
void DetectSCTPChunkTypeRegisterTests(void);
#endif

void DetectSCTPChunkTypeRegister(void)
{
    sigmatch_table[DETECT_SCTP_CHUNK_TYPE].name = "sctp.chunk_type";
    sigmatch_table[DETECT_SCTP_CHUNK_TYPE].desc = "match on any SCTP chunk type in the packet";
    sigmatch_table[DETECT_SCTP_CHUNK_TYPE].url = "/rules/header-keywords.html#sctp-chunk-type";
    sigmatch_table[DETECT_SCTP_CHUNK_TYPE].Match = DetectSCTPChunkTypeMatch;
    sigmatch_table[DETECT_SCTP_CHUNK_TYPE].Setup = DetectSCTPChunkTypeSetup;
    sigmatch_table[DETECT_SCTP_CHUNK_TYPE].Free = DetectSCTPChunkTypeFree;
    sigmatch_table[DETECT_SCTP_CHUNK_TYPE].flags = SIGMATCH_INFO_UINT8;
    sigmatch_table[DETECT_SCTP_CHUNK_TYPE].SupportsPrefilter =
            PrefilterSCTPChunkTypeIsPrefilterable;
    sigmatch_table[DETECT_SCTP_CHUNK_TYPE].SetupPrefilter = PrefilterSetupSCTPChunkType;
#ifdef UNITTESTS
    sigmatch_table[DETECT_SCTP_CHUNK_TYPE].RegisterTests = DetectSCTPChunkTypeRegisterTests;
#endif
}

static int DetectSCTPChunkTypeMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    if (!PacketIsSCTP(p)) {
        return 0;
    }

    const DetectU8Data *data = (const DetectU8Data *)ctx;
    const uint8_t cnt = MIN(p->l4.vars.sctp.chunk_cnt, SCTP_MAX_TRACKED_CHUNKS);
    for (uint8_t i = 0; i < cnt; i++) {
        if (DetectU8Match(p->l4.vars.sctp.chunk_types[i], data)) {
            return 1;
        }
    }
    return 0;
}

static int DetectSCTPChunkTypeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (!(DetectProtoContainsProto(s->proto, IPPROTO_SCTP)))
        return -1;

    DetectU8Data *data = DetectU8Parse(str);
    if (data == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_SCTP_CHUNK_TYPE, (SigMatchCtx *)data,
                DETECT_SM_LIST_MATCH) == NULL) {
        DetectSCTPChunkTypeFree(de_ctx, data);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

void DetectSCTPChunkTypeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectU8Data *data = (DetectU8Data *)ptr;
    SCDetectU8Free(data);
}

static void PrefilterPacketSCTPChunkTypeMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    if (!PacketIsSCTP(p)) {
        return;
    }

    const PrefilterPacketU8HashCtx *h = pectx;
    const uint8_t cnt = MIN(p->l4.vars.sctp.chunk_cnt, SCTP_MAX_TRACKED_CHUNKS);
    /* bitmap to dedup repeated chunk types within a single packet */
    uint32_t seen[8] = { 0 };
    for (uint8_t i = 0; i < cnt; i++) {
        const uint8_t val = p->l4.vars.sctp.chunk_types[i];
        if (seen[val >> 5] & (1U << (val & 0x1F))) {
            continue;
        }
        seen[val >> 5] |= 1U << (val & 0x1F);
        const SigsArray *sa = h->array[val];
        if (sa) {
            PrefilterAddSids(&det_ctx->pmq, sa->sigs, sa->cnt);
        }
    }
}

static int PrefilterSetupSCTPChunkType(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeaderU8Hash(de_ctx, sgh, DETECT_SCTP_CHUNK_TYPE,
            SIG_MASK_REQUIRE_REAL_PKT, PrefilterPacketU8Set, PrefilterPacketU8Compare,
            PrefilterPacketSCTPChunkTypeMatch);
}

static bool PrefilterSCTPChunkTypeIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_SCTP_CHUNK_TYPE);
}

#ifdef UNITTESTS
#include "tests/detect-sctp-chunk-type.c"
#endif
