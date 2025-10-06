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
 * \author Breno Silva <breno.silva@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements fragbits keyword
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "rust.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-uint.h"

#include "flow-var.h"
#include "decode-events.h"
#include "app-layer.h"
#include "app-layer-detect-proto.h"

#include "detect-fragbits.h"
#include "util-unittest.h"
#include "util-debug.h"

#include "pkt-var.h"
#include "host.h"
#include "util-profiling.h"

static int DetectFragBitsMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectFragBitsSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectFragBitsFree(DetectEngineCtx *, void *);

static int PrefilterSetupFragBits(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterFragBitsIsPrefilterable(const Signature *s);
#ifdef UNITTESTS
static void FragBitsRegisterTests(void);
#endif

/**
 * \brief Registration function for fragbits: keyword
 */

void DetectFragBitsRegister (void)
{
    sigmatch_table[DETECT_FRAGBITS].name = "fragbits";
    sigmatch_table[DETECT_FRAGBITS].desc = "check if the fragmentation and reserved bits are set in the IP header";
    sigmatch_table[DETECT_FRAGBITS].url = "/rules/header-keywords.html#fragbits-ip-fragmentation";
    sigmatch_table[DETECT_FRAGBITS].Match = DetectFragBitsMatch;
    sigmatch_table[DETECT_FRAGBITS].Setup = DetectFragBitsSetup;
    sigmatch_table[DETECT_FRAGBITS].Free  = DetectFragBitsFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FRAGBITS].RegisterTests = FragBitsRegisterTests;
#endif
    sigmatch_table[DETECT_FRAGBITS].SetupPrefilter = PrefilterSetupFragBits;
    sigmatch_table[DETECT_FRAGBITS].SupportsPrefilter = PrefilterFragBitsIsPrefilterable;
    sigmatch_table[DETECT_FRAGBITS].flags = SIGMATCH_INFO_UINT16 | SIGMATCH_INFO_BITFLAGS_UINT;
}

/**
 * \internal
 * \brief This function is used to match fragbits on a packet with those passed via fragbits:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param s pointer to the Signature
 * \param m pointer to the sigmatch
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectFragBitsMatch (DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));
    if (!ctx || !PacketIsIPv4(p))
        return 0;

    const IPV4Hdr *ip4h = PacketGetIPv4(p);
    DetectU16Data *du16 = (DetectU16Data *)ctx;
    return DetectU16Match(IPV4_GET_RAW_IPOFFSET(ip4h), du16);
}

/**
 * \internal
 * \brief this function is used to add the parsed fragbits into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param rawstr pointer to the user provided fragbits options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFragBitsSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU16Data *du16 = SCDetectIpv4FragbitsParse(rawstr);
    if (du16 == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_FRAGBITS, (SigMatchCtx *)du16, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (du16)
        DetectFragBitsFree(NULL, du16);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectU16Data
 *
 * \param de pointer to DetectU16Data
 */
static void DetectFragBitsFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    SCDetectU16Free(de_ptr);
}

static void
PrefilterPacketFragBitsMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));
    const PrefilterPacketHeaderCtx *ctx = pectx;

    if (!PacketIsIPv4(p))
        return;

    const IPV4Hdr *ip4h = PacketGetIPv4(p);
    DetectU16Data du16;
    du16.mode = ctx->v1.u8[0];
    du16.arg1 = ctx->v1.u16[1];
    du16.arg2 = ctx->v1.u16[2];

    if (DetectU16Match(IPV4_GET_RAW_IPOFFSET(ip4h), &du16)) {
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupFragBits(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_FRAGBITS, SIG_MASK_REQUIRE_REAL_PKT,
            PrefilterPacketU16Set, PrefilterPacketU16Compare, PrefilterPacketFragBitsMatch);
}

static bool PrefilterFragBitsIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_FRAGBITS:
                return true;
        }
    }
    return false;
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "packet.h"

/**
 * \test FragBitsTestParse03 test if DONT FRAG is set. Must return success
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FragBitsTestParse03 (void)
{
    uint8_t raw_eth[] = {
        0x00 ,0x40 ,0x33 ,0xd9 ,0x7c ,0xfd ,0x00 ,0x00,
        0x39 ,0xcf ,0xd9 ,0xcd ,0x08 ,0x00 ,0x45 ,0x00,
        0x01 ,0x13 ,0x9c ,0x5d ,0x40 ,0x00 ,0xf6 ,0x11,
        0x44 ,0xca ,0x97 ,0xa4 ,0x01 ,0x08 ,0x0a ,0x00,
        0x00 ,0x06 ,0x00 ,0x35 ,0x04 ,0x0b ,0x00 ,0xff,
        0x3c ,0x87 ,0x7d ,0x9e ,0x85 ,0x80 ,0x00 ,0x01,
        0x00 ,0x01 ,0x00 ,0x05 ,0x00 ,0x05 ,0x06 ,0x70,
        0x69 ,0x63 ,0x61 ,0x72 ,0x64 ,0x07 ,0x75 ,0x74,
        0x68 ,0x73 ,0x63 ,0x73 ,0x61 ,0x03 ,0x65 ,0x64,
        0x75 ,0x00 ,0x00 ,0x01 ,0x00 ,0x01 ,0xc0 ,0x0c,
        0x00 ,0x01 ,0x00 ,0x01 ,0x00 ,0x00 ,0x0e ,0x10,
        0x00 ,0x04 ,0x81 ,0x6f ,0x1e ,0x1b ,0x07 ,0x75,
        0x74 ,0x68 ,0x73 ,0x63 ,0x73 ,0x61 ,0x03 ,0x65,
        0x64 ,0x75 ,0x00 ,0x00 ,0x02 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x09 ,0x06 ,0x6b ,0x65,
        0x6e ,0x6f ,0x62 ,0x69 ,0xc0 ,0x34 ,0xc0 ,0x34,
        0x00 ,0x02 ,0x00 ,0x01 ,0x00 ,0x00 ,0x0e ,0x10,
        0x00 ,0x07 ,0x04 ,0x6a ,0x69 ,0x6e ,0x6e ,0xc0,
        0x34 ,0xc0 ,0x34 ,0x00 ,0x02 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x0c ,0x04 ,0x64 ,0x6e,
        0x73 ,0x31 ,0x04 ,0x6e ,0x6a ,0x69 ,0x74 ,0xc0,
        0x3c ,0xc0 ,0x34 ,0x00 ,0x02 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x08 ,0x05 ,0x65 ,0x6c,
        0x7a ,0x69 ,0x70 ,0xc0 ,0x34 ,0xc0 ,0x34 ,0x00,
        0x02 ,0x00 ,0x01 ,0x00 ,0x00 ,0x0e ,0x10 ,0x00,
        0x08 ,0x05 ,0x61 ,0x72 ,0x77 ,0x65 ,0x6e ,0xc0,
        0x34 ,0xc0 ,0x4b ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x1a,
        0x06 ,0xc0 ,0x60 ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x1a,
        0x07 ,0xc0 ,0x73 ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x01 ,0x03 ,0x82 ,0x00 ,0x04 ,0x80 ,0xeb ,0xfb,
        0x0a ,0xc0 ,0x8b ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x01,
        0x0b ,0xc0 ,0x9f ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x0b,
        0x51};
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    dtv.app_tctx = AppLayerGetCtxThread();

    FlowInitConfig(FLOW_QUIET);

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth));

    DetectU16Data *de = SCDetectIpv4FragbitsParse("D");
    FAIL_IF(de == NULL);
    FAIL_IF(de->arg1 != 0x4000);
    FAIL_IF(de->mode != DetectUintModeEqual);

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF(sm == NULL);
    sm->type = DETECT_FRAGBITS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFragBitsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF(ret == 0);

    DetectFragBitsFree(NULL, de);
    SCFree(sm);
    PacketFree(p);

    AppLayerDestroyCtxThread(dtv.app_tctx);
    FlowShutdown();
    PASS;
}

/**
 * \test FragBitsTestParse04 test if DONT FRAG is not set. Must fails.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FragBitsTestParse04 (void)
{
    uint8_t raw_eth[] = {
        0x00 ,0x40 ,0x33 ,0xd9 ,0x7c ,0xfd ,0x00 ,0x00,
        0x39 ,0xcf ,0xd9 ,0xcd ,0x08 ,0x00 ,0x45 ,0x00,
        0x01 ,0x13 ,0x9c ,0x5d ,0x40 ,0x00 ,0xf6 ,0x11,
        0x44 ,0xca ,0x97 ,0xa4 ,0x01 ,0x08 ,0x0a ,0x00,
        0x00 ,0x06 ,0x00 ,0x35 ,0x04 ,0x0b ,0x00 ,0xff,
        0x3c ,0x87 ,0x7d ,0x9e ,0x85 ,0x80 ,0x00 ,0x01,
        0x00 ,0x01 ,0x00 ,0x05 ,0x00 ,0x05 ,0x06 ,0x70,
        0x69 ,0x63 ,0x61 ,0x72 ,0x64 ,0x07 ,0x75 ,0x74,
        0x68 ,0x73 ,0x63 ,0x73 ,0x61 ,0x03 ,0x65 ,0x64,
        0x75 ,0x00 ,0x00 ,0x01 ,0x00 ,0x01 ,0xc0 ,0x0c,
        0x00 ,0x01 ,0x00 ,0x01 ,0x00 ,0x00 ,0x0e ,0x10,
        0x00 ,0x04 ,0x81 ,0x6f ,0x1e ,0x1b ,0x07 ,0x75,
        0x74 ,0x68 ,0x73 ,0x63 ,0x73 ,0x61 ,0x03 ,0x65,
        0x64 ,0x75 ,0x00 ,0x00 ,0x02 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x09 ,0x06 ,0x6b ,0x65,
        0x6e ,0x6f ,0x62 ,0x69 ,0xc0 ,0x34 ,0xc0 ,0x34,
        0x00 ,0x02 ,0x00 ,0x01 ,0x00 ,0x00 ,0x0e ,0x10,
        0x00 ,0x07 ,0x04 ,0x6a ,0x69 ,0x6e ,0x6e ,0xc0,
        0x34 ,0xc0 ,0x34 ,0x00 ,0x02 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x0c ,0x04 ,0x64 ,0x6e,
        0x73 ,0x31 ,0x04 ,0x6e ,0x6a ,0x69 ,0x74 ,0xc0,
        0x3c ,0xc0 ,0x34 ,0x00 ,0x02 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x08 ,0x05 ,0x65 ,0x6c,
        0x7a ,0x69 ,0x70 ,0xc0 ,0x34 ,0xc0 ,0x34 ,0x00,
        0x02 ,0x00 ,0x01 ,0x00 ,0x00 ,0x0e ,0x10 ,0x00,
        0x08 ,0x05 ,0x61 ,0x72 ,0x77 ,0x65 ,0x6e ,0xc0,
        0x34 ,0xc0 ,0x4b ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x1a,
        0x06 ,0xc0 ,0x60 ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x1a,
        0x07 ,0xc0 ,0x73 ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x01 ,0x03 ,0x82 ,0x00 ,0x04 ,0x80 ,0xeb ,0xfb,
        0x0a ,0xc0 ,0x8b ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x01,
        0x0b ,0xc0 ,0x9f ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x0b,
        0x51};
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    dtv.app_tctx = AppLayerGetCtxThread();

    FlowInitConfig(FLOW_QUIET);

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth));

    DetectU16Data *de = SCDetectIpv4FragbitsParse("!D");
    FAIL_IF(de == NULL);
    FAIL_IF(de->arg1 != 0x4000);
    FAIL_IF(de->arg2 != 0x4000);
    FAIL_IF(de->mode != DetectUintModeNegBitmask);

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF(sm == NULL);
    sm->type = DETECT_FRAGBITS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFragBitsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF(ret);
    DetectFragBitsFree(NULL, de);
    SCFree(sm);
    PacketFree(p);

    AppLayerDestroyCtxThread(dtv.app_tctx);
    FlowShutdown();
    PASS;
}

/**
 * \brief this function registers unit tests for FragBits
 */
static void FragBitsRegisterTests(void)
{
    UtRegisterTest("FragBitsTestParse03", FragBitsTestParse03);
    UtRegisterTest("FragBitsTestParse04", FragBitsTestParse04);
}
#endif /* UNITTESTS */
