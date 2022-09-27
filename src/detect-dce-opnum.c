/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements dce_opnum keyword
 */

#include "suricata-common.h"

#include "detect-parse.h"

#include "detect-engine.h"

#include "detect-dce-opnum.h"

#include "rust.h"

#ifdef UNITTESTS
#endif
#define PARSE_REGEX "^\\s*([0-9]{1,5}(\\s*-\\s*[0-9]{1,5}\\s*)?)(,\\s*[0-9]{1,5}(\\s*-\\s*[0-9]{1,5})?\\s*)*$"

static DetectParseRegex parse_regex;

static int DetectDceOpnumMatchRust(DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m);
static int DetectDceOpnumSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectDceOpnumFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectDceOpnumRegisterTests(void);
#endif
static int g_dce_generic_list_id = 0;

/**
 * \brief Registers the keyword handlers for the "dce_opnum" keyword.
 */
void DetectDceOpnumRegister(void)
{
    sigmatch_table[DETECT_DCE_OPNUM].name = "dcerpc.opnum";
    sigmatch_table[DETECT_DCE_OPNUM].alias = "dce_opnum";
    sigmatch_table[DETECT_DCE_OPNUM].AppLayerTxMatch = DetectDceOpnumMatchRust;
    sigmatch_table[DETECT_DCE_OPNUM].Setup = DetectDceOpnumSetup;
    sigmatch_table[DETECT_DCE_OPNUM].Free  = DetectDceOpnumFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_DCE_OPNUM].RegisterTests = DetectDceOpnumRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    g_dce_generic_list_id = DetectBufferTypeRegister("dce_generic");
}

/**
 * \brief App layer match function for the "dce_opnum" keyword.
 *
 * \param t       Pointer to the ThreadVars instance.
 * \param det_ctx Pointer to the DetectEngineThreadCtx.
 * \param f       Pointer to the flow.
 * \param flags   Pointer to the flags indicating the flow direction.
 * \param state   Pointer to the app layer state data.
 * \param s       Pointer to the Signature instance.
 * \param m       Pointer to the SigMatch.
 *
 * \retval 1 On Match.
 * \retval 0 On no match.
 */
static int DetectDceOpnumMatchRust(DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    SCEnter();

    if (f->alproto == ALPROTO_DCERPC) {
        return rs_dcerpc_opnum_match(txv, (void *)m);
    }

    if (rs_smb_tx_match_dce_opnum(txv, (void *)m) != 1)
        SCReturnInt(0);

    SCReturnInt(1);
}

/**
 * \brief Creates a SigMatch for the "dce_opnum" keyword being sent as argument,
 *        and appends it to the rs_dcerpc_opnum_matchSignature(s).
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval 0 on success, -1 on failure
 */

static int DetectDceOpnumSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (arg == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Error parsing dce_opnum option in "
                   "signature, option needs a value");
        return -1;
    }

    if (DetectSignatureSetAppProto(s, ALPROTO_DCERPC) < 0)
        return -1;

    void *dod = rs_dcerpc_opnum_parse(arg);
    if (dod == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Error parsing dce_opnum option in "
                   "signature");
        return -1;
    }

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectDceOpnumFree(de_ctx, dod);
        return -1;
    }

    sm->type = DETECT_DCE_OPNUM;
    sm->ctx = (void *)dod;

    SigMatchAppendSMToList(s, sm, g_dce_generic_list_id);
    return 0;
}

static void DetectDceOpnumFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();
    if (ptr != NULL) {
        rs_dcerpc_opnum_free(ptr);
    }
    SCReturn;
}

/************************************Unittests*********************************/

#ifdef UNITTESTS

/* Disabled because of bug_753.  Would be enabled, once we rewrite
 * dce parser */
#if 0

/**
 * \test Test a valid dce_opnum(with multiple values) with a bind, bind_ack,
 *       and multiple request/responses with a match test after each frag parsing.
 */
static int DetectDceOpnumTestParse10(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    DCERPCState *dcerpc_state = NULL;
    int r = 0;

    uint8_t dcerpc_bind[] = {
        0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x01, 0xd0, 0x8c, 0x33, 0x44, 0x22, 0xf1, 0x31,
        0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03,
        0x01, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
        0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
        0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_bindack[] = {
        0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xb8, 0x10, 0xb8, 0x10, 0x65, 0x8e, 0x00, 0x00,
        0x0d, 0x00, 0x5c, 0x50, 0x49, 0x50, 0x45, 0x5c,
        0x77, 0x69, 0x6e, 0x72, 0x65, 0x67, 0x00, 0x6d,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
        0x02, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_request1[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x2c, 0xfd, 0xb5, 0x00, 0x40, 0xaa, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x02,
    };

    uint8_t dcerpc_response1[] = {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf6, 0x72, 0x28, 0x9c,
        0xf0, 0x57, 0xd8, 0x11, 0xb0, 0x05, 0x00, 0x0c,
        0x29, 0x87, 0xea, 0xe9, 0x00, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_request2[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0xa4, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x8c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf6, 0x72, 0x28, 0x9c,
        0xf0, 0x57, 0xd8, 0x11, 0xb0, 0x05, 0x00, 0x0c,
        0x29, 0x87, 0xea, 0xe9, 0x5c, 0x00, 0x5c, 0x00,
        0xa8, 0xb9, 0x14, 0x00, 0x2e, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00,
        0x53, 0x00, 0x4f, 0x00, 0x46, 0x00, 0x54, 0x00,
        0x57, 0x00, 0x41, 0x00, 0x52, 0x00, 0x45, 0x00,
        0x5c, 0x00, 0x4d, 0x00, 0x69, 0x00, 0x63, 0x00,
        0x72, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x6f, 0x00,
        0x66, 0x00, 0x74, 0x00, 0x5c, 0x00, 0x57, 0x00,
        0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00,
        0x77, 0x00, 0x73, 0x00, 0x5c, 0x00, 0x43, 0x00,
        0x75, 0x00, 0x72, 0x00, 0x72, 0x00, 0x65, 0x00,
        0x6e, 0x00, 0x74, 0x00, 0x56, 0x00, 0x65, 0x00,
        0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6f, 0x00,
        0x6e, 0x00, 0x5c, 0x00, 0x52, 0x00, 0x75, 0x00,
        0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_response2[] = {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf7, 0x72, 0x28, 0x9c,
        0xf0, 0x57, 0xd8, 0x11, 0xb0, 0x05, 0x00, 0x0c,
        0x29, 0x87, 0xea, 0xe9, 0x00, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_request3[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x70, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf7, 0x72, 0x28, 0x9c,
        0xf0, 0x57, 0xd8, 0x11, 0xb0, 0x05, 0x00, 0x0c,
        0x29, 0x87, 0xea, 0xe9, 0x0c, 0x00, 0x0c, 0x00,
        0x98, 0xda, 0x14, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x4f, 0x00, 0x73, 0x00, 0x61, 0x00, 0x33, 0x00,
        0x32, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x54, 0x00,
        0x4f, 0x00, 0x53, 0x00, 0x41, 0x00, 0x33, 0x00,
        0x32, 0x00, 0x2e, 0x00, 0x45, 0x00, 0x58, 0x00,
        0x45, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_response3[] = {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    uint32_t dcerpc_bind_len = sizeof(dcerpc_bind);
    uint32_t dcerpc_bindack_len = sizeof(dcerpc_bindack);

    uint32_t dcerpc_request1_len = sizeof(dcerpc_request1);
    uint32_t dcerpc_response1_len = sizeof(dcerpc_response1);

    uint32_t dcerpc_request2_len = sizeof(dcerpc_request2);
    uint32_t dcerpc_response2_len = sizeof(dcerpc_response2);

    uint32_t dcerpc_request3_len = sizeof(dcerpc_request3);
    uint32_t dcerpc_response3_len = sizeof(dcerpc_response3);

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
            "(msg:\"DCERPC\"; dce_opnum:2,15,22; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCLogDebug("sending bind");

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER | STREAM_START,
                            dcerpc_bind, dcerpc_bind_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc bind failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        SCLogDebug("no dcerpc state: ");
        goto end;
    }
    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    SCLogDebug("sending bind_ack");

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT,
                            dcerpc_bindack, dcerpc_bindack_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }
    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    SCLogDebug("sending request1");

    /* request1 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER,
                            dcerpc_request1, dcerpc_request1_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't match, but should have: ");
        goto end;
    }

    SCLogDebug("sending response1");

    /* response1 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT,
                            dcerpc_response1, dcerpc_response1_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 did match, shouldn't have on response1: ");
        goto end;
    }

    /* request2 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER,
                            dcerpc_request2, dcerpc_request2_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't match, but should have on request2: ");
        goto end;
    }

    /* response2 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT,
                            dcerpc_response2, dcerpc_response2_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 did match, shouldn't have on response2: ");
        goto end;
    }

    /* request3 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER,
                            dcerpc_request3, dcerpc_request3_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't match, but should have on request3: ");
        goto end;
    }

    /* response3 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT | STREAM_EOF,
                            dcerpc_response3, dcerpc_response3_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 did match, shouldn't have on response2: ");
        goto end;
    }

    result = 1;

 end:
    if (alp_tctx != NULL)
        AppLayerDestroyCtxThread(alp_tctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test a valid dce_opnum entry(with multiple values) with multiple
 *       request/responses.
 */
static int DetectDceOpnumTestParse11(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    DCERPCState *dcerpc_state = NULL;
    int r = 0;

    uint8_t dcerpc_request1[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x2c, 0xfd, 0xb5, 0x00, 0x40, 0xaa, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x02,
    };

    uint8_t dcerpc_response1[] = {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf6, 0x72, 0x28, 0x9c,
        0xf0, 0x57, 0xd8, 0x11, 0xb0, 0x05, 0x00, 0x0c,
        0x29, 0x87, 0xea, 0xe9, 0x00, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_request2[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0xa4, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x8c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf6, 0x72, 0x28, 0x9c,
        0xf0, 0x57, 0xd8, 0x11, 0xb0, 0x05, 0x00, 0x0c,
        0x29, 0x87, 0xea, 0xe9, 0x5c, 0x00, 0x5c, 0x00,
        0xa8, 0xb9, 0x14, 0x00, 0x2e, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00,
        0x53, 0x00, 0x4f, 0x00, 0x46, 0x00, 0x54, 0x00,
        0x57, 0x00, 0x41, 0x00, 0x52, 0x00, 0x45, 0x00,
        0x5c, 0x00, 0x4d, 0x00, 0x69, 0x00, 0x63, 0x00,
        0x72, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x6f, 0x00,
        0x66, 0x00, 0x74, 0x00, 0x5c, 0x00, 0x57, 0x00,
        0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00,
        0x77, 0x00, 0x73, 0x00, 0x5c, 0x00, 0x43, 0x00,
        0x75, 0x00, 0x72, 0x00, 0x72, 0x00, 0x65, 0x00,
        0x6e, 0x00, 0x74, 0x00, 0x56, 0x00, 0x65, 0x00,
        0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6f, 0x00,
        0x6e, 0x00, 0x5c, 0x00, 0x52, 0x00, 0x75, 0x00,
        0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_response2[] = {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf7, 0x72, 0x28, 0x9c,
        0xf0, 0x57, 0xd8, 0x11, 0xb0, 0x05, 0x00, 0x0c,
        0x29, 0x87, 0xea, 0xe9, 0x00, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_request3[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x70, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf7, 0x72, 0x28, 0x9c,
        0xf0, 0x57, 0xd8, 0x11, 0xb0, 0x05, 0x00, 0x0c,
        0x29, 0x87, 0xea, 0xe9, 0x0c, 0x00, 0x0c, 0x00,
        0x98, 0xda, 0x14, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x4f, 0x00, 0x73, 0x00, 0x61, 0x00, 0x33, 0x00,
        0x32, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x54, 0x00,
        0x4f, 0x00, 0x53, 0x00, 0x41, 0x00, 0x33, 0x00,
        0x32, 0x00, 0x2e, 0x00, 0x45, 0x00, 0x58, 0x00,
        0x45, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_response3[] = {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    uint32_t dcerpc_request1_len = sizeof(dcerpc_request1);
    uint32_t dcerpc_response1_len = sizeof(dcerpc_response1);

    uint32_t dcerpc_request2_len = sizeof(dcerpc_request2);
    uint32_t dcerpc_response2_len = sizeof(dcerpc_response2);

    uint32_t dcerpc_request3_len = sizeof(dcerpc_request3);
    uint32_t dcerpc_response3_len = sizeof(dcerpc_response3);

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,
                                   "alert tcp any any -> any any "
                                   "(msg:\"DCERPC\"; "
                                   "dce_opnum:2-22; "
                                   "sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* request1 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER | STREAM_START,
                            dcerpc_request1, dcerpc_request1_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        printf("AppLayerParse for dcerpcrequest1 failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        SCLogDebug("no dcerpc state: ");
        printf("no dcerpc state: ");
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1))
        goto end;

    /* response1 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT,
                            dcerpc_response1, dcerpc_response1_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        printf("AppLayerParse for dcerpcresponse1 failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1))
        goto end;

    /* request2 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER,
                            dcerpc_request2, dcerpc_request2_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        printf("AppLayerParse for dcerpcrequest2 failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1))
        goto end;

    /* response2 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT,
                            dcerpc_response2, dcerpc_response2_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        printf("AppLayerParse for dcerpcresponse2 failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1))
        goto end;

    /* request3 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER,
                            dcerpc_request3, dcerpc_request3_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        printf("AppLayerParse for dcerpc request3 failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1))
        goto end;

    /* response3 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT | STREAM_EOF,
                            dcerpc_response3, dcerpc_response3_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        printf("AppLayerParse for dcerpc response3 failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1))
        goto end;

    result = 1;

 end:
    if (alp_tctx != NULL)
        AppLayerDestroyCtxThread(alp_tctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test a valid dce_opnum(with multiple values) with a bind, bind_ack,
 *       and multiple request/responses with a match test after each frag parsing.
 */
static int DetectDceOpnumTestParse12(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    DCERPCState *dcerpc_state = NULL;
    int r = 0;

    uint8_t dcerpc_bind[] = {
        0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xd0, 0x16, 0xd0, 0x16, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x40, 0xfd, 0x2c, 0x34, 0x6c, 0x3c, 0xce, 0x11,
        0xa8, 0x93, 0x08, 0x00, 0x2b, 0x2e, 0x9c, 0x6d,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
        0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
        0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_bindack[] = {
        0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xb8, 0x10, 0xb8, 0x10, 0x7d, 0xd8, 0x00, 0x00,
        0x0d, 0x00, 0x5c, 0x70, 0x69, 0x70, 0x65, 0x5c,
        0x6c, 0x6c, 0x73, 0x72, 0x70, 0x63, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
        0x02, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_request1[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x9a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, //opnum is 0x28 0x00
        0x00, 0x00, 0x00, 0x00, 0x07, 0x9f, 0x13, 0xd9,
        0x2d, 0x97, 0xf4, 0x4a, 0xac, 0xc2, 0xbc, 0x70,
        0xec, 0xaa, 0x9a, 0xd3, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x40, 0x80, 0x40, 0x00,
        0x44, 0x80, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x4d, 0x6f, 0x00, 0x4e,
        0x61, 0x6d, 0x65, 0x00, 0x35, 0x39, 0x31, 0x63,
        0x64, 0x30, 0x35, 0x38, 0x00, 0x00, 0x00, 0x00,
        0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x17, 0x00, 0x00, 0x00, 0xd0, 0x2e, 0x08, 0x00,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x00, 0x00
    };

    uint8_t dcerpc_response1[] = {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_request2[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x54, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x9f, 0x13, 0xd9,
        0x2d, 0x97, 0xf4, 0x4a, 0xac, 0xc2, 0xbc, 0x70,
        0xec, 0xaa, 0x9a, 0xd3, 0x09, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x4d, 0x6f, 0x00, 0x4e, 0x61, 0x6d, 0x65, 0x00,
        0x35, 0x39, 0x31, 0x63, 0x64, 0x30, 0x35, 0x38,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x4e, 0x6f, 0x6e, 0x65
    };

    uint8_t dcerpc_response2[] = {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x8c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xd8, 0x17, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x58, 0x1d, 0x08, 0x00, 0xe8, 0x32, 0x08, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x4d, 0x6f, 0x00, 0x4e, 0x61, 0x6d, 0x65, 0x00,
        0x35, 0x39, 0x31, 0x63, 0x64, 0x30, 0x35, 0x38,
        0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
        0xd0, 0x2e, 0x08, 0x00, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    uint32_t dcerpc_bind_len = sizeof(dcerpc_bind);
    uint32_t dcerpc_bindack_len = sizeof(dcerpc_bindack);

    uint32_t dcerpc_request1_len = sizeof(dcerpc_request1);
    uint32_t dcerpc_response1_len = sizeof(dcerpc_response1);

    uint32_t dcerpc_request2_len = sizeof(dcerpc_request2);
    uint32_t dcerpc_response2_len = sizeof(dcerpc_response2);

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
            "(msg:\"DCERPC\"; dce_opnum:30, 40; sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER | STREAM_START,
                            dcerpc_bind, dcerpc_bind_len);
    if (r != 0) {
        printf("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }
    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        printf("no dcerpc state: ");
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_bindack,
                            dcerpc_bindack_len);
    if (r != 0) {
        printf("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }
    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    /* request1 */
    SCLogDebug("Sending request1");

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request1,
                            dcerpc_request1_len);
    if (r != 0) {
        printf("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        printf("no dcerpc state: ");
        goto end;
    }

    if (dcerpc_state->dcerpc.dcerpcrequest.opnum != 40) {
        printf("dcerpc state holding invalid opnum.  Holding %d, while we are "
               "expecting 40: ", dcerpc_state->dcerpc.dcerpcrequest.opnum);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("signature 1 didn't match, should have: ");
        goto end;
    }

    /* response1 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_response1,
                            dcerpc_response1_len);
    if (r != 0) {
        printf("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        printf("no dcerpc state: ");
        goto end;
    }

    if (dcerpc_state->dcerpc.dcerpcrequest.opnum != 40) {
        printf("dcerpc state holding invalid opnum.  Holding %d, while we are "
               "expecting 40\n", dcerpc_state->dcerpc.dcerpcrequest.opnum);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched on response 1, but shouldn't: ");
        goto end;
    }

    /* request2 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request2,
                            dcerpc_request2_len);
    if (r != 0) {
        printf("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        printf("no dcerpc state: ");
        goto end;
    }

    if (dcerpc_state->dcerpc.dcerpcrequest.opnum != 30) {
        printf("dcerpc state holding invalid opnum.  Holding %d, while we are "
               "expecting 30\n", dcerpc_state->dcerpc.dcerpcrequest.opnum);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't match on request 2: ");
        goto end;
    }

    /* response2 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT | STREAM_EOF, dcerpc_response2,
                            dcerpc_response2_len);
    if (r != 0) {
        printf("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        printf("no dcerpc state: ");
        goto end;
    }

    if (dcerpc_state->dcerpc.dcerpcrequest.opnum != 30) {
        printf("dcerpc state holding invalid opnum.  Holding %d, while we are "
               "expecting 30\n", dcerpc_state->dcerpc.dcerpcrequest.opnum);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched on response2, but shouldn't: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerDestroyCtxThread(alp_tctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test a valid dce_opnum(with multiple values) with a bind, bind_ack,
 *       and multiple request/responses with a match test after each frag parsing.
 */
static int DetectDceOpnumTestParse13(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    DCERPCState *dcerpc_state = NULL;
    int r = 0;

    uint8_t dcerpc_request1[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x9a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x9f, 0x13, 0xd9,
        0x2d, 0x97, 0xf4, 0x4a, 0xac, 0xc2, 0xbc, 0x70,
        0xec, 0xaa, 0x9a, 0xd3, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x40, 0x80, 0x40, 0x00,
        0x44, 0x80, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x00, 0x00, 0x4d, 0x6f, 0x00, 0x4e,
        0x61, 0x6d, 0x65, 0x00, 0x35, 0x39, 0x31, 0x63,
        0x64, 0x30, 0x35, 0x38, 0x00, 0x00, 0x00, 0x00,
        0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x17, 0x00, 0x00, 0x00, 0xd0, 0x2e, 0x08, 0x00,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x00, 0x00
    };

    uint8_t dcerpc_response1[] = {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_request2[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x54, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x9f, 0x13, 0xd9,
        0x2d, 0x97, 0xf4, 0x4a, 0xac, 0xc2, 0xbc, 0x70,
        0xec, 0xaa, 0x9a, 0xd3, 0x09, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x4d, 0x6f, 0x00, 0x4e, 0x61, 0x6d, 0x65, 0x00,
        0x35, 0x39, 0x31, 0x63, 0x64, 0x30, 0x35, 0x38,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x4e, 0x6f, 0x6e, 0x65
    };

    uint8_t dcerpc_response2[] = {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x8c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xd8, 0x17, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x58, 0x1d, 0x08, 0x00, 0xe8, 0x32, 0x08, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
        0x4d, 0x6f, 0x00, 0x4e, 0x61, 0x6d, 0x65, 0x00,
        0x35, 0x39, 0x31, 0x63, 0x64, 0x30, 0x35, 0x38,
        0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00,
        0xd0, 0x2e, 0x08, 0x00, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    uint32_t dcerpc_request1_len = sizeof(dcerpc_request1);
    uint32_t dcerpc_response1_len = sizeof(dcerpc_response1);

    uint32_t dcerpc_request2_len = sizeof(dcerpc_request2);
    uint32_t dcerpc_response2_len = sizeof(dcerpc_response2);

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,
                                   "alert tcp any any -> any any "
                                   "(msg:\"DCERPC\"; "
                                   "dce_opnum:30, 40; "
                                   "sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* request1 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request1,
                            dcerpc_request1_len);
    if (r != 0) {
        printf("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        printf("no dcerpc state: ");
        goto end;
    }

    if (dcerpc_state->dcerpc.dcerpcrequest.opnum != 40) {
        printf("dcerpc state holding invalid opnum after request1.  Holding %d, while we are "
               "expecting 40\n", dcerpc_state->dcerpc.dcerpcrequest.opnum);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1))
        goto end;

    /* response1 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_response1,
                            dcerpc_response1_len);
    if (r != 0) {
        printf("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        printf("no dcerpc state: ");
        goto end;
    }

    if (dcerpc_state->dcerpc.dcerpcrequest.opnum != 40) {
        printf("dcerpc state holding invalid opnum after response1.  Holding %d, while we are "
               "expecting 40\n", dcerpc_state->dcerpc.dcerpcrequest.opnum);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1))
        goto end;

    /* request2 */
    printf("Sending Request2\n");
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request2,
                            dcerpc_request2_len);
    if (r != 0) {
        printf("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        printf("no dcerpc state: ");
        goto end;
    }

    if (dcerpc_state->dcerpc.dcerpcrequest.opnum != 30) {
        printf("dcerpc state holding invalid opnum after request2.  Holding %d, while we are "
               "expecting 30\n", dcerpc_state->dcerpc.dcerpcrequest.opnum);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1))
        goto end;

    /* response2 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT | STREAM_EOF, dcerpc_response2,
                            dcerpc_response2_len);
    if (r != 0) {
        printf("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        printf("no dcerpc state: ");
        goto end;
    }

    if (dcerpc_state->dcerpc.dcerpcrequest.opnum != 30) {
        printf("dcerpc state holding invalid opnum after response2.  Holding %d, while we are "
               "expecting 30\n", dcerpc_state->dcerpc.dcerpcrequest.opnum);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1))
        goto end;

    result = 1;

 end:
    if (alp_tctx != NULL)
        AppLayerDestroyCtxThread(alp_tctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);
    return result;
}
#endif

static void DetectDceOpnumRegisterTests(void)
{
    /* Disabled because of bug_753.  Would be enabled, once we rewrite
     * dce parser */
#if 0
    UtRegisterTest("DetectDceOpnumTestParse10", DetectDceOpnumTestParse10, 1);
    UtRegisterTest("DetectDceOpnumTestParse11", DetectDceOpnumTestParse11, 1);
    UtRegisterTest("DetectDceOpnumTestParse12", DetectDceOpnumTestParse12, 1);
    UtRegisterTest("DetectDceOpnumTestParse13", DetectDceOpnumTestParse13, 1);
#endif
}
#endif /* UNITTESTS */
