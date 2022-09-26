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
 * Implements dce_iface keyword.
 */

#include "suricata-common.h"

#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-dce-iface.h"

#include "rust.h"

#ifdef UNITTESTS
#endif
#define PARSE_REGEX "^\\s*([0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12})(?:\\s*,\\s*(<|>|=|!)([0-9]{1,5}))?(?:\\s*,\\s*(any_frag))?\\s*$"

static DetectParseRegex parse_regex;

static int DetectDceIfaceMatchRust(DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m);
static int DetectDceIfaceSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectDceIfaceFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectDceIfaceRegisterTests(void);
#endif
static int g_dce_generic_list_id = 0;

/**
 * \brief Registers the keyword handlers for the "dce_iface" keyword.
 */
void DetectDceIfaceRegister(void)
{
    sigmatch_table[DETECT_DCE_IFACE].name = "dcerpc.iface";
    sigmatch_table[DETECT_DCE_IFACE].alias = "dce_iface";
    sigmatch_table[DETECT_DCE_IFACE].AppLayerTxMatch = DetectDceIfaceMatchRust;
    sigmatch_table[DETECT_DCE_IFACE].Setup = DetectDceIfaceSetup;
    sigmatch_table[DETECT_DCE_IFACE].Free  = DetectDceIfaceFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_DCE_IFACE].RegisterTests = DetectDceIfaceRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    g_dce_generic_list_id = DetectBufferTypeRegister("dce_generic");

    DetectAppLayerInspectEngineRegister2("dce_generic", ALPROTO_DCERPC, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister2(
            "dce_generic", ALPROTO_SMB, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);

    DetectAppLayerInspectEngineRegister2("dce_generic", ALPROTO_DCERPC, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister2(
            "dce_generic", ALPROTO_SMB, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);
}

/**
 * \brief App layer match function for the "dce_iface" keyword.
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
static int DetectDceIfaceMatchRust(DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    SCEnter();

    if (f->alproto == ALPROTO_DCERPC) {
        // TODO check if state is NULL
        return rs_dcerpc_iface_match(txv, state, (void *)m);
    }

    int ret = 0;

    if (rs_smb_tx_get_dce_iface(f->alstate, txv, (void *)m) != 1) {
        SCLogDebug("rs_smb_tx_get_dce_iface: didn't match");
    } else {
        SCLogDebug("rs_smb_tx_get_dce_iface: matched!");
        ret = 1;
        // TODO validate frag
    }
    SCReturnInt(ret);
}

/**
 * \brief Creates a SigMatch for the "dce_iface" keyword being sent as argument,
 *        and appends it to the Signature(s).
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval 0 on success, -1 on failure.
 */

static int DetectDceIfaceSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    SCEnter();

    if (DetectSignatureSetAppProto(s, ALPROTO_DCERPC) < 0)
        return -1;

    void *did = rs_dcerpc_iface_parse(arg);
    if (did == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Error parsing dce_iface option in "
                   "signature");
        return -1;
    }

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        return -1;
    }

    sm->type = DETECT_DCE_IFACE;
    sm->ctx = did;

    SigMatchAppendSMToList(s, sm, g_dce_generic_list_id);
    return 0;
}

static void DetectDceIfaceFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();
    if (ptr != NULL) {
        rs_dcerpc_iface_free(ptr);
    }
    SCReturn;
}

/************************************Unittests*********************************/

#ifdef UNITTESTS

/* Disabled because of bug_753.  Would be enabled, once we rewrite
 * dce parser */
#if 0

/**
 * \test Test a valid dce_iface entry with a bind, bind_ack and 3 request/responses.
 */
static int DetectDceIfaceTestParse13(void)
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
    memset(&p, 0, sizeof(p));
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

    s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any any "
            "(msg:\"DCERPC\"; dce_iface:338cd001-2244-31f1-aaaa-900038001003,=1,any_frag; sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCLogDebug("chunk 1, bind");

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER | STREAM_START,
                            dcerpc_bind, dcerpc_bind_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        SCLogDebug("no dcerpc state: ");
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        SCLogDebug("sig 1 didn't match after bind request: ");
        goto end;
    }

    SCLogDebug("chunk 2, bind_ack");

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_bindack,
                            dcerpc_bindack_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        SCLogDebug("sig 1 matched again after bind ack: ");
        goto end;
    }

    SCLogDebug("chunk 3, request 1");

    /* request1 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request1,
                            dcerpc_request1_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        SCLogDebug("sig 1 didn't match after request1: ");
        goto end;
    }

    SCLogDebug("sending response1");

    /* response1 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_response1,
                            dcerpc_response1_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        SCLogDebug("sig 1 matched after response1, but shouldn't: ");
        goto end;
    }

    SCLogDebug("sending request2");

    /* request2 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request2,
                            dcerpc_request2_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        SCLogDebug("sig 1 didn't match after request2: ");
        goto end;
    }

    /* response2 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_response2,
                            dcerpc_response2_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        SCLogDebug("sig 1 matched after response2, but shouldn't have: ");
        goto end;
    }

    /* request3 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request3,
                            dcerpc_request3_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        SCLogDebug("sig 1 didn't match after request3: ");
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
        SCLogDebug("sig 1 matched after response3, but shouldn't have: ");
        goto end;
    }

    result = 1;

 end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    UTHFreePackets(&p, 1);
    return result;
}

#endif

static void DetectDceIfaceRegisterTests(void)
{
    /* Disabled because of bug_753.  Would be enabled, once we rewrite
     * dce parser */
#if 0
    UtRegisterTest("DetectDceIfaceTestParse13", DetectDceIfaceTestParse13, 1);
#endif
}
#endif /* UNITTESTS */
