/*
 * Copyright (C) 2014 ANSSI
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * \author David DIALLO <diallo@et.esiea.fr>
 *
 * Implements the Modbus function and access keywords
 * You can specify a:
 * - concrete function like Modbus:
 *     function 8, subfunction 4 (diagnostic: Force Listen Only Mode)
 * - data (in primary table) register access (r/w) like Modbus:
 *     access read coils, address 1000 (.i.e Read coils: at address 1000)
 * - write data value at specific address Modbus:
 *     access write, address 1500<>2000, value >2000 (Write multiple coils/register:
 *     at address between 1500 and 2000 value greater than 2000)
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-modbus.h"

#include "util-debug.h"
#include "util-byte.h"

#include "stream-tcp.h"
#include "rust.h"

static int g_modbus_buffer_id = 0;

#ifdef UNITTESTS
static void DetectModbusRegisterTests(void);
#endif

/** \internal
 *
 * \brief this function will free memory associated with DetectModbus
 *
 * \param ptr pointer to DetectModbus
 */
static void DetectModbusFree(DetectEngineCtx *de_ctx, void *ptr) {
    SCEnter();
    if (ptr != NULL) {
        rs_modbus_free(ptr);
    }
    SCReturn;
}

/** \internal
 *
 * \brief this function is used to add the parsed "id" option into the current signature
 *
 * \param de_ctx    Pointer to the Detection Engine Context
 * \param s         Pointer to the Current Signature
 * \param str       Pointer to the user provided "id" option
 *
 * \retval 0 on Success or -1 on Failure
 */
static int DetectModbusSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();
    DetectModbusRust *modbus = NULL;
    SigMatch        *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_MODBUS) != 0)
        return -1;

    if ((modbus = rs_modbus_parse(str)) == NULL) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid modbus option");
        goto error;
    }

    /* Okay so far so good, lets get this into a SigMatch and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type    = DETECT_AL_MODBUS;
    sm->ctx     = (void *) modbus;

    SigMatchAppendSMToList(s, sm, g_modbus_buffer_id);

    SCReturnInt(0);

error:
    if (modbus != NULL)
        DetectModbusFree(de_ctx, modbus);
    if (sm != NULL)
        SCFree(sm);
    SCReturnInt(-1);
}

static int DetectModbusMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state,
        void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    return rs_modbus_inspect(txv, (void *)ctx);
}

/** \brief Do the content inspection & validation for a signature
 *
 *  \param de_ctx   Detection engine context
 *  \param det_ctx  Detection engine thread context
 *  \param s        Signature to inspect ( and sm: SigMatch to inspect)
 *  \param f        Flow
 *  \param flags    App layer flags
 *  \param alstate  App layer state
 *  \param txv      Pointer to Modbus Transaction structure
 *
 *  \retval 0 no match or 1 match
 */
static int DetectEngineInspectModbus(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(
            de_ctx, det_ctx, s, engine->smd, f, flags, alstate, txv, tx_id);
}

/**
 * \brief Registration function for Modbus keyword
 */
void DetectModbusRegister(void)
{
    sigmatch_table[DETECT_AL_MODBUS].name = "modbus";
    sigmatch_table[DETECT_AL_MODBUS].desc = "match on various properties of Modbus requests";
    sigmatch_table[DETECT_AL_MODBUS].url = "/rules/modbus-keyword.html#modbus-keyword";
    sigmatch_table[DETECT_AL_MODBUS].Match = NULL;
    sigmatch_table[DETECT_AL_MODBUS].Setup = DetectModbusSetup;
    sigmatch_table[DETECT_AL_MODBUS].Free = DetectModbusFree;
    sigmatch_table[DETECT_AL_MODBUS].AppLayerTxMatch = DetectModbusMatch;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_MODBUS].RegisterTests = DetectModbusRegisterTests;
#endif

    DetectAppLayerInspectEngineRegister2(
            "modbus", ALPROTO_MODBUS, SIG_FLAG_TOSERVER, 0, DetectEngineInspectModbus, NULL);

    g_modbus_buffer_id = DetectBufferTypeGetByName("modbus");
}

#ifdef UNITTESTS /* UNITTESTS */
#include "app-layer-parser.h"

#include "flow-util.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

/**
 * Sample data for tests derived from
 * https://github.com/bro/bro/blob/master/testing/btest/Traces/modbus/modbus.trace
 */
static uint8_t writeSingleCoil[] = {
    /* Transaction ID */ 0x00, 0x01,
    /* Protocol ID */ 0x00, 0x00,
    /* Length */ 0x00, 0x06,
    /* Unit ID */ 0x0a,
    /* Function code */ 0x05,
    /* Read Starting Address */ 0x00, 0x02,
    /* Data */ 0x00, 0x00
};

static uint8_t restartCommOption[] = {
    /* Transaction ID */ 0x00, 0x00,
    /* Protocol ID */ 0x00, 0x00,
    /* Length */ 0x00, 0x06,
    /* Unit ID */ 0x0a,
    /* Function code */ 0x08,
    /* Diagnostic Code */ 0x00, 0x01,
    /* Data */ 0x00, 0x00
};

/** \test Signature containing an access type. */
static int DetectModbusTestAccess(void)
{
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(restartCommOption, sizeof(restartCommOption), IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto = ALPROTO_MODBUS;
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                           "(msg:\"Testing modbus code function\"; "
                                           "modbus: access write; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOSERVER,
            writeSingleCoil, sizeof(writeSingleCoil));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test Signature containing a function. */
static int DetectModbusTestFunction(void)
{
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(writeSingleCoil, sizeof(writeSingleCoil), IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto = ALPROTO_MODBUS;
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                           "(msg:\"Testing modbus code function\"; "
                                           "modbus: function 8; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOSERVER,
            restartCommOption, sizeof(restartCommOption));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectModbus
 */
void DetectModbusRegisterTests(void)
{
    UtRegisterTest("DetectModbusTestAccess", DetectModbusTestAccess);
    UtRegisterTest("DetectModbusTestFunction", DetectModbusTestFunction);
}
#endif /* UNITTESTS */
