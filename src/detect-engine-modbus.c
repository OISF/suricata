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

/** \file
 *
 *  \author David DIALLO <diallo@et.esiea.fr>
 *
 *  Based on detect-engine-dns.c
 */

#include "suricata-common.h"

#include "app-layer.h"

#include "detect.h"
#include "detect-modbus.h"

#include "detect-engine-modbus.h"

#include "flow.h"

#include "util-debug.h"

#ifdef UNITTESTS /* UNITTESTS */
#include "app-layer-parser.h"

#include "detect-parse.h"

#include "detect-engine.h"

#include "flow-util.h"

#include "stream-tcp.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

/* Modbus Application Protocol Specification V1.1b3 6.1: Read Coils */
/* Example of a request to read discrete outputs 20-38 */
static uint8_t readCoilsReq[] = {/* Transaction ID */    0x00, 0x00,
                                 /* Protocol ID */       0x00, 0x00,
                                 /* Length */            0x00, 0x06,
                                 /* Unit ID */           0x0a,
                                 /* Function code */     0x01,
                                 /* Starting Address */  0x78, 0x90,
                                 /* Quantity of coils */ 0x00, 0x13 };

/* Modbus Application Protocol Specification V1.1b3 6.4: Read Input Registers */
/* Example of a request to read input register 9 */
static uint8_t readInputsRegistersReq[] = {/* Transaction ID */          0x00, 0x0A,
                                           /* Protocol ID */             0x00, 0x00,
                                           /* Length */                  0x00, 0x06,
                                           /* Unit ID */                 0x00,
                                           /* Function code */           0x04,
                                           /* Starting Address */        0x00, 0x08,
                                           /* Quantity of Registers */   0x00, 0x60};

/* Modbus Application Protocol Specification V1.1b3 6.17: Read/Write Multiple registers */
/* Example of a request to read six registers starting at register 4, */
/* and to write three registers starting at register 15 */
static uint8_t readWriteMultipleRegistersReq[] = {/* Transaction ID */          0x12, 0x34,
                                                  /* Protocol ID */             0x00, 0x00,
                                                  /* Length */                  0x00, 0x11,
                                                  /* Unit ID */                 0x0a,
                                                  /* Function code */           0x17,
                                                  /* Read Starting Address */   0x00, 0x03,
                                                  /* Quantity to Read */        0x00, 0x06,
                                                  /* Write Starting Address */  0x00, 0x0E,
                                                  /* Quantity to Write */       0x00, 0x03,
                                                  /* Write Byte count */        0x06,
                                                  /* Write Registers Value */   0x12, 0x34, /* 15 */
                                                                                0x56, 0x78, /* 16 */
                                                                                0x9A, 0xBC};/* 17 */

/* Modbus Application Protocol Specification V1.1b3 6.8.1: 04 Force Listen Only Mode */
/* Example of a request to to remote device to its Listen Only MOde for Modbus Communications. */
static uint8_t forceListenOnlyMode[] = {/* Transaction ID */     0x0A, 0x00,
                                        /* Protocol ID */        0x00, 0x00,
                                        /* Length */             0x00, 0x06,
                                        /* Unit ID */            0x00,
                                        /* Function code */      0x08,
                                        /* Sub-function code */  0x00, 0x04,
                                        /* Data */               0x00, 0x00};

/* Modbus Application Protocol Specification V1.1b3 Annex A */
/* Modbus Reserved Function codes, Subcodes and MEI types */
static uint8_t encapsulatedInterfaceTransport[] = {
                                        /* Transaction ID */     0x00, 0x10,
                                        /* Protocol ID */        0x00, 0x00,
                                        /* Length */             0x00, 0x05,
                                        /* Unit ID */            0x00,
                                        /* Function code */      0x2B,
                                        /* MEI Type */           0x0F,
                                        /* Data */               0x00, 0x00};

static uint8_t unassigned[] = {
    /* Transaction ID */ 0x00, 0x0A,
    /* Protocol ID */ 0x00, 0x00,
    /* Length */ 0x00, 0x02,
    /* Unit ID */ 0x00,
    /* Function code */ 0x3F
};

/** \test Test code function. */
static int DetectEngineInspectModbusTest01(void)
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

    p = UTHBuildPacket(readCoilsReq, sizeof(readCoilsReq), IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                            "(msg:\"Testing modbus code function\"; "
                                            "modbus: function 23; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                readWriteMultipleRegistersReq,
                                sizeof(readWriteMultipleRegistersReq));
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

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test code function and code subfunction. */
static int DetectEngineInspectModbusTest02(void)
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

    p = UTHBuildPacket(readCoilsReq, sizeof(readCoilsReq), IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                           "(msg:\"Testing modbus function and subfunction\"; "
                                           "modbus: function 8, subfunction 4;  sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, forceListenOnlyMode,
                                sizeof(forceListenOnlyMode));
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

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test function category. */
static int DetectEngineInspectModbusTest03(void)
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

    p = UTHBuildPacket(readCoilsReq, sizeof(readCoilsReq), IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                           "(msg:\"Testing modbus category function\"; "
                                           "modbus: function reserved;  sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                encapsulatedInterfaceTransport,
                                sizeof(encapsulatedInterfaceTransport));
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

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test negative function category. */
static int DetectEngineInspectModbusTest04(void)
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

    p = UTHBuildPacket(readCoilsReq, sizeof(readCoilsReq), IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus category function\"; "
                                       "modbus: function !assigned;  sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, unassigned,
                                sizeof(unassigned));
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

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test access type. */
static int DetectEngineInspectModbusTest05(void)
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

    p = UTHBuildPacket(readCoilsReq, sizeof(readCoilsReq), IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                           "(msg:\"Testing modbus access type\"; "
                                           "modbus: access read;  sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, readCoilsReq,
                                sizeof(readCoilsReq));
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

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test access function. */
static int DetectEngineInspectModbusTest06(void)
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

    p = UTHBuildPacket(readCoilsReq, sizeof(readCoilsReq), IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                           "(msg:\"Testing modbus access type\"; "
                                           "modbus: access read input;  sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, readInputsRegistersReq,
                                sizeof(readInputsRegistersReq));
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

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test read access at an address. */
static int DetectEngineInspectModbusTest07(void)
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

    p = UTHBuildPacket(readCoilsReq, sizeof(readCoilsReq), IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                           "(msg:\"Testing modbus address access\"; "
                                           "modbus: access read, address 30870;  sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, readCoilsReq,
                                sizeof(readCoilsReq));
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

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test read access at a range of address. */
static int DetectEngineInspectModbusTest08(void)
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

    p = UTHBuildPacket(readCoilsReq, sizeof(readCoilsReq), IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    /* readInputsRegistersReq, Starting Address = 0x08, Quantity of Registers = 0x60 */
    /* Read access address from 9 to 104 */
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus access\"; "
                                      "modbus: access read input, "
                                      "address <9;  sid:1;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus access\"; "
                                      "modbus: access read input, "
                                      "address 9;  sid:2;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus access\"; "
                                      "modbus: access read input, "
                                      "address 5<>9;  sid:3;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus access\"; "
                                      "modbus: access read input, "
                                      "address <10;  sid:4;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus access\"; "
                                      "modbus: access read input, "
                                      "address 5<>10;  sid:5;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus access\"; "
                                      "modbus: access read input, "
                                      "address >103;  sid:6;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus access\"; "
                                      "modbus: access read input, "
                                      "address 103<>110;  sid:7;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus access\"; "
                                      "modbus: access read input, "
                                      "address 104;  sid:8;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus access\"; "
                                      "modbus: access read input, "
                                      "address >104;  sid:9;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus access\"; "
                                      "modbus: access read input, "
                                      "address 104<>110;  sid:10;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, readInputsRegistersReq,
                                sizeof(readInputsRegistersReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1));
    FAIL_IF(PacketAlertCheck(p, 3));
    FAIL_IF(PacketAlertCheck(p, 9));
    FAIL_IF(PacketAlertCheck(p, 10));

    FAIL_IF_NOT(PacketAlertCheck(p, 2));
    FAIL_IF_NOT(PacketAlertCheck(p, 4));
    FAIL_IF_NOT(PacketAlertCheck(p, 5));
    FAIL_IF_NOT(PacketAlertCheck(p, 6));
    FAIL_IF_NOT(PacketAlertCheck(p, 7));
    FAIL_IF_NOT(PacketAlertCheck(p, 8));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test write access at a address in a range of value. */
static int DetectEngineInspectModbusTest09(void)
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

    p = UTHBuildPacket(readCoilsReq, sizeof(readCoilsReq), IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    /* readWriteMultipleRegistersReq, Write Starting Address = 0x0E, Quantity to Write = 0x03 */
    /* Write access register address 15 = 0x1234 (4660)     */
    /* Write access register address 16 = 0x5678 (22136)    */
    /* Write access register address 17 = 0x9ABC (39612)    */
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus write access\"; "
                                      "modbus: access write holding, "
                                      "address 15, value <4660;  sid:1;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus write access\"; "
                                      "modbus: access write holding, "
                                      "address 16, value <22137;  sid:2;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus write access\"; "
                                      "modbus: access write holding, "
                                      "address 17, value 39612;  sid:3;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus write access\"; "
                                      "modbus: access write holding, "
                                      "address 15, value 4661;  sid:4;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus write access\"; "
                                      "modbus: access write holding, "
                                      "address 16, value 20000<>22136;  sid:5;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus write access\"; "
                                      "modbus: access write holding, "
                                      "address 17, value 30000<>39613;  sid:6;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus write access\"; "
                                      "modbus: access write holding, "
                                      "address 15, value 4659<>5000;  sid:7;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus write access\"; "
                                      "modbus: access write holding, "
                                      "address 16, value 22136<>30000;  sid:8;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus write access\"; "
                                      "modbus: access write holding, "
                                      "address 17, value >39611;  sid:9;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Testing modbus write access\"; "
                                      "modbus: access write holding, "
                                      "address 15, value >4660;  sid:10;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                readWriteMultipleRegistersReq,
                                sizeof(readWriteMultipleRegistersReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1));
    FAIL_IF(PacketAlertCheck(p, 4));
    FAIL_IF(PacketAlertCheck(p, 5));
    FAIL_IF(PacketAlertCheck(p, 8));
    FAIL_IF(PacketAlertCheck(p, 10));

    FAIL_IF_NOT(PacketAlertCheck(p, 2));
    FAIL_IF_NOT(PacketAlertCheck(p, 3));
    FAIL_IF_NOT(PacketAlertCheck(p, 6));
    FAIL_IF_NOT(PacketAlertCheck(p, 7));
    FAIL_IF_NOT(PacketAlertCheck(p, 9));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test Test code unit_id. */
static int DetectEngineInspectModbusTest10(void)
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

    p = UTHBuildPacket(readWriteMultipleRegistersReq,
                       sizeof(readWriteMultipleRegistersReq),
                       IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    /* readWriteMultipleRegistersReq, Write Starting Address = 0x0E, Quantity to Write = 0x03 */
    /* Unit ID                          = 0x0a (10)         */
    /* Function code                    = 0x17 (23)         */
    /* Write access register address 15 = 0x1234 (4660)     */
    /* Write access register address 16 = 0x5678 (22136)    */
    /* Write access register address 17 = 0x9ABC (39612)    */
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit 10; sid:1;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit 12; sid:2;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit 5<>15; sid:3;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit 5<>9; sid:4;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit 11<>15; sid:5;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit >9; sid:6;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit >11; sid:7;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit <11; sid:8;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit <9; sid:9;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                readWriteMultipleRegistersReq,
                                sizeof(readWriteMultipleRegistersReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 2));
    FAIL_IF(PacketAlertCheck(p, 4));
    FAIL_IF(PacketAlertCheck(p, 5));
    FAIL_IF(PacketAlertCheck(p, 7));
    FAIL_IF(PacketAlertCheck(p, 9));

    FAIL_IF_NOT(PacketAlertCheck(p, 1));
    FAIL_IF_NOT(PacketAlertCheck(p, 3));
    FAIL_IF_NOT(PacketAlertCheck(p, 6));
    FAIL_IF_NOT(PacketAlertCheck(p, 8));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test Test code unit_id and code function. */
static int DetectEngineInspectModbusTest11(void)
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

    p = UTHBuildPacket(readWriteMultipleRegistersReq,
                       sizeof(readWriteMultipleRegistersReq),
                       IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    /* readWriteMultipleRegistersReq, Write Starting Address = 0x0E, Quantity to Write = 0x03 */
    /* Unit ID                          = 0x0a (10)         */
    /* Function code                    = 0x17 (23)         */
    /* Write access register address 15 = 0x1234 (4660)     */
    /* Write access register address 16 = 0x5678 (22136)    */
    /* Write access register address 17 = 0x9ABC (39612)    */
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit 10, function 20; sid:1;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit 10, function 23; sid:2;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit 11, function 20; sid:3;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit 11, function 23; sid:4;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit 10, function public; sid:5;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit 11, function public; sid:6;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit 10, function user; sid:7;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus code unit_id\"; "
                              "modbus: unit 10, function !user; sid:8;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                readWriteMultipleRegistersReq,
                                sizeof(readWriteMultipleRegistersReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1));
    FAIL_IF(PacketAlertCheck(p, 3));
    FAIL_IF(PacketAlertCheck(p, 4));
    FAIL_IF(PacketAlertCheck(p, 6));
    FAIL_IF(PacketAlertCheck(p, 7));

    FAIL_IF_NOT(PacketAlertCheck(p, 2));
    FAIL_IF_NOT(PacketAlertCheck(p, 5));
    FAIL_IF_NOT(PacketAlertCheck(p, 8));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test unit_id and read access at an address. */
static int DetectEngineInspectModbusTest12(void)
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

    p = UTHBuildPacket(readCoilsReq, sizeof(readCoilsReq), IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    /* readCoilsReq, Read coils Starting Address = 0x7890 (30864), Quantity of coils = 0x13 (19) */
    /* Unit ID              = 0x0a (10) */
    /* Function code        = 0x01 (01) */
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus address access\"; "
                              "modbus: unit 10, access read, address 30870;  sid:1;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus address access\"; "
                              "modbus: unit 10, access read, address 30863;  sid:2;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus address access\"; "
                              "modbus: unit 11, access read, address 30870;  sid:3;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus address access\"; "
                              "modbus: unit 11, access read, address 30863;  sid:4;)");

    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                              "(msg:\"Testing modbus address access\"; "
                              "modbus: unit 10, access write;  sid:5;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, readCoilsReq,
                                sizeof(readCoilsReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 2));
    FAIL_IF(PacketAlertCheck(p, 3));
    FAIL_IF(PacketAlertCheck(p, 4));
    FAIL_IF(PacketAlertCheck(p, 5));

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}
#endif /* UNITTESTS */

void DetectEngineInspectModbusRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectEngineInspectModbusTest01 - Code function",
                   DetectEngineInspectModbusTest01);
    UtRegisterTest("DetectEngineInspectModbusTest02 - code function and code subfunction",
                   DetectEngineInspectModbusTest02);
    UtRegisterTest("DetectEngineInspectModbusTest03 - Function category",
                   DetectEngineInspectModbusTest03);
    UtRegisterTest("DetectEngineInspectModbusTest04 - Negative function category",
                   DetectEngineInspectModbusTest04);
    UtRegisterTest("DetectEngineInspectModbusTest05 - Access type",
                   DetectEngineInspectModbusTest05);
    UtRegisterTest("DetectEngineInspectModbusTest06 - Access function",
                   DetectEngineInspectModbusTest06);
    UtRegisterTest("DetectEngineInspectModbusTest07 - Read access at an address",
                   DetectEngineInspectModbusTest07);
    UtRegisterTest("DetectEngineInspectModbusTest08 - Read access at a range of address",
                   DetectEngineInspectModbusTest08);
    UtRegisterTest("DetectEngineInspectModbusTest09 - Write access at an address a range of value",
                   DetectEngineInspectModbusTest09);
    UtRegisterTest("DetectEngineInspectModbusTest10 - Code unit_id",
                   DetectEngineInspectModbusTest10);
    UtRegisterTest("DetectEngineInspectModbusTest11 - Code unit_id and code function",
                   DetectEngineInspectModbusTest11);
    UtRegisterTest("DetectEngineInspectModbusTest12 - Code unit_id and acces function",
                   DetectEngineInspectModbusTest12);
#endif /* UNITTESTS */
    return;
}
