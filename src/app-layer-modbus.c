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
 * App-layer parser for Modbus protocol
 *
 */

#include "suricata-common.h"

#include "util-debug.h"

#include "app-layer-parser.h"
#include "app-layer-modbus.h"

void ModbusParserRegisterTests(void);

/**
 * \brief Function to register the Modbus protocol parser
 */
void RegisterModbusParsers(void)
{
    rs_modbus_register_parser();
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_MODBUS, ModbusParserRegisterTests);
#endif

    SCReturn;
}

/* UNITTESTS */
#ifdef UNITTESTS
#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"

#include "flow-util.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"

#include "rust.h"

/* Modbus default stream reassembly depth */
#define MODBUS_CONFIG_DEFAULT_STREAM_DEPTH 0

/* Modbus Application Protocol Specification V1.1b3 6.1: Read Coils */
static uint8_t invalidFunctionCode[] = {
    /* Transaction ID */ 0x00, 0x00,
    /* Protocol ID */ 0x00, 0x00,
    /* Length */ 0x00, 0x02,
    /* Unit ID */ 0x00,
    /* Function code */ 0x00
};

/* Modbus Application Protocol Specification V1.1b3 6.1: Read Coils */
/* Example of a request to read discrete outputs 20-38 */
static uint8_t readCoilsReq[] = {/* Transaction ID */    0x00, 0x00,
                                 /* Protocol ID */       0x00, 0x00,
                                 /* Length */            0x00, 0x06,
                                 /* Unit ID */           0x00,
                                 /* Function code */     0x01,
                                 /* Starting Address */  0x78, 0x90,
                                 /* Quantity of coils */ 0x00, 0x13 };

static uint8_t readCoilsRsp[] = {/* Transaction ID */    0x00, 0x00,
                                 /* Protocol ID */       0x00, 0x00,
                                 /* Length */            0x00, 0x06,
                                 /* Unit ID */           0x00,
                                 /* Function code */     0x01,
                                 /* Byte count */        0x03,
                                 /* Coil Status */       0xCD, 0x6B, 0x05 };

static uint8_t readCoilsErrorRsp[] = {
    /* Transaction ID */ 0x00, 0x00,
    /* Protocol ID */ 0x00, 0x00,
    /* Length */ 0x00, 0x03,
    /* Unit ID */ 0x00,
    /* Function code */ 0x81,
    /* Invalid Exception code: should trigger the InvalidExceptionCode ModbusEvent */
    0xFF
};

/* Modbus Application Protocol Specification V1.1b3 6.6: Write Single register */
/* Example of a request to write register 2 to 00 03 hex */
static uint8_t writeSingleRegisterReq[] = {/* Transaction ID */     0x00, 0x0A,
                                           /* Protocol ID */        0x00, 0x00,
                                           /* Length */             0x00, 0x06,
                                           /* Unit ID */            0x00,
                                           /* Function code */      0x06,
                                           /* Register Address */   0x00, 0x01,
                                           /* Register Value */     0x00, 0x03};

static uint8_t invalidWriteSingleRegisterReq[] = {/* Transaction ID */      0x00, 0x0A,
                                                  /* Protocol ID */         0x00, 0x00,
                                                  /* Length */              0x00, 0x04,
                                                  /* Unit ID */             0x00,
                                                  /* Function code */       0x06,
                                                  /* Register Address */    0x00, 0x01};

static uint8_t writeSingleRegisterRsp[] = {/* Transaction ID */         0x00, 0x0A,
                                           /* Protocol ID */            0x00, 0x00,
                                           /* Length */                 0x00, 0x06,
                                           /* Unit ID */                0x00,
                                           /* Function code */          0x06,
                                           /* Register Address */       0x00, 0x01,
                                           /* Register Value */         0x00, 0x03};

/* Modbus Application Protocol Specification V1.1b3 6.12: Write Multiple registers */
/* Example of a request to write two registers starting at 2 to 00 0A and 01 02 hex */
static uint8_t writeMultipleRegistersReq[] = {/* Transaction ID */          0x00, 0x0A,
                                              /* Protocol ID */             0x00, 0x00,
                                              /* Length */                  0x00, 0x0B,
                                              /* Unit ID */                 0x00,
                                              /* Function code */           0x10,
                                              /* Starting Address */        0x00, 0x01,
                                              /* Quantity of Registers */   0x00, 0x02,
                                              /* Byte count */              0x04,
                                              /* Registers Value */         0x00, 0x0A,
                                                                            0x01, 0x02};

static uint8_t writeMultipleRegistersRsp[] = {/* Transaction ID */          0x00, 0x0A,
                                              /* Protocol ID */             0x00, 0x00,
                                              /* Length */                  0x00, 0x06,
                                              /* Unit ID */                 0x00,
                                              /* Function code */           0x10,
                                              /* Starting Address */        0x00, 0x01,
                                              /* Quantity of Registers */   0x00, 0x02};

/* Modbus Application Protocol Specification V1.1b3 6.16: Mask Write Register */
/* Example of a request to mask write to register 5 */
static uint8_t maskWriteRegisterReq[] = {/* Transaction ID */       0x00, 0x0A,
                                         /* Protocol ID */          0x00, 0x00,
                                         /* Length */               0x00, 0x08,
                                         /* Unit ID */              0x00,
                                         /* Function code */        0x16,
                                         /* Reference Address */    0x00, 0x04,
                                         /* And_Mask */             0x00, 0xF2,
                                         /* Or_Mask */              0x00, 0x25};

static uint8_t invalidMaskWriteRegisterReq[] = {/* Transaction ID */    0x00, 0x0A,
                                                /* Protocol ID */       0x00, 0x00,
                                                /* Length */            0x00, 0x06,
                                                /* Unit ID */           0x00,
                                                /* Function code */     0x16,
                                                /* Reference Address */ 0x00, 0x04,
                                                /* And_Mask */          0x00, 0xF2};

static uint8_t maskWriteRegisterRsp[] = {/* Transaction ID */       0x00, 0x0A,
                                         /* Protocol ID */          0x00, 0x00,
                                         /* Length */               0x00, 0x08,
                                         /* Unit ID */              0x00,
                                         /* Function code */        0x16,
                                         /* Reference Address */    0x00, 0x04,
                                         /* And_Mask */             0x00, 0xF2,
                                         /* Or_Mask */              0x00, 0x25};

/* Modbus Application Protocol Specification V1.1b3 6.17: Read/Write Multiple registers */
/* Example of a request to read six registers starting at register 4, */
/* and to write three registers starting at register 15 */
static uint8_t readWriteMultipleRegistersReq[] = {/* Transaction ID */          0x12, 0x34,
                                                  /* Protocol ID */             0x00, 0x00,
                                                  /* Length */                  0x00, 0x11,
                                                  /* Unit ID */                 0x00,
                                                  /* Function code */           0x17,
                                                  /* Read Starting Address */   0x00, 0x03,
                                                  /* Quantity to Read */        0x00, 0x06,
                                                  /* Write Starting Address */  0x00, 0x0E,
                                                  /* Quantity to Write */       0x00, 0x03,
                                                  /* Write Byte count */        0x06,
                                                  /* Write Registers Value */   0x12, 0x34,
                                                                                0x56, 0x78,
                                                                                0x9A, 0xBC};

/* Mismatch value in Byte count 0x0B instead of 0x0C */
static uint8_t readWriteMultipleRegistersRsp[] = {/* Transaction ID */          0x12, 0x34,
                                                  /* Protocol ID */             0x00, 0x00,
                                                  /* Length */                  0x00, 0x0E,
                                                  /* Unit ID */                 0x00,
                                                  /* Function code */           0x17,
                                                  /* Byte count */              0x0B,
                                                  /* Read Registers Value */    0x00, 0xFE,
                                                                                0x0A, 0xCD,
                                                                                0x00, 0x01,
                                                                                0x00, 0x03,
                                                                                0x00, 0x0D,
                                                                                0x00};

/* Modbus Application Protocol Specification V1.1b3 6.8.1: 04 Force Listen Only Mode */
/* Example of a request to to remote device to its Listen Only Mode for Modbus Communications. */
static uint8_t forceListenOnlyMode[] = {/* Transaction ID */     0x0A, 0x00,
                                        /* Protocol ID */        0x00, 0x00,
                                        /* Length */             0x00, 0x06,
                                        /* Unit ID */            0x00,
                                        /* Function code */      0x08,
                                        /* Sub-function code */  0x00, 0x04,
                                        /* Data */               0x00, 0x00};

static uint8_t invalidProtocolIdReq[] = {/* Transaction ID */    0x00, 0x00,
                                         /* Protocol ID */       0x00, 0x01,
                                         /* Length */            0x00, 0x06,
                                         /* Unit ID */           0x00,
                                         /* Function code */     0x01,
                                         /* Starting Address */  0x78, 0x90,
                                         /* Quantity of coils */ 0x00, 0x13 };

static uint8_t invalidLengthWriteMultipleRegistersReq[] = {
                                              /* Transaction ID */          0x00, 0x0A,
                                              /* Protocol ID */             0x00, 0x00,
                                              /* Length */                  0x00, 0x09,
                                              /* Unit ID */                 0x00,
                                              /* Function code */           0x10,
                                              /* Starting Address */        0x00, 0x01,
                                              /* Quantity of Registers */   0x00, 0x02,
                                              /* Byte count */              0x04,
                                              /* Registers Value */         0x00, 0x0A,
                                                                            0x01, 0x02};

static uint8_t exceededLengthWriteMultipleRegistersReq[] = {
                                              /* Transaction ID */          0x00, 0x0A,
                                              /* Protocol ID */             0x00, 0x00,
                                              /* Length */                  0xff, 0xfa,
                                              /* Unit ID */                 0x00,
                                              /* Function code */           0x10,
                                              /* Starting Address */        0x00, 0x01,
                                              /* Quantity of Registers */   0x7f, 0xf9,
                                              /* Byte count */              0xff};

static uint8_t invalidLengthPDUWriteMultipleRegistersReq[] = {
                                              /* Transaction ID */          0x00, 0x0A,
                                              /* Protocol ID */             0x00, 0x00,
                                              /* Length */                  0x00, 0x02,
                                              /* Unit ID */                 0x00,
                                              /* Function code */           0x10};

/** \test Send Modbus Read Coils request/response. */
static int ModbusParserTest01(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, readCoilsReq,
                                sizeof(readCoilsReq));
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusMessage request = rs_modbus_state_get_tx_request(modbus_state, 0);
    FAIL_IF_NULL(request._0);
    FAIL_IF_NOT(rs_modbus_message_get_function(&request) == 1);
    FAIL_IF_NOT(rs_modbus_message_get_read_request_address(&request) == 0x7890);
    FAIL_IF_NOT(rs_modbus_message_get_read_request_quantity(&request) == 19);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, readCoilsRsp,
                            sizeof(readCoilsRsp));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NOT(rs_modbus_state_get_tx_count(modbus_state) == 1);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Send Modbus Write Multiple registers request/response. */
static int ModbusParserTest02(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, writeMultipleRegistersReq,
                                sizeof(writeMultipleRegistersReq));
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusMessage request = rs_modbus_state_get_tx_request(modbus_state, 0);
    FAIL_IF_NULL(request._0);
    FAIL_IF_NOT(rs_modbus_message_get_function(&request) == 16);
    FAIL_IF_NOT(rs_modbus_message_get_write_multreq_address(&request) == 0x01);
    FAIL_IF_NOT(rs_modbus_message_get_write_multreq_quantity(&request) == 2);

    size_t data_len;
    const uint8_t *data = rs_modbus_message_get_write_multreq_data(&request, &data_len);
    FAIL_IF_NOT(data_len == 4);
    FAIL_IF_NOT(data[0] == 0x00);
    FAIL_IF_NOT(data[1] == 0x0A);
    FAIL_IF_NOT(data[2] == 0x01);
    FAIL_IF_NOT(data[3] == 0x02);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, writeMultipleRegistersRsp,
                            sizeof(writeMultipleRegistersRsp));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NOT(rs_modbus_state_get_tx_count(modbus_state) == 1);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Send Modbus Read/Write Multiple registers request/response with mismatch value. */
static int ModbusParserTest03(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus Data mismatch\"; "
                                      "app-layer-event: "
                                      "modbus.value_mismatch; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                readWriteMultipleRegistersReq,
                                sizeof(readWriteMultipleRegistersReq));
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusMessage request = rs_modbus_state_get_tx_request(modbus_state, 0);
    FAIL_IF_NULL(request._0);

    FAIL_IF_NOT(rs_modbus_message_get_function(&request) == 23);
    FAIL_IF_NOT(rs_modbus_message_get_rw_multreq_read_address(&request) == 0x03);
    FAIL_IF_NOT(rs_modbus_message_get_rw_multreq_read_quantity(&request) == 6);
    FAIL_IF_NOT(rs_modbus_message_get_rw_multreq_write_address(&request) == 0x0E);
    FAIL_IF_NOT(rs_modbus_message_get_rw_multreq_write_quantity(&request) == 3);

    size_t data_len;
    uint8_t const *data = rs_modbus_message_get_rw_multreq_write_data(&request, &data_len);
    FAIL_IF_NOT(data_len == 6);
    FAIL_IF_NOT(data[0] == 0x12);
    FAIL_IF_NOT(data[1] == 0x34);
    FAIL_IF_NOT(data[2] == 0x56);
    FAIL_IF_NOT(data[3] == 0x78);
    FAIL_IF_NOT(data[4] == 0x9A);
    FAIL_IF_NOT(data[5] == 0xBC);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, readWriteMultipleRegistersRsp,
                            sizeof(readWriteMultipleRegistersRsp));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NOT(rs_modbus_state_get_tx_count(modbus_state) == 1);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Send Modbus Force Listen Only Mode request. */
static int ModbusParserTest04(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, forceListenOnlyMode,
                                sizeof(forceListenOnlyMode));
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusMessage request = rs_modbus_state_get_tx_request(modbus_state, 0);
    FAIL_IF_NULL(request._0);

    FAIL_IF_NOT(rs_modbus_message_get_function(&request) == 8);
    FAIL_IF_NOT(rs_modbus_message_get_subfunction(&request) == 4);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Send Modbus invalid Protocol version in request. */
static int ModbusParserTest05(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus invalid Protocol version\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_protocol_id; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, invalidProtocolIdReq,
                                sizeof(invalidProtocolIdReq));
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Send Modbus unsolicited response. */
static int ModbusParserTest06(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus unsolicited response\"; "
                                      "app-layer-event: "
                                      "modbus.unsolicited_response; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOCLIENT, readCoilsRsp,
                                sizeof(readCoilsRsp));
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Send Modbus invalid Length request. */
static int ModbusParserTest07(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus invalid Length\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_length; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                invalidLengthWriteMultipleRegistersReq,
                                sizeof(invalidLengthWriteMultipleRegistersReq));
    FAIL_IF_NOT(r == 1);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Send Modbus Read Coils request and error response with Exception code invalid. */
static int ModbusParserTest08(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus Exception code invalid\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_exception_code; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, readCoilsReq,
                                sizeof(readCoilsReq));
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusMessage request = rs_modbus_state_get_tx_request(modbus_state, 0);
    FAIL_IF_NULL(request._0);

    FAIL_IF_NOT(rs_modbus_message_get_function(&request) == 1);
    FAIL_IF_NOT(rs_modbus_message_get_read_request_address(&request) == 0x7890);
    FAIL_IF_NOT(rs_modbus_message_get_read_request_quantity(&request) == 19);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, readCoilsErrorRsp,
                            sizeof(readCoilsErrorRsp));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NOT(rs_modbus_state_get_tx_count(modbus_state) == 1);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Modbus fragmentation - 1 ADU over 2 TCP packets. */
static int ModbusParserTest09(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    uint32_t    input_len = sizeof(readCoilsReq), part2_len = 3;
    uint8_t     *input = readCoilsReq;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, input, input_len - part2_len);
    FAIL_IF_NOT(r == 1);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOSERVER, input, input_len);
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusMessage request = rs_modbus_state_get_tx_request(modbus_state, 0);
    FAIL_IF_NULL(request._0);

    FAIL_IF_NOT(rs_modbus_message_get_function(&request) == 1);
    FAIL_IF_NOT(rs_modbus_message_get_read_request_address(&request) == 0x7890);
    FAIL_IF_NOT(rs_modbus_message_get_read_request_quantity(&request) == 19);

    input_len = sizeof(readCoilsRsp);
    part2_len = 10;
    input = readCoilsRsp;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, input, input_len - part2_len);
    FAIL_IF_NOT(r == 1);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, input, input_len);
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NOT(rs_modbus_state_get_tx_count(modbus_state) == 1);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Modbus fragmentation - 2 ADU in 1 TCP packet. */
static int ModbusParserTest10(void) {
    uint32_t    input_len = sizeof(readCoilsReq) + sizeof(writeMultipleRegistersReq);
    uint8_t     *input, *ptr;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    FAIL_IF_NULL(alp_tctx);

    input  = (uint8_t *) SCMalloc (input_len * sizeof(uint8_t));
    FAIL_IF_NULL(input);

    memcpy(input, readCoilsReq, sizeof(readCoilsReq));
    memcpy(input + sizeof(readCoilsReq), writeMultipleRegistersReq, sizeof(writeMultipleRegistersReq));

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, input, input_len);
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    FAIL_IF_NOT(rs_modbus_state_get_tx_count(modbus_state) == 2);

    ModbusMessage request = rs_modbus_state_get_tx_request(modbus_state, 1);
    FAIL_IF_NULL(request._0);

    FAIL_IF_NOT(rs_modbus_message_get_function(&request) == 16);
    FAIL_IF_NOT(rs_modbus_message_get_write_multreq_address(&request) == 0x01);
    FAIL_IF_NOT(rs_modbus_message_get_write_multreq_quantity(&request) == 2);

    size_t data_len;
    uint8_t const *data = rs_modbus_message_get_write_multreq_data(&request, &data_len);
    FAIL_IF_NOT(data_len == 4);
    FAIL_IF_NOT(data[0] == 0x00);
    FAIL_IF_NOT(data[1] == 0x0A);
    FAIL_IF_NOT(data[2] == 0x01);
    FAIL_IF_NOT(data[3] == 0x02);

    input_len = sizeof(readCoilsRsp) + sizeof(writeMultipleRegistersRsp);

    ptr = (uint8_t *) SCRealloc (input, input_len * sizeof(uint8_t));
    FAIL_IF_NULL(ptr);
    input = ptr;

    memcpy(input, readCoilsRsp, sizeof(readCoilsRsp));
    memcpy(input + sizeof(readCoilsRsp), writeMultipleRegistersRsp, sizeof(writeMultipleRegistersRsp));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOCLIENT, input, input_len);
    FAIL_IF_NOT(r == 0);

    SCFree(input);
    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Send Modbus exceed Length request. */
static int ModbusParserTest11(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    size_t input_len = 65536;
    uint8_t *input = SCCalloc(1, input_len);

    FAIL_IF(input == NULL);

    memcpy(input, exceededLengthWriteMultipleRegistersReq,
            sizeof(exceededLengthWriteMultipleRegistersReq));

    FAIL_IF(alp_tctx == NULL);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus invalid Length\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_length; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOSERVER, input, input_len);
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Send Modbus invalid PDU Length. */
static int ModbusParserTest12(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus invalid Length\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_length; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                invalidLengthPDUWriteMultipleRegistersReq,
                                sizeof(invalidLengthPDUWriteMultipleRegistersReq));
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Send Modbus Mask Write register request/response. */
static int ModbusParserTest13(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, maskWriteRegisterReq,
                                sizeof(maskWriteRegisterReq));
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusMessage request = rs_modbus_state_get_tx_request(modbus_state, 0);
    FAIL_IF_NULL(request._0);

    FAIL_IF_NOT(rs_modbus_message_get_function(&request) == 22);
    FAIL_IF_NOT(rs_modbus_message_get_and_mask(&request) == 0x00F2);
    FAIL_IF_NOT(rs_modbus_message_get_or_mask(&request) == 0x0025);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, maskWriteRegisterRsp,
                            sizeof(maskWriteRegisterRsp));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NOT(rs_modbus_state_get_tx_count(modbus_state) == 1);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Send Modbus Write single register request/response. */
static int ModbusParserTest14(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, writeSingleRegisterReq,
                                sizeof(writeSingleRegisterReq));
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusMessage request = rs_modbus_state_get_tx_request(modbus_state, 0);
    FAIL_IF_NULL(request._0);

    FAIL_IF_NOT(rs_modbus_message_get_function(&request) == 6);
    FAIL_IF_NOT(rs_modbus_message_get_write_address(&request) == 0x0001);
    FAIL_IF_NOT(rs_modbus_message_get_write_data(&request) == 0x0003);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, writeSingleRegisterRsp,
                            sizeof(writeSingleRegisterRsp));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NOT(rs_modbus_state_get_tx_count(modbus_state) == 1);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Send invalid Modbus Mask Write register request. */
static int ModbusParserTest15(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus invalid Length\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_length; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, invalidMaskWriteRegisterReq,
                                sizeof(invalidMaskWriteRegisterReq));
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusMessage request = rs_modbus_state_get_tx_request(modbus_state, 0);
    FAIL_IF_NULL(request._0);

    FAIL_IF_NOT(rs_modbus_message_get_function(&request) == 22);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, maskWriteRegisterRsp,
                            sizeof(maskWriteRegisterRsp));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NOT(rs_modbus_state_get_tx_count(modbus_state) == 1);
    ModbusMessage response = rs_modbus_state_get_tx_response(modbus_state, 0);
    FAIL_IF_NULL(response._0);

    FAIL_IF_NOT(rs_modbus_message_get_function(&response) == 22);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Send invalid Modbus Mask Write register request. */
static int ModbusParserTest16(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus invalid Length\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_length; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                invalidWriteSingleRegisterReq,
                                sizeof(invalidWriteSingleRegisterReq));
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusMessage request = rs_modbus_state_get_tx_request(modbus_state, 0);
    FAIL_IF_NULL(request._0);

    FAIL_IF_NOT(rs_modbus_message_get_function(&request) == 6);
    size_t data_len;
    const uint8_t *data = rs_modbus_message_get_bytevec_data(&request, &data_len);
    FAIL_IF_NOT(data_len == 2);
    FAIL_IF_NOT(data[0] == 0x00);
    FAIL_IF_NOT(data[1] == 0x01);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, writeSingleRegisterRsp,
                            sizeof(writeSingleRegisterRsp));
    FAIL_IF_NOT(r == 0);

    FAIL_IF_NOT(rs_modbus_state_get_tx_count(modbus_state) == 1);
    ModbusMessage response = rs_modbus_state_get_tx_response(modbus_state, 0);
    FAIL_IF_NULL(response._0);

    FAIL_IF_NOT(rs_modbus_message_get_function(&response) == 6);
    FAIL_IF_NOT(rs_modbus_message_get_write_address(&response) == 0x0001);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;}

/** \test Checks if stream_depth is correct */
static int ModbusParserTest17(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOSERVER,
                                readCoilsReq, sizeof(readCoilsReq));
    FAIL_IF(r != 0);

    FAIL_IF(f.alstate == NULL);

    FAIL_IF(((TcpSession *)(f.protoctx))->reassembly_depth != MODBUS_CONFIG_DEFAULT_STREAM_DEPTH);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOCLIENT,
                            readCoilsRsp, sizeof(readCoilsRsp));
    FAIL_IF(r != 0);

    FAIL_IF(((TcpSession *)(f.protoctx))->reassembly_depth != MODBUS_CONFIG_DEFAULT_STREAM_DEPTH);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    PASS;
}

/*/ \test Checks if stream depth is correct over 2 TCP packets */
static int ModbusParserTest18(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    uint32_t    input_len = sizeof(readCoilsReq), part2_len = 3;
    uint8_t     *input = readCoilsReq;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOSERVER,
                                input, input_len - part2_len);
    FAIL_IF(r != 1);

    FAIL_IF(((TcpSession *)(f.protoctx))->reassembly_depth != MODBUS_CONFIG_DEFAULT_STREAM_DEPTH);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOSERVER,
                            input, input_len);
    FAIL_IF(r != 0);

    FAIL_IF(((TcpSession *)(f.protoctx))->reassembly_depth != MODBUS_CONFIG_DEFAULT_STREAM_DEPTH);

    FAIL_IF(f.alstate == NULL);

    input_len = sizeof(readCoilsRsp);
    part2_len = 10;
    input = readCoilsRsp;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOCLIENT,
                            input, input_len - part2_len);
    FAIL_IF(r != 1);

    FAIL_IF(((TcpSession *)(f.protoctx))->reassembly_depth != MODBUS_CONFIG_DEFAULT_STREAM_DEPTH);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOCLIENT,
                            input, input_len);
    FAIL_IF(r != 0);

    FAIL_IF(((TcpSession *)(f.protoctx))->reassembly_depth != MODBUS_CONFIG_DEFAULT_STREAM_DEPTH);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Send Modbus invalid function. */
static int ModbusParserTest19(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus invalid Function code\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_function_code; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                invalidFunctionCode,
                                sizeof(invalidFunctionCode));
    FAIL_IF_NOT(r == 0);

    ModbusState *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}
#endif /* UNITTESTS */

void ModbusParserRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("ModbusParserTest01 - Modbus Read Coils request",
                   ModbusParserTest01);
    UtRegisterTest("ModbusParserTest02 - Modbus Write Multiple registers request",
                   ModbusParserTest02);
    UtRegisterTest("ModbusParserTest03 - Modbus Read/Write Multiple registers request",
                   ModbusParserTest03);
    UtRegisterTest("ModbusParserTest04 - Modbus Force Listen Only Mode request",
                   ModbusParserTest04);
    UtRegisterTest("ModbusParserTest05 - Modbus invalid Protocol version",
                   ModbusParserTest05);
    UtRegisterTest("ModbusParserTest06 - Modbus unsolicited response",
                   ModbusParserTest06);
    UtRegisterTest("ModbusParserTest07 - Modbus invalid Length request",
                   ModbusParserTest07);
    UtRegisterTest("ModbusParserTest08 - Modbus Exception code invalid",
                   ModbusParserTest08);
    UtRegisterTest("ModbusParserTest09 - Modbus fragmentation - 1 ADU in 2 TCP packets",
                   ModbusParserTest09);
    UtRegisterTest("ModbusParserTest10 - Modbus fragmentation - 2 ADU in 1 TCP packet",
                   ModbusParserTest10);
    UtRegisterTest("ModbusParserTest11 - Modbus exceeded Length request",
                   ModbusParserTest11);
    UtRegisterTest("ModbusParserTest12 - Modbus invalid PDU Length",
                   ModbusParserTest12);
    UtRegisterTest("ModbusParserTest13 - Modbus Mask Write register request",
                   ModbusParserTest13);
    UtRegisterTest("ModbusParserTest14 - Modbus Write single register request",
                   ModbusParserTest14);
    UtRegisterTest("ModbusParserTest15 - Modbus invalid Mask Write register request",
                   ModbusParserTest15);
    UtRegisterTest("ModbusParserTest16 - Modbus invalid Write single register request",
                   ModbusParserTest16);
    UtRegisterTest("ModbusParserTest17 - Modbus stream depth",
                   ModbusParserTest17);
    UtRegisterTest("ModbusParserTest18 - Modbus stream depth in 2 TCP packets",
                   ModbusParserTest18);
    UtRegisterTest("ModbusParserTest19 - Modbus invalid Function code",
                   ModbusParserTest19);
#endif /* UNITTESTS */
}
