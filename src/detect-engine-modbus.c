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
#include "app-layer-modbus.h"

#include "detect.h"
#include "detect-modbus.h"

#include "detect-engine-modbus.h"

#include "flow.h"

#include "util-debug.h"

/** \internal
 *
 * \brief Value match detection code
 *
 *  \param  value   Modbus value context (min, max and mode)
 *  \param  min     Minimum value to compare
 *  \param  inter   Interval or maximum (min + inter) value to compare
 *
 *  \retval 1 match or 0 no match
 */
static int DetectEngineInspectModbusValueMatch(DetectModbusValue    *value,
                                               uint16_t             min,
                                               uint16_t             inter)
{
    SCEnter();
    uint16_t max = min + inter;

    int ret = 0;

    switch (value->mode) {
        case DETECT_MODBUS_EQ:
            if ((value->min >= min) && (value->min <= max))
                ret = 1;
            break;

        case DETECT_MODBUS_LT:
            if (value->min > min)
                ret = 1;
            break;

        case DETECT_MODBUS_GT:
            if (value->min < max)
                ret = 1;
            break;

        case DETECT_MODBUS_RA:
            if ((value->max > min) && (value->min < max))
                ret = 1;
            break;
    }

    SCReturnInt(ret);
}

/** \internal
 *
 * \brief Do data (and address) inspection & validation for a signature
 *
 *  \param tx       Pointer to Modbus Transaction
 *  \param address  Address inspection
 *  \param data     Pointer to data signature structure to match
 *
 *  \retval 0 no match or 1 match
 */
static int DetectEngineInspectModbusData(ModbusTransaction  *tx,
                                         uint16_t           address,
                                         DetectModbusValue  *data)
{
    SCEnter();
    uint16_t offset, value = 0, type = tx->type;

    if (type & MODBUS_TYP_SINGLE) {
        /* Output/Register(s) Value */
        if (type & MODBUS_TYP_COILS)
            value = (tx->data[0])? 1 : 0;
        else
            value = tx->data[0];
    } else if (type & MODBUS_TYP_MULTIPLE) {
        int i, size = (int) sizeof(tx->data);

        offset = address - (tx->write.address + 1);

        /* In case of Coils, offset is in bit (convert in byte) */
        if (type & MODBUS_TYP_COILS)
            offset >>= 3;

        for (i=0; i< size; i++) {
            /* Select the correct register/coils amongst the output value */
            if (!(offset--)) {
                value = tx->data[i];
                break;
            }
        }

        /* In case of Coils,  offset is now in the bit is the rest of previous convert */
        if (type & MODBUS_TYP_COILS) {
            offset  = (address - (tx->write.address + 1)) & 0x7;
            value   = (value >> offset) & 0x1;
        }
    } else {
        /* It is not possible to define the value that is writing for Mask      */
        /* Write Register function because the current content is not available.*/
        SCReturnInt(0);
    }

    SCReturnInt(DetectEngineInspectModbusValueMatch(data, value, 0));
}

/** \internal
 *
 * \brief Do address inspection & validation for a signature
 *
 *  \param tx       Pointer to Modbus Transaction
 *  \param address  Pointer to address signature structure to match
 *  \param access   Access mode (READ or WRITE)
 *
 *  \retval 0 no match or 1 match
 */
static int DetectEngineInspectModbusAddress(ModbusTransaction   *tx,
                                            DetectModbusValue   *address,
                                            uint8_t             access)
{
    SCEnter();
    int ret = 0;

    /* Check if read/write address of request is at/in the address range of signature */
    if (access == MODBUS_TYP_READ) {
        /* In the PDU Coils are addresses starting at zero */
        /* therefore Coils numbered 1-16 are addressed as 0-15 */
        ret = DetectEngineInspectModbusValueMatch(address,
                                                  tx->read.address + 1,
                                                  tx->read.quantity - 1);
    } else {
        /* In the PDU Registers are addresses starting at zero */
        /* therefore Registers numbered 1-16 are addressed as 0-15 */
        if (tx->type & MODBUS_TYP_SINGLE)
            ret = DetectEngineInspectModbusValueMatch(address,
                                                      tx->write.address + 1,
                                                      0);
        else
            ret = DetectEngineInspectModbusValueMatch(address,
                                                      tx->write.address + 1,
                                                      tx->write.quantity - 1);
    }

    SCReturnInt(ret);
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
int DetectEngineInspectModbus(ThreadVars            *tv,
                              DetectEngineCtx       *de_ctx,
                              DetectEngineThreadCtx *det_ctx,
                              const Signature       *s,
                              const SigMatchData    *smd,
                              Flow                  *f,
                              uint8_t               flags,
                              void                  *alstate,
                              void                  *txv,
                              uint64_t              tx_id)
{
    SCEnter();
    ModbusTransaction   *tx = (ModbusTransaction *)txv;
    DetectModbus        *modbus = (DetectModbus *) smd->ctx;

    int ret = 0;

    if (modbus == NULL) {
        SCLogDebug("no modbus state, no match");
        SCReturnInt(0);
    }

    if (modbus->type == MODBUS_TYP_NONE) {
        if (modbus->category == MODBUS_CAT_NONE) {
            if (modbus->function == tx->function) {
                if (modbus->subfunction != NULL) {
                    SCLogDebug("looking for Modbus server function %d and subfunction %d",
                                modbus->function, *(modbus->subfunction));
                    ret = (*(modbus->subfunction) == (tx->subFunction))? 1 : 0;
                } else {
                    SCLogDebug("looking for Modbus server function %d", modbus->function);
                    ret = 1;
                }
            }
        } else {
            SCLogDebug("looking for Modbus category function %d", modbus->category);
            ret = (tx->category & modbus->category)? 1 : 0;
        }
    } else {
        uint8_t access      = modbus->type & MODBUS_TYP_ACCESS_MASK;
        uint8_t function    = modbus->type & MODBUS_TYP_ACCESS_FUNCTION_MASK;

        if ((access & tx->type) && ((function == MODBUS_TYP_NONE) || (function & tx->type))) {
            if (modbus->address != NULL) {
                ret = DetectEngineInspectModbusAddress(tx, modbus->address, access);

                if (ret && (modbus->data != NULL)) {
                    ret = DetectEngineInspectModbusData(tx, modbus->address->min, modbus->data);
                }
            } else {
                SCLogDebug("looking for Modbus access type %d and function type %d", access, function);
                ret = 1;
            }
        }
    }

    SCReturnInt(ret);
}

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
                                 /* Unit ID */           0x00,
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
                                                  /* Unit ID */                 0x00,
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

static uint8_t unassigned[] = {/* Transaction ID */     0x00, 0x0A,
                               /* Protocol ID */        0x00, 0x00,
                               /* Length */             0x00, 0x02,
                               /* Unit ID */            0x00,
                               /* Function code */      0x12};

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

    int result = 0;

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

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                            "(msg:\"Testing modbus code function\"; "
                                            "modbus: function 23; sid:1;)");

    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                readWriteMultipleRegistersReq,
                                sizeof(readWriteMultipleRegistersReq));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    if (modbus_state == NULL) {
        printf("no modbus state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
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

    int result = 0;

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

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                           "(msg:\"Testing modbus function and subfunction\"; "
                                           "modbus: function 8, subfunction 4;  sid:1;)");

    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, forceListenOnlyMode,
                                sizeof(forceListenOnlyMode));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    if (modbus_state == NULL) {
        printf("no modbus state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
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

    int result = 0;

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

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                           "(msg:\"Testing modbus category function\"; "
                                           "modbus: function reserved;  sid:1;)");

    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                encapsulatedInterfaceTransport,
                                sizeof(encapsulatedInterfaceTransport));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    if (modbus_state == NULL) {
        printf("no modbus state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
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

    int result = 0;

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

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus category function\"; "
                                       "modbus: function !assigned;  sid:1;)");

    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, unassigned,
                                sizeof(unassigned));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    if (modbus_state == NULL) {
        printf("no modbus state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
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

    int result = 0;

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

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                           "(msg:\"Testing modbus access type\"; "
                                           "modbus: access read;  sid:1;)");

    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, readCoilsReq,
                                sizeof(readCoilsReq));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    if (modbus_state == NULL) {
        printf("no modbus state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
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

    int result = 0;

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

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                           "(msg:\"Testing modbus access type\"; "
                                           "modbus: access read input;  sid:1;)");

    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, readInputsRegistersReq,
                                sizeof(readInputsRegistersReq));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    ModbusState *modbus_state = f.alstate;
    if (modbus_state == NULL) {
        printf("no modbus state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
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

    int result = 0;

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

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                           "(msg:\"Testing modbus address access\"; "
                                           "modbus: access read, address 30870;  sid:1;)");

    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, readCoilsReq,
                                sizeof(readCoilsReq));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    if (modbus_state == NULL) {
        printf("no modbus state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
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

    int result = 0;

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

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

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

    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, readInputsRegistersReq,
                                sizeof(readInputsRegistersReq));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    if (modbus_state == NULL) {
        printf("no modbus state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 did match but should not have: ");
        goto end;
    }

    if (!(PacketAlertCheck(p, 2))) {
        printf("sid 2 didn't match but should have: ");
        goto end;
    }

    if (PacketAlertCheck(p, 3)) {
        printf("sid 3 did match but should not have: ");
        goto end;
    }

    if (!(PacketAlertCheck(p, 4))) {
        printf("sid 4 didn't match but should have: ");
        goto end;
    }

    if (!(PacketAlertCheck(p, 5))) {
        printf("sid 5 didn't match but should have: ");
        goto end;
    }

    if (!(PacketAlertCheck(p, 6))) {
        printf("sid 6 didn't match but should have: ");
        goto end;
    }

    if (!(PacketAlertCheck(p, 7))) {
        printf("sid 7 didn't match but should have: ");
        goto end;
    }

    if (!(PacketAlertCheck(p, 8))) {
        printf("sid 8 didn't match but should have: ");
        goto end;
    }

    if (PacketAlertCheck(p, 9)) {
        printf("sid 9 did match but should not have: ");
        goto end;
    }

    if (PacketAlertCheck(p, 10)) {
        printf("sid 10 did match but should not have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
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

    int result = 0;

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

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

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

    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                readWriteMultipleRegistersReq,
                                sizeof(readWriteMultipleRegistersReq));
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    if (modbus_state == NULL) {
        printf("no modbus state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 did match but should not have: ");
        goto end;
    }

    if (!(PacketAlertCheck(p, 2))) {
        printf("sid 2 didn't match but should have: ");
        goto end;
    }

    if (!(PacketAlertCheck(p, 3))) {
        printf("sid 3 didn't match but should have: ");
        goto end;
    }

    if (PacketAlertCheck(p, 4)) {
        printf("sid 4 did match but should not have: ");
        goto end;
    }

    if (PacketAlertCheck(p, 5)) {
        printf("sid 5 did match but should not have: ");
        goto end;
    }

    if (!(PacketAlertCheck(p, 6))) {
        printf("sid 6 didn't match but should have: ");
        goto end;
    }

    if (!(PacketAlertCheck(p, 7))) {
        printf("sid 7 didn't match but should have: ");
        goto end;
    }

    if (PacketAlertCheck(p, 8)) {
        printf("sid 8 did match but should not have: ");
        goto end;
    }

    if (!(PacketAlertCheck(p, 9))) {
        printf("sid 9 didn't match but should have: ");
        goto end;
    }

    if (PacketAlertCheck(p, 10)) {
        printf("sid 10 did match but should not have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
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
#endif /* UNITTESTS */
    return;
}
