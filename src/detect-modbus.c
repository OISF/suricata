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

#include "app-layer-modbus.h"

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
#include "util-unittest.h"

/** Convert rust structure to C for regression tests.
 *
 * Note: Newly allocated `DetectModbus` structure must be freed.
 *
 * TODO: remove this after regression testing commit.
 */
static DetectModbusValue *DetectModbusValueRustToC(uint16_t min, uint16_t max)
{
    DetectModbusValue *value = SCMalloc(sizeof(*value));
    FAIL_IF_NULL(value);

    value->min = min;
    value->max = max;

    if (min == max) {
        value->mode = DETECT_MODBUS_EQ;
    } else if (min == 0) {
        value->mode = DETECT_MODBUS_LT;
    } else if (max == UINT16_MAX) {
        value->mode = DETECT_MODBUS_GT;
    } else {
        value->mode = DETECT_MODBUS_RA;
    }

    return value;
}

static DetectModbus *DetectModbusRustToC(DetectModbusRust *ctx)
{
    DetectModbus *modbus = SCMalloc(sizeof(*modbus));
    FAIL_IF_NULL(modbus);

    modbus->category = rs_modbus_get_category(ctx);
    modbus->function = rs_modbus_get_function(ctx);
    modbus->subfunction = rs_modbus_get_subfunction(ctx);
    modbus->has_subfunction = rs_modbus_get_has_subfunction(ctx);
    modbus->type = rs_modbus_get_access_type(ctx);

    modbus->unit_id = DetectModbusValueRustToC(
            rs_modbus_get_unit_id_min(ctx), rs_modbus_get_unit_id_max(ctx));

    modbus->address = DetectModbusValueRustToC(
            rs_modbus_get_address_min(ctx), rs_modbus_get_address_max(ctx));

    modbus->data =
            DetectModbusValueRustToC(rs_modbus_get_data_min(ctx), rs_modbus_get_data_max(ctx));

    return modbus;
}

static void DetectModbusCFree(DetectModbus *modbus)
{
    if (modbus) {
        if (modbus->unit_id)
            SCFree(modbus->unit_id);

        if (modbus->address)
            SCFree(modbus->address);

        if (modbus->data)
            SCFree(modbus->data);

        SCFree(modbus);
    }
}

/** \test Signature containing a function. */
static int DetectModbusTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectModbus    *modbus = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus function\"; "
                                       "modbus: function 1;  sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    modbus = DetectModbusRustToC(
            (DetectModbusRust *)de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    FAIL_IF_NOT(modbus->function == 1);

    DetectModbusCFree(modbus);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Signature containing a function and a subfunction. */
static int DetectModbusTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectModbus    *modbus = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus function and subfunction\"; "
                                       "modbus: function 8, subfunction 4;  sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    modbus = DetectModbusRustToC(
            (DetectModbusRust *)de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    FAIL_IF_NOT(modbus->function == 8);
    FAIL_IF_NOT(modbus->subfunction == 4);

    DetectModbusCFree(modbus);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Signature containing a function category. */
static int DetectModbusTest03(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectModbus    *modbus = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus.function\"; "
                                       "modbus: function reserved;  sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    modbus = DetectModbusRustToC(
            (DetectModbusRust *)de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    FAIL_IF_NOT(modbus->category == MODBUS_CAT_RESERVED);

    DetectModbusCFree(modbus);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Signature containing a negative function category. */
static int DetectModbusTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectModbus    *modbus = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus function\"; "
                                       "modbus: function !assigned;  sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    modbus = DetectModbusRustToC(
            (DetectModbusRust *)de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    FAIL_IF(modbus->category & MODBUS_CAT_PUBLIC_ASSIGNED);
    FAIL_IF_NOT(modbus->category & MODBUS_CAT_PUBLIC_UNASSIGNED);
    FAIL_IF_NOT(modbus->category & MODBUS_CAT_USER_DEFINED);
    FAIL_IF_NOT(modbus->category & MODBUS_CAT_RESERVED);

    DetectModbusCFree(modbus);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Signature containing a access type. */
static int DetectModbusTest05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectModbus    *modbus = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus.access\"; "
                                       "modbus: access read;  sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    modbus = DetectModbusRustToC(
            (DetectModbusRust *)de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    FAIL_IF_NOT(modbus->type == MODBUS_TYP_READ);

    DetectModbusCFree(modbus);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Signature containing a access function. */
static int DetectModbusTest06(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectModbus    *modbus = NULL;

    uint8_t type = (MODBUS_TYP_READ | MODBUS_TYP_DISCRETES);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus.access\"; "
                                       "modbus: access read discretes;  sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    modbus = DetectModbusRustToC(
            (DetectModbusRust *)de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    FAIL_IF_NOT(modbus->type == type);

    DetectModbusCFree(modbus);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Signature containing a read access at an address. */
static int DetectModbusTest07(void)
{
    DetectEngineCtx     *de_ctx = NULL;
    DetectModbus        *modbus = NULL;
    DetectModbusMode    mode = DETECT_MODBUS_EQ;

    uint8_t type = MODBUS_TYP_READ;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus.access\"; "
                                       "modbus: access read, address 1000;  sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    modbus = DetectModbusRustToC(
            (DetectModbusRust *)de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    FAIL_IF_NOT(modbus->type == type);
    FAIL_IF_NOT((*modbus->address).mode == mode);
    FAIL_IF_NOT((*modbus->address).min == 1000);

    DetectModbusCFree(modbus);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Signature containing a write access at a range of address. */
static int DetectModbusTest08(void)
{
    DetectEngineCtx     *de_ctx = NULL;
    DetectModbus        *modbus = NULL;
    DetectModbusMode    mode = DETECT_MODBUS_GT;

    uint8_t type = (MODBUS_TYP_WRITE | MODBUS_TYP_COILS);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus.access\"; "
                                       "modbus: access write coils, address >500;  sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    modbus = DetectModbusRustToC(
            (DetectModbusRust *)de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    FAIL_IF_NOT(modbus->type == type);
    FAIL_IF_NOT((*modbus->address).mode == mode);
    FAIL_IF_NOT((*modbus->address).min == 500);

    DetectModbusCFree(modbus);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Signature containing a write access at a address a range of value. */
static int DetectModbusTest09(void)
{
    DetectEngineCtx     *de_ctx = NULL;
    DetectModbus        *modbus = NULL;
    DetectModbusMode    addressMode = DETECT_MODBUS_EQ;
    DetectModbusMode    valueMode = DETECT_MODBUS_RA;

    uint8_t type = (MODBUS_TYP_WRITE | MODBUS_TYP_HOLDING);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus.access\"; "
                                       "modbus: access write holding, address 100, value 500<>1000;  sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    modbus = DetectModbusRustToC(
            (DetectModbusRust *)de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    FAIL_IF_NOT(modbus->type == type);
    FAIL_IF_NOT((*modbus->address).mode == addressMode);
    FAIL_IF_NOT((*modbus->address).min == 100);
    FAIL_IF_NOT((*modbus->data).mode == valueMode);
    FAIL_IF_NOT((*modbus->data).min == 500);
    FAIL_IF_NOT((*modbus->data).max == 1000);

    DetectModbusCFree(modbus);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Signature containing a unit_id. */
static int DetectModbusTest10(void)
{
    DetectEngineCtx 	*de_ctx = NULL;
    DetectModbus    	*modbus = NULL;
    DetectModbusMode    mode = DETECT_MODBUS_EQ;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus unit_id\"; "
                                       "modbus: unit 10;  sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    modbus = DetectModbusRustToC(
            (DetectModbusRust *)de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    FAIL_IF_NOT((*modbus->unit_id).min == 10);
    FAIL_IF_NOT((*modbus->unit_id).mode == mode);

    DetectModbusCFree(modbus);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Signature containing a unit_id, a function and a subfunction. */
static int DetectModbusTest11(void)
{
    DetectEngineCtx 	*de_ctx = NULL;
    DetectModbus    	*modbus = NULL;
    DetectModbusMode    mode = DETECT_MODBUS_EQ;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus function and subfunction\"; "
                                       "modbus: unit 10, function 8, subfunction 4;  sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    modbus = DetectModbusRustToC(
            (DetectModbusRust *)de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    FAIL_IF_NOT((*modbus->unit_id).min == 10);
    FAIL_IF_NOT((*modbus->unit_id).mode == mode);
    FAIL_IF_NOT(modbus->function == 8);
    FAIL_IF_NOT(modbus->subfunction == 4);

    DetectModbusCFree(modbus);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Signature containing an unit_id and a read access at an address. */
static int DetectModbusTest12(void)
{
    DetectEngineCtx     *de_ctx = NULL;
    DetectModbus        *modbus = NULL;
    DetectModbusMode    mode = DETECT_MODBUS_EQ;

    uint8_t type = MODBUS_TYP_READ;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus.access\"; "
                                       "modbus: unit 10, access read, address 1000;  sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    modbus = DetectModbusRustToC(
            (DetectModbusRust *)de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    FAIL_IF_NOT((*modbus->unit_id).min == 10);
    FAIL_IF_NOT((*modbus->unit_id).mode == mode);
    FAIL_IF_NOT(modbus->type == type);
    FAIL_IF_NOT((*modbus->address).mode == mode);
    FAIL_IF_NOT((*modbus->address).min == 1000);

    DetectModbusCFree(modbus);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Signature containing a range of unit_id. */
static int DetectModbusTest13(void)
{
    DetectEngineCtx     *de_ctx = NULL;
    DetectModbus        *modbus = NULL;
    DetectModbusMode    mode = DETECT_MODBUS_RA;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus.access\"; "
                                       "modbus: unit 10<>500;  sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    modbus = DetectModbusRustToC(
            (DetectModbusRust *)de_ctx->sig_list->sm_lists_tail[g_modbus_buffer_id]->ctx);

    FAIL_IF_NOT((*modbus->unit_id).min == 10);
    FAIL_IF_NOT((*modbus->unit_id).max == 500);
    FAIL_IF_NOT((*modbus->unit_id).mode == mode);

    DetectModbusCFree(modbus);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectModbus
 */
void DetectModbusRegisterTests(void)
{
    UtRegisterTest("DetectModbusTest01 - Testing function",
                   DetectModbusTest01);
    UtRegisterTest("DetectModbusTest02 - Testing function and subfunction",
                   DetectModbusTest02);
    UtRegisterTest("DetectModbusTest03 - Testing category function",
                   DetectModbusTest03);
    UtRegisterTest("DetectModbusTest04 - Testing category function in negative",
                   DetectModbusTest04);
    UtRegisterTest("DetectModbusTest05 - Testing access type",
                   DetectModbusTest05);
    UtRegisterTest("DetectModbusTest06 - Testing access function",
                   DetectModbusTest06);
    UtRegisterTest("DetectModbusTest07 - Testing access at address",
                   DetectModbusTest07);
    UtRegisterTest("DetectModbusTest08 - Testing a range of address",
                   DetectModbusTest08);
    UtRegisterTest("DetectModbusTest09 - Testing write a range of value",
                   DetectModbusTest09);
    UtRegisterTest("DetectModbusTest10 - Testing unit_id",
                   DetectModbusTest10);
    UtRegisterTest("DetectModbusTest11 - Testing unit_id, function and subfunction",
                   DetectModbusTest11);
    UtRegisterTest("DetectModbusTest12 - Testing unit_id and access at address",
                   DetectModbusTest12);
    UtRegisterTest("DetectModbusTest13 - Testing a range of unit_id",
                   DetectModbusTest13);
}
#endif /* UNITTESTS */
