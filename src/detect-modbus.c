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

/** \internal
 *
 * \brief this function will free memory associated with DetectModbus
 *
 * \param ptr pointer to DetectModbus
 */
static void DetectModbusFree(DetectEngineCtx *de_ctx, void *ptr) {
    SCEnter();
    if (ptr != NULL) {
        SCModbusFree(ptr);
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

    if (DetectSignatureSetAppProto(s, ALPROTO_MODBUS) != 0)
        return -1;

    if ((modbus = SCModbusParse(str)) == NULL) {
        SCLogError("invalid modbus option");
        goto error;
    }

    /* Okay so far so good, lets get this into a SigMatch and put it in the Signature. */
    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_MODBUS, (SigMatchCtx *)modbus, g_modbus_buffer_id) == NULL) {
        goto error;
    }

    SCReturnInt(0);

error:
    if (modbus != NULL)
        DetectModbusFree(de_ctx, modbus);
    SCReturnInt(-1);
}

static int DetectModbusMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state,
        void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    return SCModbusInspect(txv, (void *)ctx);
}

/**
 * \brief Registration function for Modbus keyword
 */
void DetectModbusRegister(void)
{
    sigmatch_table[DETECT_MODBUS].name = "modbus";
    sigmatch_table[DETECT_MODBUS].desc = "match on various properties of Modbus requests";
    sigmatch_table[DETECT_MODBUS].url = "/rules/modbus-keyword.html#modbus-keyword";
    sigmatch_table[DETECT_MODBUS].Match = NULL;
    sigmatch_table[DETECT_MODBUS].Setup = DetectModbusSetup;
    sigmatch_table[DETECT_MODBUS].Free = DetectModbusFree;
    sigmatch_table[DETECT_MODBUS].AppLayerTxMatch = DetectModbusMatch;

    DetectAppLayerInspectEngineRegister(
            "modbus", ALPROTO_MODBUS, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);

    g_modbus_buffer_id = DetectBufferTypeGetByName("modbus");
}
