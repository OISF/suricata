/* Copyright (C) 2015-2020 Open Information Security Foundation
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
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-uint.h"
#include "detect-engine-content-inspection.h"
#include "detect-snmp-pdu_type.h"
#include "app-layer-parser.h"
#include "rust.h"

/**
 *   [snmp.pdu_type]:<type>;
 */

static int DetectSNMPPduTypeSetup (DetectEngineCtx *, Signature *s, const char *str);
static void DetectSNMPPduTypeFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectSNMPPduTypeRegisterTests(void);
#endif
static int g_snmp_pdu_type_buffer_id = 0;

static int DetectSNMPPduTypeMatch (DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);

void DetectSNMPPduTypeRegister(void)
{
    sigmatch_table[DETECT_AL_SNMP_PDU_TYPE].name = "snmp.pdu_type";
    sigmatch_table[DETECT_AL_SNMP_PDU_TYPE].desc = "match SNMP PDU type";
    sigmatch_table[DETECT_AL_SNMP_PDU_TYPE].url = "/rules/snmp-keywords.html#snmp-pdu-type";
    sigmatch_table[DETECT_AL_SNMP_PDU_TYPE].Match = NULL;
    sigmatch_table[DETECT_AL_SNMP_PDU_TYPE].AppLayerTxMatch = DetectSNMPPduTypeMatch;
    sigmatch_table[DETECT_AL_SNMP_PDU_TYPE].Setup = DetectSNMPPduTypeSetup;
    sigmatch_table[DETECT_AL_SNMP_PDU_TYPE].Free = DetectSNMPPduTypeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_SNMP_PDU_TYPE].RegisterTests = DetectSNMPPduTypeRegisterTests;
#endif

    DetectAppLayerInspectEngineRegister2("snmp.pdu_type", ALPROTO_SNMP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGenericList, NULL);

    DetectAppLayerInspectEngineRegister2("snmp.pdu_type", ALPROTO_SNMP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);

    g_snmp_pdu_type_buffer_id = DetectBufferTypeGetByName("snmp.pdu_type");
}

/**
 * \internal
 * \brief Function to match pdu_type of a TX
 *
 * \param t       Pointer to thread vars.
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param s       Pointer to the Signature.
 * \param m       Pointer to the sigmatch that we will cast into
 *                DetectU32Data.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectSNMPPduTypeMatch (DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectU32Data *dd = (const DetectU32Data *)ctx;
    uint32_t pdu_type;
    rs_snmp_tx_get_pdu_type(txv, &pdu_type);
    SCLogDebug("pdu_type %u ref_pdu_type %d", pdu_type, dd->arg1);
    if (pdu_type == dd->arg1)
        SCReturnInt(1);
    SCReturnInt(0);
}

/**
 * \brief Function to add the parsed snmp pdu_type field into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 * \param type   Defines if this is notBefore or notAfter.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectSNMPPduTypeSetup (DetectEngineCtx *de_ctx, Signature *s,
                                   const char *rawstr)
{
    DetectU32Data *dd = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_SNMP) != 0)
        return -1;

    dd = DetectU32Parse(rawstr);
    if (dd == NULL) {
        SCLogError("Parsing \'%s\' failed", rawstr);
        goto error;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_SNMP_PDU_TYPE;
    sm->ctx = (void *)dd;

    SCLogDebug("snmp.pdu_type %d", dd->arg1);
    SigMatchAppendSMToList(s, sm, g_snmp_pdu_type_buffer_id);
    return 0;

error:
    DetectSNMPPduTypeFree(de_ctx, dd);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectU32Data.
 *
 * \param de_ptr Pointer to DetectU32Data.
 */
static void DetectSNMPPduTypeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u32_free(ptr);
}

#ifdef UNITTESTS
#include "tests/detect-snmp-pdu_type.c"
#endif /* UNITTESTS */
