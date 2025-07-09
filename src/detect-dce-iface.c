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

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-build.h"
#include "detect-dce-iface.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "app-layer.h"
#include "queue.h"
#include "stream-tcp-reassemble.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "stream-tcp.h"

#include "rust.h"

#define PARSE_REGEX "^\\s*([0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12})(?:\\s*,\\s*(<|>|=|!)([0-9]{1,5}))?(?:\\s*,\\s*(any_frag))?\\s*$"

static DetectParseRegex parse_regex;

static int DetectDceIfaceMatchRust(DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m);
static int DetectDceIfaceSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectDceIfaceFree(DetectEngineCtx *, void *);
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
    sigmatch_table[DETECT_DCE_IFACE].Free = DetectDceIfaceFree;
    sigmatch_table[DETECT_DCE_IFACE].desc =
            "match on the value of the interface UUID in a DCERPC header";
    sigmatch_table[DETECT_DCE_IFACE].url = "/rules/dcerpc-keywords.html#dcerpc-iface";
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    g_dce_generic_list_id = DetectBufferTypeRegister("dce_generic");

    DetectAppLayerInspectEngineRegister("dce_generic", ALPROTO_DCERPC, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister(
            "dce_generic", ALPROTO_SMB, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);

    DetectAppLayerInspectEngineRegister("dce_generic", ALPROTO_DCERPC, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister(
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
        return SCDcerpcIfaceMatch(txv, state, (void *)m);
    }

    int ret = 0;

    if (SCSmbTxGetDceIface(f->alstate, txv, (void *)m) != 1) {
        SCLogDebug("SCSmbTxGetDceIface: didn't match");
    } else {
        SCLogDebug("SCSmbTxGetDceIface: matched!");
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

    if (SCDetectSignatureSetAppProto(s, ALPROTO_DCERPC) < 0)
        return -1;

    void *did = SCDcerpcIfaceParse(arg);
    if (did == NULL) {
        SCLogError("Error parsing dce_iface option in "
                   "signature");
        return -1;
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_DCE_IFACE, did, g_dce_generic_list_id) == NULL) {
        DetectDceIfaceFree(de_ctx, did);
        return -1;
    }
    return 0;
}

static void DetectDceIfaceFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();
    if (ptr != NULL) {
        SCDcerpcIfaceFree(ptr);
    }
    SCReturn;
}
