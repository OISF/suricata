/* Copyright (C) 2020 Open Information Security Foundation
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
 *
 * \author Frank Honza <frank.honza@dcso.de>
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-ike-exch-type.h"
#include "app-layer-parser.h"
#include "util-byte.h"
#include "detect-engine-uint.h"

#include "rust-bindings.h"

/**
 *   [ike.exchtype]:[<|>|<=|>=]<type>;
 */

static int DetectIkeExchTypeSetup(DetectEngineCtx *, Signature *s, const char *str);
static void DetectIkeExchTypeFree(DetectEngineCtx *, void *);
static int g_ike_exch_type_buffer_id = 0;

static int DetectIkeExchTypeMatch(DetectEngineThreadCtx *, Flow *, uint8_t, void *, void *,
        const Signature *, const SigMatchCtx *);

/**
 * \brief Registration function for ike.exchtype keyword.
 */
void DetectIkeExchTypeRegister(void)
{
    sigmatch_table[DETECT_IKE_EXCH_TYPE].name = "ike.exchtype";
    sigmatch_table[DETECT_IKE_EXCH_TYPE].desc = "match IKE exchange type";
    sigmatch_table[DETECT_IKE_EXCH_TYPE].url = "/rules/ike-keywords.html#ike-exchtype";
    sigmatch_table[DETECT_IKE_EXCH_TYPE].Match = NULL;
    sigmatch_table[DETECT_IKE_EXCH_TYPE].AppLayerTxMatch = DetectIkeExchTypeMatch;
    sigmatch_table[DETECT_IKE_EXCH_TYPE].Setup = DetectIkeExchTypeSetup;
    sigmatch_table[DETECT_IKE_EXCH_TYPE].Free = DetectIkeExchTypeFree;

    DetectAppLayerInspectEngineRegister("ike.exchtype", ALPROTO_IKE, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectGenericList, NULL);

    DetectAppLayerInspectEngineRegister("ike.exchtype", ALPROTO_IKE, SIG_FLAG_TOCLIENT, 1,
            DetectEngineInspectGenericList, NULL);

    g_ike_exch_type_buffer_id = DetectBufferTypeGetByName("ike.exchtype");
}

/**
 * \internal
 * \brief Function to match exchange type of a IKE state
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the Ike Transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectU8Data.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectIkeExchTypeMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    uint8_t exch_type;
    if (!SCIkeStateGetExchType(txv, &exch_type))
        SCReturnInt(0);

    const DetectU8Data *du8 = (const DetectU8Data *)ctx;
    SCReturnInt(DetectU8Match(exch_type, du8));
}

/**
 * \brief Function to add the parsed IKE exchange type field into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectIkeExchTypeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (SCDetectSignatureSetAppProto(s, ALPROTO_IKE) != 0)
        return -1;

    DetectU8Data *ike_exch_type = DetectU8Parse(rawstr);
    if (ike_exch_type == NULL)
        return -1;

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_IKE_EXCH_TYPE, (SigMatchCtx *)ike_exch_type,
                g_ike_exch_type_buffer_id) == NULL) {
        goto error;
    }
    return 0;

error:
    DetectIkeExchTypeFree(de_ctx, ike_exch_type);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectU8Data.
 *
 * \param de_ptr Pointer to DetectU8Data.
 */
static void DetectIkeExchTypeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU8Free(ptr);
}
