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
#include "detect-ikev1-exch-type.h"
#include "app-layer-parser.h"
#include "util-byte.h"
#include "detect-engine-uint.h"

#include "rust-bindings.h"

/**
 *   [ikev1.exchtype]:[<|>|<=|>=]<type>;
 */

static int DetectIkev1ExchTypeSetup (DetectEngineCtx *, Signature *s, const char *str);
static void DetectIkev1ExchTypeFree(DetectEngineCtx *, void *);
static int g_ikev1_exch_type_buffer_id = 0;

static int DetectEngineInspectIkev1ExchTypeGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id);

static int DetectIkev1ExchTypeMatch (DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);

/**
 * \brief Registration function for ikev1.exchtype keyword.
 */
void DetectIkev1ExchTypeRegister (void)
{
    sigmatch_table[DETECT_AL_IKEV1_EXCH_TYPE].name = "ikev1.exchtype";
    sigmatch_table[DETECT_AL_IKEV1_EXCH_TYPE].desc = "match IKEv1 exchange type";
    sigmatch_table[DETECT_AL_IKEV1_EXCH_TYPE].url = "/rules/ikev1-keywords.html#ikev1-exchtype";
    sigmatch_table[DETECT_AL_IKEV1_EXCH_TYPE].AppLayerTxMatch = DetectIkev1ExchTypeMatch;
    sigmatch_table[DETECT_AL_IKEV1_EXCH_TYPE].Setup = DetectIkev1ExchTypeSetup;
    sigmatch_table[DETECT_AL_IKEV1_EXCH_TYPE].Free = DetectIkev1ExchTypeFree;

    DetectAppLayerInspectEngineRegister("ikev1.exchtype",
            ALPROTO_IKEV1, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectIkev1ExchTypeGeneric);

    DetectAppLayerInspectEngineRegister("ikev1.exchtype",
            ALPROTO_IKEV1, SIG_FLAG_TOCLIENT, 1,
            DetectEngineInspectIkev1ExchTypeGeneric);

    g_ikev1_exch_type_buffer_id = DetectBufferTypeGetByName("ikev1.exchtype");

    DetectU32Register();
}

static int DetectEngineInspectIkev1ExchTypeGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(tv, de_ctx, det_ctx, s, smd,
                                          f, flags, alstate, txv, tx_id);
}

/**
 * \internal
 * \brief Function to match exchange type of a IKEv1 state
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the Ikev1 Transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectU32Data.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectIkev1ExchTypeMatch (DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    SCEnter();

    uint32_t exch_type;
    if (!rs_ikev1_state_get_exch_type(txv, &exch_type))
        SCReturnInt(0);

    const DetectU32Data *du32 = (const DetectU32Data *)ctx;
    return DetectU32Match(exch_type, du32);
}

/**
 * \brief Function to add the parsed IKEv1 exchange type field into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectIkev1ExchTypeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_IKEV1) != 0)
        return -1;

    DetectU32Data *ikev1_exch_type = DetectU32Parse(rawstr);
    if (ikev1_exch_type == NULL)
        return -1;

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_IKEV1_EXCH_TYPE;
    sm->ctx = (SigMatchCtx *)ikev1_exch_type;

    SigMatchAppendSMToList(s, sm, g_ikev1_exch_type_buffer_id);
    return 0;

error:
    DetectIkev1ExchTypeFree(de_ctx, ikev1_exch_type);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectU32Data.
 *
 * \param de_ptr Pointer to DetectU32Data.
 */
static void DetectIkev1ExchTypeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}
