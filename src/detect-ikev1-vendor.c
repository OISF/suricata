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
#include "detect-ikev1-vendor.h"
#include "app-layer-parser.h"
#include "util-byte.h"

#include "rust-bindings.h"

typedef struct {
    char *vendor;
} DetectIkev1VendorData;

static DetectIkev1VendorData *DetectIkev1VendorParse (const char *);
static int DetectIkev1VendorSetup (DetectEngineCtx *, Signature *s, const char *str);
static void DetectIkev1VendorFree(DetectEngineCtx *, void *);
static int g_ikev1_vendor_buffer_id = 0;

static int DetectEngineInspectIkev1VendorGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id);

static int DetectIkev1VendorMatch (DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);

/**
 * \brief Registration function for ikev1.vendor keyword.
 */
void DetectIkev1VendorRegister (void)
{
    sigmatch_table[DETECT_AL_IKEV1_VENDOR].name = "ikev1.vendor";
    sigmatch_table[DETECT_AL_IKEV1_VENDOR].desc = "match IKEv1 Vendor";
    sigmatch_table[DETECT_AL_IKEV1_VENDOR].url = "/rules/ikev1-keywords.html#ikev1-vendor";
    sigmatch_table[DETECT_AL_IKEV1_VENDOR].AppLayerTxMatch = DetectIkev1VendorMatch;
    sigmatch_table[DETECT_AL_IKEV1_VENDOR].Setup = DetectIkev1VendorSetup;
    sigmatch_table[DETECT_AL_IKEV1_VENDOR].Free = DetectIkev1VendorFree;

    DetectAppLayerInspectEngineRegister("ikev1.vendor",
            ALPROTO_IKEV1, SIG_FLAG_TOSERVER, 2,
            DetectEngineInspectIkev1VendorGeneric);

    g_ikev1_vendor_buffer_id = DetectBufferTypeGetByName("ikev1.vendor");
}

static int DetectEngineInspectIkev1VendorGeneric(ThreadVars *tv,
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
 * \brief Function to match vendor in a IKEv1 state
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the Ikev1 Transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectIkev1VendorData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectIkev1VendorMatch (DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectIkev1VendorData *dd = (const DetectIkev1VendorData *)ctx;
    if (rs_ikev1_state_vendors_contain(txv, dd->vendor) == 1)
        SCReturnInt(1);
    else
        SCReturnInt(0);
}

/**
 * \internal
 * \brief Function to parse options passed via ikev1.vendor keywords.
 *
 * \param rawstr Pointer to the user provided options.
 *
 * \retval dd pointer to DetectIkev1VendorData on success.
 * \retval NULL on failure.
 */
static DetectIkev1VendorData *DetectIkev1VendorParse (const char *rawstr)
{
    DetectIkev1VendorData *dd = SCCalloc(1, sizeof(DetectIkev1VendorData));
    if (unlikely(dd == NULL))
        goto error;

    /* set the vendor we want to check for */
    dd->vendor = SCStrdup(rawstr);
    if (dd->vendor == NULL)
        goto error;

    return dd;

error:
    if (dd->vendor)
        SCFree(dd->vendor);
    if (dd)
        SCFree(dd);
    return NULL;
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
static int DetectIkev1VendorSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_IKEV1) != 0)
        return -1;

    DetectIkev1VendorData *dd = DetectIkev1VendorParse(rawstr);
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Parsing \'%s\' failed", rawstr);
        goto error;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_IKEV1_VENDOR;
    sm->ctx = (void *)dd;

    SigMatchAppendSMToList(s, sm, g_ikev1_vendor_buffer_id);
    return 0;

error:
    DetectIkev1VendorFree(de_ctx, dd);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectIkev1VendorData.
 *
 * \param de_ptr Pointer to DetectIkev1VendorData.
 */
static void DetectIkev1VendorFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectIkev1VendorData *dd = (DetectIkev1VendorData *)ptr;
    if (dd == NULL)
        return;
    if (dd->vendor != NULL)
        SCFree(dd->vendor);

    SCFree(ptr);
}
