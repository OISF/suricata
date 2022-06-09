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
 * \author Sascha Steinbiss <sascha.steinbiss@dcso.de>
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-rfb-sectype.h"
#include "detect-engine-uint.h"
#include "app-layer-parser.h"
#include "util-byte.h"

#include "rust-bindings.h"


static int DetectRfbSectypeSetup (DetectEngineCtx *, Signature *s, const char *str);
static void DetectRfbSectypeFree(DetectEngineCtx *, void *);
static int g_rfb_sectype_buffer_id = 0;

static uint8_t DetectEngineInspectRfbSectypeGeneric(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const struct DetectEngineAppInspectionEngine_ *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);

static int DetectRfbSectypeMatch (DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);

/**
 * \brief Registration function for rfb.sectype keyword.
 */
void DetectRfbSectypeRegister (void)
{
    sigmatch_table[DETECT_AL_RFB_SECTYPE].name = "rfb.sectype";
    sigmatch_table[DETECT_AL_RFB_SECTYPE].desc = "match RFB security type";
    sigmatch_table[DETECT_AL_RFB_SECTYPE].url = "/rules/rfb-keywords.html#rfb-sectype";
    sigmatch_table[DETECT_AL_RFB_SECTYPE].AppLayerTxMatch = DetectRfbSectypeMatch;
    sigmatch_table[DETECT_AL_RFB_SECTYPE].Setup = DetectRfbSectypeSetup;
    sigmatch_table[DETECT_AL_RFB_SECTYPE].Free = DetectRfbSectypeFree;

    DetectAppLayerInspectEngineRegister2("rfb.sectype", ALPROTO_RFB, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectRfbSectypeGeneric, NULL);

    g_rfb_sectype_buffer_id = DetectBufferTypeGetByName("rfb.sectype");
}

static uint8_t DetectEngineInspectRfbSectypeGeneric(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const struct DetectEngineAppInspectionEngine_ *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(
            de_ctx, det_ctx, s, engine->smd, f, flags, alstate, txv, tx_id);
}

/**
 * \internal
 * \brief Function to match security type of a RFB TX
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the RFBTransaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectU32Data.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectRfbSectypeMatch (DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectU32Data *dd = (const DetectU32Data *)ctx;
    uint32_t version;
    rs_rfb_tx_get_sectype(txv, &version);
    if (DetectU32Match(version, dd))
        SCReturnInt(1);
    SCReturnInt(0);
}

/**
 * \internal
 * \brief Function to parse options passed via rfb.sectype keywords.
 *
 * \param rawstr Pointer to the user provided options.
 *
 * \retval dd pointer to DetectU32Data on success.
 * \retval NULL on failure.
 */
static DetectU32Data *DetectRfbSectypeParse(const char *rawstr)
{
    return DetectU32Parse(rawstr);
}

/**
 * \brief Function to add the parsed RFB security type field into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectRfbSectypeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_RFB) != 0)
        return -1;

    DetectU32Data *dd = DetectRfbSectypeParse(rawstr);
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Parsing \'%s\' failed", rawstr);
        goto error;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_RFB_SECTYPE;
    sm->ctx = (void *)dd;

    SigMatchAppendSMToList(s, sm, g_rfb_sectype_buffer_id);
    return 0;

error:
    DetectRfbSectypeFree(de_ctx, dd);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectU32Data.
 *
 * \param de_ptr Pointer to DetectU32Data.
 */
static void DetectRfbSectypeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u32_free(ptr);
}
