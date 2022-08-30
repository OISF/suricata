/* Copyright (C) 2015-2022 Open Information Security Foundation
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
#include "detect-engine-content-inspection.h"
#include "detect-snmp-version.h"
#include "detect-engine-uint.h"
#include "app-layer-parser.h"
#include "rust.h"


static int DetectSNMPVersionSetup (DetectEngineCtx *, Signature *s, const char *str);
static void DetectSNMPVersionFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectSNMPVersionRegisterTests(void);
#endif
static int g_snmp_version_buffer_id = 0;

static int DetectSNMPVersionMatch (DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);

/**
 * \brief Registration function for snmp.procedure keyword.
 */
void DetectSNMPVersionRegister (void)
{
    sigmatch_table[DETECT_AL_SNMP_VERSION].name = "snmp.version";
    sigmatch_table[DETECT_AL_SNMP_VERSION].desc = "match SNMP version";
    sigmatch_table[DETECT_AL_SNMP_VERSION].url = "/rules/snmp-keywords.html#snmp-version";
    sigmatch_table[DETECT_AL_SNMP_VERSION].Match = NULL;
    sigmatch_table[DETECT_AL_SNMP_VERSION].AppLayerTxMatch = DetectSNMPVersionMatch;
    sigmatch_table[DETECT_AL_SNMP_VERSION].Setup = DetectSNMPVersionSetup;
    sigmatch_table[DETECT_AL_SNMP_VERSION].Free = DetectSNMPVersionFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_SNMP_VERSION].RegisterTests = DetectSNMPVersionRegisterTests;
#endif

    DetectAppLayerInspectEngineRegister2("snmp.version", ALPROTO_SNMP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGenericList, NULL);

    DetectAppLayerInspectEngineRegister2("snmp.version", ALPROTO_SNMP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);

    g_snmp_version_buffer_id = DetectBufferTypeGetByName("snmp.version");
}

/**
 * \internal
 * \brief Function to match version of a TX
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
static int DetectSNMPVersionMatch (DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectU32Data *dd = (const DetectU32Data *)ctx;
    uint32_t version;
    rs_snmp_tx_get_version(txv, &version);
    SCLogDebug("version %u mode %u ref_version %d", version, dd->mode, dd->arg1);
    if (DetectU32Match(version, dd))
        SCReturnInt(1);
    SCReturnInt(0);
}

/**
 * \internal
 * \brief Function to parse options passed via snmp.version keywords.
 *
 * \param rawstr Pointer to the user provided options.
 *
 * \retval dd pointer to DetectU32Data on success.
 * \retval NULL on failure.
 */
static DetectU32Data *DetectSNMPVersionParse(const char *rawstr)
{
    return DetectU32Parse(rawstr);
}



/**
 * \brief Function to add the parsed snmp version field into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 * \param type   Defines if this is notBefore or notAfter.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectSNMPVersionSetup (DetectEngineCtx *de_ctx, Signature *s,
                                   const char *rawstr)
{
    DetectU32Data *dd = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_SNMP) != 0)
        return -1;

    dd = DetectSNMPVersionParse(rawstr);
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Parsing \'%s\' failed", rawstr);
        goto error;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_SNMP_VERSION;
    sm->ctx = (void *)dd;

    SCLogDebug("snmp.version %d", dd->arg1);
    SigMatchAppendSMToList(s, sm, g_snmp_version_buffer_id);
    return 0;

error:
    DetectSNMPVersionFree(de_ctx, dd);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectU32Data.
 *
 * \param de_ptr Pointer to DetectU32Data.
 */
static void DetectSNMPVersionFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u32_free(ptr);
}


#ifdef UNITTESTS
#include "tests/detect-snmp-version.c"
#endif /* UNITTESTS */
