/* Copyright (C) 2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License leasetime 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * leasetime 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "suricata-common.h"
#include "rust.h"
#include "detect-dhcp-leasetime.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-uint.h"
#include "detect-parse.h"

static int g_buffer_id = 0;

/**
 * \internal
 * \brief Function to match leasetime of a TX
 *
 * \param t       Pointer to thread vars.
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param s       Pointer to the Signature.
 * \param m       Pointer to the sigmatch that we will cast into
 *                DetectU64Data.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectDHCPLeaseTimeMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    uint64_t leasetime;
    if (rs_dhcp_tx_get_leasetime(txv, &leasetime)) {
        const DetectU64Data *dd = (const DetectU64Data *)ctx;
        if (DetectU64Match(leasetime, dd)) {
            SCReturnInt(1);
        }
    }
    SCReturnInt(0);
}

/**
 * \internal
 * \brief Function to free memory associated with DetectU64Data.
 *
 * \param de_ptr Pointer to DetectU64Data.
 */
static void DetectDHCPLeaseTimeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u64_free(ptr);
}

/**
 * \brief Function to add the parsed dhcp leasetime field into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 * \param type   Defines if this is notBefore or notAfter.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectDHCPLeaseTimeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_DHCP) != 0)
        return -1;

    DetectU64Data *dd = DetectU64Parse(rawstr);
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Parsing \'%s\' failed for %s", rawstr,
                sigmatch_table[DETECT_AL_DHCP_LEASETIME].name);
        return -1;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_DHCP_LEASETIME;
    sm->ctx = (void *)dd;

    SigMatchAppendSMToList(s, sm, g_buffer_id);
    return 0;

error:
    DetectDHCPLeaseTimeFree(de_ctx, dd);
    return -1;
}

/**
 * \brief Registration function for dhcp.procedure keyword.
 */
void DetectDHCPLeaseTimeRegister(void)
{
    sigmatch_table[DETECT_AL_DHCP_LEASETIME].name = "dhcp.leasetime";
    sigmatch_table[DETECT_AL_DHCP_LEASETIME].desc = "match DHCP leasetime";
    sigmatch_table[DETECT_AL_DHCP_LEASETIME].url = "/rules/dhcp-keywords.html#dhcp-leasetime";
    sigmatch_table[DETECT_AL_DHCP_LEASETIME].AppLayerTxMatch = DetectDHCPLeaseTimeMatch;
    sigmatch_table[DETECT_AL_DHCP_LEASETIME].Setup = DetectDHCPLeaseTimeSetup;
    sigmatch_table[DETECT_AL_DHCP_LEASETIME].Free = DetectDHCPLeaseTimeFree;

    DetectAppLayerInspectEngineRegister2("dhcp.leasetime", ALPROTO_DHCP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGenericList, NULL);

    DetectAppLayerInspectEngineRegister2("dhcp.leasetime", ALPROTO_DHCP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);

    g_buffer_id = DetectBufferTypeGetByName("dhcp.leasetime");
}
