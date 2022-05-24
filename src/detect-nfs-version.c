/* Copyright (C) 2017-2020 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-nfs-version.h"
#include "detect-engine-uint.h"

#include "app-layer-parser.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-byte.h"

#include "app-layer-nfs-tcp.h"
#include "rust.h"


static int DetectNfsVersionSetup (DetectEngineCtx *, Signature *s, const char *str);
static void DetectNfsVersionFree(DetectEngineCtx *de_ctx, void *);
static int g_nfs_request_buffer_id = 0;

static int DetectNfsVersionMatch (DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);

/**
 * \brief Registration function for nfs_procedure keyword.
 */
void DetectNfsVersionRegister (void)
{
    sigmatch_table[DETECT_AL_NFS_VERSION].name = "nfs.version";
    sigmatch_table[DETECT_AL_NFS_VERSION].alias = "nfs_version";
    sigmatch_table[DETECT_AL_NFS_VERSION].desc = "match NFS version";
    sigmatch_table[DETECT_AL_NFS_VERSION].url = "/rules/nfs-keywords.html#version";
    sigmatch_table[DETECT_AL_NFS_VERSION].AppLayerTxMatch = DetectNfsVersionMatch;
    sigmatch_table[DETECT_AL_NFS_VERSION].Setup = DetectNfsVersionSetup;
    sigmatch_table[DETECT_AL_NFS_VERSION].Free = DetectNfsVersionFree;
    // unit tests were the same as DetectNfsProcedureRegisterTests
    DetectAppLayerInspectEngineRegister2(
            "nfs_request", ALPROTO_NFS, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);

    g_nfs_request_buffer_id = DetectBufferTypeGetByName("nfs_request");

    SCLogDebug("g_nfs_request_buffer_id %d", g_nfs_request_buffer_id);
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
static int DetectNfsVersionMatch (DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectU32Data *dd = (const DetectU32Data *)ctx;
    uint32_t version;
    rs_nfs_tx_get_version(txv, &version);
    SCLogDebug("version %u mode %u lo %u hi %u", version, dd->mode, dd->arg1, dd->arg2);
    if (DetectU32Match(version, dd))
        SCReturnInt(1);
    SCReturnInt(0);
}

/**
 * \internal
 * \brief Function to parse options passed via tls validity keywords.
 *
 * \param rawstr Pointer to the user provided options.
 *
 * \retval dd pointer to DetectU32Data on success.
 * \retval NULL on failure.
 */
static DetectU32Data *DetectNfsVersionParse(const char *rawstr)
{
    return rs_detect_u32_parse_inclusive(rawstr);
}



/**
 * \brief Function to add the parsed tls validity field into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 * \param type   Defines if this is notBefore or notAfter.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectNfsVersionSetup (DetectEngineCtx *de_ctx, Signature *s,
                                   const char *rawstr)
{
    SCLogDebug("\'%s\'", rawstr);

    if (DetectSignatureSetAppProto(s, ALPROTO_NFS) != 0)
        return -1;

    DetectU32Data *dd = DetectNfsVersionParse(rawstr);
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Parsing \'%s\' failed", rawstr);
        return -1;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_NFS_VERSION;
    sm->ctx = (void *)dd;

    SCLogDebug("low %u hi %u", dd->arg1, dd->arg2);
    SigMatchAppendSMToList(s, sm, g_nfs_request_buffer_id);
    return 0;

error:
    DetectNfsVersionFree(de_ctx, dd);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectU32Data.
 *
 * \param de_ptr Pointer to DetectU32Data.
 */
void DetectNfsVersionFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u32_free(ptr);
}
