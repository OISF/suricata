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
#include "detect-nfs-procedure.h"
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

static int DetectNfsProcedureSetup (DetectEngineCtx *, Signature *s, const char *str);
static void DetectNfsProcedureFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectNfsProcedureRegisterTests(void);
#endif
static int g_nfs_request_buffer_id = 0;

static int DetectNfsProcedureMatch (DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);

/**
 * \brief Registration function for nfs_procedure keyword.
 */
void DetectNfsProcedureRegister (void)
{
    sigmatch_table[DETECT_NFS_PROCEDURE].name = "nfs_procedure";
    sigmatch_table[DETECT_NFS_PROCEDURE].desc = "match NFS procedure";
    sigmatch_table[DETECT_NFS_PROCEDURE].url = "/rules/nfs-keywords.html#procedure";
    sigmatch_table[DETECT_NFS_PROCEDURE].Match = NULL;
    sigmatch_table[DETECT_NFS_PROCEDURE].AppLayerTxMatch = DetectNfsProcedureMatch;
    sigmatch_table[DETECT_NFS_PROCEDURE].Setup = DetectNfsProcedureSetup;
    sigmatch_table[DETECT_NFS_PROCEDURE].Free = DetectNfsProcedureFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_NFS_PROCEDURE].RegisterTests = DetectNfsProcedureRegisterTests;
#endif

    DetectAppLayerInspectEngineRegister(
            "nfs_request", ALPROTO_NFS, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);

    g_nfs_request_buffer_id = DetectBufferTypeGetByName("nfs_request");

    SCLogDebug("g_nfs_request_buffer_id %d", g_nfs_request_buffer_id);
}

/**
 * \internal
 * \brief Function to match procedure of a TX
 *
 * For 'file txs'
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
static int DetectNfsProcedureMatch (DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectU32Data *dd = (const DetectU32Data *)ctx;
    uint16_t i;
    for (i = 0; i < 256; i++) {
        uint32_t procedure;
        if (SCNfsTxGetProcedures(txv, i, &procedure) == 1) {
            SCLogDebug("proc %u mode %u lo %u hi %u", procedure, dd->mode, dd->arg1, dd->arg2);
            if (DetectU32Match(procedure, dd))
                SCReturnInt(1);
            continue;
        }
        break;
    }
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
static DetectU32Data *DetectNfsProcedureParse(const char *rawstr)
{
    return SCDetectU32ParseInclusive(rawstr);
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
static int DetectNfsProcedureSetup (DetectEngineCtx *de_ctx, Signature *s,
                                   const char *rawstr)
{
    DetectU32Data *dd = NULL;

    SCLogDebug("\'%s\'", rawstr);

    if (SCDetectSignatureSetAppProto(s, ALPROTO_NFS) != 0)
        return -1;

    dd = DetectNfsProcedureParse(rawstr);
    if (dd == NULL) {
        SCLogError("Parsing \'%s\' failed", rawstr);
        return -1;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */

    SCLogDebug("low %u hi %u", dd->arg1, dd->arg2);
    if (SigMatchAppendSMToList(de_ctx, s, DETECT_NFS_PROCEDURE, (SigMatchCtx *)dd,
                g_nfs_request_buffer_id) == NULL) {
        DetectNfsProcedureFree(de_ctx, dd);
        return -1;
    }
    return 0;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectU32Data.
 *
 * \param de_ptr Pointer to DetectU32Data.
 */
void DetectNfsProcedureFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU32Free(ptr);
}

#ifdef UNITTESTS

/**
 * \test This is a test for a valid value 1430000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse01 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse("1430000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 1430000000 && dd->mode == DETECT_UINT_EQ);
    DetectNfsProcedureFree(NULL, dd);
    PASS;
}

/**
 * \test This is a test for a valid value >1430000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse02 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse(">1430000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 1430000000 && dd->mode == DETECT_UINT_GT);
    DetectNfsProcedureFree(NULL, dd);
    PASS;
}

/**
 * \test This is a test for a valid value <1430000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse03 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse("<1430000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 1430000000 && dd->mode == DETECT_UINT_LT);
    DetectNfsProcedureFree(NULL, dd);
    PASS;
}

/**
 * \test This is a test for a valid value 1430000000<>1470000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse04 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse("1430000001<>1470000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 1430000000 && dd->arg2 == 1470000001 && dd->mode == DETECT_UINT_RA);
    DetectNfsProcedureFree(NULL, dd);
    PASS;
}

/**
 * \test This is a test for a invalid value A.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse05 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse("A");
    FAIL_IF_NOT_NULL(dd);
    PASS;
}

/**
 * \test This is a test for a invalid value >1430000000<>1470000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse06 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse(">1430000000<>1470000000");
    FAIL_IF_NOT_NULL(dd);
    PASS;
}

/**
 * \test This is a test for a invalid value 1430000000<>.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse07 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse("1430000000<>");
    FAIL_IF_NOT_NULL(dd);
    PASS;
}

/**
 * \test This is a test for a invalid value <>1430000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse08 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse("<>1430000000");
    FAIL_IF_NOT_NULL(dd);
    PASS;
}

/**
 * \test This is a test for a invalid value "".
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse09 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse("");
    FAIL_IF_NOT_NULL(dd);
    PASS;
}

/**
 * \test This is a test for a invalid value " ".
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse10 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse(" ");
    FAIL_IF_NOT_NULL(dd);
    PASS;
}

/**
 * \test This is a test for a invalid value 1490000000<>1430000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse11 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse("1490000000<>1430000000");
    FAIL_IF_NOT_NULL(dd);
    PASS;
}

/**
 * \test This is a test for a valid value 1430000000 <> 1490000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse12 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse("1430000001 <> 1490000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 1430000000 && dd->arg2 == 1490000001 && dd->mode == DETECT_UINT_RA);
    DetectNfsProcedureFree(NULL, dd);
    PASS;
}

/**
 * \test This is a test for a valid value > 1430000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse13 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse("> 1430000000 ");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 1430000000 && dd->mode == DETECT_UINT_GT);
    DetectNfsProcedureFree(NULL, dd);
    PASS;
}

/**
 * \test This is a test for a valid value <   1490000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse14 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse("<   1490000000 ");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 1490000000 && dd->mode == DETECT_UINT_LT);
    DetectNfsProcedureFree(NULL, dd);
    PASS;
}

/**
 * \test This is a test for a valid value    1490000000.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int ValidityTestParse15 (void)
{
    DetectU32Data *dd = NULL;
    dd = DetectNfsProcedureParse("   1490000000 ");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 1490000000 && dd->mode == DETECT_UINT_EQ);
    DetectNfsProcedureFree(NULL, dd);
    PASS;
}

/**
 * \brief Register unit tests for nfs_procedure.
 */
void DetectNfsProcedureRegisterTests(void)
{
    UtRegisterTest("ValidityTestParse01", ValidityTestParse01);
    UtRegisterTest("ValidityTestParse02", ValidityTestParse02);
    UtRegisterTest("ValidityTestParse03", ValidityTestParse03);
    UtRegisterTest("ValidityTestParse04", ValidityTestParse04);
    UtRegisterTest("ValidityTestParse05", ValidityTestParse05);
    UtRegisterTest("ValidityTestParse06", ValidityTestParse06);
    UtRegisterTest("ValidityTestParse07", ValidityTestParse07);
    UtRegisterTest("ValidityTestParse08", ValidityTestParse08);
    UtRegisterTest("ValidityTestParse09", ValidityTestParse09);
    UtRegisterTest("ValidityTestParse10", ValidityTestParse10);
    UtRegisterTest("ValidityTestParse11", ValidityTestParse11);
    UtRegisterTest("ValidityTestParse12", ValidityTestParse12);
    UtRegisterTest("ValidityTestParse13", ValidityTestParse13);
    UtRegisterTest("ValidityTestParse14", ValidityTestParse14);
    UtRegisterTest("ValidityTestParse15", ValidityTestParse15);
}
#endif /* UNITTESTS */
