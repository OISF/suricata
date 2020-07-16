/* Copyright (C) 2021 Open Information Security Foundation
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
 * Implements the quic.version
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-uint.h"
#include "detect-quic-version.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "rust.h"

#ifdef UNITTESTS
static void DetectQuicVersionRegisterTests(void);
#endif

static int quic_version_id = 0;

static int DetectQuicVersionMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx);
static int DetectQuicVersionSetup(DetectEngineCtx *, Signature *, const char *);
void DetectQuicVersionFree(DetectEngineCtx *de_ctx, void *);

static int DetectEngineInspectQuicVersionGeneric(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const struct DetectEngineAppInspectionEngine_ *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);

/**
 * \brief Registration function for quic.version: keyword
 */
void DetectQuicVersionRegister(void)
{
    sigmatch_table[DETECT_AL_QUIC_VERSION].name = "quic.version";
    sigmatch_table[DETECT_AL_QUIC_VERSION].desc = "match Quic version";
    sigmatch_table[DETECT_AL_QUIC_VERSION].url = "/rules/quic-keywords.html#quic-version";
    sigmatch_table[DETECT_AL_QUIC_VERSION].AppLayerTxMatch = DetectQuicVersionMatch;
    sigmatch_table[DETECT_AL_QUIC_VERSION].Setup = DetectQuicVersionSetup;
    sigmatch_table[DETECT_AL_QUIC_VERSION].Free = DetectQuicVersionFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_QUIC_VERSION].RegisterTests = DetectQuicVersionRegisterTests;
#endif

    DetectAppLayerInspectEngineRegister2("quic.version", ALPROTO_QUIC, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectQuicVersionGeneric, NULL);

    quic_version_id = DetectBufferTypeGetByName("quic.version");
}

static int DetectEngineInspectQuicVersionGeneric(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const struct DetectEngineAppInspectionEngine_ *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(
            de_ctx, det_ctx, s, engine->smd, f, flags, alstate, txv, tx_id);
}

/**
 * \internal
 * \brief Function to match protocol version of an Quic Tx
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectQuicVersionData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectQuicVersionMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectU32Data *de = (const DetectU32Data *)ctx;
    uint32_t version;

    version = rs_quic_tx_get_version(txv);

    return DetectU32Match(version, de);
}

/**
 * \internal
 * \brief this function is used to add the parsed sigmatch  into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rawstr pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectQuicVersionSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    SigMatch *sm = NULL;
    DetectU32Data *de = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_QUIC) < 0)
        return -1;

    de = DetectU32Parse(rawstr);
    if (de == NULL)
        return -1;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_QUIC_VERSION;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, quic_version_id);

    return 0;

error:
    if (de != NULL)
        SCFree(de);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectQuicVersionData
 *
 * \param de pointer to DetectQuicVersionData
 */
void DetectQuicVersionFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    if (de_ptr != NULL)
        SCFree(de_ptr);
}

#ifdef UNITTESTS

/**
 * \test QuicVersionTestParse01 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int QuicVersionTestParse01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(
            de_ctx, "alert ip any any -> any any (quic.version:3; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(
            de_ctx, "alert ip any any -> any any (quic.version:3; sid:2; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test QuicVersionTestParse02 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int QuicVersionTestParse02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(
            de_ctx, "alert ip any any -> any any (quic.version:>3; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(
            de_ctx, "alert ip any any -> any any (quic.version:<44; sid:2; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test QuicVersionTestParse03 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int QuicVersionTestParse03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(
            de_ctx, "alert ip any any -> any any (quic.version:; sid:1; rev:1;)");
    FAIL_IF_NOT_NULL(sig);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test QuicVersionTestParse04 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int QuicVersionTestParse04(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(
            de_ctx, "alert ip any any -> any any (quic.version:<4294967296; sid:1; rev:1;)");
    FAIL_IF_NOT_NULL(sig);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \brief this function registers unit tests for QuicVersion
 */
void DetectQuicVersionRegisterTests(void)
{
    UtRegisterTest("QuicVersionTestParse01", QuicVersionTestParse01);
    UtRegisterTest("QuicVersionTestParse02", QuicVersionTestParse02);
    UtRegisterTest("QuicVersionTestParse03", QuicVersionTestParse03);
    UtRegisterTest("QuicVersionTestParse04", QuicVersionTestParse04);
}

#endif /* UNITTESTS */
