/* Copyright (C) 2017 Open Information Security Foundation
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
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-nfs3-procedure.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#ifndef HAVE_RUST
void DetectNfs3ProcedureRegister(void)
{
}

#else

#include "app-layer-nfs3.h"
#include "rust.h"
#include "rust-nfs-nfs3-gen.h"

/**
 *   [nfs3_procedure]:[<|>]<proc>[<><proc>];
 */
#define PARSE_REGEX "^\\s*(<=|>=|<|>)?\\s*([0-9]+)\\s*(?:(<>)\\s*([0-9]+))?\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

enum DetectNfs3ProcedureMode {
    PROCEDURE_EQ = 1, /* equal */
    PROCEDURE_LT, /* less than */
    PROCEDURE_LE, /* less than */
    PROCEDURE_GT, /* greater than */
    PROCEDURE_GE, /* greater than */
    PROCEDURE_RA, /* range */
};

typedef struct DetectNfs3ProcedureData_ {
    uint32_t lo;
    uint32_t hi;
    enum DetectNfs3ProcedureMode mode;
} DetectNfs3ProcedureData;

static DetectNfs3ProcedureData *DetectNfs3ProcedureParse (const char *);
static int DetectNfs3ProcedureSetup (DetectEngineCtx *, Signature *s, const char *str);
static void DetectNfs3ProcedureFree(void *);
static void DetectNfs3ProcedureRegisterTests(void);
static int g_nfs3_request_buffer_id = 0;

static int DetectEngineInspectNfs3RequestGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id);

static int DetectNfs3ProcedureMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);

/**
 * \brief Registration function for nfs3_procedure keyword.
 */
void DetectNfs3ProcedureRegister (void)
{
    sigmatch_table[DETECT_AL_NFS3_PROCEDURE].name = "nfs3_procedure";
    sigmatch_table[DETECT_AL_NFS3_PROCEDURE].desc = "match NFSv3 procedure";
    sigmatch_table[DETECT_AL_NFS3_PROCEDURE].url = DOC_URL DOC_VERSION "/rules/nfs3-keywords.html#procedure";
    sigmatch_table[DETECT_AL_NFS3_PROCEDURE].Match = NULL;
    sigmatch_table[DETECT_AL_NFS3_PROCEDURE].AppLayerTxMatch = DetectNfs3ProcedureMatch;
    sigmatch_table[DETECT_AL_NFS3_PROCEDURE].Setup = DetectNfs3ProcedureSetup;
    sigmatch_table[DETECT_AL_NFS3_PROCEDURE].Free = DetectNfs3ProcedureFree;
    sigmatch_table[DETECT_AL_NFS3_PROCEDURE].RegisterTests = DetectNfs3ProcedureRegisterTests;


    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);

    DetectAppLayerInspectEngineRegister("nfs3_request",
            ALPROTO_NFS3, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectNfs3RequestGeneric);

    g_nfs3_request_buffer_id = DetectBufferTypeGetByName("nfs3_request");

    SCLogDebug("g_nfs3_request_buffer_id %d", g_nfs3_request_buffer_id);
}

static int DetectEngineInspectNfs3RequestGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(tv, de_ctx, det_ctx, s, smd,
                                          f, flags, alstate, txv, tx_id);
}

static inline int
ProcedureMatch(const uint32_t procedure,
        enum DetectNfs3ProcedureMode mode, uint32_t lo, uint32_t hi)
{
    switch (mode) {
        case PROCEDURE_EQ:
            if (procedure == lo)
                SCReturnInt(1);
            break;
        case PROCEDURE_LT:
            if (procedure < lo)
                SCReturnInt(1);
            break;
        case PROCEDURE_LE:
            if (procedure <= lo)
                SCReturnInt(1);
            break;
        case PROCEDURE_GT:
            if (procedure > lo)
                SCReturnInt(1);
            break;
        case PROCEDURE_GE:
            if (procedure >= lo)
                SCReturnInt(1);
            break;
        case PROCEDURE_RA:
            if (procedure >= lo && procedure <= hi)
                SCReturnInt(1);
            break;
    }
    SCReturnInt(0);
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
 *                DetectNfs3ProcedureData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectNfs3ProcedureMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectNfs3ProcedureData *dd = (const DetectNfs3ProcedureData *)ctx;
    uint16_t i;
    for (i = 0; i < 256; i++) {
        uint32_t procedure;
        if (rs_nfs3_tx_get_procedures(txv, i, &procedure) == 1) {
            SCLogDebug("proc %u mode %u lo %u hi %u",
                    procedure, dd->mode, dd->lo, dd->hi);
            if (ProcedureMatch(procedure, dd->mode, dd->lo, dd->hi))
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
 * \retval dd pointer to DetectNfs3ProcedureData on success.
 * \retval NULL on failure.
 */
static DetectNfs3ProcedureData *DetectNfs3ProcedureParse (const char *rawstr)
{
    DetectNfs3ProcedureData *dd = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    char mode[2] = "";
    char value1[20] = "";
    char value2[20] = "";
    char range[3] = "";

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0,
                    0, ov, MAX_SUBSTRINGS);
    if (ret < 3 || ret > 5) {
        SCLogError(SC_ERR_PCRE_MATCH, "Parse error %s", rawstr);
        goto error;
    }

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, mode,
                              sizeof(mode));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }
    SCLogDebug("mode \"%s\"", mode);

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, value1,
                              sizeof(value1));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }
    SCLogDebug("value1 \"%s\"", value1);

    if (ret > 3) {
        res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 3,
                                  range, sizeof(range));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            goto error;
        }
        SCLogDebug("range \"%s\"", range);

        if (ret > 4) {
            res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 4,
                                      value2, sizeof(value2));
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING,
                           "pcre_copy_substring failed");
                goto error;
            }
            SCLogDebug("value2 \"%s\"", value2);
        }
    }

    dd = SCCalloc(1, sizeof(DetectNfs3ProcedureData));
    if (unlikely(dd == NULL))
        goto error;

    if (strlen(mode) == 1) {
        if (mode[0] == '<')
            dd->mode = PROCEDURE_LT;
        else if (mode[0] == '>')
            dd->mode = PROCEDURE_GT;
    } else if (strlen(mode) == 2) {
        if (strcmp(mode, "<=") == 0)
            dd->mode = PROCEDURE_LE;
        if (strcmp(mode, ">=") == 0)
            dd->mode = PROCEDURE_GE;
    }

    if (strlen(range) > 0) {
        if (strcmp("<>", range) == 0)
            dd->mode = PROCEDURE_RA;
    }

    if (strlen(range) != 0 && strlen(mode) != 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "Range specified but mode also set");
        goto error;
    }

    if (dd->mode == 0) {
        dd->mode = PROCEDURE_EQ;
    }

    /* set the first value */
    dd->lo = atoi(value1); //TODO

    /* set the second value if specified */
    if (strlen(value2) > 0) {
        if (!(dd->mode == PROCEDURE_RA)) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Multiple tls validity values specified but mode is not range");
            goto error;
        }

        //
        dd->hi = atoi(value2); // TODO

        if (dd->hi <= dd->lo) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Second value in range must not be smaller than the first");
            goto error;
        }
    }
    return dd;

error:
    if (dd)
        SCFree(dd);
    return NULL;
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
static int DetectNfs3ProcedureSetup (DetectEngineCtx *de_ctx, Signature *s,
                                   const char *rawstr)
{
    DetectNfs3ProcedureData *dd = NULL;
    SigMatch *sm = NULL;

    SCLogDebug("\'%s\'", rawstr);

    if (DetectSignatureSetAppProto(s, ALPROTO_NFS3) != 0)
        return -1;

    dd = DetectNfs3ProcedureParse(rawstr);
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Parsing \'%s\' failed", rawstr);
        goto error;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_NFS3_PROCEDURE;
    sm->ctx = (void *)dd;

    s->flags |= SIG_FLAG_STATE_MATCH;
    SCLogDebug("low %u hi %u", dd->lo, dd->hi);
    SigMatchAppendSMToList(s, sm, g_nfs3_request_buffer_id);
    return 0;

error:
    DetectNfs3ProcedureFree(dd);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectNfs3ProcedureData.
 *
 * \param de_ptr Pointer to DetectNfs3ProcedureData.
 */
void DetectNfs3ProcedureFree(void *ptr)
{
    SCFree(ptr);
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse("1430000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1430000000 && dd->mode == PROCEDURE_EQ);
    DetectNfs3ProcedureFree(dd);
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse(">1430000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1430000000 && dd->mode == PROCEDURE_GT);
    DetectNfs3ProcedureFree(dd);
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse("<1430000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1430000000 && dd->mode == PROCEDURE_LT);
    DetectNfs3ProcedureFree(dd);
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse("1430000000<>1470000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1430000000 && dd->hi == 1470000000 &&
                dd->mode == PROCEDURE_RA);
    DetectNfs3ProcedureFree(dd);
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse("A");
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse(">1430000000<>1470000000");
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse("1430000000<>");
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse("<>1430000000");
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse("");
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse(" ");
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse("1490000000<>1430000000");
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse("1430000000 <> 1490000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1430000000 && dd->hi == 1490000000 &&
                dd->mode == PROCEDURE_RA);
    DetectNfs3ProcedureFree(dd);
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse("> 1430000000 ");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1430000000 && dd->mode == PROCEDURE_GT);
    DetectNfs3ProcedureFree(dd);
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse("<   1490000000 ");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1490000000 && dd->mode == PROCEDURE_LT);
    DetectNfs3ProcedureFree(dd);
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
    DetectNfs3ProcedureData *dd = NULL;
    dd = DetectNfs3ProcedureParse("   1490000000 ");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1490000000 && dd->mode == PROCEDURE_EQ);
    DetectNfs3ProcedureFree(dd);
    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief Register unit tests for nfs3_procedure.
 */
void DetectNfs3ProcedureRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
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
#endif /* UNITTESTS */
}
#endif /* HAVE_RUST */
