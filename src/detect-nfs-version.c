/* Copyright (C) 2017-2019 Open Information Security Foundation
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
#include "detect-nfs-version.h"

#include "app-layer-parser.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer-nfs-tcp.h"
#include "rust.h"
#include "rust-nfs-nfs-gen.h"

/**
 *   [nfs_procedure]:[<|>]<proc>[<><proc>];
 */
#define PARSE_REGEX "^\\s*(<=|>=|<|>)?\\s*([0-9]+)\\s*(?:(<>)\\s*([0-9]+))?\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

enum DetectNfsVersionMode {
    PROCEDURE_EQ = 1, /* equal */
    PROCEDURE_LT, /* less than */
    PROCEDURE_LE, /* less than */
    PROCEDURE_GT, /* greater than */
    PROCEDURE_GE, /* greater than */
    PROCEDURE_RA, /* range */
};

typedef struct DetectNfsVersionData_ {
    uint32_t lo;
    uint32_t hi;
    enum DetectNfsVersionMode mode;
} DetectNfsVersionData;

static DetectNfsVersionData *DetectNfsVersionParse (const char *);
static int DetectNfsVersionSetup (DetectEngineCtx *, Signature *s, const char *str);
static void DetectNfsVersionFree(void *);
static void DetectNfsVersionRegisterTests(void);
static int g_nfs_request_buffer_id = 0;

static int DetectEngineInspectNfsRequestGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id);

static int DetectNfsVersionMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *,
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
    sigmatch_table[DETECT_AL_NFS_VERSION].url = DOC_URL DOC_VERSION "/rules/nfs-keywords.html#version";
    sigmatch_table[DETECT_AL_NFS_VERSION].AppLayerTxMatch = DetectNfsVersionMatch;
    sigmatch_table[DETECT_AL_NFS_VERSION].Setup = DetectNfsVersionSetup;
    sigmatch_table[DETECT_AL_NFS_VERSION].Free = DetectNfsVersionFree;
    sigmatch_table[DETECT_AL_NFS_VERSION].RegisterTests = DetectNfsVersionRegisterTests;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);

    DetectAppLayerInspectEngineRegister("nfs_request",
            ALPROTO_NFS, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectNfsRequestGeneric);

    g_nfs_request_buffer_id = DetectBufferTypeGetByName("nfs_request");

    SCLogDebug("g_nfs_request_buffer_id %d", g_nfs_request_buffer_id);
}

static int DetectEngineInspectNfsRequestGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(tv, de_ctx, det_ctx, s, smd,
                                          f, flags, alstate, txv, tx_id);
}

static inline int
VersionMatch(const uint32_t version,
        enum DetectNfsVersionMode mode, uint32_t lo, uint32_t hi)
{
    switch (mode) {
        case PROCEDURE_EQ:
            if (version == lo)
                SCReturnInt(1);
            break;
        case PROCEDURE_LT:
            if (version < lo)
                SCReturnInt(1);
            break;
        case PROCEDURE_LE:
            if (version <= lo)
                SCReturnInt(1);
            break;
        case PROCEDURE_GT:
            if (version > lo)
                SCReturnInt(1);
            break;
        case PROCEDURE_GE:
            if (version >= lo)
                SCReturnInt(1);
            break;
        case PROCEDURE_RA:
            if (version >= lo && version <= hi)
                SCReturnInt(1);
            break;
    }
    SCReturnInt(0);
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
 *                DetectNfsVersionData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectNfsVersionMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectNfsVersionData *dd = (const DetectNfsVersionData *)ctx;
    uint32_t version;
    rs_nfs_tx_get_version(txv, &version);
    SCLogDebug("version %u mode %u lo %u hi %u",
            version, dd->mode, dd->lo, dd->hi);
    if (VersionMatch(version, dd->mode, dd->lo, dd->hi))
        SCReturnInt(1);
    SCReturnInt(0);
}

/**
 * \internal
 * \brief Function to parse options passed via tls validity keywords.
 *
 * \param rawstr Pointer to the user provided options.
 *
 * \retval dd pointer to DetectNfsVersionData on success.
 * \retval NULL on failure.
 */
static DetectNfsVersionData *DetectNfsVersionParse (const char *rawstr)
{
    DetectNfsVersionData *dd = NULL;
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

    dd = SCCalloc(1, sizeof(DetectNfsVersionData));
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
static int DetectNfsVersionSetup (DetectEngineCtx *de_ctx, Signature *s,
                                   const char *rawstr)
{
    SCLogDebug("\'%s\'", rawstr);

    if (DetectSignatureSetAppProto(s, ALPROTO_NFS) != 0)
        return -1;

    DetectNfsVersionData *dd = DetectNfsVersionParse(rawstr);
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

    SCLogDebug("low %u hi %u", dd->lo, dd->hi);
    SigMatchAppendSMToList(s, sm, g_nfs_request_buffer_id);
    return 0;

error:
    DetectNfsVersionFree(dd);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectNfsVersionData.
 *
 * \param de_ptr Pointer to DetectNfsVersionData.
 */
void DetectNfsVersionFree(void *ptr)
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse("1430000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1430000000 && dd->mode == PROCEDURE_EQ);
    DetectNfsVersionFree(dd);
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse(">1430000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1430000000 && dd->mode == PROCEDURE_GT);
    DetectNfsVersionFree(dd);
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse("<1430000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1430000000 && dd->mode == PROCEDURE_LT);
    DetectNfsVersionFree(dd);
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse("1430000000<>1470000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1430000000 && dd->hi == 1470000000 &&
                dd->mode == PROCEDURE_RA);
    DetectNfsVersionFree(dd);
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse("A");
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse(">1430000000<>1470000000");
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse("1430000000<>");
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse("<>1430000000");
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse("");
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse(" ");
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse("1490000000<>1430000000");
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse("1430000000 <> 1490000000");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1430000000 && dd->hi == 1490000000 &&
                dd->mode == PROCEDURE_RA);
    DetectNfsVersionFree(dd);
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse("> 1430000000 ");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1430000000 && dd->mode == PROCEDURE_GT);
    DetectNfsVersionFree(dd);
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse("<   1490000000 ");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1490000000 && dd->mode == PROCEDURE_LT);
    DetectNfsVersionFree(dd);
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
    DetectNfsVersionData *dd = NULL;
    dd = DetectNfsVersionParse("   1490000000 ");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->lo == 1490000000 && dd->mode == PROCEDURE_EQ);
    DetectNfsVersionFree(dd);
    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief Register unit tests for nfs_procedure.
 */
void DetectNfsVersionRegisterTests(void)
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
