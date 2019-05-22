/* Copyright (C) 2015-2019 Open Information Security Foundation
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
#include "app-layer-parser.h"

#include "rust-snmp-snmp-gen.h"
#include "rust-snmp-detect-gen.h"

/**
 *   [snmp.version]:[<|>|<=|>=]<version>;
 */
#define PARSE_REGEX "^\\s*(<=|>=|<|>)?\\s*([0-9]+)\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

enum DetectSNMPVersionMode {
    PROCEDURE_EQ = 1, /* equal */
    PROCEDURE_LT, /* less than */
    PROCEDURE_LE, /* less than */
    PROCEDURE_GT, /* greater than */
    PROCEDURE_GE, /* greater than */
};

typedef struct DetectSNMPVersionData_ {
    uint32_t version;
    enum DetectSNMPVersionMode mode;
} DetectSNMPVersionData;

static DetectSNMPVersionData *DetectSNMPVersionParse (const char *);
static int DetectSNMPVersionSetup (DetectEngineCtx *, Signature *s, const char *str);
static void DetectSNMPVersionFree(void *);
#ifdef UNITTESTS
static void DetectSNMPVersionRegisterTests(void);
#endif
static int g_snmp_version_buffer_id = 0;

static int DetectEngineInspectSNMPRequestGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id);

static int DetectSNMPVersionMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);

/**
 * \brief Registration function for snmp.procedure keyword.
 */
void DetectSNMPVersionRegister (void)
{
    sigmatch_table[DETECT_AL_SNMP_VERSION].name = "snmp.version";
    sigmatch_table[DETECT_AL_SNMP_VERSION].desc = "match SNMP version";
    sigmatch_table[DETECT_AL_SNMP_VERSION].url = DOC_URL DOC_VERSION "/rules/snmp-keywords.html#snmp.version";
    sigmatch_table[DETECT_AL_SNMP_VERSION].Match = NULL;
    sigmatch_table[DETECT_AL_SNMP_VERSION].AppLayerTxMatch = DetectSNMPVersionMatch;
    sigmatch_table[DETECT_AL_SNMP_VERSION].Setup = DetectSNMPVersionSetup;
    sigmatch_table[DETECT_AL_SNMP_VERSION].Free = DetectSNMPVersionFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_SNMP_VERSION].RegisterTests = DetectSNMPVersionRegisterTests;
#endif
    sigmatch_table[DETECT_AL_SNMP_VERSION].flags |= SIGMATCH_NOOPT;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);

    DetectAppLayerInspectEngineRegister("snmp.version",
            ALPROTO_SNMP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectSNMPRequestGeneric);

    DetectAppLayerInspectEngineRegister("snmp.version",
            ALPROTO_SNMP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectSNMPRequestGeneric);

    g_snmp_version_buffer_id = DetectBufferTypeGetByName("snmp.version");
}

static int DetectEngineInspectSNMPRequestGeneric(ThreadVars *tv,
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
        enum DetectSNMPVersionMode mode, uint32_t ref_version)
{
    switch (mode) {
        case PROCEDURE_EQ:
            if (version == ref_version)
                SCReturnInt(1);
            break;
        case PROCEDURE_LT:
            if (version < ref_version)
                SCReturnInt(1);
            break;
        case PROCEDURE_LE:
            if (version <= ref_version)
                SCReturnInt(1);
            break;
        case PROCEDURE_GT:
            if (version > ref_version)
                SCReturnInt(1);
            break;
        case PROCEDURE_GE:
            if (version >= ref_version)
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
 *                DetectSNMPVersionData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectSNMPVersionMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectSNMPVersionData *dd = (const DetectSNMPVersionData *)ctx;
    uint32_t version;
    rs_snmp_tx_get_version(txv, &version);
    SCLogDebug("version %u mode %u ref_version %d",
            version, dd->mode, dd->version);
    if (VersionMatch(version, dd->mode, dd->version))
        SCReturnInt(1);
    SCReturnInt(0);
}

/**
 * \internal
 * \brief Function to parse options passed via snmp.version keywords.
 *
 * \param rawstr Pointer to the user provided options.
 *
 * \retval dd pointer to DetectSNMPVersionData on success.
 * \retval NULL on failure.
 */
static DetectSNMPVersionData *DetectSNMPVersionParse (const char *rawstr)
{
    DetectSNMPVersionData *dd = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    char mode[2] = "";
    char value1[20] = "";
    char *endptr = NULL;

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

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, value1,
                              sizeof(value1));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    dd = SCCalloc(1, sizeof(DetectSNMPVersionData));
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

    if (dd->mode == 0) {
        dd->mode = PROCEDURE_EQ;
    }

    /* set the first value */
    dd->version = strtoul(value1, &endptr, 10);
    if (endptr == NULL || *endptr != '\0') {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid character as arg "
                   "to snmp.version keyword");
        goto error;
    }

    return dd;

error:
    if (dd)
        SCFree(dd);
    return NULL;
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
    DetectSNMPVersionData *dd = NULL;
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

    SCLogDebug("snmp.version %d", dd->version);
    SigMatchAppendSMToList(s, sm, g_snmp_version_buffer_id);
    return 0;

error:
    DetectSNMPVersionFree(dd);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectSNMPVersionData.
 *
 * \param de_ptr Pointer to DetectSNMPVersionData.
 */
static void DetectSNMPVersionFree(void *ptr)
{
    SCFree(ptr);
}


#ifdef UNITTESTS
#include "tests/detect-snmp-version.c"
#endif /* UNITTESTS */
