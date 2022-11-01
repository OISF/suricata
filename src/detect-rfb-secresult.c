/* Copyright (C) 2020-2021 Open Information Security Foundation
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
 * \author Sascha Steinbiss <sascha.steinbiss@dcso.de>
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-rfb-secresult.h"

#include "rust.h"

#define PARSE_REGEX "\\S[A-z]"
static DetectParseRegex parse_regex;

static int rfb_secresult_id = 0;

static int DetectRfbSecresultMatch(DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx);
static int DetectRfbSecresultSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void RfbSecresultRegisterTests(void);
#endif
void DetectRfbSecresultFree(DetectEngineCtx *, void *);

typedef struct DetectRfbSecresultData_ {
    uint32_t result; /** result code */
} DetectRfbSecresultData;

/**
 * \brief Registration function for rfb.secresult: keyword
 */
void DetectRfbSecresultRegister (void)
{
    sigmatch_table[DETECT_AL_RFB_SECRESULT].name = "rfb.secresult";
    sigmatch_table[DETECT_AL_RFB_SECRESULT].desc = "match RFB security result";
    sigmatch_table[DETECT_AL_RFB_SECRESULT].url = "/rules/rfb-keywords.html#rfb-secresult";
    sigmatch_table[DETECT_AL_RFB_SECRESULT].AppLayerTxMatch = DetectRfbSecresultMatch;
    sigmatch_table[DETECT_AL_RFB_SECRESULT].Setup = DetectRfbSecresultSetup;
    sigmatch_table[DETECT_AL_RFB_SECRESULT].Free  = DetectRfbSecresultFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_RFB_SECRESULT].RegisterTests = RfbSecresultRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    DetectAppLayerInspectEngineRegister2("rfb.secresult", ALPROTO_RFB, SIG_FLAG_TOCLIENT, 1,
            DetectEngineInspectGenericList, NULL);

    rfb_secresult_id = DetectBufferTypeGetByName("rfb.secresult");
}

enum {
    RFB_SECRESULT_OK = 0,
    RFB_SECRESULT_FAIL,
    RFB_SECRESULT_TOOMANY,
    RFB_SECRESULT_UNKNOWN
};

/**
 * \struct DetectRfbSecresult_
 * DetectRfbSecresult_ is used to store values
 */

struct DetectRfbSecresult_ {
    const char *result;
    uint16_t code;
} results[] = {
    { "ok", RFB_SECRESULT_OK, },
    { "fail", RFB_SECRESULT_FAIL, },
    { "toomany", RFB_SECRESULT_TOOMANY, },
    { "unknown", RFB_SECRESULT_UNKNOWN, },
    { NULL, 0 },
};

/**
 * \internal
 * \brief Function to match security result of a RFB TX
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the RFBTransaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectRfbSecresultData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectRfbSecresultMatch(DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    const DetectRfbSecresultData *de = (const DetectRfbSecresultData *)ctx;
    uint32_t resultcode;
    int ret = 0;

    if (!de)
        return 0;

    ret = rs_rfb_tx_get_secresult(txv, &resultcode);
    if (ret == 0) {
        return 0;
    }

    if (de->result < 3) {
        /* we are asking for a defined code... */
        if (resultcode == de->result) {
            /* ... which needs to match */
            return 1;
        }
    } else {
        /* we are asking for an unknown code */
        if (resultcode > 2) {
            /* match any unknown code */
            return 1;
        }
    }

    return 0;
}

/**
 * \internal
 * \brief This function is used to parse options passed via rfb.secresults: keyword
 *
 * \param rawstr Pointer to the user provided secresult options
 *
 * \retval de pointer to DetectRfbSecresultData on success
 * \retval NULL on failure
 */
static DetectRfbSecresultData *DetectRfbSecresultParse (const char *rawstr)
{
    int i;
    DetectRfbSecresultData *de = NULL;
    int ret = 0, found = 0;

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret < 1) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, rawstr);
        goto error;
    }

    for(i = 0; results[i].result != NULL; i++)  {
        if((strcasecmp(results[i].result,rawstr)) == 0) {
            found = 1;
            break;
        }
    }

    if(found == 0) {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "unknown secresult value %s", rawstr);
        goto error;
    }

    de = SCMalloc(sizeof(DetectRfbSecresultData));
    if (unlikely(de == NULL))
        goto error;

    de->result = results[i].code;

    return de;

error:
    if (de) SCFree(de);
    return NULL;
}

/**
 * \internal
 * \brief this function is used to add the parsed secresult into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rawstr pointer to the user provided secresult options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectRfbSecresultSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectRfbSecresultData *de = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_RFB) < 0)
        return -1;

    de = DetectRfbSecresultParse(rawstr);
    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_RFB_SECRESULT;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, rfb_secresult_id);

    return 0;

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectRfbSecresultData
 *
 * \param de pointer to DetectRfbSecresultData
 */
void DetectRfbSecresultFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    DetectRfbSecresultData *de = (DetectRfbSecresultData *)de_ptr;
    if(de) SCFree(de);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test RfbSecresultTestParse01 is a test for a valid secresult value
 */
static int RfbSecresultTestParse01 (void)
{
    DetectRfbSecresultData *de = DetectRfbSecresultParse("fail");

    FAIL_IF_NULL(de);

    DetectRfbSecresultFree(NULL, de);

    PASS;
}

/**
 * \test RfbSecresultTestParse02 is a test for an invalid secresult value
 */
static int RfbSecresultTestParse02 (void)
{
    DetectRfbSecresultData *de = DetectRfbSecresultParse("invalidopt");

    FAIL_IF_NOT_NULL(de);

    PASS;
}

/**
 * \brief this function registers unit tests for RfbSecresult
 */
void RfbSecresultRegisterTests(void)
{
    UtRegisterTest("RfbSecresultTestParse01", RfbSecresultTestParse01);
    UtRegisterTest("RfbSecresultTestParse02", RfbSecresultTestParse02);
}
#endif /* UNITTESTS */
