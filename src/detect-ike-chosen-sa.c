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
 * \author Frank Honza <frank.honza@dcso.de>
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-ike-chosen-sa.h"
#include "app-layer-parser.h"
#include "util-byte.h"
#include "util-unittest.h"

#include "rust-bindings.h"

/**
 *   [ike.chosen_sa_attribute]:<sa_attribute>=<type>;
 */

// support the basic attributes, which are parsed as integer and life_duration, if variable length
// is 4 it is stored as integer too
#define PARSE_REGEX                                                                                \
    "^\\s*(alg_enc|alg_hash|alg_auth|alg_dh|\
sa_group_type|sa_life_type|sa_life_duration|alg_prf|sa_key_length|sa_field_size)\
\\s*=\\s*([0-9]+)\\s*$"

static DetectParseRegex parse_regex;

typedef struct {
    char *sa_type;
    uint32_t sa_value;
} DetectIkeChosenSaData;

static DetectIkeChosenSaData *DetectIkeChosenSaParse(const char *);
static int DetectIkeChosenSaSetup(DetectEngineCtx *, Signature *s, const char *str);
static void DetectIkeChosenSaFree(DetectEngineCtx *, void *);
static int g_ike_chosen_sa_buffer_id = 0;

static int DetectIkeChosenSaMatch(DetectEngineThreadCtx *, Flow *, uint8_t, void *, void *,
        const Signature *, const SigMatchCtx *);
void IKEChosenSaRegisterTests(void);

/**
 * \brief Registration function for ike.ChosenSa keyword.
 */
void DetectIkeChosenSaRegister(void)
{
    sigmatch_table[DETECT_AL_IKE_CHOSEN_SA].name = "ike.chosen_sa_attribute";
    sigmatch_table[DETECT_AL_IKE_CHOSEN_SA].desc = "match IKE chosen SA Attribute";
    sigmatch_table[DETECT_AL_IKE_CHOSEN_SA].url =
            "/rules/ike-keywords.html#ike-chosen_sa_attribute";
    sigmatch_table[DETECT_AL_IKE_CHOSEN_SA].AppLayerTxMatch = DetectIkeChosenSaMatch;
    sigmatch_table[DETECT_AL_IKE_CHOSEN_SA].Setup = DetectIkeChosenSaSetup;
    sigmatch_table[DETECT_AL_IKE_CHOSEN_SA].Free = DetectIkeChosenSaFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_IKE_CHOSEN_SA].RegisterTests = IKEChosenSaRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    DetectAppLayerInspectEngineRegister2("ike.chosen_sa_attribute", ALPROTO_IKE, SIG_FLAG_TOCLIENT,
            1, DetectEngineInspectGenericList, NULL);

    g_ike_chosen_sa_buffer_id = DetectBufferTypeGetByName("ike.chosen_sa_attribute");
}

/**
 * \internal
 * \brief Function to match SA attributes of a IKE state
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the Ike Transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectIkeChosenSaData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectIkeChosenSaMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectIkeChosenSaData *dd = (const DetectIkeChosenSaData *)ctx;

    uint32_t value;
    if (!rs_ike_state_get_sa_attribute(txv, dd->sa_type, &value))
        SCReturnInt(0);
    if (value == dd->sa_value)
        SCReturnInt(1);
    SCReturnInt(0);
}

/**
 * \internal
 * \brief Function to parse options passed via ike.chosen_sa_attribute keywords.
 *
 * \param rawstr Pointer to the user provided options.
 *
 * \retval dd pointer to DetectIkeChosenSaData on success.
 * \retval NULL on failure.
 */
static DetectIkeChosenSaData *DetectIkeChosenSaParse(const char *rawstr)
{
    /*
     * idea: do not implement one c file per type, invent an own syntax:
     * ike.chosen_sa_attribute:"encryption_algorithm=4"
     * ike.chosen_sa_attribute:"hash_algorithm=8"
     */
    DetectIkeChosenSaData *dd = NULL;
    int ret = 0, res = 0;
    size_t pcre2len;
    char attribute[100];
    char value[100];

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret < 3 || ret > 5) {
        SCLogError(SC_ERR_PCRE_MATCH,
                "pcre match for ike.chosen_sa_attribute failed, should be: <sa_attribute>=<type>, "
                "but was: %s; error code %d",
                rawstr, ret);
        goto error;
    }

    pcre2len = sizeof(attribute);
    res = pcre2_substring_copy_bynumber(parse_regex.match, 1, (PCRE2_UCHAR8 *)attribute, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        goto error;
    }

    pcre2len = sizeof(value);
    res = pcre2_substring_copy_bynumber(parse_regex.match, 2, (PCRE2_UCHAR8 *)value, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        goto error;
    }

    dd = SCCalloc(1, sizeof(DetectIkeChosenSaData));
    if (unlikely(dd == NULL))
        goto error;

    dd->sa_type = SCStrdup(attribute);
    if (dd->sa_type == NULL)
        goto error;

    if (ByteExtractStringUint32(&dd->sa_value, 10, strlen(value), value) <= 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid input as arg "
                                             "to ike.chosen_sa_attribute keyword");
        goto error;
    }

    return dd;

error:
    if (dd) {
        if (dd->sa_type != NULL)
            SCFree(dd->sa_type);
        SCFree(dd);
    }
    return NULL;
}

/**
 * \brief Function to add the parsed IKE SA attribute query into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectIkeChosenSaSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_IKE) != 0)
        return -1;

    DetectIkeChosenSaData *dd = DetectIkeChosenSaParse(rawstr);
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Parsing \'%s\' failed", rawstr);
        goto error;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_IKE_CHOSEN_SA;
    sm->ctx = (void *)dd;

    SigMatchAppendSMToList(s, sm, g_ike_chosen_sa_buffer_id);
    return 0;

error:
    DetectIkeChosenSaFree(de_ctx, dd);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectIkeChosenSaData.
 *
 * \param de_ptr Pointer to DetectIkeChosenSaData.
 */
static void DetectIkeChosenSaFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectIkeChosenSaData *dd = (DetectIkeChosenSaData *)ptr;
    if (dd == NULL)
        return;
    if (dd->sa_type != NULL)
        SCFree(dd->sa_type);

    SCFree(ptr);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS

/**
 * \test IKEChosenSaParserTest is a test for valid values
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int IKEChosenSaParserTest(void)
{
    DetectIkeChosenSaData *de = NULL;
    de = DetectIkeChosenSaParse("alg_hash=2");

    FAIL_IF_NULL(de);
    FAIL_IF(de->sa_value != 2);
    FAIL_IF(strcmp(de->sa_type, "alg_hash") != 0);

    DetectIkeChosenSaFree(NULL, de);
    PASS;
}

#endif /* UNITTESTS */

void IKEChosenSaRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("IKEChosenSaParserTest", IKEChosenSaParserTest);
#endif /* UNITTESTS */
}
