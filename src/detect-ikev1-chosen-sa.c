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
#include "detect-ikev1-chosen-sa.h"
#include "app-layer-parser.h"
#include "util-byte.h"
#include "util-unittest.h"

#include "rust-bindings.h"

/**
 *   [ikev1.chosen_sa_attribute]:<sa_attribute>=<type>;
 */

// support the basic attributes, which are parsed as integer and life_duration, if variable length is 4 it is stored as integer too
#define PARSE_REGEX "^\\s*(encryption_algorithm|hash_algorithm|authentication_method|group_description|group_type|life_type|life_duration|prf|key_length|field_size)\\s*=\\s*([0-9]+)\\s*$"
static DetectParseRegex parse_regex;

typedef struct {
    char *sa_type;
    uint32_t sa_value;
} DetectIkev1ChosenSaData;

static DetectIkev1ChosenSaData *DetectIkev1ChosenSaParse (const char *);
static int DetectIkev1ChosenSaSetup (DetectEngineCtx *, Signature *s, const char *str);
static void DetectIkev1ChosenSaFree(DetectEngineCtx *, void *);
static int g_ikev1_chosen_sa_buffer_id = 0;

static int DetectEngineInspectIkev1ChosenSaGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id);

static int DetectIkev1ChosenSaMatch (DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);
void IKEV1ChosenSaRegisterTests(void);

/**
 * \brief Registration function for ikev1.ChosenSa keyword.
 */
void DetectIkev1ChosenSaRegister (void)
{
    sigmatch_table[DETECT_AL_IKEV1_CHOSEN_SA].name = "ikev1.chosen_sa_attribute";
    sigmatch_table[DETECT_AL_IKEV1_CHOSEN_SA].desc = "match IKEv1 chosen SA Attribute";
    sigmatch_table[DETECT_AL_IKEV1_CHOSEN_SA].url = "/rules/ikev1-keywords.html#ikev1-chosen_sa_attribute";
    sigmatch_table[DETECT_AL_IKEV1_CHOSEN_SA].AppLayerTxMatch = DetectIkev1ChosenSaMatch;
    sigmatch_table[DETECT_AL_IKEV1_CHOSEN_SA].Setup = DetectIkev1ChosenSaSetup;
    sigmatch_table[DETECT_AL_IKEV1_CHOSEN_SA].Free = DetectIkev1ChosenSaFree;
    sigmatch_table[DETECT_AL_IKEV1_CHOSEN_SA].RegisterTests = IKEV1ChosenSaRegisterTests;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    DetectAppLayerInspectEngineRegister("ikev1.chosen_sa_attribute",
            ALPROTO_IKEV1, SIG_FLAG_TOCLIENT, 2,
            DetectEngineInspectIkev1ChosenSaGeneric);

    g_ikev1_chosen_sa_buffer_id = DetectBufferTypeGetByName("ikev1.chosen_sa_attribute");
}

static int DetectEngineInspectIkev1ChosenSaGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(tv, de_ctx, det_ctx, s, smd,
                                          f, flags, alstate, txv, tx_id);
}

/**
 * \internal
 * \brief Function to match SA attributes of a IKEv1 state
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the Ikev1 Transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectIkev1ChosenSaData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectIkev1ChosenSaMatch(DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectIkev1ChosenSaData *dd = (const DetectIkev1ChosenSaData *)ctx;

    uint32_t value;
    if (!rs_ikev1_state_get_sa_attribute(txv, dd->sa_type, &value))
        SCReturnInt(0);
    if (value == dd->sa_value)
        SCReturnInt(1);
    SCReturnInt(0);
}

/**
 * \internal
 * \brief Function to parse options passed via ikev1.chosen_sa_attribute keywords.
 *
 * \param rawstr Pointer to the user provided options.
 *
 * \retval dd pointer to DetectIkev1ChosenSaData on success.
 * \retval NULL on failure.
 */
static DetectIkev1ChosenSaData *DetectIkev1ChosenSaParse (const char *rawstr)
{
    /*
     * idea: do not implement one c file per type, invent an own syntax:
     * ikev1.chosen_sa_attribute:"encryption_algorithm=4"
     * ikev1.chosen_sa_attribute:"hash_algorithm=8"
     */
    DetectIkev1ChosenSaData *dd = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    char attribute[100];
    char value[100];

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 3 || ret > 5) {
        SCLogError(SC_ERR_PCRE_MATCH, "Parse error %s", rawstr);
        goto error;
    }

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, attribute,
                              sizeof(attribute));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, value,
                              sizeof(value));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    dd = SCCalloc(1, sizeof(DetectIkev1ChosenSaData));
    if (unlikely(dd == NULL))
        goto error;

    dd->sa_type = SCStrdup(attribute);
    if (dd->sa_type == NULL)
        goto error;


    if (ByteExtractStringUint32(&dd->sa_value, 10, strlen(value), value) <= 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid input as arg "
                                             "to ikev1.chosen_sa_attribute keyword");
        goto error;
    }

    return dd;

error:
    if (dd)
        SCFree(dd);
    return NULL;
}

/**
 * \brief Function to add the parsed IKEv1 SA attribute query into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectIkev1ChosenSaSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_IKEV1) != 0)
        return -1;

    DetectIkev1ChosenSaData *dd = DetectIkev1ChosenSaParse(rawstr);
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Parsing \'%s\' failed", rawstr);
        goto error;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_IKEV1_CHOSEN_SA;
    sm->ctx = (void *)dd;

    SigMatchAppendSMToList(s, sm, g_ikev1_chosen_sa_buffer_id);
    return 0;

error:
    DetectIkev1ChosenSaFree(de_ctx, dd);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectIkev1ChosenSaData.
 *
 * \param de_ptr Pointer to DetectIkev1ChosenSaData.
 */
static void DetectIkev1ChosenSaFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectIkev1ChosenSaData *dd = (DetectIkev1ChosenSaData *)ptr;
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
 * \test IKEV1ChosenSaParserTest is a test for valid values
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int IKEV1ChosenSaParserTest (void)
{
    DetectIkev1ChosenSaData *de = NULL;
    de = DetectIkev1ChosenSaParse("hash_algorithm=2");
    if (de) {
        DetectIkev1ChosenSaFree(NULL, de);
        return 1;
    }

    return 0;
}

#endif /* UNITTESTS */

void IKEV1ChosenSaRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("IKEV1ChosenSaParserTest", IKEV1ChosenSaParserTest);
#endif /* UNITTESTS */
}
