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
#include "detect-ikev1-exch-type.h"
#include "app-layer-parser.h"
#include "util-byte.h"

#include "rust-bindings.h"

/**
 *   [ikev1.exchtype]:[<|>|<=|>=]<type>;
 */
#define PARSE_REGEX "^\\s*(<=|>=|<|>)?\\s*([0-9]+)\\s*$"
static DetectParseRegex parse_regex;

enum DetectIkev1ExchTypeCompareMode {
    PROCEDURE_EQ = 1, /* equal */
    PROCEDURE_LT, /* less than */
    PROCEDURE_LE, /* less than or equal */
    PROCEDURE_GT, /* greater than */
    PROCEDURE_GE, /* greater than or equal */
};

typedef struct {
    uint32_t exch_type;
    enum DetectIkev1ExchTypeCompareMode mode;
} DetectIkev1ExchTypeData;

static DetectIkev1ExchTypeData *DetectIkev1ExchTypeParse (const char *);
static int DetectIkev1ExchTypeSetup (DetectEngineCtx *, Signature *s, const char *str);
static void DetectIkev1ExchTypeFree(DetectEngineCtx *, void *);
static int g_ikev1_exch_type_buffer_id = 0;

static int DetectEngineInspectIkev1ExchTypeGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id);

static int DetectIkev1ExchTypeMatch (DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);

/**
 * \brief Registration function for ikev1.exchtype keyword.
 */
void DetectIkev1ExchTypeRegister (void)
{
    sigmatch_table[DETECT_AL_IKEV1_EXCH_TYPE].name = "ikev1.exchtype";
    sigmatch_table[DETECT_AL_IKEV1_EXCH_TYPE].desc = "match IKEv1 exchange type";
    sigmatch_table[DETECT_AL_IKEV1_EXCH_TYPE].url = "/rules/ikev1-keywords.html#ikev1-exchtype";
    sigmatch_table[DETECT_AL_IKEV1_EXCH_TYPE].AppLayerTxMatch = DetectIkev1ExchTypeMatch;
    sigmatch_table[DETECT_AL_IKEV1_EXCH_TYPE].Setup = DetectIkev1ExchTypeSetup;
    sigmatch_table[DETECT_AL_IKEV1_EXCH_TYPE].Free = DetectIkev1ExchTypeFree;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    DetectAppLayerInspectEngineRegister("ikev1.exchtype",
            ALPROTO_IKEV1, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectIkev1ExchTypeGeneric);

    DetectAppLayerInspectEngineRegister("ikev1.exchtype",
            ALPROTO_IKEV1, SIG_FLAG_TOCLIENT, 1,
            DetectEngineInspectIkev1ExchTypeGeneric);

    g_ikev1_exch_type_buffer_id = DetectBufferTypeGetByName("ikev1.exchtype");
}

static int DetectEngineInspectIkev1ExchTypeGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(tv, de_ctx, det_ctx, s, smd,
                                          f, flags, alstate, txv, tx_id);
}

static inline int ExchTypeMatch(const uint32_t exch_type,
        enum DetectIkev1ExchTypeCompareMode mode, uint32_t ref_exch_type)
{
    switch (mode) {
        case PROCEDURE_EQ:
            if (exch_type == ref_exch_type)
                SCReturnInt(1);
            break;
        case PROCEDURE_LT:
            if (exch_type < ref_exch_type)
                SCReturnInt(1);
            break;
        case PROCEDURE_LE:
            if (exch_type <= ref_exch_type)
                SCReturnInt(1);
            break;
        case PROCEDURE_GT:
            if (exch_type > ref_exch_type)
                SCReturnInt(1);
            break;
        case PROCEDURE_GE:
            if (exch_type >= ref_exch_type)
                SCReturnInt(1);
            break;
    }
    SCReturnInt(0);
}

/**
 * \internal
 * \brief Function to match exchange type of a IKEv1 state
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the Ikev1 Transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectIkev1ExchTypeData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectIkev1ExchTypeMatch (DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectIkev1ExchTypeData *dd = (const DetectIkev1ExchTypeData *)ctx;
    uint32_t exch_type;
    if (!rs_ikev1_state_get_exch_type(txv, &exch_type))
        SCReturnInt(0);
    if (ExchTypeMatch(exch_type, dd->mode, dd->exch_type))
        SCReturnInt(1);
    SCReturnInt(0);
}

/**
 * \internal
 * \brief Function to parse options passed via ikev1.exchtype keywords.
 *
 * \param rawstr Pointer to the user provided options.
 *
 * \retval dd pointer to DetectIkev1ExchTypeData on success.
 * \retval NULL on failure.
 */
static DetectIkev1ExchTypeData *DetectIkev1ExchTypeParse (const char *rawstr)
{
    DetectIkev1ExchTypeData *dd = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    char mode[2] = "";
    char value1[20] = "";

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0, ov, MAX_SUBSTRINGS);
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

    dd = SCCalloc(1, sizeof(DetectIkev1ExchTypeData));
    if (unlikely(dd == NULL))
        goto error;

    if (strlen(mode) == 0) {
        dd->mode = PROCEDURE_EQ;
    } else if (strlen(mode) == 1) {
        if (mode[0] == '<')
            dd->mode = PROCEDURE_LT;
        else if (mode[0] == '>')
            dd->mode = PROCEDURE_GT;
    } else if (strlen(mode) == 2) {
        if (strcmp(mode, "<=") == 0)
            dd->mode = PROCEDURE_LE;
        if (strcmp(mode, ">=") == 0)
            dd->mode = PROCEDURE_GE;
    } else {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid mode for ikev1.exchtype keyword");
        goto error;
    }

    if (dd->mode == 0) {
        dd->mode = PROCEDURE_EQ;
    }

    /* set the first value */
    if (ByteExtractStringUint32(&dd->exch_type, 10, strlen(value1), value1) <= 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid character as arg "
                   "to ikev1.exchtype keyword");
        goto error;
    }

    return dd;

error:
    if (dd)
        SCFree(dd);
    return NULL;
}

/**
 * \brief Function to add the parsed IKEv1 exchange type field into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectIkev1ExchTypeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_IKEV1) != 0)
        return -1;

    DetectIkev1ExchTypeData *dd = DetectIkev1ExchTypeParse(rawstr);
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Parsing \'%s\' failed", rawstr);
        goto error;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_IKEV1_EXCH_TYPE;
    sm->ctx = (void *)dd;

    SigMatchAppendSMToList(s, sm, g_ikev1_exch_type_buffer_id);
    return 0;

error:
    DetectIkev1ExchTypeFree(de_ctx, dd);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectIkev1ExchTypeData.
 *
 * \param de_ptr Pointer to DetectIkev1ExchTypeData.
 */
static void DetectIkev1ExchTypeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}
