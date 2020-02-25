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
#include "detect-ikev1-key-exchange-payload-length.h"
#include "app-layer-parser.h"
#include "util-byte.h"

#include "rust-bindings.h"

/**
 *   [ikev1.key_exchange_payload_length]:<client|server>[=|<|>|<=|>=]<length>;
 */
#define PARSE_REGEX "^\\s*(client|server)\\s*(=|<=|>=|<|>)\\s*([0-9]+)\\s*$"
static DetectParseRegex parse_regex;

enum DetectIkev1KeyExchangePayloadLengthCompareMode {
    PROCEDURE_EQ = 1, /* equal */
    PROCEDURE_LT, /* less than */
    PROCEDURE_LE, /* less than or equal */
    PROCEDURE_GT, /* greater than */
    PROCEDURE_GE, /* greater than or equal */
};

enum DetectIkev1KeyExchangePayloadLengthHost {
    HOST_CLIENT = 1,
    HOST_SERVER = 2
};

typedef struct {
    enum DetectIkev1KeyExchangePayloadLengthHost host_type;
    enum DetectIkev1KeyExchangePayloadLengthCompareMode mode;
    uint32_t length;
} DetectIkev1KeyExchangePayloadLengthData;

static DetectIkev1KeyExchangePayloadLengthData *DetectIkev1KeyExchangePayloadLengthParse (const char *);
static int DetectIkev1KeyExchangePayloadLengthSetup (DetectEngineCtx *, Signature *s, const char *str);
static void DetectIkev1KeyExchangePayloadLengthFree(DetectEngineCtx *, void *);
static int g_ikev1_key_exch_payload_length_buffer_id = 0;

static int DetectEngineInspectIkev1KeyExchangePayloadLengthGeneric(ThreadVars *tv,
                                                   DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                                                   const Signature *s, const SigMatchData *smd,
                                                   Flow *f, uint8_t flags, void *alstate,
                                                   void *txv, uint64_t tx_id);

static int DetectIkev1KeyExchangePayloadLengthMatch (DetectEngineThreadCtx *, Flow *,
                                     uint8_t, void *, void *, const Signature *,
                                     const SigMatchCtx *);

/**
 * \brief Registration function for ikev1.key_exchange_payload_length keyword.
 */
void DetectIkev1KeyExchangePayloadLengthRegister (void)
{
    sigmatch_table[DETECT_AL_IKEV1_KEY_EXCHANGE_PAYLOAD_LENGTH].name = "ikev1.key_exchange_payload_length";
    sigmatch_table[DETECT_AL_IKEV1_KEY_EXCHANGE_PAYLOAD_LENGTH].desc = "match IKEv1 key exchange payload length";
    sigmatch_table[DETECT_AL_IKEV1_KEY_EXCHANGE_PAYLOAD_LENGTH].url = "/rules/ikev1-keywords.html#ikev1-key-exchange-payload-length";
    sigmatch_table[DETECT_AL_IKEV1_KEY_EXCHANGE_PAYLOAD_LENGTH].AppLayerTxMatch = DetectIkev1KeyExchangePayloadLengthMatch;
    sigmatch_table[DETECT_AL_IKEV1_KEY_EXCHANGE_PAYLOAD_LENGTH].Setup = DetectIkev1KeyExchangePayloadLengthSetup;
    sigmatch_table[DETECT_AL_IKEV1_KEY_EXCHANGE_PAYLOAD_LENGTH].Free = DetectIkev1KeyExchangePayloadLengthFree;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    DetectAppLayerInspectEngineRegister("ikev1.key_exchange_payload_length",
                                        ALPROTO_IKEV1, SIG_FLAG_TOSERVER, 3,
                                        DetectEngineInspectIkev1KeyExchangePayloadLengthGeneric);

    DetectAppLayerInspectEngineRegister("ikev1.key_exchange_payload_length",
                                        ALPROTO_IKEV1, SIG_FLAG_TOCLIENT, 4,
                                        DetectEngineInspectIkev1KeyExchangePayloadLengthGeneric);

    g_ikev1_key_exch_payload_length_buffer_id = DetectBufferTypeGetByName("ikev1.key_exchange_payload_length");
}

static int DetectEngineInspectIkev1KeyExchangePayloadLengthGeneric(ThreadVars *tv,
                                                   DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                                                   const Signature *s, const SigMatchData *smd,
                                                   Flow *f, uint8_t flags, void *alstate,
                                                   void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(tv, de_ctx, det_ctx, s, smd,
                                          f, flags, alstate, txv, tx_id);
}

static inline int KeyExchangePayloadLengthMatch(const uint32_t connection_length,
                                enum DetectIkev1KeyExchangePayloadLengthCompareMode mode, uint32_t rule_length)
{
    switch (mode) {
        case PROCEDURE_EQ:
            if (connection_length == rule_length)
                SCReturnInt(1);
            break;
        case PROCEDURE_LT:
            if (connection_length < rule_length)
                SCReturnInt(1);
            break;
        case PROCEDURE_LE:
            if (connection_length <= rule_length)
                SCReturnInt(1);
            break;
        case PROCEDURE_GT:
            if (connection_length > rule_length)
                SCReturnInt(1);
            break;
        case PROCEDURE_GE:
            if (connection_length >= rule_length)
                SCReturnInt(1);
            break;
    }
    SCReturnInt(0);
}

/**
 * \internal
 * \brief Function to match key exchange payload length of a IKEv1 state
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the Ikev1 Transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectIkev1KeyExchangePayloadLengthData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectIkev1KeyExchangePayloadLengthMatch (DetectEngineThreadCtx *det_ctx,
                                     Flow *f, uint8_t flags, void *state,
                                     void *txv, const Signature *s,
                                     const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectIkev1KeyExchangePayloadLengthData *dd = (const DetectIkev1KeyExchangePayloadLengthData *)ctx;
    uint32_t length;
    if (!rs_ikev1_state_get_key_exchange_payload_length(state, dd->host_type, &length))
        SCReturnInt(0);
    if (KeyExchangePayloadLengthMatch(length, dd->mode, dd->length))
        SCReturnInt(1);
    SCReturnInt(0);
}

/**
 * \internal
 * \brief Function to parse options passed via ikev1.key_exchange_payload_length keywords.
 *
 * \param rawstr Pointer to the user provided options.
 *
 * \retval dd pointer to DetectIkev1KeyExchangePayloadLengthData on success.
 * \retval NULL on failure.
 */
static DetectIkev1KeyExchangePayloadLengthData *DetectIkev1KeyExchangePayloadLengthParse (const char *rawstr)
{
    DetectIkev1KeyExchangePayloadLengthData *dd = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    char host_type[10] = "";
    char mode[2] = "";
    char length[20] = "";

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 3 || ret > 5) {
        SCLogError(SC_ERR_PCRE_MATCH, "Parse error %s", rawstr);
        goto error;
    }

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, host_type,
                              sizeof(host_type));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, mode,
                              sizeof(mode));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 3, length,
                              sizeof(length));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    dd = SCCalloc(1, sizeof(DetectIkev1KeyExchangePayloadLengthData));
    if (unlikely(dd == NULL))
        goto error;

    if (strcmp(host_type, "client") == 0) {
        dd->host_type = HOST_CLIENT;
    } else if (strcmp(host_type, "server") == 0) {
        dd->host_type = HOST_SERVER;
    } else {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid mode for ikev1.key_exchange_payload_length keyword");
        goto error;
    }

    if (strlen(mode) == 1) {
        if (mode[0] == '=')
            dd->mode = PROCEDURE_EQ;
        else if (mode[0] == '<')
            dd->mode = PROCEDURE_LT;
        else if (mode[0] == '>')
            dd->mode = PROCEDURE_GT;
    } else if (strlen(mode) == 2) {
        if (strcmp(mode, "<=") == 0)
            dd->mode = PROCEDURE_LE;
        if (strcmp(mode, ">=") == 0)
            dd->mode = PROCEDURE_GE;
    } else {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid mode for ikev1.key_exchange_payload_length keyword");
        goto error;
    }

    /* set the first value */
    if (ByteExtractStringUint32(&dd->length, 10, strlen(length), length) <= 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid character as arg "
                                             "to ikev1.key_exchange_payload_length keyword");
        goto error;
    }

    return dd;

    error:
    if (dd)
        SCFree(dd);
    return NULL;
}

/**
 * \brief Function to add the parsed IKEv1 key exchange payload length query into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param rawstr Pointer to the user provided flags options.
 *
 * \retval 0 on Success.
 * \retval -1 on Failure.
 */
static int DetectIkev1KeyExchangePayloadLengthSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_IKEV1) != 0)
        return -1;

    DetectIkev1KeyExchangePayloadLengthData *dd = DetectIkev1KeyExchangePayloadLengthParse(rawstr);
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Parsing \'%s\' failed", rawstr);
        goto error;
    }

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_IKEV1_KEY_EXCHANGE_PAYLOAD_LENGTH;
    sm->ctx = (void *)dd;

    SigMatchAppendSMToList(s, sm, g_ikev1_key_exch_payload_length_buffer_id);
    return 0;

    error:
    DetectIkev1KeyExchangePayloadLengthFree(de_ctx, dd);
    return -1;
}

/**
 * \internal
 * \brief Function to free memory associated with DetectIkev1KeyExchangePayloadLengthData.
 *
 * \param de_ptr Pointer to DetectIkev1KeyExchangePayloadLengthData.
 */
static void DetectIkev1KeyExchangePayloadLengthFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}
