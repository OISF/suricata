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
 * \file
 *
 * \author Sascha Steinbiss <sascha@steinbiss.name>
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "util-unittest.h"
#include "detect-engine-content-inspection.h"
#include "detect.h"
#include "conf.h"
#endif
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-mqtt-reason-code.h"
#include "util-byte.h"

#include "rust.h"

#define PARSE_REGEX "^\\s*\\d+\\s*$"
static DetectParseRegex parse_regex;

static int mqtt_reason_code_id = 0;

static int DetectMQTTReasonCodeMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx);
static int DetectMQTTReasonCodeSetup (DetectEngineCtx *, Signature *, const char *);
void MQTTReasonCodeRegisterTests(void);
void DetectMQTTReasonCodeFree(DetectEngineCtx *de_ctx, void *);

/**
 * \brief Registration function for mqtt.reason_code: keyword
 */
void DetectMQTTReasonCodeRegister (void)
{
    sigmatch_table[DETECT_AL_MQTT_REASON_CODE].name = "mqtt.reason_code";
    sigmatch_table[DETECT_AL_MQTT_REASON_CODE].alias = "mqtt.connack.return_code";
    sigmatch_table[DETECT_AL_MQTT_REASON_CODE].desc = "match MQTT 5.0+ reason code";
    sigmatch_table[DETECT_AL_MQTT_REASON_CODE].url = "/rules/mqtt-keywords.html#mqtt-reason-code";
    sigmatch_table[DETECT_AL_MQTT_REASON_CODE].AppLayerTxMatch = DetectMQTTReasonCodeMatch;
    sigmatch_table[DETECT_AL_MQTT_REASON_CODE].Setup = DetectMQTTReasonCodeSetup;
    sigmatch_table[DETECT_AL_MQTT_REASON_CODE].Free  = DetectMQTTReasonCodeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_MQTT_REASON_CODE].RegisterTests = MQTTReasonCodeRegisterTests;
#endif

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    DetectAppLayerInspectEngineRegister2("mqtt.reason_code", ALPROTO_MQTT, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectGenericList, NULL);

    mqtt_reason_code_id = DetectBufferTypeGetByName("mqtt.reason_code");
}

/**
 * \internal
 * \brief Function to match reason code of an MQTT 5.0 Tx
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectMQTTReasonCodeData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectMQTTReasonCodeMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx)
{
    const uint8_t *de = (const uint8_t *)ctx;
    uint8_t code;

    if (!de)
        return 0;

    if (rs_mqtt_tx_get_reason_code(txv, &code) == 0) {
        /* this function does not return a code that needs to be compared,
           so we can just return the result of the check implemented in
           Rust */
        return rs_mqtt_tx_unsuback_has_reason_code(txv, *de);
    } else {
        if (code == *de)
            return 1;
    }
    return 0;
}

/**
 * \internal
 * \brief This function is used to parse options passed via mqtt.reason_code: keyword
 *
 * \param rawstr Pointer to the user provided options
 *
 * \retval de pointer to DetectMQTTReasonCodeData on success
 * \retval NULL on failure
 */
static uint8_t *DetectMQTTReasonCodeParse(const char *rawstr)
{
    uint8_t *de = NULL;
    int ret = 0;
    uint8_t val;

    ret = StringParseUint8(&val, 10, 0, rawstr);
    if (ret < 0) {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "invalid MQTT reason code: %s", rawstr);
        return NULL;
    }

    de = SCMalloc(sizeof(uint8_t));
    if (unlikely(de == NULL))
        return NULL;
    *de = (uint8_t) val;

    return de;
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
static int DetectMQTTReasonCodeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    uint8_t *de = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_MQTT) < 0)
        return -1;

    de = DetectMQTTReasonCodeParse(rawstr);
    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_MQTT_REASON_CODE;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, mqtt_reason_code_id);

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
 * \brief this function will free memory associated with DetectMQTTReasonCodeData
 *
 * \param de pointer to DetectMQTTReasonCodeData
 */
void DetectMQTTReasonCodeFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    if (de_ptr != NULL)
        SCFree(de_ptr);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test MQTTReasonCodeTestParse01 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTReasonCodeTestParse01 (void)
{
    uint8_t *de = NULL;

    de = DetectMQTTReasonCodeParse("3");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(*de == 3);
    DetectMQTTReasonCodeFree(NULL, de);

    de = DetectMQTTReasonCodeParse("   4");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(*de == 4);
    DetectMQTTReasonCodeFree(NULL, de);

    de = DetectMQTTReasonCodeParse("  5");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(*de == 5);
    DetectMQTTReasonCodeFree(NULL, de);

    de = DetectMQTTReasonCodeParse("255");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(*de == 255);
    DetectMQTTReasonCodeFree(NULL, de);

    PASS;
}

/**
 * \test MQTTReasonCodeTestParse02 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTReasonCodeTestParse02 (void)
{
    uint8_t *de = NULL;
    de = DetectMQTTReasonCodeParse("6X");
    if (de) {
        DetectMQTTReasonCodeFree(NULL, de);
        FAIL;
    }

    PASS;
}

/**
 * \test MQTTReasonCodeTestParse03 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTReasonCodeTestParse03 (void)
{
    uint8_t *de = NULL;
    de = DetectMQTTReasonCodeParse("");
    if (de) {
        DetectMQTTReasonCodeFree(NULL, de);
        FAIL;
    }

    PASS;
}

/**
 * \test MQTTReasonCodeTestParse04 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTReasonCodeTestParse04 (void)
{
    uint8_t *de = NULL;
    de = DetectMQTTReasonCodeParse("256");
    if (de) {
        DetectMQTTReasonCodeFree(NULL, de);
        FAIL;
    }

    PASS;
}



#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for MQTTReasonCode
 */
void MQTTReasonCodeRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("MQTTReasonCodeTestParse01", MQTTReasonCodeTestParse01);
    UtRegisterTest("MQTTReasonCodeTestParse02", MQTTReasonCodeTestParse02);
    UtRegisterTest("MQTTReasonCodeTestParse03", MQTTReasonCodeTestParse03);
    UtRegisterTest("MQTTReasonCodeTestParse04", MQTTReasonCodeTestParse04);
#endif /* UNITTESTS */
}
