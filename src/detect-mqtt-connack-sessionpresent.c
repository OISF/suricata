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
#include "detect-mqtt-connack-sessionpresent.h"

#include "rust.h"

#define PARSE_REGEX "^true|false|yes|no$"
static DetectParseRegex parse_regex;

static int mqtt_connack_session_present_id = 0;

static int DetectMQTTConnackSessionPresentMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx);
static int DetectMQTTConnackSessionPresentSetup (DetectEngineCtx *, Signature *, const char *);
void MQTTConnackSessionPresentRegisterTests(void);
void DetectMQTTConnackSessionPresentFree(DetectEngineCtx *de_ctx, void *);

/**
 * \brief Registration function for mqtt.connack.session_present: keyword
 */
void DetectMQTTConnackSessionPresentRegister (void)
{
    sigmatch_table[DETECT_AL_MQTT_CONNACK_SESSION_PRESENT].name = "mqtt.connack.session_present";
    sigmatch_table[DETECT_AL_MQTT_CONNACK_SESSION_PRESENT].desc = "match MQTT CONNACK session present flag";
    sigmatch_table[DETECT_AL_MQTT_CONNACK_SESSION_PRESENT].url = "/rules/mqtt-keywords.html#mqtt-connack-session-present";
    sigmatch_table[DETECT_AL_MQTT_CONNACK_SESSION_PRESENT].AppLayerTxMatch = DetectMQTTConnackSessionPresentMatch;
    sigmatch_table[DETECT_AL_MQTT_CONNACK_SESSION_PRESENT].Setup = DetectMQTTConnackSessionPresentSetup;
    sigmatch_table[DETECT_AL_MQTT_CONNACK_SESSION_PRESENT].Free  = DetectMQTTConnackSessionPresentFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_MQTT_CONNACK_SESSION_PRESENT].RegisterTests = MQTTConnackSessionPresentRegisterTests;
#endif

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    DetectAppLayerInspectEngineRegister2("mqtt.connack.session_present", ALPROTO_MQTT,
            SIG_FLAG_TOSERVER, 1, DetectEngineInspectGenericList, NULL);

    mqtt_connack_session_present_id = DetectBufferTypeGetByName("mqtt.connack.session_present");
}

/**
 * \internal
 * \brief Function to match session_present flag of an MQTT CONNACK message
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectMQTTConnackSessionPresentData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectMQTTConnackSessionPresentMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx)
{
    const bool *de = (const bool *)ctx;
    bool value = false;

    if (!de)
        return 0;

    if (rs_mqtt_tx_get_connack_sessionpresent(txv, &value) ==0 ) {
        return 0;
    }
    if (value != *de) {
        return 0;
    }

    return 1;
}

/**
 * \internal
 * \brief This function is used to parse options passed via mqtt.connack.session_present: keyword
 *
 * \param rawstr Pointer to the user provided options
 *
 * \retval de pointer to DetectMQTTConnackSessionPresentData on success
 * \retval NULL on failure
 */
static bool *DetectMQTTConnackSessionPresentParse(const char *rawstr)
{
    bool *de = NULL;
    de = SCMalloc(sizeof(bool));
    if (unlikely(de == NULL))
        return NULL;
    *de = false;

    if (strcmp(rawstr, "yes") == 0) {
        *de = true;
    } else if (strcmp(rawstr, "true") == 0) {
        *de = true;
    } else if (strcmp(rawstr, "no") == 0) {
        *de = false;
    } else if (strcmp(rawstr, "false") == 0) {
        *de = false;
    } else {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "invalid session_present flag definition: %s", rawstr);
        goto error;
    }

    return de;

error:
    /* de can't be NULL here */
    SCFree(de);
    return NULL;
}

/**
 * \internal
 * \brief this function is used to add the parsed type query into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rawstr pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectMQTTConnackSessionPresentSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    bool *de = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_MQTT) < 0)
        return -1;

    de = DetectMQTTConnackSessionPresentParse(rawstr);
    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_MQTT_CONNACK_SESSION_PRESENT;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, mqtt_connack_session_present_id);

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
 * \brief this function will free memory associated with DetectMQTTConnackSessionPresentData
 *
 * \param de pointer to DetectMQTTConnackSessionPresentData
 */
void DetectMQTTConnackSessionPresentFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    if (de_ptr != NULL)
        SCFree(de_ptr);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test MQTTConnackSessionPresentTestParse01 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTConnackSessionPresentTestParse01 (void)
{
    bool *de = NULL;

    de = DetectMQTTConnackSessionPresentParse("yes");
    FAIL_IF_NULL(de);
    DetectMQTTConnackSessionPresentFree(NULL, de);

    de = DetectMQTTConnackSessionPresentParse("true");
    FAIL_IF_NULL(de);
    DetectMQTTConnackSessionPresentFree(NULL, de);

    de = DetectMQTTConnackSessionPresentParse("false");
    FAIL_IF_NULL(de);
    DetectMQTTConnackSessionPresentFree(NULL, de);

    de = DetectMQTTConnackSessionPresentParse("no");
    FAIL_IF_NULL(de);
    DetectMQTTConnackSessionPresentFree(NULL, de);

    PASS;
}

/**
 * \test MQTTConnackSessionPresentTestParse02 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTConnackSessionPresentTestParse02 (void)
{
    bool *de = NULL;
    de = DetectMQTTConnackSessionPresentParse("nix");
    if (de) {
        DetectMQTTConnackSessionPresentFree(NULL, de);
        FAIL;
    }

    PASS;
}

/**
 * \test MQTTConnackSessionPresentTestParse03 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTConnackSessionPresentTestParse03 (void)
{
    bool *de = NULL;
    de = DetectMQTTConnackSessionPresentParse("");
    if (de) {
        DetectMQTTConnackSessionPresentFree(NULL, de);
        FAIL;
    }

    PASS;
}

/**
 * \test MQTTConnackSessionPresentTestParse04 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTConnackSessionPresentTestParse04 (void)
{
    bool *de = NULL;
    de = DetectMQTTConnackSessionPresentParse(",");
    if (de) {
        DetectMQTTConnackSessionPresentFree(NULL, de);
        FAIL;
    }

    PASS;
}


#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for MQTTConnackSessionPresent
 */
void MQTTConnackSessionPresentRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("MQTTConnackSessionPresentTestParse01", MQTTConnackSessionPresentTestParse01);
    UtRegisterTest("MQTTConnackSessionPresentTestParse02", MQTTConnackSessionPresentTestParse02);
    UtRegisterTest("MQTTConnackSessionPresentTestParse03", MQTTConnackSessionPresentTestParse03);
    UtRegisterTest("MQTTConnackSessionPresentTestParse04", MQTTConnackSessionPresentTestParse04);
#endif /* UNITTESTS */
}
