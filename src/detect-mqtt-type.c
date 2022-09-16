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
#endif
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-mqtt-type.h"

#include "rust.h"

static int mqtt_type_id = 0;

static int DetectMQTTTypeMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx);
static int DetectMQTTTypeSetup (DetectEngineCtx *, Signature *, const char *);
void MQTTTypeRegisterTests(void);
void DetectMQTTTypeFree(DetectEngineCtx *de_ctx, void *);

/**
 * \brief Registration function for ipopts: keyword
 */
void DetectMQTTTypeRegister (void)
{
    sigmatch_table[DETECT_AL_MQTT_TYPE].name = "mqtt.type";
    sigmatch_table[DETECT_AL_MQTT_TYPE].desc = "match MQTT control packet type";
    sigmatch_table[DETECT_AL_MQTT_TYPE].url = "/rules/mqtt-keywords.html#mqtt-type";
    sigmatch_table[DETECT_AL_MQTT_TYPE].AppLayerTxMatch = DetectMQTTTypeMatch;
    sigmatch_table[DETECT_AL_MQTT_TYPE].Setup = DetectMQTTTypeSetup;
    sigmatch_table[DETECT_AL_MQTT_TYPE].Free  = DetectMQTTTypeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_MQTT_TYPE].RegisterTests = MQTTTypeRegisterTests;
#endif

    DetectAppLayerInspectEngineRegister2(
            "mqtt.type", ALPROTO_MQTT, SIG_FLAG_TOSERVER, 1, DetectEngineInspectGenericList, NULL);

    mqtt_type_id = DetectBufferTypeGetByName("mqtt.type");
}

/**
 * \internal
 * \brief Function to match control packet type of an MQTT Tx
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectMQTTTypeData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectMQTTTypeMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx)
{
    const uint8_t *de = (const uint8_t *)ctx;

    if (!de)
        return 0;

    return rs_mqtt_tx_has_type(txv, *de);
}

/**
 * \internal
 * \brief This function is used to parse options passed via mqtt.type: keyword
 *
 * \param rawstr Pointer to the user provided options
 *
 * \retval de pointer to DetectMQTTTypeData on success
 * \retval NULL on failure
 */
static uint8_t *DetectMQTTTypeParse(const char *rawstr)
{
    uint8_t *de = NULL;
    int ret = 0;

    ret = rs_mqtt_cstr_message_code(rawstr);
    // negative value denotes invalid input
    if(ret < 0) {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "unknown mqtt.type value %s", rawstr);
        goto error;
    }

    de = SCMalloc(sizeof(uint8_t));
    if (unlikely(de == NULL))
        goto error;

    *de = (uint8_t) ret;

    return de;

error:
    if (de != NULL)
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
static int DetectMQTTTypeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    uint8_t *de = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_MQTT) < 0)
        return -1;

    de = DetectMQTTTypeParse(rawstr);
    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_MQTT_TYPE;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, mqtt_type_id);

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
 * \brief this function will free memory associated with DetectMQTTTypeData
 *
 * \param de pointer to DetectMQTTTypeData
 */
void DetectMQTTTypeFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    if (de_ptr != NULL)
        SCFree(de_ptr);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test MQTTTypeTestParse01 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTTypeTestParse01 (void)
{
    uint8_t *de = NULL;
    de = DetectMQTTTypeParse("CONNECT");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(*de == 1);
    DetectMQTTTypeFree(NULL, de);

    de = DetectMQTTTypeParse("PINGRESP");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(*de == 13);
    DetectMQTTTypeFree(NULL, de);

    PASS;
}

/**
 * \test MQTTTypeTestParse02 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTTypeTestParse02 (void)
{
    uint8_t *de = NULL;
    de = DetectMQTTTypeParse("auth");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(*de == 15);
    DetectMQTTTypeFree(NULL, de);

    PASS;
}

/**
 * \test MQTTTypeTestParse03 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTTypeTestParse03 (void)
{
    uint8_t *de = NULL;
    de = DetectMQTTTypeParse("invalidopt");
    if (de) {
        DetectMQTTTypeFree(NULL, de);
        FAIL;
    }

    de = DetectMQTTTypeParse("unassigned");
    if (de) {
        DetectMQTTTypeFree(NULL, de);
        FAIL;
    }

    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for MQTTType
 */
void MQTTTypeRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("MQTTTypeTestParse01", MQTTTypeTestParse01);
    UtRegisterTest("MQTTTypeTestParse02", MQTTTypeTestParse02);
    UtRegisterTest("MQTTTypeTestParse03", MQTTTypeTestParse03);
#endif /* UNITTESTS */
}
