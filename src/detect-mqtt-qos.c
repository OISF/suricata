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
#include "detect-mqtt-qos.h"
#include "util-byte.h"

#include "rust.h"

static int mqtt_qos_id = 0;

static int DetectMQTTQosMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx);
static int DetectMQTTQosSetup (DetectEngineCtx *, Signature *, const char *);
void MQTTQosRegisterTests(void);
void DetectMQTTQosFree(DetectEngineCtx *de_ctx, void *);

/**
 * \brief Registration function for mqtt.qos: keyword
 */
void DetectMQTTQosRegister (void)
{
    sigmatch_table[DETECT_AL_MQTT_QOS].name = "mqtt.qos";
    sigmatch_table[DETECT_AL_MQTT_QOS].desc = "match MQTT fixed header QOS level";
    sigmatch_table[DETECT_AL_MQTT_QOS].url = "/rules/mqtt-keywords.html#mqtt-qos";
    sigmatch_table[DETECT_AL_MQTT_QOS].AppLayerTxMatch = DetectMQTTQosMatch;
    sigmatch_table[DETECT_AL_MQTT_QOS].Setup = DetectMQTTQosSetup;
    sigmatch_table[DETECT_AL_MQTT_QOS].Free  = DetectMQTTQosFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_MQTT_QOS].RegisterTests = MQTTQosRegisterTests;
#endif

    DetectAppLayerInspectEngineRegister2(
            "mqtt.qos", ALPROTO_MQTT, SIG_FLAG_TOSERVER, 1, DetectEngineInspectGenericList, NULL);

    mqtt_qos_id = DetectBufferTypeGetByName("mqtt.qos");
}

/**
 * \internal
 * \brief Function to match fixed header QOS field of an MQTT Tx
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into uint8_t.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectMQTTQosMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx)
{
    const uint8_t *de = (const uint8_t *)ctx;

    if (!de)
        return 0;

    return rs_mqtt_tx_has_qos(txv, *de);
}

/**
 * \internal
 * \brief This function is used to parse options passed via mqtt.qos: keyword
 *
 * \param rawstr Pointer to the user provided options
 *
 * \retval de pointer to DetectMQTTQosData on success
 * \retval NULL on failure
 */
static uint8_t *DetectMQTTQosParse(const char *rawstr)
{
    uint8_t *de = NULL;
    int ret = 0;
    uint8_t val;

    ret = StringParseU8RangeCheck(&val, 10, 0, rawstr, 0, 2);
    if (ret < 0) {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "invalid MQTT QOS level: %s", rawstr);
        return NULL;
    }

    de = SCMalloc(sizeof(uint8_t));
    if (unlikely(de == NULL))
        return NULL;
    *de = val;

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
static int DetectMQTTQosSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    uint8_t *de = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_MQTT) < 0)
        return -1;

    de = DetectMQTTQosParse(rawstr);
    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_MQTT_QOS;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, mqtt_qos_id);

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
 * \brief this function will free memory associated with DetectMQTTQosData
 *
 * \param de pointer to DetectMQTTQosData
 */
void DetectMQTTQosFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    if (de_ptr != NULL)
        SCFree(de_ptr);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test MQTTQosTestParse01 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTQosTestParse01 (void)
{
    uint8_t *de = NULL;

    de = DetectMQTTQosParse("0");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(*de == 0);
    DetectMQTTQosFree(NULL, de);

    de = DetectMQTTQosParse("   0");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(*de == 0);
    DetectMQTTQosFree(NULL, de);

    de = DetectMQTTQosParse("1");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(*de == 1);
    DetectMQTTQosFree(NULL, de);

    de = DetectMQTTQosParse("2");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(*de == 2);
    DetectMQTTQosFree(NULL, de);

    PASS;
}

/**
 * \test MQTTQosTestParse02 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTQosTestParse02 (void)
{
    uint8_t *de = NULL;
    de = DetectMQTTQosParse("3");
    if (de) {
        DetectMQTTQosFree(NULL, de);
        FAIL;
    }

    PASS;
}

/**
 * \test MQTTQosTestParse04 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTQosTestParse03 (void)
{
    uint8_t *de = NULL;
    de = DetectMQTTQosParse("12");
    if (de) {
        DetectMQTTQosFree(NULL, de);
        FAIL;
    }

    PASS;
}


#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for MQTTQos
 */
void MQTTQosRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("MQTTQosTestParse01", MQTTQosTestParse01);
    UtRegisterTest("MQTTQosTestParse02", MQTTQosTestParse02);
    UtRegisterTest("MQTTQosTestParse03", MQTTQosTestParse03);
#endif /* UNITTESTS */
}
