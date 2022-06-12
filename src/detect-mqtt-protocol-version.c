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
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-uint.h"
#include "detect-mqtt-protocol-version.h"
#include "util-byte.h"
#include "util-unittest.h"

#include "rust.h"

static int mqtt_protocol_version_id = 0;

static int DetectMQTTProtocolVersionMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx);
static int DetectMQTTProtocolVersionSetup (DetectEngineCtx *, Signature *, const char *);
void MQTTProtocolVersionRegisterTests(void);
void DetectMQTTProtocolVersionFree(DetectEngineCtx *de_ctx, void *);

static uint8_t DetectEngineInspectMQTTProtocolVersionGeneric(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const struct DetectEngineAppInspectionEngine_ *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);

/**
 * \brief Registration function for mqtt.protocol_version: keyword
 */
void DetectMQTTProtocolVersionRegister (void)
{
    sigmatch_table[DETECT_AL_MQTT_PROTOCOL_VERSION].name = "mqtt.protocol_version";
    sigmatch_table[DETECT_AL_MQTT_PROTOCOL_VERSION].desc = "match MQTT protocol version";
    sigmatch_table[DETECT_AL_MQTT_PROTOCOL_VERSION].url = "/rules/mqtt-keywords.html#mqtt-protocol-version";
    sigmatch_table[DETECT_AL_MQTT_PROTOCOL_VERSION].AppLayerTxMatch = DetectMQTTProtocolVersionMatch;
    sigmatch_table[DETECT_AL_MQTT_PROTOCOL_VERSION].Setup = DetectMQTTProtocolVersionSetup;
    sigmatch_table[DETECT_AL_MQTT_PROTOCOL_VERSION].Free  = DetectMQTTProtocolVersionFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_MQTT_PROTOCOL_VERSION].RegisterTests = MQTTProtocolVersionRegisterTests;
#endif

    DetectAppLayerInspectEngineRegister2("mqtt.protocol_version", ALPROTO_MQTT, SIG_FLAG_TOSERVER,
            1, DetectEngineInspectMQTTProtocolVersionGeneric, NULL);

    mqtt_protocol_version_id = DetectBufferTypeGetByName("mqtt.protocol_version");
}

static uint8_t DetectEngineInspectMQTTProtocolVersionGeneric(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const struct DetectEngineAppInspectionEngine_ *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(
            de_ctx, det_ctx, s, engine->smd, f, flags, alstate, txv, tx_id);
}

/**
 * \internal
 * \brief Function to match protocol version of an MQTT Tx
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectMQTTProtocolVersionData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectMQTTProtocolVersionMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx)
{
    const DetectU8Data *de = (const DetectU8Data *)ctx;
    uint8_t version;

    version = rs_mqtt_tx_get_protocol_version(state);

    return DetectU8Match(version, de);
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
static int DetectMQTTProtocolVersionSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    SigMatch *sm = NULL;
    DetectU8Data *de = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_MQTT) < 0)
        return -1;

    de = DetectU8Parse(rawstr);
    if (de == NULL)
        return -1;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_MQTT_PROTOCOL_VERSION;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, mqtt_protocol_version_id);

    return 0;

error:
    if (de != NULL)
        rs_detect_u8_free(de);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectMQTTProtocolVersionData
 *
 * \param de pointer to DetectMQTTProtocolVersionData
 */
void DetectMQTTProtocolVersionFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    rs_detect_u8_free(de_ptr);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test MQTTProtocolVersionTestParse01 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTProtocolVersionTestParse01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (mqtt.protocol_version:3; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (mqtt.protocol_version:3; sid:2; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test MQTTProtocolVersionTestParse02 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTProtocolVersionTestParse02 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (mqtt.protocol_version:>3; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (mqtt.protocol_version:<44; sid:2; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test MQTTProtocolVersionTestParse03 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTProtocolVersionTestParse03 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (mqtt.protocol_version:; sid:1; rev:1;)");
    FAIL_IF_NOT_NULL(sig);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test MQTTProtocolVersionTestParse04 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTProtocolVersionTestParse04 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (mqtt.protocol_version:<444; sid:1; rev:1;)");
    FAIL_IF_NOT_NULL(sig);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for MQTTProtocolVersion
 */
void MQTTProtocolVersionRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("MQTTProtocolVersionTestParse01", MQTTProtocolVersionTestParse01);
    UtRegisterTest("MQTTProtocolVersionTestParse02", MQTTProtocolVersionTestParse02);
    UtRegisterTest("MQTTProtocolVersionTestParse03", MQTTProtocolVersionTestParse03);
    UtRegisterTest("MQTTProtocolVersionTestParse04", MQTTProtocolVersionTestParse04);
#endif /* UNITTESTS */
}
