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

#include <inttypes.h>
#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-mqtt-protocol-version.h"
#include "util-byte.h"
#include "util-unittest.h"

#include "rust-bindings.h"

#define PARSE_REGEX "^\\s*[345]\\s*$"
static DetectParseRegex parse_regex;

static int mqtt_protocol_version_id = 0;

static int DetectMQTTProtocolVersionMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx);
static int DetectMQTTProtocolVersionSetup (DetectEngineCtx *, Signature *, const char *);
void MQTTProtocolVersionRegisterTests(void);
void DetectMQTTProtocolVersionFree(void *);

static int DetectEngineInspectMQTTProtocolVersionGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id);

typedef struct DetectMQTTProtocolVersionData_ {
    uint8_t version;
} DetectMQTTProtocolVersionData;

/**
 * \brief Registration function for mqtt.protocol_version: keyword
 */
void DetectMQTTProtocolVersionRegister (void)
{
    sigmatch_table[DETECT_AL_MQTT_PROTOCOL_VERSION].name = "mqtt.protocol_version";
    sigmatch_table[DETECT_AL_MQTT_PROTOCOL_VERSION].desc = "match MQTT fixed header QOS level";
    sigmatch_table[DETECT_AL_MQTT_PROTOCOL_VERSION].url = DOC_URL DOC_VERSION "/rules/mqtt-keywords.html#mqtt-protocol-version";
    sigmatch_table[DETECT_AL_MQTT_PROTOCOL_VERSION].AppLayerTxMatch = DetectMQTTProtocolVersionMatch;
    sigmatch_table[DETECT_AL_MQTT_PROTOCOL_VERSION].Setup = DetectMQTTProtocolVersionSetup;
    sigmatch_table[DETECT_AL_MQTT_PROTOCOL_VERSION].Free  = DetectMQTTProtocolVersionFree;
    sigmatch_table[DETECT_AL_MQTT_PROTOCOL_VERSION].RegisterTests = MQTTProtocolVersionRegisterTests;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    DetectAppLayerInspectEngineRegister("mqtt.protocol_version",
            ALPROTO_MQTT, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectMQTTProtocolVersionGeneric);

    mqtt_protocol_version_id = DetectBufferTypeGetByName("mqtt.protocol_version");
}

static int DetectEngineInspectMQTTProtocolVersionGeneric(ThreadVars *tv,
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
    const DetectMQTTProtocolVersionData *de = (const DetectMQTTProtocolVersionData *)ctx;
    uint8_t version;

    if (!de)
        return 0;

    rs_mqtt_tx_get_protocol_version(state, &version);
    if (version == de->version)
        return 1;

    return 0;
}

/**
 * \internal
 * \brief This function is used to parse options passed via mqtt.protocol_version: keyword
 *
 * \param rawstr Pointer to the user provided options
 *
 * \retval de pointer to DetectMQTTProtocolVersionData on success
 * \retval NULL on failure
 */
static DetectMQTTProtocolVersionData *DetectMQTTProtocolVersionParse(const char *rawstr)
{
    DetectMQTTProtocolVersionData *de = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0;
    uint8_t val;
    int ov[MAX_SUBSTRINGS];

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid MQTT protocol version: %s", rawstr);
        return NULL;
    }

    ret = ByteExtractStringUint8(&val, 10, 0, rawstr);
    if (ret < 0) {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "invalid MQTT protocol version: %s", rawstr);
        return NULL;
    }

    de = SCMalloc(sizeof(DetectMQTTProtocolVersionData));
    if (unlikely(de == NULL))
        return NULL;
    de->version = val;

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
static int DetectMQTTProtocolVersionSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectMQTTProtocolVersionData *de = NULL;
    SigMatch *sm = NULL;

    de = DetectMQTTProtocolVersionParse(rawstr);
    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_MQTT_PROTOCOL_VERSION;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, mqtt_protocol_version_id);

    return 0;

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectMQTTProtocolVersionData
 *
 * \param de pointer to DetectMQTTProtocolVersionData
 */
void DetectMQTTProtocolVersionFree(void *de_ptr)
{
    DetectMQTTProtocolVersionData *de = (DetectMQTTProtocolVersionData *)de_ptr;
    if(de) SCFree(de);
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
    DetectMQTTProtocolVersionData *de = NULL;
    de = DetectMQTTProtocolVersionParse("3");
    if (!de) {
        return 0;
    }
    DetectMQTTProtocolVersionFree(de);
    de = DetectMQTTProtocolVersionParse("   4");
    if (!de) {
        return 0;
    }
    DetectMQTTProtocolVersionFree(de);
    de = DetectMQTTProtocolVersionParse("  5   ");
    if (!de) {
        return 0;
    }
    DetectMQTTProtocolVersionFree(de);
    de = DetectMQTTProtocolVersionParse("3   ");
    if (!de) {
        return 0;
    }
    DetectMQTTProtocolVersionFree(de);

    return 1;
}

/**
 * \test MQTTProtocolVersionTestParse02 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTProtocolVersionTestParse02 (void)
{
    DetectMQTTProtocolVersionData *de = NULL;
    de = DetectMQTTProtocolVersionParse("2");
    if (de) {
        DetectMQTTProtocolVersionFree(de);
        return 0;
    }

    return 1;
}

/**
 * \test MQTTProtocolVersionTestParse03 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTProtocolVersionTestParse03 (void)
{
    DetectMQTTProtocolVersionData *de = NULL;
    de = DetectMQTTProtocolVersionParse("6");
    if (de) {
        DetectMQTTProtocolVersionFree(de);
        return 0;
    }

    return 1;
}

/**
 * \test MQTTProtocolVersionTestParse04 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTProtocolVersionTestParse04 (void)
{
    DetectMQTTProtocolVersionData *de = NULL;
    de = DetectMQTTProtocolVersionParse("");
    if (de) {
        DetectMQTTProtocolVersionFree(de);
        return 0;
    }

    return 1;
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