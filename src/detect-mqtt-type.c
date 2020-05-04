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
#include "detect-mqtt-type.h"
#include "util-unittest.h"

#include "rust-bindings.h"

#define PARSE_REGEX "\\S[A-z]"
static DetectParseRegex parse_regex;

static int mqtt_type_id = 0;

static int DetectMQTTTypeMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx);
static int DetectMQTTTypeSetup (DetectEngineCtx *, Signature *, const char *);
void MQTTTypeRegisterTests(void);
void DetectMQTTTypeFree(DetectEngineCtx *de_ctx, void *);

static int DetectEngineInspectMQTTTypeGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id);

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
    sigmatch_table[DETECT_AL_MQTT_TYPE].RegisterTests = MQTTTypeRegisterTests;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    DetectAppLayerInspectEngineRegister("mqtt.type",
            ALPROTO_MQTT, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectMQTTTypeGeneric);

    mqtt_type_id = DetectBufferTypeGetByName("mqtt.type");
}

static int DetectEngineInspectMQTTTypeGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(tv, de_ctx, det_ctx, s, smd,
                                          f, flags, alstate, txv, tx_id);
}

struct DetectMQTTType_ {
    const char *type;
    uint16_t code;
} types[] = {
    { "CONNECT", 1, },
    { "CONNACK", 2, },
    { "PUBLISH", 3, },
    { "PUBACK", 4, },
    { "PUBREC", 5, },
    { "PUBREL", 6, },
    { "PUBCOMP", 7, },
    { "SUBSCRIBE", 8, },
    { "SUBACK", 9, },
    { "UNSUBSCRIBE", 10, },
    { "UNSUBACK", 11, },
    { "PINGREQ", 12, },
    { "PINGRESP", 13, },
    { "DISCONNECT", 14, },
    { "AUTH", 15, },
    { NULL, 0 },
};

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
    const uint32_t *de = (const uint32_t *)ctx;
    uint32_t type;

    if (!de)
        return 0;

    rs_mqtt_tx_get_type(txv, &type);
    if (*de == type) {
        return 1;
    }

    return 0;
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
static uint32_t *DetectMQTTTypeParse(const char *rawstr)
{
    int i;
    uint32_t *de = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, found = 0;
    int ov[MAX_SUBSTRINGS];

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, rawstr);
        goto error;
    }

    for(i = 0; types[i].type != NULL; i++)  {
        if((strcasecmp(types[i].type,rawstr)) == 0) {
            found = 1;
            break;
        }
    }

    if(found == 0) {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "unknown mqtt.type value %s", rawstr);
        goto error;
    }

    de = SCMalloc(sizeof(uint32_t));
    if (unlikely(de == NULL))
        goto error;

    *de = types[i].code;

    return de;

error:
    if (de) SCFree(de);
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
    uint32_t *de = NULL;
    SigMatch *sm = NULL;

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
    if (de) SCFree(de);
    if (sm) SCFree(sm);
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
    uint32_t *de = (uint32_t *)de_ptr;
    if(de) SCFree(de);
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
    uint32_t *de = NULL;
    de = DetectMQTTTypeParse("CONNECT");
    if (de) {
        DetectMQTTTypeFree(NULL, de);
        PASS;
    }

    FAIL;
}

/**
 * \test MQTTTypeTestParse02 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTTypeTestParse02 (void)
{
    uint32_t *de = NULL;
    de = DetectMQTTTypeParse("auth");
    if (de) {
        DetectMQTTTypeFree(NULL, de);
        PASS;
    }

    FAIL;
}

/**
 * \test MQTTTypeTestParse03 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTTypeTestParse03 (void)
{
    uint32_t *de = NULL;
    de = DetectMQTTTypeParse("invalidopt");
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