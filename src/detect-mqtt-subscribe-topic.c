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

/* TODO add prefiltering? */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-mqtt-subscribe-topic.h"
#include "util-unittest.h"

#include "rust-bindings.h"

static int mqtt_subscribe_topic_id = 0;

static int DetectMQTTSubscribeTopicMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx);
static int DetectMQTTSubscribeTopicSetup (DetectEngineCtx *, Signature *, const char *);
void MQTTSubscribeTopicRegisterTests(void);
void DetectMQTTSubscribeTopicFree(void *);

static int DetectEngineInspectMQTTSubscribeTopicGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id);

typedef struct DetectMQTTSubscribeTopicData_ {
    const char *topic;
} DetectMQTTSubscribeTopicData;

/**
 * \brief Registration function for mqtt.subscribe.topic: keyword
 */
void DetectMQTTSubscribeTopicRegister (void)
{
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].name = "mqtt.subscribe.topic";
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].alias = "mqtt.unsubscribe.topic";
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].desc = "match MQTT (UN)SUBSCRIBE topic";
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].url = DOC_URL DOC_VERSION "/rules/mqtt-keywords.html#mqtt-subscribe-topic";
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].AppLayerTxMatch = DetectMQTTSubscribeTopicMatch;
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].Setup = DetectMQTTSubscribeTopicSetup;
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].Free  = DetectMQTTSubscribeTopicFree;
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].RegisterTests = MQTTSubscribeTopicRegisterTests;

    DetectAppLayerInspectEngineRegister("mqtt.subscribe.topic",
            ALPROTO_MQTT, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectMQTTSubscribeTopicGeneric);

    mqtt_subscribe_topic_id = DetectBufferTypeGetByName("mqtt.subscribe.topic");
}

static int DetectEngineInspectMQTTSubscribeTopicGeneric(ThreadVars *tv,
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
 * \brief Function to match SUBSCRIBE topic of an MQTT Tx
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectMQTTSubscribeTopicData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectMQTTSubscribeTopicMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx)
{
    const DetectMQTTSubscribeTopicData *de = (const DetectMQTTSubscribeTopicData *)ctx;
    bool matched = false;

    if (!de)
        return 0;

    rs_mqtt_tx_has_topic(txv, &matched, de->topic);
    if (matched) {
        return 1;
    }   

    return 0;
}

/**
 * \internal
 * \brief This function is used to parse options passed via mqtt.subscribe.topic: keyword
 *
 * \param rawstr Pointer to the user provided options
 *
 * \retval de pointer to DetectMQTTSubscribeTopicData on success
 * \retval NULL on failure
 */
static DetectMQTTSubscribeTopicData *DetectMQTTSubscribeTopicParse(const char *rawstr)
{
    DetectMQTTSubscribeTopicData *de = NULL;

    de = SCMalloc(sizeof(DetectMQTTSubscribeTopicData));
    if (unlikely(de == NULL))
        return NULL;
    
    de->topic = SCStrdup(rawstr);
    if (unlikely(de->topic == NULL))
        return NULL;

    return de;
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
static int DetectMQTTSubscribeTopicSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectMQTTSubscribeTopicData *de = NULL;
    SigMatch *sm = NULL;

    de = DetectMQTTSubscribeTopicParse(rawstr);
    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_MQTT_SUBSCRIBE_TOPIC;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, mqtt_subscribe_topic_id);

    return 0;

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectMQTTSubscribeTopicData
 *
 * \param de pointer to DetectMQTTSubscribeTopicData
 */
void DetectMQTTSubscribeTopicFree(void *de_ptr)
{
    DetectMQTTSubscribeTopicData *de = (DetectMQTTSubscribeTopicData *)de_ptr;
    SCFree((void*) de->topic);
    if(de) SCFree(de);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test MQTTSubscribeTopicTestParse01 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTSubscribeTopicTestParse01 (void)
{
    DetectMQTTSubscribeTopicData *de = NULL;
    de = DetectMQTTSubscribeTopicParse("topic");
    if (!de) {
        return 0;
    }
    DetectMQTTSubscribeTopicFree(de);

    return 1;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for MQTTSubscribeTopic
 */
void MQTTSubscribeTopicRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("MQTTSubscribeTopicTestParse01", MQTTSubscribeTopicTestParse01);
#endif /* UNITTESTS */
}