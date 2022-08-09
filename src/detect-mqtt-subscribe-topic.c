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

#include "app-layer.h"
#include "app-layer-parser.h"

#include "conf.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"
#include "detect-content.h"
#include "detect-parse.h"
#include "detect-pcre.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-mqtt-subscribe-topic.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "rust-bindings.h"

#include "threads.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"

static int DetectMQTTSubscribeTopicSetup(DetectEngineCtx *, Signature *, const char *);

static int g_mqtt_subscribe_topic_buffer_id = 0;

static uint32_t subscribe_topic_match_limit = 100;

struct MQTTSubscribeTopicGetDataArgs {
    uint32_t local_id;
    void *txv;
};

static InspectionBuffer *MQTTSubscribeTopicGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *f, struct MQTTSubscribeTopicGetDataArgs *cbdata, int list_id, bool first)
{
    SCEnter();

    InspectionBuffer *buffer =
            InspectionBufferMultipleForListGet(det_ctx, list_id, cbdata->local_id);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    const uint8_t *data;
    uint32_t data_len;
    if (rs_mqtt_tx_get_subscribe_topic(cbdata->txv, cbdata->local_id, &data, &data_len) == 0) {
        return NULL;
    }

    InspectionBufferSetupMulti(buffer, transforms, data, data_len);

    SCReturnPtr(buffer, "InspectionBuffer");
}

static uint8_t DetectEngineInspectMQTTSubscribeTopic(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    uint32_t local_id = 0;

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    while ((subscribe_topic_match_limit == 0) || local_id < subscribe_topic_match_limit) {
        struct MQTTSubscribeTopicGetDataArgs cbdata = { local_id, txv, };
        InspectionBuffer *buffer = MQTTSubscribeTopicGetData(det_ctx,
            transforms, f, &cbdata, engine->sm_list, false);
        if (buffer == NULL || buffer->inspect == NULL)
            break;

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;

        const int match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd,
                                              NULL, f,
                                              (uint8_t *)buffer->inspect,
                                              buffer->inspect_len,
                                              buffer->inspect_offset, DETECT_CI_FLAGS_SINGLE,
                                              DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match == 1) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
        local_id++;
    }
    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

typedef struct PrefilterMpmMQTTSubscribeTopic {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmMQTTSubscribeTopic;

/** \brief MQTTSubscribeTopic MQTTSubscribeTopic Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxMQTTSubscribeTopic(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmMQTTSubscribeTopic *ctx = (const PrefilterMpmMQTTSubscribeTopic *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    uint32_t local_id = 0;
    while ((subscribe_topic_match_limit == 0) || local_id < subscribe_topic_match_limit) {
        struct MQTTSubscribeTopicGetDataArgs cbdata = { local_id, txv };
        InspectionBuffer *buffer = MQTTSubscribeTopicGetData(det_ctx, ctx->transforms,
                f, &cbdata, list_id, true);
        if (buffer == NULL)
            break;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                    &det_ctx->mtcu, &det_ctx->pmq,
                    buffer->inspect, buffer->inspect_len);
        }
        local_id++;
    }
}

static void PrefilterMpmMQTTSubscribeTopicFree(void *ptr)
{
    if (ptr != NULL)
        SCFree(ptr);
}

static int PrefilterMpmMQTTSubscribeTopicRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    PrefilterMpmMQTTSubscribeTopic *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxMQTTSubscribeTopic,
            mpm_reg->app_v2.alproto, mpm_reg->app_v2.tx_min_progress,
            pectx, PrefilterMpmMQTTSubscribeTopicFree, mpm_reg->pname);
}

/**
 * \brief Registration function for keyword: mqtt.subscribe.topic
 */
void DetectMQTTSubscribeTopicRegister (void)
{
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].name = "mqtt.subscribe.topic";
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].desc = "sticky buffer to match MQTT SUBSCRIBE topic";
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].url = "/rules/mqtt-keywords.html#mqtt-subscribe-topic";
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].Setup = DetectMQTTSubscribeTopicSetup;
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_MQTT_SUBSCRIBE_TOPIC].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    intmax_t val = 0;
    if (ConfGetInt("app-layer.protocols.mqtt.subscribe-topic-match-limit", &val)) {
        subscribe_topic_match_limit = val;
    }
    if (subscribe_topic_match_limit <= 0) {
        SCLogDebug("Using unrestricted MQTT SUBSCRIBE topic matching");
    } else {
        SCLogDebug("Using MQTT SUBSCRIBE topic match-limit setting of: %u",
                subscribe_topic_match_limit);
    }

    DetectAppLayerMpmRegister2("mqtt.subscribe.topic", SIG_FLAG_TOSERVER, 1,
            PrefilterMpmMQTTSubscribeTopicRegister, NULL,
            ALPROTO_MQTT, 1);

    DetectAppLayerInspectEngineRegister2("mqtt.subscribe.topic",
            ALPROTO_MQTT, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectMQTTSubscribeTopic, NULL);

    DetectBufferTypeSetDescriptionByName("mqtt.subscribe.topic",
            "subscribe topic query");

    g_mqtt_subscribe_topic_buffer_id = DetectBufferTypeGetByName("mqtt.subscribe.topic");
}

/**
 * \brief setup the sticky buffer keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectMQTTSubscribeTopicSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_mqtt_subscribe_topic_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_MQTT) < 0)
        return -1;
    return 0;
}
