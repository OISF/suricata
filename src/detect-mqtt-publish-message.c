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
 * \author Sascha Steinbiss <sascha@steinbiss.name>
 *
 * Implements the mqtt.publish.message sticky buffer
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-mqtt-publish-message.h"
#include "rust.h"

#define KEYWORD_NAME "mqtt.publish.message"
#define KEYWORD_DOC  "mqtt-keywords.html#mqtt-publish-message"
#define BUFFER_NAME  "mqtt.publish.message"
#define BUFFER_DESC  "MQTT PUBLISH message"
static int g_buffer_id = 0;

static int DetectMQTTPublishMessageSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_MQTT) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const uint8_t *b = NULL;
        uint32_t b_len = 0;

        if (rs_mqtt_tx_get_publish_message(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

void DetectMQTTPublishMessageRegister(void)
{
    /* mqtt.publish.message sticky buffer */
    sigmatch_table[DETECT_AL_MQTT_PUBLISH_MESSAGE].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_MQTT_PUBLISH_MESSAGE].desc = "sticky buffer to match on the MQTT PUBLISH message";
    sigmatch_table[DETECT_AL_MQTT_PUBLISH_MESSAGE].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_MQTT_PUBLISH_MESSAGE].Setup = DetectMQTTPublishMessageSetup;
    sigmatch_table[DETECT_AL_MQTT_PUBLISH_MESSAGE].flags |= SIGMATCH_NOOPT;

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_MQTT,
            SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_MQTT,
	        1);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    SCLogDebug("registering " BUFFER_NAME " rule option");
}
