/* Copyright (C) 2023 Open Information Security Foundation
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
 * Implements the mqtt.connect.protocolstring sticky buffer
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-mqtt-connect-protocol-string.h"
#include "rust.h"

#define KEYWORD_NAME "mqtt.connect.protocol_string"
#define KEYWORD_DOC  "mqtt-keywords.html#mqtt-connect-protocol_string"
#define BUFFER_NAME  "mqtt.connect.protocol_string"
#define BUFFER_DESC  "MQTT CONNECT protocol string"
static int g_buffer_id = 0;

static int DetectMQTTConnectProtocolStringSetup(
        DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_MQTT) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const uint8_t *b = NULL;
        uint32_t b_len = 0;

        if (rs_mqtt_tx_get_connect_protocol_string(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

void DetectMQTTConnectProtocolStringRegister(void)
{
    /* mqtt.connect.protocol_string sticky buffer */
    sigmatch_table[DETECT_AL_MQTT_CONNECT_PROTOCOL_STRING].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_MQTT_CONNECT_PROTOCOL_STRING].desc =
            "sticky buffer to match on the MQTT CONNECT protocol string";
    sigmatch_table[DETECT_AL_MQTT_CONNECT_PROTOCOL_STRING].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_MQTT_CONNECT_PROTOCOL_STRING].Setup =
            DetectMQTTConnectProtocolStringSetup;
    sigmatch_table[DETECT_AL_MQTT_CONNECT_PROTOCOL_STRING].flags |= SIGMATCH_NOOPT;

    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_MQTT, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_MQTT, 1);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    SCLogDebug("registering " BUFFER_NAME " rule option");
}
