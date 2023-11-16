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
 * Implements the mqtt.connect.password sticky buffer
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-helper.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-mqtt-connect-password.h"
#include "rust.h"

#define KEYWORD_NAME "mqtt.connect.password"
#define KEYWORD_DOC  "mqtt-keywords.html#mqtt-connect-password"
#define BUFFER_NAME  "mqtt.connect.password"
#define BUFFER_DESC  "MQTT CONNECT password"
static int g_buffer_id = 0;

static int DetectMQTTConnectPasswordSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_MQTT) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    return DetectHelperGetData(det_ctx, transforms, _f, flow_flags, txv, list_id,
            (SimpleGetTxBuffer)rs_mqtt_tx_get_connect_password);
}

void DetectMQTTConnectPasswordRegister(void)
{
    /* mqtt.connect.password sticky buffer */
    sigmatch_table[DETECT_AL_MQTT_CONNECT_PASSWORD].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_MQTT_CONNECT_PASSWORD].desc = "sticky buffer to match on the MQTT CONNECT password";
    sigmatch_table[DETECT_AL_MQTT_CONNECT_PASSWORD].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_MQTT_CONNECT_PASSWORD].Setup = DetectMQTTConnectPasswordSetup;
    sigmatch_table[DETECT_AL_MQTT_CONNECT_PASSWORD].flags |= SIGMATCH_NOOPT;

    g_buffer_id = DetectHelperBufferMpmRegister(
            BUFFER_NAME, BUFFER_DESC, ALPROTO_MQTT, false, true, GetData);

    SCLogDebug("registering " BUFFER_NAME " rule option");
}
