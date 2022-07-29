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

#include "util-misc.h"

#include "app-layer-parser.h"

#include "app-layer-mqtt.h"

void RegisterMQTTParsers(void)
{
    SCLogDebug("Registering Rust mqtt parser.");
    uint32_t max_msg_len = 1048576; /* default: 1MB */

    if (AppLayerParserConfParserEnabled("tcp", "mqtt")) {
        ConfNode *p = ConfGetNode("app-layer.protocols.mqtt.max-msg-length");
        if (p != NULL) {
            uint32_t value;
            if (ParseSizeStringU32(p->val, &value) < 0) {
                SCLogError(SC_ERR_SIZE_PARSE, "invalid value for max-msg-length: %s", p->val);
            } else {
                max_msg_len = value;
            }
        }
        rs_mqtt_register_parser(max_msg_len);
    }
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_MQTT,
        MQTTParserRegisterTests);
#endif
}

void MQTTParserRegisterTests(void)
{
}
