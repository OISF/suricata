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
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-mqtt.h"
#include "rust.h"

void RegisterMQTTParsers(void)
{
    SCLogDebug("Registering Rust mqtt parser.");
    rs_mqtt_register_parser();
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_MQTT,
        MQTTParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void MQTTParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
