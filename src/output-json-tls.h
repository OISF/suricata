/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 */

#ifndef SURICATA_OUTPUT_JSON_TLS_H
#define SURICATA_OUTPUT_JSON_TLS_H

void JsonTlsLogRegister(void);

#include "app-layer-ssl.h"

void JsonTlsLogJSONBasic(JsonBuilder *js, SSLState *ssl_state);
bool JsonTlsLogJSONExtended(void *vtx, JsonBuilder *js, void *ctx);

#endif /* SURICATA_OUTPUT_JSON_TLS_H */
