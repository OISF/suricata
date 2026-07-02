/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef SURICATA_DETECT_APP_LAYER_PROTOCOL__H
#define SURICATA_DETECT_APP_LAYER_PROTOCOL__H

#include "app-layer-protos.h"

void DetectAppLayerProtocolRegister(void);
const char *DetectAppLayerProtocolModeName(uint8_t mode);
struct DetectAppLayerProtocolData_;
uint16_t DetectAppLayerProtocolGetValues(
        const struct DetectAppLayerProtocolData_ *data, AppProto *out, uint16_t max);

/**
 * \brief Per-rule keyword data for `app-layer-protocol:`.
 *
 * The set of protocol values is a bitmask (`alprotos`), one bit per AppProto,
 * sized g_alproto_max bits. `alproto` is the single-value prefilter bucket
 * key (ALPROTO_UNKNOWN for multi-value rules, which are not prefilterable).
 */
typedef struct DetectAppLayerProtocolData_ {
    AppProto alproto; /**< single-value bucket key; ALPROTO_UNKNOWN if list */
    bool negated;
    uint8_t mode;
    bool is_list;      /**< true if the rule carried more than one value */
    uint8_t *alprotos; /**< bitmask of g_alproto_max bits */
} DetectAppLayerProtocolData;

#endif /* SURICATA_DETECT_APP_LAYER_PROTOCOL__H */
