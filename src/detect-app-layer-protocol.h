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
 * `alprotos` is the effective match set: a bitmask (one bit per AppProto,
 * sized g_alproto_max) holding every flow protocol that should match, with the
 * AppProtoEquals() equivalences (or, with the `exact` option, only the exact
 * values) already expanded in at rule load. The per-packet match is then a
 * single bitmask test. `alproto` is the first configured value, used as the
 * prefilter bucket key for single-value (prefilterable) rules.
 */
typedef struct DetectAppLayerProtocolData_ {
    AppProto alproto; /**< first configured value; single-value prefilter key */
    bool negated;
    bool exact;   /**< `exact` option: strict identity, no equivalences/umbrella */
    bool is_list; /**< more than one value configured (not prefilterable) */
    uint8_t mode;
    uint8_t *alprotos; /**< effective match set (g_alproto_max bits) */
} DetectAppLayerProtocolData;

#endif /* SURICATA_DETECT_APP_LAYER_PROTOCOL__H */
