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

/**
 * \brief Per-rule keyword data for `app-layer-protocol:`.
 *
 * Single-value rules use `alproto` directly (no heap allocation) and
 * participate in prefilter bucketing. Multi-value rules use the
 * heap-allocated `list_alprotos` array and skip prefilter (the bucket
 * key is single-valued).
 */
typedef struct DetectAppLayerProtocolData_ {
    AppProto alproto; /**< single value; also used as prefilter bucket key */
    uint8_t negated;
    uint8_t mode;
    uint8_t list_count;      /**< 0 = single-value; >0 = list-valued */
    uint8_t mode_explicit;   /**< 1 iff input had explicit mode token */
    AppProto *list_alprotos; /**< heap array of length list_count */
} DetectAppLayerProtocolData;

#endif /* SURICATA_DETECT_APP_LAYER_PROTOCOL__H */
