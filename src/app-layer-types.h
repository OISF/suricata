/* Copyright (C) 2024 Open Information Security Foundation
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

#ifndef SURICATA_APP_LAYER_TYPES_H
#define SURICATA_APP_LAYER_TYPES_H

#include <stdint.h>

typedef enum SCAppLayerEventType {
    APP_LAYER_EVENT_TYPE_TRANSACTION = 1,
    APP_LAYER_EVENT_TYPE_PACKET = 2,
} SCAppLayerEventType;

typedef int (*SCAppLayerStateGetEventInfoByIdFn)(
        uint8_t event_id, const char **event_name, SCAppLayerEventType *event_type);

#endif /* !SURICATA_APP_LAYER_TYPES_H */
