/* Copyright (C) 2007-2013 Open Information Security Foundation
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

#include "suricata-common.h"
#include "util-enum.h"

SCEnumCharMap app_layer_event_pkt_table[ ] = {
    { "APPLAYER_MISMATCH_PROTOCOL_BOTH_DIRECTIONS",
      APPLAYER_MISMATCH_PROTOCOL_BOTH_DIRECTIONS },
    { "APPLAYER_WRONG_DIRECTION_FIRST_DATA",
      APPLAYER_WRONG_DIRECTION_FIRST_DATA },
    { "APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION",
      APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION },
    { "APPLAYER_PROTO_DETECTION_SKIPPED",
      APPLAYER_PROTO_DETECTION_SKIPPED },
    { NULL,
      -1 },
};

int AppLayerGetPktEventInfo(const char *event_name, int *event_id)
{
    *event_id = SCMapEnumNameToValue(event_name, app_layer_event_pkt_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "app-layer-event's packet event table.",  event_name);
        /* this should be treated as fatal */
        return -1;
    }

    return 0;
}
