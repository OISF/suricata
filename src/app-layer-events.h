/* Copyright (C) 2014-2022 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef SURICATA_APP_LAYER_EVENTS_H
#define SURICATA_APP_LAYER_EVENTS_H

/* contains fwd declaration of AppLayerDecoderEvents_ */
#include "suricata-common.h"
#include "app-layer-types.h"
#include "util-enum.h"

/**
 * \brief Data structure to store app layer decoder events.
 */
typedef struct AppLayerDecoderEvents_ {
    /* array of events */
    uint8_t *events;
    /* number of events in the above buffer */
    uint8_t cnt;
    /* current event buffer size */
    uint8_t events_buffer_size;
    /* last logged */
    uint8_t event_last_logged;
} AppLayerDecoderEvents;

/* app layer pkt level events */
enum {
    APPLAYER_MISMATCH_PROTOCOL_BOTH_DIRECTIONS,
    APPLAYER_WRONG_DIRECTION_FIRST_DATA,
    APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION,
    APPLAYER_PROTO_DETECTION_SKIPPED,
    APPLAYER_NO_TLS_AFTER_STARTTLS,
    APPLAYER_UNEXPECTED_PROTOCOL,
};

int AppLayerGetPktEventInfo(const char *event_name, uint8_t *event_id);

int AppLayerGetEventInfoById(
        uint8_t event_id, const char **event_name, SCAppLayerEventType *event_type);
void AppLayerDecoderEventsSetEventRaw(AppLayerDecoderEvents **sevents, uint8_t event);

static inline int AppLayerDecoderEventsIsEventSet(
        const AppLayerDecoderEvents *devents, uint8_t event)
{
    if (devents == NULL)
        return 0;

    int cnt = devents->cnt;
    for (int i = 0; i < cnt; i++) {
        if (devents->events[i] == event)
            return 1;
    }

    return 0;
}

void AppLayerDecoderEventsResetEvents(AppLayerDecoderEvents *events);
void AppLayerDecoderEventsFreeEvents(AppLayerDecoderEvents **events);
int DetectEngineGetEventInfo(
        const char *event_name, uint8_t *event_id, SCAppLayerEventType *event_type);
int SCAppLayerGetEventIdByName(const char *event_name, SCEnumCharMap *table, uint8_t *event_id);

#endif /* SURICATA_APP_LAYER_EVENTS_H */
