/* Copyright (C) 2014 Open Information Security Foundation
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

#ifndef __APP_LAYER_EVENTS_H__
#define __APP_LAYER_EVENTS_H__

/* contains fwd declaration of AppLayerDecoderEvents_ */
#include "decode.h"

/**
 * \brief Data structure to store app layer decoder events.
 */
struct AppLayerDecoderEvents_ {
    /* array of events */
    uint8_t *events;
    /* number of events in the above buffer */
    uint8_t cnt;
    /* current event buffer size */
    uint8_t events_buffer_size;
};

/* app layer pkt level events */
enum {
    APPLAYER_MISMATCH_PROTOCOL_BOTH_DIRECTIONS,
    APPLAYER_WRONG_DIRECTION_FIRST_DATA,
    APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION,
    APPLAYER_PROTO_DETECTION_SKIPPED,
};

/* the event types for app events */
typedef enum AppLayerEventType_ {
    APP_LAYER_EVENT_TYPE_GENERAL = 1,
    APP_LAYER_EVENT_TYPE_TRANSACTION,
    APP_LAYER_EVENT_TYPE_PACKET,
} AppLayerEventType;

int AppLayerGetPktEventInfo(const char *event_name, int *event_id);

void AppLayerDecoderEventsSetEventRaw(AppLayerDecoderEvents **sevents, uint8_t event);
void AppLayerDecoderEventsSetEvent(Flow *f, uint8_t event);

static inline int AppLayerDecoderEventsIsEventSet(AppLayerDecoderEvents *devents,
                                                  uint8_t event)
{
    if (devents == NULL)
        return 0;

    int i;
    int cnt = devents->cnt;
    for (i = 0; i < cnt; i++) {
        if (devents->events[i] == event)
            return 1;
    }

    return 0;
}

void AppLayerDecoderEventsResetEvents(AppLayerDecoderEvents *events);
void AppLayerDecoderEventsFreeEvents(AppLayerDecoderEvents **events);

#endif /* __APP_LAYER_EVENTS_H__ */

