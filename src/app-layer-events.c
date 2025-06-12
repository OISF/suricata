/* Copyright (C) 2014-2024 Open Information Security Foundation
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

#include "suricata-common.h"
#include "rust.h"
#include "app-layer-events.h"
#include "util-enum.h"

int SCAppLayerGetEventIdByName(const char *event_name, SCEnumCharMap *table, uint8_t *event_id)
{
    int value = SCMapEnumNameToValue(event_name, table);
    if (value == -1) {
        SCLogError("event \"%s\" not present in enum table.", event_name);
        /* this should be treated as fatal */
        return -1;
    } else if (value < -1 || value > UINT8_MAX) {
        SCLogError("event \"%s\" has out of range value", event_name);
        /* this should be treated as fatal */
        return -1;
    }
    *event_id = (uint8_t)value;
    return 0;
}

/* events raised during protocol detection are stored in the
 * packets storage, not in the flow. */
SCEnumCharMap app_layer_event_pkt_table[ ] = {
    { "APPLAYER_MISMATCH_PROTOCOL_BOTH_DIRECTIONS",
      APPLAYER_MISMATCH_PROTOCOL_BOTH_DIRECTIONS },
    { "APPLAYER_WRONG_DIRECTION_FIRST_DATA",
      APPLAYER_WRONG_DIRECTION_FIRST_DATA },
    { "APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION",
      APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION },
    { "APPLAYER_PROTO_DETECTION_SKIPPED",
      APPLAYER_PROTO_DETECTION_SKIPPED },
    { "APPLAYER_NO_TLS_AFTER_STARTTLS",
      APPLAYER_NO_TLS_AFTER_STARTTLS },
    { "APPLAYER_UNEXPECTED_PROTOCOL",
      APPLAYER_UNEXPECTED_PROTOCOL },
    { NULL,
      -1 },
};

int AppLayerGetEventInfoById(
        uint8_t event_id, const char **event_name, AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, app_layer_event_pkt_table);
    if (*event_name == NULL) {
        SCLogError("event \"%d\" not present in "
                   "app-layer-event's enum map table.",
                event_id);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_PACKET;

    return 0;
}

int AppLayerGetPktEventInfo(const char *event_name, uint8_t *event_id)
{
    return SCAppLayerGetEventIdByName(event_name, app_layer_event_pkt_table, event_id);
}

#define DECODER_EVENTS_BUFFER_STEPS 8

/**
 * \brief Set an app layer decoder event.
 *
 * \param sevents Pointer to a AppLayerDecoderEvents pointer. If *sevents is NULL
 *                memory will be allocated.
 * \param event   The event to be stored.
 */
void SCAppLayerDecoderEventsSetEventRaw(AppLayerDecoderEvents **sevents, uint8_t event)
{
    if (*sevents == NULL) {
        AppLayerDecoderEvents *new_devents = SCCalloc(1, sizeof(AppLayerDecoderEvents));
        if (new_devents == NULL)
            return;

        *sevents = new_devents;

    }
    if ((*sevents)->cnt == UCHAR_MAX) {
        /* we're full */
        return;
    }
    if ((*sevents)->cnt == (*sevents)->events_buffer_size) {
        int steps = DECODER_EVENTS_BUFFER_STEPS;
        if (UCHAR_MAX - (*sevents)->cnt < steps)
            steps = UCHAR_MAX - (*sevents)->cnt < steps;

        void *ptr = SCRealloc((*sevents)->events,
                              ((*sevents)->cnt + steps) * sizeof(uint8_t));
        if (ptr == NULL) {
            /* couldn't grow buffer, but no reason to free old
             * so we keep the events that may already be here */
            return;
        }
        (*sevents)->events = ptr;
        (*sevents)->events_buffer_size += steps;
    }

    (*sevents)->events[(*sevents)->cnt++] = event;
}

void AppLayerDecoderEventsResetEvents(AppLayerDecoderEvents *events)
{
    if (events != NULL) {
        events->cnt = 0;
        events->event_last_logged = 0;
    }
}

void SCAppLayerDecoderEventsFreeEvents(AppLayerDecoderEvents **events)
{
    if (events && *events != NULL) {
        if ((*events)->events != NULL)
            SCFree((*events)->events);
        SCFree(*events);
        *events = NULL;
    }
}

SCEnumCharMap det_ctx_event_table[] = {
    { "NO_MEMORY", FILE_DECODER_EVENT_NO_MEM },
    { "INVALID_SWF_LENGTH", FILE_DECODER_EVENT_INVALID_SWF_LENGTH },
    { "INVALID_SWF_VERSION", FILE_DECODER_EVENT_INVALID_SWF_VERSION },
    { "Z_DATA_ERROR", FILE_DECODER_EVENT_Z_DATA_ERROR },
    { "Z_STREAM_ERROR", FILE_DECODER_EVENT_Z_STREAM_ERROR },
    { "Z_BUF_ERROR", FILE_DECODER_EVENT_Z_BUF_ERROR },
    { "Z_UNKNOWN_ERROR", FILE_DECODER_EVENT_Z_UNKNOWN_ERROR },
    { "LZMA_IO_ERROR", FILE_DECODER_EVENT_LZMA_IO_ERROR },
    { "LZMA_HEADER_TOO_SHORT_ERROR", FILE_DECODER_EVENT_LZMA_HEADER_TOO_SHORT_ERROR },
    { "LZMA_DECODER_ERROR", FILE_DECODER_EVENT_LZMA_DECODER_ERROR },
    { "LZMA_MEMLIMIT_ERROR", FILE_DECODER_EVENT_LZMA_MEMLIMIT_ERROR },
    { "LZMA_XZ_ERROR", FILE_DECODER_EVENT_LZMA_XZ_ERROR },
    { "LZMA_UNKNOWN_ERROR", FILE_DECODER_EVENT_LZMA_UNKNOWN_ERROR },
    {
            "TOO_MANY_BUFFERS",
            DETECT_EVENT_TOO_MANY_BUFFERS,
    },
    {
            "POST_MATCH_QUEUE_FAILED",
            DETECT_EVENT_POST_MATCH_QUEUE_FAILED,
    },
    { NULL, -1 },
};

int DetectEngineGetEventInfo(
        const char *event_name, uint8_t *event_id, AppLayerEventType *event_type)
{
    if (SCAppLayerGetEventIdByName(event_name, det_ctx_event_table, event_id) == 0) {
        *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;
        return 0;
    }
    return -1;
}
