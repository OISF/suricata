/* Copyright (C) 2007-2011 Open Information Security Foundation
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
#include "app-layer-parser.h"
#include "decode-events.h"
#include "flow.h"

AppLayerDecoderEventsModule *decoder_events_module = NULL;

void AppLayerDecoderEventsModuleRegister(uint16_t alproto, SCEnumCharMap *table)
{
    AppLayerDecoderEventsModule *dvm = decoder_events_module;

    if (table == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "argument \"table\" NULL");
        return;
    }

    while (dvm != NULL) {
        if (dvm->alproto == alproto) {
            SCLogInfo("Decoder event module for alproto - %"PRIu16" already "
                      "registered", alproto);
            return;
        }
        dvm = dvm->next;
    }

    AppLayerDecoderEventsModule *new_dev =
        SCMalloc(sizeof(AppLayerDecoderEventsModule));
    if (unlikely(new_dev == NULL))
        return;

    new_dev->alproto = alproto;
    new_dev->table = table;
    new_dev->next = NULL;

    if (decoder_events_module != NULL)
        new_dev->next = decoder_events_module;
    decoder_events_module = new_dev;

    return;
}

uint16_t AppLayerDecoderEventsModuleGetAlproto(const char *alproto)
{
    return AppLayerGetProtoByName(alproto);
}

int AppLayerDecoderEventsModuleGetEventId(uint16_t alproto,
                                          const char *event_name)
{
    AppLayerDecoderEventsModule *dvm = decoder_events_module;

    while (dvm != NULL) {
        if (dvm->alproto == alproto)
            break;
        dvm = dvm->next;
    }
    if (dvm == NULL) {
        SCLogError(SC_ERR_FATAL, "decoder event module not found for "
                   "alproto - %"PRIu16, alproto);
        return -1;
    }

    int event_id = SCMapEnumNameToValue(event_name, dvm->table);
    if (event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "module enum map table.",  event_name);
        /* yes this is fatal */
        return -1;
    }

    return event_id;
}

void AppLayerDecoderEventsModuleDeRegister(void)
{
    AppLayerDecoderEventsModule *dvm = decoder_events_module;
    AppLayerDecoderEventsModule *prev_dvm;

    while (dvm != NULL) {
        prev_dvm = dvm;
        dvm = dvm->next;
        SCFree(prev_dvm);
    }

    decoder_events_module = NULL;
}

/************************************Unittests*********************************/

AppLayerDecoderEventsModule *decoder_events_module_backup = NULL;

void AppLayerDecoderEventsModuleCreateBackup(void)
{
    decoder_events_module_backup = decoder_events_module;
    decoder_events_module = NULL;

    return;
}

void AppLayerDecoderEventsModuleRestoreBackup(void)
{
    AppLayerDecoderEventsModuleDeRegister();
    decoder_events_module = decoder_events_module_backup;
    decoder_events_module_backup = NULL;

    return;
}
