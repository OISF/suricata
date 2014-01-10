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

/** \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "suricata.h"

#include "app-layer-parser.h"
#include "detect-app-layer-event.h"
#include "detect-engine-state.h"
#include "stream.h"
#include "detect-engine-apt-event.h"
#include "util-profiling.h"
#include "util-unittest.h"

int DetectEngineAptEventInspect(ThreadVars *tv,
                                DetectEngineCtx *de_ctx,
                                DetectEngineThreadCtx *det_ctx,
                                Signature *s, Flow *f, uint8_t flags,
                                void *alstate,
                                void *tx, uint64_t tx_id)
{
    AppLayerDecoderEvents *decoder_events = NULL;
    int r = 0;
    AppProto alproto;
    SigMatch *sm;
    DetectAppLayerEventData *aled = NULL;

    alproto = f->alproto;
    decoder_events = AppLayerParserGetEventsByTx(f->proto, alproto, alstate, tx_id);
    if (decoder_events == NULL)
        goto end;

    for (sm = s->sm_lists[DETECT_SM_LIST_APP_EVENT]; sm != NULL; sm = sm->next) {
        aled = (DetectAppLayerEventData *)sm->ctx;
        KEYWORD_PROFILING_START;
        if (AppLayerDecoderEventsIsEventSet(decoder_events, aled->event_id)) {
            KEYWORD_PROFILING_END(det_ctx, sm->type, 1);
            continue;
        }

        KEYWORD_PROFILING_END(det_ctx, sm->type, 0);
        goto end;
    }

    r = 1;

 end:
    if (r == 1) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    } else {
        if (AppLayerParserGetStateProgress(f->proto, alproto, tx, flags) ==
            AppLayerParserGetStateProgressCompletionStatus(f->proto, alproto, flags))
        {
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
        } else {
            return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
        }
    }
}

