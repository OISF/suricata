/* Copyright (C) 2007-2023 Open Information Security Foundation
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
#include "threads.h"
#include "decode.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer/smtp/parser.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-engine-build.h"
#include "detect-app-layer-event.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "decode-events.h"
#include "util/byte.h"
#include "util/debug.h"
#include "util/enum.h"
#include "util/profiling.h"
#include "util/unittest.h"
#include "util/unittest-helper.h"
#include "stream-tcp-util.h"

#define MAX_ALPROTO_NAME 50

typedef struct DetectAppLayerEventData_ {
    AppProto alproto;
    uint8_t event_id;
} DetectAppLayerEventData;

static int DetectAppLayerEventPktMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx);
static int DetectAppLayerEventSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectAppLayerEventFree(DetectEngineCtx *, void *);
static uint8_t DetectEngineAptEventInspect(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *tx, uint64_t tx_id);
static int g_applayer_events_list_id = 0;

/**
 * \brief Registers the keyword handlers for the "app-layer-event" keyword.
 */
void DetectAppLayerEventRegister(void)
{
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].name = "app-layer-event";
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].desc =
            "match on events generated by the App Layer Parsers and the protocol detection engine";
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].url = "/rules/app-layer.html#app-layer-event";
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].Match = DetectAppLayerEventPktMatch;
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].Setup = DetectAppLayerEventSetup;
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].Free = DetectAppLayerEventFree;

    DetectAppLayerInspectEngineRegister2("app-layer-events", ALPROTO_UNKNOWN, SIG_FLAG_TOSERVER, 0,
            DetectEngineAptEventInspect, NULL);
    DetectAppLayerInspectEngineRegister2("app-layer-events", ALPROTO_UNKNOWN, SIG_FLAG_TOCLIENT, 0,
            DetectEngineAptEventInspect, NULL);

    g_applayer_events_list_id = DetectBufferTypeGetByName("app-layer-events");
}

static uint8_t DetectEngineAptEventInspect(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *tx, uint64_t tx_id)
{
    int r = 0;
    const AppProto alproto = f->alproto;
    const AppLayerDecoderEvents *decoder_events =
            AppLayerParserGetEventsByTx(f->proto, alproto, tx);
    if (decoder_events == NULL) {
        goto end;
    }
    const SigMatchData *smd = engine->smd;
    while (1) {
        const DetectAppLayerEventData *aled = (const DetectAppLayerEventData *)smd->ctx;
        KEYWORD_PROFILING_START;

        if (AppLayerDecoderEventsIsEventSet(decoder_events, aled->event_id)) {
            KEYWORD_PROFILING_END(det_ctx, smd->type, 1);

            if (smd->is_last)
                break;
            smd++;
            continue;
        }

        KEYWORD_PROFILING_END(det_ctx, smd->type, 0);
        goto end;
    }

    r = 1;

end:
    if (r == 1) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    } else {
        if (AppLayerParserGetStateProgress(f->proto, alproto, tx, flags) ==
                AppLayerParserGetStateProgressCompletionStatus(alproto, flags)) {
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
        } else {
            return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
        }
    }
}

static int DetectAppLayerEventPktMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectAppLayerEventData *aled = (const DetectAppLayerEventData *)ctx;

    return AppLayerDecoderEventsIsEventSet(p->app_layer_events, aled->event_id);
}

static DetectAppLayerEventData *DetectAppLayerEventParsePkt(
        const char *arg, AppLayerEventType *event_type)
{
    int event_id = 0;
    int r = AppLayerGetPktEventInfo(arg, &event_id);
    if (r < 0 || r > UINT8_MAX) {
        SCLogError("app-layer-event keyword "
                   "supplied with packet based event - \"%s\" that isn't "
                   "supported yet.",
                arg);
        return NULL;
    }

    DetectAppLayerEventData *aled = SCCalloc(1, sizeof(DetectAppLayerEventData));
    if (unlikely(aled == NULL))
        return NULL;
    aled->event_id = (uint8_t)event_id;
    *event_type = APP_LAYER_EVENT_TYPE_PACKET;

    return aled;
}

static bool OutdatedEvent(const char *raw)
{
    if (strcmp(raw, "tls.certificate_missing_element") == 0 ||
            strcmp(raw, "tls.certificate_unknown_element") == 0 ||
            strcmp(raw, "tls.certificate_invalid_string") == 0) {
        return true;
    }
    return false;
}

static AppProto AppLayerEventGetProtoByName(char *alproto_name)
{
    AppProto alproto = AppLayerGetProtoByName(alproto_name);
    if (alproto == ALPROTO_HTTP) {
        // app-layer events http refer to http1
        alproto = ALPROTO_HTTP1;
    }
    return alproto;
}

static int DetectAppLayerEventSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (arg == NULL) {
        SCLogError("app-layer-event keyword supplied "
                   "with no arguments.  This keyword needs an argument.");
        return -1;
    }

    while (*arg != '\0' && isspace((unsigned char)*arg))
        arg++;

    AppLayerEventType event_type;
    DetectAppLayerEventData *data = NULL;

    if (strchr(arg, '.') == NULL) {
        data = DetectAppLayerEventParsePkt(arg, &event_type);
        if (data == NULL)
            return -1;
    } else {
        SCLogDebug("parsing %s", arg);
        char alproto_name[MAX_ALPROTO_NAME];
        bool needs_detctx = false;

        const char *p_idx = strchr(arg, '.');
        if (strlen(arg) > MAX_ALPROTO_NAME) {
            SCLogError("app-layer-event keyword is too long or malformed");
            return -1;
        }
        const char *event_name = p_idx + 1; // skip .
        /* + 1 for trailing \0 */
        strlcpy(alproto_name, arg, p_idx - arg + 1);

        const AppProto alproto = AppLayerEventGetProtoByName(alproto_name);
        if (alproto == ALPROTO_UNKNOWN) {
            if (!strcmp(alproto_name, "file")) {
                needs_detctx = true;
            } else {
                SCLogError("app-layer-event keyword "
                           "supplied with unknown protocol \"%s\"",
                        alproto_name);
                return -1;
            }
        }
        if (OutdatedEvent(arg)) {
            if (SigMatchStrictEnabled(DETECT_AL_APP_LAYER_EVENT)) {
                SCLogError("app-layer-event keyword no longer supports event \"%s\"", arg);
                return -1;
            } else {
                SCLogWarning("app-layer-event keyword no longer supports event \"%s\"", arg);
                return -3;
            }
        }

        uint8_t ipproto = 0;
        if (s->proto.proto[IPPROTO_TCP / 8] & 1 << (IPPROTO_TCP % 8)) {
            ipproto = IPPROTO_TCP;
        } else if (s->proto.proto[IPPROTO_UDP / 8] & 1 << (IPPROTO_UDP % 8)) {
            ipproto = IPPROTO_UDP;
        } else {
            SCLogError("protocol %s is disabled", alproto_name);
            return -1;
        }

        int r;
        int event_id = 0;
        if (!needs_detctx) {
            r = AppLayerParserGetEventInfo(ipproto, alproto, event_name, &event_id, &event_type);
        } else {
            r = DetectEngineGetEventInfo(event_name, &event_id, &event_type);
        }
        if (r < 0) {
            if (SigMatchStrictEnabled(DETECT_AL_APP_LAYER_EVENT)) {
                SCLogError("app-layer-event keyword's "
                           "protocol \"%s\" doesn't have event \"%s\" registered",
                        alproto_name, event_name);
                return -1;
            } else {
                SCLogWarning("app-layer-event keyword's "
                             "protocol \"%s\" doesn't have event \"%s\" registered",
                        alproto_name, event_name);
                return -3;
            }
        }
        if (event_id > UINT8_MAX) {
            SCLogWarning("app-layer-event keyword's id has invalid value");
            return -4;
        }
        data = SCCalloc(1, sizeof(*data));
        if (unlikely(data == NULL))
            return -1;
        data->alproto = alproto;
        data->event_id = (uint8_t)event_id;
    }
    SCLogDebug("data->event_id %u", data->event_id);

    if (event_type == APP_LAYER_EVENT_TYPE_PACKET) {
        if (SigMatchAppendSMToList(de_ctx, s, DETECT_AL_APP_LAYER_EVENT, (SigMatchCtx *)data,
                    DETECT_SM_LIST_MATCH) == NULL) {
            goto error;
        }
    } else {
        if (DetectSignatureSetAppProto(s, data->alproto) != 0)
            goto error;

        if (SigMatchAppendSMToList(de_ctx, s, DETECT_AL_APP_LAYER_EVENT, (SigMatchCtx *)data,
                    g_applayer_events_list_id) == NULL) {
            goto error;
        }
        s->flags |= SIG_FLAG_APPLAYER;
    }

    return 0;

error:
    if (data) {
        DetectAppLayerEventFree(de_ctx, data);
    }
    return -1;
}

static void DetectAppLayerEventFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}
