/* Copyright (C) 2007-2012 Open Information Security Foundation
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

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-smtp.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-app-layer-event.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "decode-events.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"


int DetectAppLayerEventMatch(ThreadVars *, DetectEngineThreadCtx *, Flow *,
                             uint8_t, void *, Signature *, SigMatch *);
int DetectAppLayerEventSetup(DetectEngineCtx *, Signature *, char *);
void DetectAppLayerEventRegisterTests(void);
void DetectAppLayerEventFree(void *);

/**
 * \brief Registers the keyword handlers for the "app-layer-event" keyword.
 */
void DetectAppLayerEventRegister(void)
{
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].name = "app-layer-event";
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].Match = NULL;
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].AppLayerMatch =
        DetectAppLayerEventMatch;
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].Setup = DetectAppLayerEventSetup;
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].Free = DetectAppLayerEventFree;
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].RegisterTests =
        DetectAppLayerEventRegisterTests;

    return;
}

int DetectAppLayerEventMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                             Flow *f, uint8_t flags, void *state, Signature *s,
                             SigMatch *m)
{
    SCEnter();
    int r = 0;

    DetectAppLayerEventData *aled = (DetectAppLayerEventData *)m->ctx;

    FLOWLOCK_RDLOCK(f);

    AppLayerDecoderEvents *decoder_events = AppLayerGetDecoderEventsForFlow(f);
    if (decoder_events != NULL &&
            AppLayerDecoderEventsIsEventSet(decoder_events, aled->event_id)) {
        r = 1;
    }

    FLOWLOCK_UNLOCK(f);
    SCReturnInt(r);
}

static DetectAppLayerEventData *DetectAppLayerEventParse(const char *arg)
{
    /* period index */
    const char *p_idx;

    if (arg == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "app-layer-event keyword supplied "
                   "with no arguments.  This keyword needs an argument.");
        return NULL;
    }

    while (*arg != '\0' && isspace((unsigned char)*arg)) {
        arg++;
    }

    p_idx = strchr(arg, '.');
    if (p_idx == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "app-layer-event keyword supplied "
                   "with an argument which is not in the right format.  The "
                   "right format is \"<alproto>.<event>\"");
        return NULL;
    }

    char buffer[50] = "";
    strlcpy(buffer, arg, p_idx - arg + 1); /* + 1 for trailing \0 */

    //int module_id = DecoderEventModuleGetModuleId(buffer);
    //uint16_t alproto = AppLayerGetProtoByName(buffer);
    uint16_t alproto = AppLayerDecoderEventsModuleGetAlproto(buffer);
    if (alproto == ALPROTO_UNKNOWN)
        return NULL;
    int event_id = AppLayerDecoderEventsModuleGetEventId(alproto, p_idx + 1);
    if (event_id == -1)
        return NULL;

    DetectAppLayerEventData *aled = SCMalloc(sizeof(DetectAppLayerEventData));
    if (unlikely(aled == NULL))
        return NULL;
    aled->alproto = alproto;
    aled->event_id = event_id;

    return aled;
}

int DetectAppLayerEventSetup(DetectEngineCtx *de_ctx, Signature *s, char *arg)
{
    DetectAppLayerEventData *data = NULL;
    SigMatch *sm = NULL;

    data = DetectAppLayerEventParse(arg);
    if (data == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_APP_LAYER_EVENT;
    sm->ctx = (void *)data;

    if (s->alproto != ALPROTO_UNKNOWN) {
        if (s->alproto != ((DetectAppLayerEventData *)sm->ctx)->alproto) {
            SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains "
                       "conflicting keywords needing different alprotos");
            goto error;
        }
    } else {
        s->alproto = ((DetectAppLayerEventData *)sm->ctx)->alproto;
    }

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);
    s->flags |= SIG_FLAG_APPLAYER;

    return 0;

 error:
    return -1;
}

void DetectAppLayerEventFree(void *ptr)
{
    SCFree(ptr);

    return;
}

/**********************************Unittests***********************************/

#ifdef UNITTESTS /* UNITTESTS */

#define APP_LAYER_EVENT_TEST_MAP_EVENT1 0
#define APP_LAYER_EVENT_TEST_MAP_EVENT2 1
#define APP_LAYER_EVENT_TEST_MAP_EVENT3 2
#define APP_LAYER_EVENT_TEST_MAP_EVENT4 3
#define APP_LAYER_EVENT_TEST_MAP_EVENT5 4
#define APP_LAYER_EVENT_TEST_MAP_EVENT6 5

SCEnumCharMap app_layer_event_test_map[ ] = {
    { "event1", APP_LAYER_EVENT_TEST_MAP_EVENT1 },
    { "event2", APP_LAYER_EVENT_TEST_MAP_EVENT2 },
    { "event3", APP_LAYER_EVENT_TEST_MAP_EVENT3 },
    { "event4", APP_LAYER_EVENT_TEST_MAP_EVENT4 },
    { "event5", APP_LAYER_EVENT_TEST_MAP_EVENT5 },
    { "event6", APP_LAYER_EVENT_TEST_MAP_EVENT6 },
};

int DetectAppLayerEventTest01(void)
{
    AppLayerDecoderEventsModuleCreateBackup();
    AppLayerDecoderEventsModuleRegister(ALPROTO_SMTP, app_layer_event_test_map);

    int result = 0;

    DetectAppLayerEventData *aled = DetectAppLayerEventParse("smtp.event1");
    if (aled == NULL)
        goto end;
    if (aled->alproto != ALPROTO_SMTP ||
        aled->event_id != APP_LAYER_EVENT_TEST_MAP_EVENT1) {
        printf("test failure.  Holding wrong state\n");
        goto end;
    }

    result = 1;

 end:
    AppLayerDecoderEventsModuleRestoreBackup();
    if (aled != NULL)
        DetectAppLayerEventFree(aled);
    return result;
}

int DetectAppLayerEventTest02(void)
{
    AppLayerDecoderEventsModuleCreateBackup();
    AppLayerDecoderEventsModuleRegister(ALPROTO_SMTP, app_layer_event_test_map);
    AppLayerDecoderEventsModuleRegister(ALPROTO_HTTP, app_layer_event_test_map);
    AppLayerDecoderEventsModuleRegister(ALPROTO_SMB, app_layer_event_test_map);
    AppLayerDecoderEventsModuleRegister(ALPROTO_FTP, app_layer_event_test_map);

    int result = 0;

    DetectAppLayerEventData *aled = DetectAppLayerEventParse("smtp.event1");
    if (aled == NULL)
        goto end;
    if (aled->alproto != ALPROTO_SMTP ||
        aled->event_id != APP_LAYER_EVENT_TEST_MAP_EVENT1) {
        printf("test failure.  Holding wrong state\n");
        goto end;
    }

    aled = DetectAppLayerEventParse("smtp.event4");
    if (aled == NULL)
        goto end;
    if (aled->alproto != ALPROTO_SMTP ||
        aled->event_id != APP_LAYER_EVENT_TEST_MAP_EVENT4) {
        printf("test failure.  Holding wrong state\n");
        goto end;
    }

    aled = DetectAppLayerEventParse("http.event2");
    if (aled == NULL)
        goto end;
    if (aled->alproto != ALPROTO_HTTP ||
        aled->event_id != APP_LAYER_EVENT_TEST_MAP_EVENT2) {
        printf("test failure.  Holding wrong state\n");
        goto end;
    }

    aled = DetectAppLayerEventParse("smb.event3");
    if (aled == NULL)
        goto end;
    if (aled->alproto != ALPROTO_SMB ||
        aled->event_id != APP_LAYER_EVENT_TEST_MAP_EVENT3) {
        printf("test failure.  Holding wrong state\n");
        goto end;
    }

    aled = DetectAppLayerEventParse("ftp.event5");
    if (aled == NULL)
        goto end;
    if (aled->alproto != ALPROTO_FTP ||
        aled->event_id != APP_LAYER_EVENT_TEST_MAP_EVENT5) {
        printf("test failure.  Holding wrong state\n");
        goto end;
    }

    result = 1;

 end:
    AppLayerDecoderEventsModuleRestoreBackup();
    if (aled != NULL)
        DetectAppLayerEventFree(aled);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for "app-layer-event" keyword.
 */
void DetectAppLayerEventRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectAppLayerEventTest01", DetectAppLayerEventTest01, 1);
    UtRegisterTest("DetectAppLayerEventTest02", DetectAppLayerEventTest02, 1);
#endif /* UNITTESTS */

    return;
}
