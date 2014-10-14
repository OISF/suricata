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
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-app-layer-protocol.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

void DetectAppLayerProtocolRegisterTests(void);

int DetectAppLayerProtocolMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                                Flow *f, uint8_t flags, void *state,
                                Signature *s, SigMatch *m)
{
    int r = 0;
    DetectAppLayerProtocolData *data = (DetectAppLayerProtocolData *)m->ctx;

    r = (data->negated) ? (f->alproto != data->alproto) :
        (f->alproto == data->alproto);

    return r;
}

static DetectAppLayerProtocolData *DetectAppLayerProtocolParse(const char *arg)
{
    DetectAppLayerProtocolData *data;
    AppProto alproto = ALPROTO_UNKNOWN;
    uint8_t negated = 0;

    if (arg == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "app-layer-protocol keyword "
                   "supplied with no arguments.  This keyword needs "
                   "an argument.");
        return NULL;
    }

    while (*arg != '\0' && isspace((unsigned char)*arg))
        arg++;

    if (arg[0] == '!') {
        negated = 1;
        arg++;
    }

    while (*arg != '\0' && isspace((unsigned char)*arg))
        arg++;

    alproto = AppLayerGetProtoByName((char *)arg);
    if (alproto == ALPROTO_UNKNOWN) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "app-layer-protocol "
                   "keyword supplied with unknown protocol \"%s\"", arg);
        return NULL;
    }

    data = SCMalloc(sizeof(DetectAppLayerProtocolData));
    if (unlikely(data == NULL))
        return NULL;
    data->alproto = alproto;
    data->negated = negated;

    return data;
}

int DetectAppLayerProtocolSetup(DetectEngineCtx *de_ctx, Signature *s,
                                char *arg)
{
    DetectAppLayerProtocolData *data = NULL;
    SigMatch *sm = NULL;

    if (s->alproto != ALPROTO_UNKNOWN) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "Either we already "
                   "have the rule match on an app layer protocol set through "
                   "other keywords that match on this protocol, or have "
                   "already seen a non-negated app-layer-protocol.");
        goto error;
    }

    data = DetectAppLayerProtocolParse(arg);
    if (data == NULL)
        goto error;

    if (!data->negated)
        s->alproto = data->alproto;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_APP_LAYER_PROTOCOL;
    sm->ctx = (void *)data;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);
    s->flags |= SIG_FLAG_APPLAYER;

    return 0;

error:
    if (data != NULL)
        SCFree(data);
    return -1;
}

void DetectAppLayerProtocolFree(void *ptr)
{
    SCFree(ptr);

    return;
}

void DetectAppLayerProtocolRegister(void)
{
    sigmatch_table[DETECT_AL_APP_LAYER_PROTOCOL].name = "app-layer-protocol";
    sigmatch_table[DETECT_AL_APP_LAYER_PROTOCOL].Match = NULL;
    sigmatch_table[DETECT_AL_APP_LAYER_PROTOCOL].AppLayerMatch =
        DetectAppLayerProtocolMatch;
    sigmatch_table[DETECT_AL_APP_LAYER_PROTOCOL].Setup =
        DetectAppLayerProtocolSetup;
    sigmatch_table[DETECT_AL_APP_LAYER_PROTOCOL].Free =
        DetectAppLayerProtocolFree;
    sigmatch_table[DETECT_AL_APP_LAYER_PROTOCOL].RegisterTests =
        DetectAppLayerProtocolRegisterTests;

    return;
}

/**********************************Unittests***********************************/

#ifdef UNITTESTS

int DetectAppLayerProtocolTest01(void)
{
    int result = 0;

    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("http");
    if (data == NULL)
        goto end;
    if (data->alproto != ALPROTO_HTTP || data->negated) {
        printf("test failure.  Holding wrong state\n");
        goto end;
    }

    result = 1;

 end:
    if (data != NULL)
        DetectAppLayerProtocolFree(data);
    return result;
}

int DetectAppLayerProtocolTest02(void)
{
    int result = 0;

    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("!http");
    if (data == NULL)
        goto end;
    if (data->alproto != ALPROTO_HTTP || !data->negated) {
        printf("test failure.  Holding wrong state\n");
        goto end;
    }

    result = 1;

 end:
    if (data != NULL)
        DetectAppLayerProtocolFree(data);
    return result;
}

int DetectAppLayerProtocolTest03(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectAppLayerProtocolData *data = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(app-layer-protocol:http; sid:1;)");
    if (s->alproto != ALPROTO_HTTP) {
        printf("signature alproto should be http\n");
        goto end;
    }
    data = (DetectAppLayerProtocolData *)s->sm_lists[DETECT_SM_LIST_AMATCH]->ctx;
    if (data->alproto != ALPROTO_HTTP || data->negated) {
        printf("if (data->alproto != ALPROTO_HTTP || data->negated)\n");
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectAppLayerProtocolTest04(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectAppLayerProtocolData *data = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(app-layer-protocol:!http; sid:1;)");
    if (s->alproto != ALPROTO_UNKNOWN) {
        printf("signature alproto should be unknown\n");
        goto end;
    }
    if (s->sm_lists[DETECT_SM_LIST_AMATCH] == NULL) {
        printf("if (s->sm_lists[DETECT_SM_LIST_AMATCH] == NULL)\n");
        goto end;
    }
    data = (DetectAppLayerProtocolData*)s->sm_lists[DETECT_SM_LIST_AMATCH]->ctx;
    if (data == NULL) {
        printf("if (data == NULL)\n");
        goto end;
    }
    if (data->alproto != ALPROTO_HTTP || !data->negated) {
        printf("if (data->alproto != ALPROTO_HTTP || !data->negated)\n");
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectAppLayerProtocolTest05(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(app-layer-protocol:!http; app-layer-protocol:!smtp; sid:1;)");
    if (s->alproto != ALPROTO_UNKNOWN) {
        printf("signature alproto should be unknown\n");
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectAppLayerProtocolTest06(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx, "alert http any any -> any any "
                "(app-layer-protocol:smtp; sid:1;)");
    if (s != NULL) {
        printf("if (s != NULL)\n");
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectAppLayerProtocolTest07(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx, "alert http any any -> any any "
                "(app-layer-protocol:!smtp; sid:1;)");
    if (s != NULL) {
        printf("if (s != NULL)\n");
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectAppLayerProtocolTest08(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(app-layer-protocol:!smtp; app-layer-protocol:http; sid:1;)");
    if (s != NULL) {
        printf("if (s != NULL)\n");
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectAppLayerProtocolTest09(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(app-layer-protocol:http; app-layer-protocol:!smtp; sid:1;)");
    if (s != NULL) {
        printf("if (s != NULL)\n");
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

#endif /* UNITTESTS */

void DetectAppLayerProtocolRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectAppLayerProtocolTest01", DetectAppLayerProtocolTest01, 1);
    UtRegisterTest("DetectAppLayerProtocolTest02", DetectAppLayerProtocolTest02, 1);
    UtRegisterTest("DetectAppLayerProtocolTest03", DetectAppLayerProtocolTest03, 1);
    UtRegisterTest("DetectAppLayerProtocolTest04", DetectAppLayerProtocolTest04, 1);
    UtRegisterTest("DetectAppLayerProtocolTest05", DetectAppLayerProtocolTest05, 1);
    UtRegisterTest("DetectAppLayerProtocolTest06", DetectAppLayerProtocolTest06, 1);
    UtRegisterTest("DetectAppLayerProtocolTest07", DetectAppLayerProtocolTest07, 1);
    UtRegisterTest("DetectAppLayerProtocolTest08", DetectAppLayerProtocolTest08, 1);
    UtRegisterTest("DetectAppLayerProtocolTest09", DetectAppLayerProtocolTest09, 1);
#endif /* UNITTESTS */

    return;
}
