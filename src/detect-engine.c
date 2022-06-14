/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "suricata.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "flow-private.h"
#include "flow-util.h"
#include "flow-worker.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "datasets.h"

#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "detect-parse.h"
#include "detect-engine-sigorder.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-port.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-mpm.h"
#include "detect-engine-iponly.h"
#include "detect-engine-tag.h"

#include "detect-engine-file.h"

#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-engine-payload.h"
#include "detect-fast-pattern.h"
#include "detect-byte-extract.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-tcphdr.h"
#include "detect-engine-threshold.h"
#include "detect-engine-content-inspection.h"

#include "detect-engine-loader.h"

#include "util-classification-config.h"
#include "util-reference-config.h"
#include "util-threshold-config.h"
#include "util-error.h"
#include "util-hash.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-action.h"
#include "util-magic.h"
#include "util-signal.h"
#include "util-spm.h"
#include "util-device.h"
#include "util-var-name.h"
#include "util-profiling.h"
#include "util-validate.h"
#include "util-hash-string.h"

#include "tm-threads.h"
#include "runmodes.h"

#include "reputation.h"
#include <stdint.h>

#define DETECT_ENGINE_DEFAULT_INSPECTION_RECURSION_LIMIT 3000

static int DetectEngineCtxLoadConf(DetectEngineCtx *);

static DetectEngineMasterCtx g_master_de_ctx = { SCMUTEX_INITIALIZER,
    0, 99, NULL, NULL, TENANT_SELECTOR_UNKNOWN, NULL, NULL, 0};

static uint32_t TenantIdHash(HashTable *h, void *data, uint16_t data_len);
static char TenantIdCompare(void *d1, uint16_t d1_len, void *d2, uint16_t d2_len);
static void TenantIdFree(void *d);
static uint32_t DetectEngineTentantGetIdFromLivedev(const void *ctx, const Packet *p);
static uint32_t DetectEngineTentantGetIdFromVlanId(const void *ctx, const Packet *p);
static uint32_t DetectEngineTentantGetIdFromPcap(const void *ctx, const Packet *p);

static DetectEngineAppInspectionEngine *g_app_inspect_engines = NULL;
static DetectEnginePktInspectionEngine *g_pkt_inspect_engines = NULL;
static DetectEngineFrameInspectionEngine *g_frame_inspect_engines = NULL;

SCEnumCharMap det_ctx_event_table[] = {
#ifdef UNITTESTS
    { "TEST", DET_CTX_EVENT_TEST },
#endif
    { "NO_MEMORY", FILE_DECODER_EVENT_NO_MEM },
    { "INVALID_SWF_LENGTH", FILE_DECODER_EVENT_INVALID_SWF_LENGTH },
    { "INVALID_SWF_VERSION", FILE_DECODER_EVENT_INVALID_SWF_VERSION },
    { "Z_DATA_ERROR", FILE_DECODER_EVENT_Z_DATA_ERROR },
    { "Z_STREAM_ERROR", FILE_DECODER_EVENT_Z_STREAM_ERROR },
    { "Z_BUF_ERROR", FILE_DECODER_EVENT_Z_BUF_ERROR },
    { "Z_UNKNOWN_ERROR", FILE_DECODER_EVENT_Z_UNKNOWN_ERROR },
    { "LZMA_DECODER_ERROR", FILE_DECODER_EVENT_LZMA_DECODER_ERROR },
    { "LZMA_MEMLIMIT_ERROR", FILE_DECODER_EVENT_LZMA_MEMLIMIT_ERROR },
    { "LZMA_OPTIONS_ERROR", FILE_DECODER_EVENT_LZMA_OPTIONS_ERROR },
    { "LZMA_FORMAT_ERROR", FILE_DECODER_EVENT_LZMA_FORMAT_ERROR },
    { "LZMA_DATA_ERROR", FILE_DECODER_EVENT_LZMA_DATA_ERROR },
    { "LZMA_BUF_ERROR", FILE_DECODER_EVENT_LZMA_BUF_ERROR },
    { "LZMA_UNKNOWN_ERROR", FILE_DECODER_EVENT_LZMA_UNKNOWN_ERROR },
    {
            "TOO_MANY_BUFFERS",
            DETECT_EVENT_TOO_MANY_BUFFERS,
    },
    { NULL, -1 },
};

/** \brief register inspect engine at start up time
 *
 *  \note errors are fatal */
void DetectPktInspectEngineRegister(const char *name,
        InspectionBufferGetPktDataPtr GetPktData,
        InspectionBufferPktInspectFunc Callback)
{
    DetectBufferTypeRegister(name);
    const int sm_list = DetectBufferTypeGetByName(name);
    if (sm_list == -1) {
        FatalError(SC_ERR_INITIALIZATION,
            "failed to register inspect engine %s", name);
    }

    if ((sm_list < DETECT_SM_LIST_MATCH) || (sm_list >= SHRT_MAX) ||
        (Callback == NULL))
    {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid arguments");
        BUG_ON(1);
    }

    DetectEnginePktInspectionEngine *new_engine = SCCalloc(1, sizeof(*new_engine));
    if (unlikely(new_engine == NULL)) {
        FatalError(SC_ERR_INITIALIZATION,
            "failed to register inspect engine %s: %s", name, strerror(errno));
    }
    new_engine->sm_list = (uint16_t)sm_list;
    new_engine->sm_list_base = (uint16_t)sm_list;
    new_engine->v1.Callback = Callback;
    new_engine->v1.GetData = GetPktData;

    if (g_pkt_inspect_engines == NULL) {
        g_pkt_inspect_engines = new_engine;
    } else {
        DetectEnginePktInspectionEngine *t = g_pkt_inspect_engines;
        while (t->next != NULL) {
            t = t->next;
        }

        t->next = new_engine;
    }
}

/** \brief register inspect engine at start up time
 *
 *  \note errors are fatal */
void DetectFrameInspectEngineRegister(const char *name, int dir,
        InspectionBufferFrameInspectFunc Callback, AppProto alproto, uint8_t type)
{
    DetectBufferTypeRegister(name);
    const int sm_list = DetectBufferTypeGetByName(name);
    if (sm_list == -1) {
        FatalError(SC_ERR_INITIALIZATION, "failed to register inspect engine %s", name);
    }

    if ((sm_list < DETECT_SM_LIST_MATCH) || (sm_list >= SHRT_MAX) || (Callback == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid arguments");
        BUG_ON(1);
    }

    uint8_t direction;
    if (dir == SIG_FLAG_TOSERVER) {
        direction = 0;
    } else {
        direction = 1;
    }

    DetectEngineFrameInspectionEngine *new_engine = SCCalloc(1, sizeof(*new_engine));
    if (unlikely(new_engine == NULL)) {
        FatalError(SC_ERR_INITIALIZATION, "failed to register inspect engine %s: %s", name,
                strerror(errno));
    }
    new_engine->sm_list = (uint16_t)sm_list;
    new_engine->sm_list_base = (uint16_t)sm_list;
    new_engine->dir = direction;
    new_engine->v1.Callback = Callback;
    new_engine->alproto = alproto;
    new_engine->type = type;

    if (g_frame_inspect_engines == NULL) {
        g_frame_inspect_engines = new_engine;
    } else {
        DetectEngineFrameInspectionEngine *t = g_frame_inspect_engines;
        while (t->next != NULL) {
            t = t->next;
        }

        t->next = new_engine;
    }
}

/** \brief register inspect engine at start up time
 *
 *  \note errors are fatal */
void DetectAppLayerInspectEngineRegister2(const char *name,
        AppProto alproto, uint32_t dir, int progress,
        InspectEngineFuncPtr2 Callback2,
        InspectionBufferGetDataPtr GetData)
{
    BUG_ON(progress >= 48);

    DetectBufferTypeRegister(name);
    const int sm_list = DetectBufferTypeGetByName(name);
    if (sm_list == -1) {
        FatalError(SC_ERR_INITIALIZATION,
            "failed to register inspect engine %s", name);
    }

    if ((alproto >= ALPROTO_FAILED) ||
        (!(dir == SIG_FLAG_TOSERVER || dir == SIG_FLAG_TOCLIENT)) ||
        (sm_list < DETECT_SM_LIST_MATCH) || (sm_list >= SHRT_MAX) ||
        (progress < 0 || progress >= SHRT_MAX) ||
        (Callback2 == NULL))
    {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid arguments");
        BUG_ON(1);
    } else if (Callback2 == DetectEngineInspectBufferGeneric && GetData == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid arguments: must register "
                "GetData with DetectEngineInspectBufferGeneric");
        BUG_ON(1);
    }

    uint8_t direction;
    if (dir == SIG_FLAG_TOSERVER) {
        direction = 0;
    } else {
        direction = 1;
    }

    DetectEngineAppInspectionEngine *new_engine = SCMalloc(sizeof(DetectEngineAppInspectionEngine));
    if (unlikely(new_engine == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(new_engine, 0, sizeof(*new_engine));
    new_engine->alproto = alproto;
    new_engine->dir = direction;
    new_engine->sm_list = (uint16_t)sm_list;
    new_engine->sm_list_base = (uint16_t)sm_list;
    new_engine->progress = (int16_t)progress;
    new_engine->v2.Callback = Callback2;
    new_engine->v2.GetData = GetData;

    if (g_app_inspect_engines == NULL) {
        g_app_inspect_engines = new_engine;
    } else {
        DetectEngineAppInspectionEngine *t = g_app_inspect_engines;
        while (t->next != NULL) {
            t = t->next;
        }

        t->next = new_engine;
    }
}

/* copy an inspect engine with transforms to a new list id. */
static void DetectAppLayerInspectEngineCopy(
        DetectEngineCtx *de_ctx,
        int sm_list, int new_list,
        const DetectEngineTransforms *transforms)
{
    const DetectEngineAppInspectionEngine *t = g_app_inspect_engines;
    while (t) {
        if (t->sm_list == sm_list) {
            DetectEngineAppInspectionEngine *new_engine = SCCalloc(1, sizeof(DetectEngineAppInspectionEngine));
            if (unlikely(new_engine == NULL)) {
                exit(EXIT_FAILURE);
            }
            new_engine->alproto = t->alproto;
            new_engine->dir = t->dir;
            DEBUG_VALIDATE_BUG_ON(new_list < 0 || new_list > UINT16_MAX);
            new_engine->sm_list = (uint16_t)new_list; /* use new list id */
            DEBUG_VALIDATE_BUG_ON(sm_list < 0 || sm_list > UINT16_MAX);
            new_engine->sm_list_base = (uint16_t)sm_list;
            new_engine->progress = t->progress;
            new_engine->v2 = t->v2;
            new_engine->v2.transforms = transforms; /* assign transforms */

            if (de_ctx->app_inspect_engines == NULL) {
                de_ctx->app_inspect_engines = new_engine;
            } else {
                DetectEngineAppInspectionEngine *list = de_ctx->app_inspect_engines;
                while (list->next != NULL) {
                    list = list->next;
                }

                list->next = new_engine;
            }
        }
        t = t->next;
    }
}

/* copy inspect engines from global registrations to de_ctx list */
static void DetectAppLayerInspectEngineCopyListToDetectCtx(DetectEngineCtx *de_ctx)
{
    const DetectEngineAppInspectionEngine *t = g_app_inspect_engines;
    DetectEngineAppInspectionEngine *list = de_ctx->app_inspect_engines;
    while (t) {
        DetectEngineAppInspectionEngine *new_engine = SCCalloc(1, sizeof(DetectEngineAppInspectionEngine));
        if (unlikely(new_engine == NULL)) {
            exit(EXIT_FAILURE);
        }
        new_engine->alproto = t->alproto;
        new_engine->dir = t->dir;
        new_engine->sm_list = t->sm_list;
        new_engine->sm_list_base = t->sm_list;
        new_engine->progress = t->progress;
        new_engine->v2 = t->v2;

        if (list == NULL) {
            de_ctx->app_inspect_engines = new_engine;
        } else {
            list->next = new_engine;
        }
        list = new_engine;

        t = t->next;
    }
}

/* copy an inspect engine with transforms to a new list id. */
static void DetectPktInspectEngineCopy(
        DetectEngineCtx *de_ctx,
        int sm_list, int new_list,
        const DetectEngineTransforms *transforms)
{
    const DetectEnginePktInspectionEngine *t = g_pkt_inspect_engines;
    while (t) {
        if (t->sm_list == sm_list) {
            DetectEnginePktInspectionEngine *new_engine = SCCalloc(1, sizeof(DetectEnginePktInspectionEngine));
            if (unlikely(new_engine == NULL)) {
                exit(EXIT_FAILURE);
            }
            DEBUG_VALIDATE_BUG_ON(new_list < 0 || new_list > UINT16_MAX);
            new_engine->sm_list = (uint16_t)new_list; /* use new list id */
            DEBUG_VALIDATE_BUG_ON(sm_list < 0 || sm_list > UINT16_MAX);
            new_engine->sm_list_base = (uint16_t)sm_list;
            new_engine->v1 = t->v1;
            new_engine->v1.transforms = transforms; /* assign transforms */

            if (de_ctx->pkt_inspect_engines == NULL) {
                de_ctx->pkt_inspect_engines = new_engine;
            } else {
                DetectEnginePktInspectionEngine *list = de_ctx->pkt_inspect_engines;
                while (list->next != NULL) {
                    list = list->next;
                }

                list->next = new_engine;
            }
        }
        t = t->next;
    }
}

/* copy inspect engines from global registrations to de_ctx list */
static void DetectPktInspectEngineCopyListToDetectCtx(DetectEngineCtx *de_ctx)
{
    const DetectEnginePktInspectionEngine *t = g_pkt_inspect_engines;
    while (t) {
        SCLogDebug("engine %p", t);
        DetectEnginePktInspectionEngine *new_engine = SCCalloc(1, sizeof(DetectEnginePktInspectionEngine));
        if (unlikely(new_engine == NULL)) {
            exit(EXIT_FAILURE);
        }
        new_engine->sm_list = t->sm_list;
        new_engine->sm_list_base = t->sm_list;
        new_engine->v1 = t->v1;

        if (de_ctx->pkt_inspect_engines == NULL) {
            de_ctx->pkt_inspect_engines = new_engine;
        } else {
            DetectEnginePktInspectionEngine *list = de_ctx->pkt_inspect_engines;
            while (list->next != NULL) {
                list = list->next;
            }

            list->next = new_engine;
        }

        t = t->next;
    }
}

/** \brief register inspect engine at start up time
 *
 *  \note errors are fatal */
void DetectEngineFrameInspectEngineRegister(DetectEngineCtx *de_ctx, const char *name, int dir,
        InspectionBufferFrameInspectFunc Callback, AppProto alproto, uint8_t type)
{
    const int sm_list = DetectEngineBufferTypeRegister(de_ctx, name);
    if (sm_list < 0) {
        FatalError(SC_ERR_INITIALIZATION, "failed to register inspect engine %s", name);
    }

    if ((sm_list < DETECT_SM_LIST_MATCH) || (sm_list >= SHRT_MAX) || (Callback == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid arguments");
        BUG_ON(1);
    }

    uint8_t direction;
    if (dir == SIG_FLAG_TOSERVER) {
        direction = 0;
    } else {
        direction = 1;
    }

    DetectEngineFrameInspectionEngine *new_engine = SCCalloc(1, sizeof(*new_engine));
    if (unlikely(new_engine == NULL)) {
        FatalError(SC_ERR_INITIALIZATION, "failed to register inspect engine %s: %s", name,
                strerror(errno));
    }
    new_engine->sm_list = (uint16_t)sm_list;
    new_engine->sm_list_base = (uint16_t)sm_list;
    new_engine->dir = direction;
    new_engine->v1.Callback = Callback;
    new_engine->alproto = alproto;
    new_engine->type = type;

    if (de_ctx->frame_inspect_engines == NULL) {
        de_ctx->frame_inspect_engines = new_engine;
    } else {
        DetectEngineFrameInspectionEngine *list = de_ctx->frame_inspect_engines;
        while (list->next != NULL) {
            list = list->next;
        }

        list->next = new_engine;
    }
}

/* copy an inspect engine with transforms to a new list id. */
static void DetectFrameInspectEngineCopy(DetectEngineCtx *de_ctx, int sm_list, int new_list,
        const DetectEngineTransforms *transforms)
{
    /* take the list from the detect engine as the buffers can be registered
     * dynamically. */
    DetectEngineFrameInspectionEngine *t = de_ctx->frame_inspect_engines;
    while (t) {
        if (t->sm_list == sm_list) {
            DetectEngineFrameInspectionEngine *new_engine =
                    SCCalloc(1, sizeof(DetectEngineFrameInspectionEngine));
            if (unlikely(new_engine == NULL)) {
                exit(EXIT_FAILURE);
            }
            DEBUG_VALIDATE_BUG_ON(new_list < 0 || new_list > UINT16_MAX);
            new_engine->sm_list = (uint16_t)new_list; /* use new list id */
            DEBUG_VALIDATE_BUG_ON(sm_list < 0 || sm_list > UINT16_MAX);
            new_engine->sm_list_base = (uint16_t)sm_list;
            new_engine->dir = t->dir;
            new_engine->alproto = t->alproto;
            new_engine->type = t->type;
            new_engine->v1 = t->v1;
            new_engine->v1.transforms = transforms; /* assign transforms */

            /* append to the list */
            DetectEngineFrameInspectionEngine *list = t;
            while (list->next != NULL) {
                list = list->next;
            }

            list->next = new_engine;
            break;
        }
        t = t->next;
    }
}

/* copy inspect engines from global registrations to de_ctx list */
static void DetectFrameInspectEngineCopyListToDetectCtx(DetectEngineCtx *de_ctx)
{
    const DetectEngineFrameInspectionEngine *t = g_frame_inspect_engines;
    while (t) {
        SCLogDebug("engine %p", t);
        DetectEngineFrameInspectionEngine *new_engine =
                SCCalloc(1, sizeof(DetectEngineFrameInspectionEngine));
        if (unlikely(new_engine == NULL)) {
            exit(EXIT_FAILURE);
        }
        new_engine->sm_list = t->sm_list;
        new_engine->sm_list_base = t->sm_list;
        new_engine->dir = t->dir;
        new_engine->alproto = t->alproto;
        new_engine->type = t->type;
        new_engine->v1 = t->v1;

        if (de_ctx->frame_inspect_engines == NULL) {
            de_ctx->frame_inspect_engines = new_engine;
        } else {
            DetectEngineFrameInspectionEngine *list = de_ctx->frame_inspect_engines;
            while (list->next != NULL) {
                list = list->next;
            }

            list->next = new_engine;
        }

        t = t->next;
    }
}

/** \internal
 *  \brief append the stream inspection
 *
 *  If stream inspection is MPM, then prepend it.
 */
static void AppendStreamInspectEngine(
        Signature *s, SigMatchData *stream, uint8_t direction, uint8_t id)
{
    bool prepend = false;

    DetectEngineAppInspectionEngine *new_engine = SCCalloc(1, sizeof(DetectEngineAppInspectionEngine));
    if (unlikely(new_engine == NULL)) {
        exit(EXIT_FAILURE);
    }
    if (s->init_data->mpm_sm_list == DETECT_SM_LIST_PMATCH) {
        SCLogDebug("stream is mpm");
        prepend = true;
        new_engine->mpm = true;
    }
    new_engine->alproto = ALPROTO_UNKNOWN; /* all */
    new_engine->dir = direction;
    new_engine->stream = true;
    new_engine->sm_list = DETECT_SM_LIST_PMATCH;
    new_engine->sm_list_base = DETECT_SM_LIST_PMATCH;
    new_engine->smd = stream;
    new_engine->v2.Callback = DetectEngineInspectStream;
    new_engine->progress = 0;

    /* append */
    if (s->app_inspect == NULL) {
        s->app_inspect = new_engine;
        new_engine->id = DE_STATE_FLAG_BASE; /* id is used as flag in stateful detect */
    } else if (prepend) {
        new_engine->next = s->app_inspect;
        s->app_inspect = new_engine;
        new_engine->id = id;

    } else {
        DetectEngineAppInspectionEngine *a = s->app_inspect;
        while (a->next != NULL) {
            a = a->next;
        }

        a->next = new_engine;
        new_engine->id = id;
    }
    SCLogDebug("sid %u: engine %p/%u added", s->id, new_engine, new_engine->id);
}

/**
 *  \note for the file inspect engine, the id DE_STATE_ID_FILE_INSPECT
 *        is assigned.
 */
int DetectEngineAppInspectionEngine2Signature(DetectEngineCtx *de_ctx, Signature *s)
{
    const int nlists = s->init_data->smlists_array_size;
    SigMatchData *ptrs[nlists];
    memset(&ptrs, 0, (nlists * sizeof(SigMatchData *)));

    const int mpm_list = s->init_data->mpm_sm ? s->init_data->mpm_sm_list : -1;

    const int files_id = DetectBufferTypeGetByName("files");

    /* convert lists to SigMatchData arrays */
    int i = 0;
    for (i = DETECT_SM_LIST_DYNAMIC_START; i < nlists; i++) {
        if (s->init_data->smlists[i] == NULL)
            continue;

        ptrs[i] = SigMatchList2DataArray(s->init_data->smlists[i]);
        SCLogDebug("ptrs[%d] is set", i);
    }

    /* set up inspect engines */
    const DetectEngineFrameInspectionEngine *u = de_ctx->frame_inspect_engines;
    while (u != NULL) {
        SCLogDebug("u %p sm_list %u nlists %u ptrs[] %p", u, u->sm_list, nlists,
                u->sm_list < nlists ? ptrs[u->sm_list] : NULL);
        if (u->sm_list < nlists && ptrs[u->sm_list] != NULL) {
            bool prepend = false;

            if (u->alproto == ALPROTO_UNKNOWN) {
                /* special case, inspect engine applies to all protocols */
            } else if (s->alproto != ALPROTO_UNKNOWN && !AppProtoEquals(s->alproto, u->alproto))
                goto next_engine;

            if (s->flags & SIG_FLAG_TOSERVER && !(s->flags & SIG_FLAG_TOCLIENT)) {
                if (u->dir == 1)
                    goto next_engine;
            } else if (s->flags & SIG_FLAG_TOCLIENT && !(s->flags & SIG_FLAG_TOSERVER)) {
                if (u->dir == 0)
                    goto next_engine;
            }
            DetectEngineFrameInspectionEngine *new_engine =
                    SCCalloc(1, sizeof(DetectEngineFrameInspectionEngine));
            if (unlikely(new_engine == NULL)) {
                exit(EXIT_FAILURE);
            }
            if (mpm_list == u->sm_list) {
                SCLogDebug("%s is mpm", DetectEngineBufferTypeGetNameById(de_ctx, u->sm_list));
                prepend = true;
                new_engine->mpm = true;
            }

            new_engine->type = u->type;
            new_engine->sm_list = u->sm_list;
            new_engine->sm_list_base = u->sm_list_base;
            new_engine->smd = ptrs[new_engine->sm_list];
            new_engine->v1 = u->v1;
            SCLogDebug("sm_list %d new_engine->v1 %p/%p", new_engine->sm_list,
                    new_engine->v1.Callback, new_engine->v1.transforms);

            if (s->frame_inspect == NULL) {
                s->frame_inspect = new_engine;
            } else if (prepend) {
                new_engine->next = s->frame_inspect;
                s->frame_inspect = new_engine;
            } else {
                DetectEngineFrameInspectionEngine *a = s->frame_inspect;
                while (a->next != NULL) {
                    a = a->next;
                }
                new_engine->next = a->next;
                a->next = new_engine;
            }
        }
    next_engine:
        u = u->next;
    }

    /* set up pkt inspect engines */
    const DetectEnginePktInspectionEngine *e = de_ctx->pkt_inspect_engines;
    while (e != NULL) {
        SCLogDebug("e %p sm_list %u nlists %u ptrs[] %p", e, e->sm_list, nlists, e->sm_list < nlists ? ptrs[e->sm_list] : NULL);
        if (e->sm_list < nlists && ptrs[e->sm_list] != NULL) {
            bool prepend = false;

            DetectEnginePktInspectionEngine *new_engine = SCCalloc(1, sizeof(DetectEnginePktInspectionEngine));
            if (unlikely(new_engine == NULL)) {
                exit(EXIT_FAILURE);
            }
            if (mpm_list == e->sm_list) {
                SCLogDebug("%s is mpm", DetectEngineBufferTypeGetNameById(de_ctx, e->sm_list));
                prepend = true;
                new_engine->mpm = true;
            }

            new_engine->sm_list = e->sm_list;
            new_engine->sm_list_base = e->sm_list_base;
            new_engine->smd = ptrs[new_engine->sm_list];
            new_engine->v1 = e->v1;
            SCLogDebug("sm_list %d new_engine->v1 %p/%p/%p",
                    new_engine->sm_list, new_engine->v1.Callback,
                    new_engine->v1.GetData, new_engine->v1.transforms);

            if (s->pkt_inspect == NULL) {
                s->pkt_inspect = new_engine;
            } else if (prepend) {
                new_engine->next = s->pkt_inspect;
                s->pkt_inspect = new_engine;
            } else {
                DetectEnginePktInspectionEngine *a = s->pkt_inspect;
                while (a->next != NULL) {
                    a = a->next;
                }
                new_engine->next = a->next;
                a->next = new_engine;
            }
        }
        e = e->next;
    }

    bool head_is_mpm = false;
    uint8_t last_id = DE_STATE_FLAG_BASE;
    const DetectEngineAppInspectionEngine *t = de_ctx->app_inspect_engines;
    while (t != NULL) {
        bool prepend = false;

        if (t->sm_list >= nlists)
            goto next;

        if (ptrs[t->sm_list] == NULL)
            goto next;

        SCLogDebug("ptrs[%d] is set", t->sm_list);

        if (t->alproto == ALPROTO_UNKNOWN) {
            /* special case, inspect engine applies to all protocols */
        } else if (s->alproto != ALPROTO_UNKNOWN && !AppProtoEquals(s->alproto, t->alproto))
            goto next;

        if (s->flags & SIG_FLAG_TOSERVER && !(s->flags & SIG_FLAG_TOCLIENT)) {
            if (t->dir == 1)
                goto next;
        } else if (s->flags & SIG_FLAG_TOCLIENT && !(s->flags & SIG_FLAG_TOSERVER)) {
            if (t->dir == 0)
                goto next;
        }
        DetectEngineAppInspectionEngine *new_engine = SCCalloc(1, sizeof(DetectEngineAppInspectionEngine));
        if (unlikely(new_engine == NULL)) {
            exit(EXIT_FAILURE);
        }
        if (mpm_list == t->sm_list) {
            SCLogDebug("%s is mpm", DetectEngineBufferTypeGetNameById(de_ctx, t->sm_list));
            prepend = true;
            head_is_mpm = true;
            new_engine->mpm = true;
        }

        new_engine->alproto = t->alproto;
        new_engine->dir = t->dir;
        new_engine->sm_list = t->sm_list;
        new_engine->sm_list_base = t->sm_list_base;
        new_engine->smd = ptrs[new_engine->sm_list];
        new_engine->progress = t->progress;
        new_engine->v2 = t->v2;
        SCLogDebug("sm_list %d new_engine->v2 %p/%p/%p",
                new_engine->sm_list, new_engine->v2.Callback,
                new_engine->v2.GetData, new_engine->v2.transforms);

        if (s->app_inspect == NULL) {
            s->app_inspect = new_engine;
            if (new_engine->sm_list == files_id) {
                SCLogDebug("sid %u: engine %p/%u is FILE ENGINE", s->id, new_engine, new_engine->id);
                new_engine->id = DE_STATE_ID_FILE_INSPECT;
            } else {
                new_engine->id = DE_STATE_FLAG_BASE; /* id is used as flag in stateful detect */
            }

        /* prepend engine if forced or if our engine has a lower progress. */
        } else if (prepend || (!head_is_mpm && s->app_inspect->progress > new_engine->progress)) {
            new_engine->next = s->app_inspect;
            s->app_inspect = new_engine;
            if (new_engine->sm_list == files_id) {
                SCLogDebug("sid %u: engine %p/%u is FILE ENGINE", s->id, new_engine, new_engine->id);
                new_engine->id = DE_STATE_ID_FILE_INSPECT;
            } else {
                new_engine->id = ++last_id;
            }

        } else {
            DetectEngineAppInspectionEngine *a = s->app_inspect;
            while (a->next != NULL) {
                if (a->next && a->next->progress > new_engine->progress) {
                    break;
                }

                a = a->next;
            }

            new_engine->next = a->next;
            a->next = new_engine;
            if (new_engine->sm_list == files_id) {
                SCLogDebug("sid %u: engine %p/%u is FILE ENGINE", s->id, new_engine, new_engine->id);
                new_engine->id = DE_STATE_ID_FILE_INSPECT;
            } else {
                new_engine->id = ++last_id;
            }
        }

        SCLogDebug("sid %u: engine %p/%u added", s->id, new_engine, new_engine->id);

        s->init_data->init_flags |= SIG_FLAG_INIT_STATE_MATCH;
next:
        t = t->next;
    }

    if ((s->init_data->init_flags & SIG_FLAG_INIT_STATE_MATCH) &&
            s->init_data->smlists[DETECT_SM_LIST_PMATCH] != NULL)
    {
        /* if engine is added multiple times, we pass it the same list */
        SigMatchData *stream = SigMatchList2DataArray(s->init_data->smlists[DETECT_SM_LIST_PMATCH]);
        BUG_ON(stream == NULL);
        if (s->flags & SIG_FLAG_TOSERVER && !(s->flags & SIG_FLAG_TOCLIENT)) {
            AppendStreamInspectEngine(s, stream, 0, last_id + 1);
        } else if (s->flags & SIG_FLAG_TOCLIENT && !(s->flags & SIG_FLAG_TOSERVER)) {
            AppendStreamInspectEngine(s, stream, 1, last_id + 1);
        } else {
            AppendStreamInspectEngine(s, stream, 0, last_id + 1);
            AppendStreamInspectEngine(s, stream, 1, last_id + 1);
        }

        if (s->init_data->init_flags & SIG_FLAG_INIT_NEED_FLUSH) {
            SCLogDebug("set SIG_FLAG_FLUSH on %u", s->id);
            s->flags |= SIG_FLAG_FLUSH;
        }
    }

#ifdef DEBUG
    const DetectEngineAppInspectionEngine *iter = s->app_inspect;
    while (iter) {
        SCLogDebug("%u: engine %s id %u progress %d %s", s->id,
                DetectEngineBufferTypeGetNameById(de_ctx, iter->sm_list), iter->id, iter->progress,
                iter->sm_list == mpm_list ? "MPM" : "");
        iter = iter->next;
    }
#endif
    return 0;
}

/** \brief free app inspect engines for a signature
 *
 *  For lists that are registered multiple times, like http_header and
 *  http_cookie, making the engines owner of the lists is complicated.
 *  Multiple engines in a sig may be pointing to the same list. To
 *  address this the 'free' code needs to be extra careful about not
 *  double freeing, so it takes an approach to first fill an array
 *  of the to-free pointers before freeing them.
 */
void DetectEngineAppInspectionEngineSignatureFree(DetectEngineCtx *de_ctx, Signature *s)
{
    int nlists = 0;

    DetectEngineAppInspectionEngine *ie = s->app_inspect;
    while (ie) {
        nlists = MAX(ie->sm_list + 1, nlists);
        ie = ie->next;
    }
    DetectEnginePktInspectionEngine *e = s->pkt_inspect;
    while (e) {
        nlists = MAX(e->sm_list + 1, nlists);
        e = e->next;
    }
    DetectEngineFrameInspectionEngine *u = s->frame_inspect;
    while (u) {
        nlists = MAX(u->sm_list + 1, nlists);
        u = u->next;
    }
    if (nlists == 0) {
        BUG_ON(s->pkt_inspect);
        BUG_ON(s->frame_inspect);
        return;
    }

    SigMatchData *ptrs[nlists];
    memset(&ptrs, 0, (nlists * sizeof(SigMatchData *)));

    /* free engines and put smd in the array */
    ie = s->app_inspect;
    while (ie) {
        DetectEngineAppInspectionEngine *next = ie->next;
        BUG_ON(ptrs[ie->sm_list] != NULL && ptrs[ie->sm_list] != ie->smd);
        ptrs[ie->sm_list] = ie->smd;
        SCFree(ie);
        ie = next;
    }
    e = s->pkt_inspect;
    while (e) {
        DetectEnginePktInspectionEngine *next = e->next;
        ptrs[e->sm_list] = e->smd;
        SCFree(e);
        e = next;
    }
    u = s->frame_inspect;
    while (u) {
        DetectEngineFrameInspectionEngine *next = u->next;
        ptrs[u->sm_list] = u->smd;
        SCFree(u);
        u = next;
    }

    /* free the smds */
    for (int i = 0; i < nlists; i++)
    {
        if (ptrs[i] == NULL)
            continue;

        SigMatchData *smd = ptrs[i];
        while(1) {
            if (sigmatch_table[smd->type].Free != NULL) {
                sigmatch_table[smd->type].Free(de_ctx, smd->ctx);
            }
            if (smd->is_last)
                break;
            smd++;
        }
        SCFree(ptrs[i]);
    }
}

/* code for registering buffers */

#include "util-hash-lookup3.h"

static HashListTable *g_buffer_type_hash = NULL;
static int g_buffer_type_id = DETECT_SM_LIST_DYNAMIC_START;
static int g_buffer_type_reg_closed = 0;

int DetectBufferTypeMaxId(void)
{
    return g_buffer_type_id;
}

static uint32_t DetectBufferTypeHashNameFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    const DetectBufferType *map = (DetectBufferType *)data;
    uint32_t hash = hashlittle_safe(map->name, strlen(map->name), 0);
    hash += hashlittle_safe((uint8_t *)&map->transforms, sizeof(map->transforms), 0);
    hash %= ht->array_size;
    return hash;
}

static uint32_t DetectBufferTypeHashIdFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    const DetectBufferType *map = (DetectBufferType *)data;
    uint32_t hash = map->id;
    hash %= ht->array_size;
    return hash;
}

static char DetectBufferTypeCompareNameFunc(void *data1, uint16_t len1, void *data2, uint16_t len2)
{
    DetectBufferType *map1 = (DetectBufferType *)data1;
    DetectBufferType *map2 = (DetectBufferType *)data2;

    char r = (strcmp(map1->name, map2->name) == 0);
    r &= (memcmp((uint8_t *)&map1->transforms, (uint8_t *)&map2->transforms, sizeof(map2->transforms)) == 0);
    return r;
}

static char DetectBufferTypeCompareIdFunc(void *data1, uint16_t len1, void *data2, uint16_t len2)
{
    DetectBufferType *map1 = (DetectBufferType *)data1;
    DetectBufferType *map2 = (DetectBufferType *)data2;
    return map1->id == map2->id;
}

static void DetectBufferTypeFreeFunc(void *data)
{
    DetectBufferType *map = (DetectBufferType *)data;

    if (map == NULL) {
        return;
    }

    /* Release transformation option memory, if any */
    for (int i = 0; i < map->transforms.cnt; i++) {
        if (map->transforms.transforms[i].options == NULL)
            continue;
        if (sigmatch_table[map->transforms.transforms[i].transform].Free == NULL) {
            SCLogError(SC_ERR_UNIMPLEMENTED,
                       "%s allocates transform option memory but has no free routine",
                       sigmatch_table[map->transforms.transforms[i].transform].name);
            continue;
        }
        sigmatch_table[map->transforms.transforms[i].transform].Free(NULL, map->transforms.transforms[i].options);
    }

    SCFree(map);
}

static int DetectBufferTypeInit(void)
{
    BUG_ON(g_buffer_type_hash);
    g_buffer_type_hash = HashListTableInit(256, DetectBufferTypeHashNameFunc,
            DetectBufferTypeCompareNameFunc, DetectBufferTypeFreeFunc);
    if (g_buffer_type_hash == NULL)
        return -1;

    return 0;
}
#if 0
static void DetectBufferTypeFree(void)
{
    if (g_buffer_type_hash == NULL)
        return;

    HashListTableFree(g_buffer_type_hash);
    g_buffer_type_hash = NULL;
    return;
}
#endif
static int DetectBufferTypeAdd(const char *string)
{
    BUG_ON(string == NULL || strlen(string) >= 32);

    DetectBufferType *map = SCCalloc(1, sizeof(*map));
    if (map == NULL)
        return -1;

    strlcpy(map->name, string, sizeof(map->name));
    map->id = g_buffer_type_id++;

    BUG_ON(HashListTableAdd(g_buffer_type_hash, (void *)map, 0) != 0);
    SCLogDebug("buffer %s registered with id %d", map->name, map->id);
    return map->id;
}

static DetectBufferType *DetectBufferTypeLookupByName(const char *string)
{
    DetectBufferType map;
    memset(&map, 0, sizeof(map));
    strlcpy(map.name, string, sizeof(map.name));

    DetectBufferType *res = HashListTableLookup(g_buffer_type_hash, &map, 0);
    return res;
}

int DetectBufferTypeRegister(const char *name)
{
    BUG_ON(g_buffer_type_reg_closed);
    if (g_buffer_type_hash == NULL)
        DetectBufferTypeInit();

    DetectBufferType *exists = DetectBufferTypeLookupByName(name);
    if (!exists) {
        return DetectBufferTypeAdd(name);
    } else {
        return exists->id;
    }
}

void DetectBufferTypeSupportsFrames(const char *name)
{
    BUG_ON(g_buffer_type_reg_closed);
    DetectBufferTypeRegister(name);
    DetectBufferType *exists = DetectBufferTypeLookupByName(name);
    BUG_ON(!exists);
    exists->frame = true;
    SCLogDebug("%p %s -- %d supports frame inspection", exists, name, exists->id);
}

void DetectBufferTypeSupportsPacket(const char *name)
{
    BUG_ON(g_buffer_type_reg_closed);
    DetectBufferTypeRegister(name);
    DetectBufferType *exists = DetectBufferTypeLookupByName(name);
    BUG_ON(!exists);
    exists->packet = true;
    SCLogDebug("%p %s -- %d supports packet inspection", exists, name, exists->id);
}

void DetectBufferTypeSupportsMpm(const char *name)
{
    BUG_ON(g_buffer_type_reg_closed);
    DetectBufferTypeRegister(name);
    DetectBufferType *exists = DetectBufferTypeLookupByName(name);
    BUG_ON(!exists);
    exists->mpm = true;
    SCLogDebug("%p %s -- %d supports mpm", exists, name, exists->id);
}

void DetectBufferTypeSupportsTransformations(const char *name)
{
    BUG_ON(g_buffer_type_reg_closed);
    DetectBufferTypeRegister(name);
    DetectBufferType *exists = DetectBufferTypeLookupByName(name);
    BUG_ON(!exists);
    exists->supports_transforms = true;
    SCLogDebug("%p %s -- %d supports transformations", exists, name, exists->id);
}

int DetectBufferTypeGetByName(const char *name)
{
    DetectBufferType *exists = DetectBufferTypeLookupByName(name);
    if (!exists) {
        return -1;
    }
    return exists->id;
}

static DetectBufferType *DetectEngineBufferTypeLookupByName(
        const DetectEngineCtx *de_ctx, const char *string)
{
    DetectBufferType map;
    memset(&map, 0, sizeof(map));
    strlcpy(map.name, string, sizeof(map.name));

    DetectBufferType *res = HashListTableLookup(de_ctx->buffer_type_hash_name, &map, 0);
    return res;
}

const DetectBufferType *DetectEngineBufferTypeGetById(const DetectEngineCtx *de_ctx, const int id)
{
    DetectBufferType lookup;
    memset(&lookup, 0, sizeof(lookup));
    lookup.id = id;
    const DetectBufferType *res =
            HashListTableLookup(de_ctx->buffer_type_hash_id, (void *)&lookup, 0);
    return res;
}

const char *DetectEngineBufferTypeGetNameById(const DetectEngineCtx *de_ctx, const int id)
{
    const DetectBufferType *res = DetectEngineBufferTypeGetById(de_ctx, id);
    return res ? res->name : NULL;
}

static int DetectEngineBufferTypeAdd(DetectEngineCtx *de_ctx, const char *string)
{
    BUG_ON(string == NULL || strlen(string) >= 32);

    DetectBufferType *map = SCCalloc(1, sizeof(*map));
    if (map == NULL)
        return -1;

    strlcpy(map->name, string, sizeof(map->name));
    map->id = de_ctx->buffer_type_id++;

    BUG_ON(HashListTableAdd(de_ctx->buffer_type_hash_name, (void *)map, 0) != 0);
    BUG_ON(HashListTableAdd(de_ctx->buffer_type_hash_id, (void *)map, 0) != 0);
    SCLogDebug("buffer %s registered with id %d", map->name, map->id);
    return map->id;
}

int DetectEngineBufferTypeRegisterWithFrameEngines(DetectEngineCtx *de_ctx, const char *name,
        const int direction, const AppProto alproto, const uint8_t frame_type)
{
    DetectBufferType *exists = DetectEngineBufferTypeLookupByName(de_ctx, name);
    if (exists) {
        return exists->id;
    }

    const int buffer_id = DetectEngineBufferTypeAdd(de_ctx, name);
    if (buffer_id < 0) {
        return -1;
    }

    /* TODO hack we need the map to get the name. Should we return the map at reg? */
    const DetectBufferType *map = DetectEngineBufferTypeGetById(de_ctx, buffer_id);
    BUG_ON(!map);

    /* register MPM/inspect engines */
    if (direction & SIG_FLAG_TOSERVER) {
        DetectEngineFrameMpmRegister(de_ctx, map->name, SIG_FLAG_TOSERVER, 2,
                PrefilterGenericMpmFrameRegister, alproto, frame_type);
        DetectEngineFrameInspectEngineRegister(de_ctx, map->name, SIG_FLAG_TOSERVER,
                DetectEngineInspectFrameBufferGeneric, alproto, frame_type);
    }
    if (direction & SIG_FLAG_TOCLIENT) {
        DetectEngineFrameMpmRegister(de_ctx, map->name, SIG_FLAG_TOCLIENT, 2,
                PrefilterGenericMpmFrameRegister, alproto, frame_type);
        DetectEngineFrameInspectEngineRegister(de_ctx, map->name, SIG_FLAG_TOCLIENT,
                DetectEngineInspectFrameBufferGeneric, alproto, frame_type);
    }

    return buffer_id;
}

int DetectEngineBufferTypeRegister(DetectEngineCtx *de_ctx, const char *name)
{
    DetectBufferType *exists = DetectEngineBufferTypeLookupByName(de_ctx, name);
    if (!exists) {
        return DetectEngineBufferTypeAdd(de_ctx, name);
    } else {
        return exists->id;
    }
}

void DetectBufferTypeSetDescriptionByName(const char *name, const char *desc)
{
    BUG_ON(desc == NULL || strlen(desc) >= 128);

    DetectBufferType *exists = DetectBufferTypeLookupByName(name);
    if (!exists) {
        return;
    }
    strlcpy(exists->description, desc, sizeof(exists->description));
}

const char *DetectEngineBufferTypeGetDescriptionById(const DetectEngineCtx *de_ctx, const int id)
{
    const DetectBufferType *exists = DetectEngineBufferTypeGetById(de_ctx, id);
    if (!exists) {
        return NULL;
    }
    return exists->description;
}

const char *DetectBufferTypeGetDescriptionByName(const char *name)
{
    const DetectBufferType *exists = DetectBufferTypeLookupByName(name);
    if (!exists) {
        return NULL;
    }
    return exists->description;
}

void DetectEngineBufferTypeSupportsFrames(DetectEngineCtx *de_ctx, const char *name)
{
    DetectBufferType *exists = DetectEngineBufferTypeLookupByName(de_ctx, name);
    BUG_ON(!exists);
    exists->frame = true;
    SCLogDebug("%p %s -- %d supports frame inspection", exists, name, exists->id);
}

void DetectEngineBufferTypeSupportsPacket(DetectEngineCtx *de_ctx, const char *name)
{
    DetectBufferType *exists = DetectEngineBufferTypeLookupByName(de_ctx, name);
    BUG_ON(!exists);
    exists->packet = true;
    SCLogDebug("%p %s -- %d supports packet inspection", exists, name, exists->id);
}

void DetectEngineBufferTypeSupportsMpm(DetectEngineCtx *de_ctx, const char *name)
{
    DetectBufferType *exists = DetectEngineBufferTypeLookupByName(de_ctx, name);
    BUG_ON(!exists);
    exists->mpm = true;
    SCLogDebug("%p %s -- %d supports mpm", exists, name, exists->id);
}

void DetectEngineBufferTypeSupportsTransformations(DetectEngineCtx *de_ctx, const char *name)
{
    DetectBufferType *exists = DetectEngineBufferTypeLookupByName(de_ctx, name);
    BUG_ON(!exists);
    exists->supports_transforms = true;
    SCLogDebug("%p %s -- %d supports transformations", exists, name, exists->id);
}

bool DetectEngineBufferTypeSupportsPacketGetById(const DetectEngineCtx *de_ctx, const int id)
{
    const DetectBufferType *map = DetectEngineBufferTypeGetById(de_ctx, id);
    if (map == NULL)
        return false;
    SCLogDebug("map %p id %d packet? %d", map, id, map->packet);
    return map->packet;
}

bool DetectEngineBufferTypeSupportsMpmGetById(const DetectEngineCtx *de_ctx, const int id)
{
    const DetectBufferType *map = DetectEngineBufferTypeGetById(de_ctx, id);
    if (map == NULL)
        return false;
    SCLogDebug("map %p id %d mpm? %d", map, id, map->mpm);
    return map->mpm;
}

void DetectBufferTypeRegisterSetupCallback(const char *name,
        void (*SetupCallback)(const DetectEngineCtx *, Signature *))
{
    BUG_ON(g_buffer_type_reg_closed);
    DetectBufferTypeRegister(name);
    DetectBufferType *exists = DetectBufferTypeLookupByName(name);
    BUG_ON(!exists);
    exists->SetupCallback = SetupCallback;
}

void DetectEngineBufferRunSetupCallback(const DetectEngineCtx *de_ctx, const int id, Signature *s)
{
    const DetectBufferType *map = DetectEngineBufferTypeGetById(de_ctx, id);
    if (map && map->SetupCallback) {
        map->SetupCallback(de_ctx, s);
    }
}

void DetectBufferTypeRegisterValidateCallback(const char *name,
        bool (*ValidateCallback)(const Signature *, const char **sigerror))
{
    BUG_ON(g_buffer_type_reg_closed);
    DetectBufferTypeRegister(name);
    DetectBufferType *exists = DetectBufferTypeLookupByName(name);
    BUG_ON(!exists);
    exists->ValidateCallback = ValidateCallback;
}

bool DetectEngineBufferRunValidateCallback(
        const DetectEngineCtx *de_ctx, const int id, const Signature *s, const char **sigerror)
{
    const DetectBufferType *map = DetectEngineBufferTypeGetById(de_ctx, id);
    if (map && map->ValidateCallback) {
        return map->ValidateCallback(s, sigerror);
    }
    return true;
}

int DetectBufferSetActiveList(Signature *s, const int list)
{
    BUG_ON(s->init_data == NULL);

    if (s->init_data->list && s->init_data->transforms.cnt) {
        return -1;
    }
    s->init_data->list = list;
    s->init_data->list_set = true;

    return 0;
}

int DetectBufferGetActiveList(DetectEngineCtx *de_ctx, Signature *s)
{
    BUG_ON(s->init_data == NULL);

    if (s->init_data->list && s->init_data->transforms.cnt) {
        if (s->init_data->list == DETECT_SM_LIST_NOTSET ||
            s->init_data->list < DETECT_SM_LIST_DYNAMIC_START) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "previous transforms not consumed "
                    "(list: %u, transform_cnt %u)", s->init_data->list,
                    s->init_data->transforms.cnt);
            SCReturnInt(-1);
        }

        SCLogDebug("buffer %d has transform(s) registered: %d",
                s->init_data->list, s->init_data->transforms.cnt);
        int new_list = DetectEngineBufferTypeGetByIdTransforms(de_ctx, s->init_data->list,
                s->init_data->transforms.transforms, s->init_data->transforms.cnt);
        if (new_list == -1) {
            SCReturnInt(-1);
        }
        SCLogDebug("new_list %d", new_list);
        s->init_data->list = new_list;
        s->init_data->list_set = false;
        // reset transforms now that we've set up the list
        s->init_data->transforms.cnt = 0;
    }

    SCReturnInt(0);
}

void InspectionBufferClean(DetectEngineThreadCtx *det_ctx)
{
    /* single buffers */
    for (uint32_t i = 0; i < det_ctx->inspect.to_clear_idx; i++)
    {
        const uint32_t idx = det_ctx->inspect.to_clear_queue[i];
        InspectionBuffer *buffer = &det_ctx->inspect.buffers[idx];
        buffer->inspect = NULL;
    }
    det_ctx->inspect.to_clear_idx = 0;

    /* multi buffers */
    for (uint32_t i = 0; i < det_ctx->multi_inspect.to_clear_idx; i++)
    {
        const uint32_t idx = det_ctx->multi_inspect.to_clear_queue[i];
        InspectionBufferMultipleForList *mbuffer = &det_ctx->multi_inspect.buffers[idx];
        for (uint32_t x = 0; x <= mbuffer->max; x++) {
            InspectionBuffer *buffer = &mbuffer->inspection_buffers[x];
            buffer->inspect = NULL;
        }
        mbuffer->init = 0;
        mbuffer->max = 0;
    }
    det_ctx->multi_inspect.to_clear_idx = 0;
}

InspectionBuffer *InspectionBufferGet(DetectEngineThreadCtx *det_ctx, const int list_id)
{
    return &det_ctx->inspect.buffers[list_id];
}

static InspectionBufferMultipleForList *InspectionBufferGetMulti(
        DetectEngineThreadCtx *det_ctx, const int list_id)
{
    InspectionBufferMultipleForList *buffer = &det_ctx->multi_inspect.buffers[list_id];
    if (!buffer->init) {
        det_ctx->multi_inspect.to_clear_queue[det_ctx->multi_inspect.to_clear_idx++] = list_id;
        buffer->init = 1;
    }
    return buffer;
}

/** \brief for a InspectionBufferMultipleForList get a InspectionBuffer
 *  \param fb the multiple buffer array
 *  \param local_id the index to get a buffer
 *  \param buffer the inspect buffer or NULL in case of error */
InspectionBuffer *InspectionBufferMultipleForListGet(
        DetectEngineThreadCtx *det_ctx, const int list_id, const uint32_t local_id)
{
    if (unlikely(local_id >= 1024)) {
        DetectEngineSetEvent(det_ctx, DETECT_EVENT_TOO_MANY_BUFFERS);
        return NULL;
    }

    InspectionBufferMultipleForList *fb = InspectionBufferGetMulti(det_ctx, list_id);

    if (local_id >= fb->size) {
        uint32_t old_size = fb->size;
        uint32_t new_size = local_id + 1;
        uint32_t grow_by = new_size - old_size;
        SCLogDebug("size is %u, need %u, so growing by %u", old_size, new_size, grow_by);

        SCLogDebug("fb->inspection_buffers %p", fb->inspection_buffers);
        void *ptr = SCRealloc(fb->inspection_buffers, (local_id + 1) * sizeof(InspectionBuffer));
        if (ptr == NULL)
            return NULL;

        InspectionBuffer *to_zero = (InspectionBuffer *)ptr + old_size;
        SCLogDebug("ptr %p to_zero %p", ptr, to_zero);
        memset((uint8_t *)to_zero, 0, (grow_by * sizeof(InspectionBuffer)));
        fb->inspection_buffers = ptr;
        fb->size = new_size;
    }

    fb->max = MAX(fb->max, local_id);
    InspectionBuffer *buffer = &fb->inspection_buffers[local_id];
    SCLogDebug("using buffer %p", buffer);
#ifdef DEBUG_VALIDATION
    buffer->multi = true;
#endif
    return buffer;
}

void InspectionBufferInit(InspectionBuffer *buffer, uint32_t initial_size)
{
    memset(buffer, 0, sizeof(*buffer));
    buffer->buf = SCCalloc(initial_size, sizeof(uint8_t));
    if (buffer->buf != NULL) {
        buffer->size = initial_size;
    }
}

/** \brief setup the buffer with our initial data */
void InspectionBufferSetupMulti(InspectionBuffer *buffer, const DetectEngineTransforms *transforms,
        const uint8_t *data, const uint32_t data_len)
{
#ifdef DEBUG_VALIDATION
    DEBUG_VALIDATE_BUG_ON(!buffer->multi);
#endif
    buffer->inspect = buffer->orig = data;
    buffer->inspect_len = buffer->orig_len = data_len;
    buffer->len = 0;

    InspectionBufferApplyTransforms(buffer, transforms);
}

/** \brief setup the buffer with our initial data */
void InspectionBufferSetup(DetectEngineThreadCtx *det_ctx, const int list_id,
        InspectionBuffer *buffer, const uint8_t *data, const uint32_t data_len)
{
#ifdef DEBUG_VALIDATION
    DEBUG_VALIDATE_BUG_ON(buffer->multi);
    DEBUG_VALIDATE_BUG_ON(buffer != InspectionBufferGet(det_ctx, list_id));
#endif
    if (buffer->inspect == NULL) {
#ifdef UNITTESTS
        if (det_ctx && list_id != -1)
#endif
            det_ctx->inspect.to_clear_queue[det_ctx->inspect.to_clear_idx++] = list_id;
    }
    buffer->inspect = buffer->orig = data;
    buffer->inspect_len = buffer->orig_len = data_len;
    buffer->len = 0;
}

void InspectionBufferFree(InspectionBuffer *buffer)
{
    if (buffer->buf != NULL) {
        SCFree(buffer->buf);
    }
    memset(buffer, 0, sizeof(*buffer));
}

/**
 * \brief make sure that the buffer has at least 'min_size' bytes
 * Expand the buffer if necessary
 */
void InspectionBufferCheckAndExpand(InspectionBuffer *buffer, uint32_t min_size)
{
    if (likely(buffer->size >= min_size))
        return;

    uint32_t new_size = (buffer->size == 0) ? 4096 : buffer->size;
    while (new_size < min_size) {
        new_size *= 2;
    }

    void *ptr = SCRealloc(buffer->buf, new_size);
    if (ptr != NULL) {
        buffer->buf = ptr;
        buffer->size = new_size;
    }
}

void InspectionBufferCopy(InspectionBuffer *buffer, uint8_t *buf, uint32_t buf_len)
{
    InspectionBufferCheckAndExpand(buffer, buf_len);

    if (buffer->size) {
        uint32_t copy_size = MIN(buf_len, buffer->size);
        memcpy(buffer->buf, buf, copy_size);
        buffer->inspect = buffer->buf;
        buffer->inspect_len = copy_size;
    }
}

/** \brief Check content byte array compatibility with transforms
 *
 *  The "content" array is presented to the transforms so that each
 *  transform may validate that it's compatible with the transform.
 *
 *  When a transform indicates the byte array is incompatible, none of the
 *  subsequent transforms, if any, are invoked. This means the first positive
 *  validation result terminates the loop.
 *
 *  \param de_ctx Detection engine context.
 *  \param sm_list The SM list id.
 *  \param content The byte array being validated
 *  \param namestr returns the name of the transform that is incompatible with
 *  content.
 *
 *  \retval true (false) If any of the transforms indicate the byte array is
 *  (is not) compatible.
 **/
bool DetectEngineBufferTypeValidateTransform(DetectEngineCtx *de_ctx, int sm_list,
        const uint8_t *content, uint16_t content_len, const char **namestr)
{
    const DetectBufferType *dbt = DetectEngineBufferTypeGetById(de_ctx, sm_list);
    BUG_ON(dbt == NULL);

    for (int i = 0; i < dbt->transforms.cnt; i++) {
        const TransformData *t = &dbt->transforms.transforms[i];
        if (!sigmatch_table[t->transform].TransformValidate)
            continue;

        if (sigmatch_table[t->transform].TransformValidate(content, content_len, t->options)) {
            continue;
        }

        if (namestr) {
            *namestr = sigmatch_table[t->transform].name;
        }

        return false;
    }

    return true;
}

void InspectionBufferApplyTransforms(InspectionBuffer *buffer,
        const DetectEngineTransforms *transforms)
{
    if (transforms) {
        for (int i = 0; i < DETECT_TRANSFORMS_MAX; i++) {
            const int id = transforms->transforms[i].transform;
            if (id == 0)
                break;
            BUG_ON(sigmatch_table[id].Transform == NULL);
            sigmatch_table[id].Transform(buffer, transforms->transforms[i].options);
            SCLogDebug("applied transform %s", sigmatch_table[id].name);
        }
    }
}

static void DetectBufferTypeSetupDetectEngine(DetectEngineCtx *de_ctx)
{
    const int size = g_buffer_type_id;
    BUG_ON(!(size > 0));

    de_ctx->buffer_type_hash_name = HashListTableInit(256, DetectBufferTypeHashNameFunc,
            DetectBufferTypeCompareNameFunc, DetectBufferTypeFreeFunc);
    BUG_ON(de_ctx->buffer_type_hash_name == NULL);
    de_ctx->buffer_type_hash_id =
            HashListTableInit(256, DetectBufferTypeHashIdFunc, DetectBufferTypeCompareIdFunc,
                    NULL); // entries owned by buffer_type_hash_name
    BUG_ON(de_ctx->buffer_type_hash_id == NULL);
    de_ctx->buffer_type_id = g_buffer_type_id;

    SCLogDebug("DETECT_SM_LIST_DYNAMIC_START %u", DETECT_SM_LIST_DYNAMIC_START);
    HashListTableBucket *b = HashListTableGetListHead(g_buffer_type_hash);
    while (b) {
        DetectBufferType *map = HashListTableGetListData(b);

        DetectBufferType *copy = SCCalloc(1, sizeof(*copy));
        BUG_ON(!copy);
        memcpy(copy, map, sizeof(*copy));
        int r = HashListTableAdd(de_ctx->buffer_type_hash_name, (void *)copy, 0);
        BUG_ON(r != 0);
        r = HashListTableAdd(de_ctx->buffer_type_hash_id, (void *)copy, 0);
        BUG_ON(r != 0);

        SCLogDebug("name %s id %d mpm %s packet %s -- %s. "
                   "Callbacks: Setup %p Validate %p",
                map->name, map->id, map->mpm ? "true" : "false", map->packet ? "true" : "false",
                map->description, map->SetupCallback, map->ValidateCallback);
        b = HashListTableGetListNext(b);
    }

    PrefilterInit(de_ctx);
    DetectMpmInitializeAppMpms(de_ctx);
    DetectAppLayerInspectEngineCopyListToDetectCtx(de_ctx);
    DetectMpmInitializeFrameMpms(de_ctx);
    DetectFrameInspectEngineCopyListToDetectCtx(de_ctx);
    DetectMpmInitializePktMpms(de_ctx);
    DetectPktInspectEngineCopyListToDetectCtx(de_ctx);
}

static void DetectBufferTypeFreeDetectEngine(DetectEngineCtx *de_ctx)
{
    if (de_ctx) {
        if (de_ctx->buffer_type_hash_name)
            HashListTableFree(de_ctx->buffer_type_hash_name);
        if (de_ctx->buffer_type_hash_id)
            HashListTableFree(de_ctx->buffer_type_hash_id);

        DetectEngineAppInspectionEngine *ilist = de_ctx->app_inspect_engines;
        while (ilist) {
            DetectEngineAppInspectionEngine *next = ilist->next;
            SCFree(ilist);
            ilist = next;
        }
        DetectBufferMpmRegistery *mlist = de_ctx->app_mpms_list;
        while (mlist) {
            DetectBufferMpmRegistery *next = mlist->next;
            SCFree(mlist);
            mlist = next;
        }
        DetectEnginePktInspectionEngine *plist = de_ctx->pkt_inspect_engines;
        while (plist) {
            DetectEnginePktInspectionEngine *next = plist->next;
            SCFree(plist);
            plist = next;
        }
        DetectBufferMpmRegistery *pmlist = de_ctx->pkt_mpms_list;
        while (pmlist) {
            DetectBufferMpmRegistery *next = pmlist->next;
            SCFree(pmlist);
            pmlist = next;
        }
        DetectEngineFrameInspectionEngine *framelist = de_ctx->frame_inspect_engines;
        while (framelist) {
            DetectEngineFrameInspectionEngine *next = framelist->next;
            SCFree(framelist);
            framelist = next;
        }
        DetectBufferMpmRegistery *framemlist = de_ctx->frame_mpms_list;
        while (framemlist) {
            DetectBufferMpmRegistery *next = framemlist->next;
            SCFree(framemlist);
            framemlist = next;
        }
        PrefilterDeinit(de_ctx);
    }
}

void DetectBufferTypeCloseRegistration(void)
{
    BUG_ON(g_buffer_type_hash == NULL);

    g_buffer_type_reg_closed = 1;
}

int DetectEngineBufferTypeGetByIdTransforms(
        DetectEngineCtx *de_ctx, const int id, TransformData *transforms, int transform_cnt)
{
    const DetectBufferType *base_map = DetectEngineBufferTypeGetById(de_ctx, id);
    if (!base_map) {
        return -1;
    }
    if (!base_map->supports_transforms) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "buffer '%s' does not support transformations",
                base_map->name);
        return -1;
    }

    SCLogDebug("base_map %s", base_map->name);

    DetectEngineTransforms t;
    memset(&t, 0, sizeof(t));
    for (int i = 0; i < transform_cnt; i++) {
        t.transforms[i] = transforms[i];
    }
    t.cnt = transform_cnt;

    DetectBufferType lookup_map;
    memset(&lookup_map, 0, sizeof(lookup_map));
    strlcpy(lookup_map.name, base_map->name, sizeof(lookup_map.name));
    lookup_map.transforms = t;
    DetectBufferType *res = HashListTableLookup(de_ctx->buffer_type_hash_name, &lookup_map, 0);

    SCLogDebug("res %p", res);
    if (res != NULL) {
        return res->id;
    }

    DetectBufferType *map = SCCalloc(1, sizeof(*map));
    if (map == NULL)
        return -1;

    strlcpy(map->name, base_map->name, sizeof(map->name));
    map->id = de_ctx->buffer_type_id++;
    map->parent_id = base_map->id;
    map->transforms = t;
    map->mpm = base_map->mpm;
    map->packet = base_map->packet;
    map->frame = base_map->frame;
    map->SetupCallback = base_map->SetupCallback;
    map->ValidateCallback = base_map->ValidateCallback;
    if (map->frame) {
        DetectFrameMpmRegisterByParentId(de_ctx, map->id, map->parent_id, &map->transforms);
    } else if (map->packet) {
        DetectPktMpmRegisterByParentId(de_ctx,
                map->id, map->parent_id, &map->transforms);
    } else {
        DetectAppLayerMpmRegisterByParentId(de_ctx,
                map->id, map->parent_id, &map->transforms);
    }

    BUG_ON(HashListTableAdd(de_ctx->buffer_type_hash_name, (void *)map, 0) != 0);
    BUG_ON(HashListTableAdd(de_ctx->buffer_type_hash_id, (void *)map, 0) != 0);
    SCLogDebug("buffer %s registered with id %d, parent %d", map->name, map->id, map->parent_id);
    de_ctx->buffer_type_id++;

    if (map->frame) {
        DetectFrameInspectEngineCopy(de_ctx, map->parent_id, map->id, &map->transforms);
    } else if (map->packet) {
        DetectPktInspectEngineCopy(de_ctx, map->parent_id, map->id, &map->transforms);
    } else {
        DetectAppLayerInspectEngineCopy(de_ctx, map->parent_id, map->id, &map->transforms);
    }
    return map->id;
}

/* returns false if no match, true if match */
static int DetectEngineInspectRulePacketMatches(
    DetectEngineThreadCtx *det_ctx,
    const DetectEnginePktInspectionEngine *engine,
    const Signature *s,
    Packet *p, uint8_t *_alert_flags)
{
    SCEnter();

    /* run the packet match functions */
    KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_MATCH);
    const SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_MATCH];

    SCLogDebug("running match functions, sm %p", smd);
    while (1) {
        KEYWORD_PROFILING_START;
        if (sigmatch_table[smd->type].Match(det_ctx, p, s, smd->ctx) <= 0) {
            KEYWORD_PROFILING_END(det_ctx, smd->type, 0);
            SCLogDebug("no match");
            return false;
        }
        KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
        if (smd->is_last) {
            SCLogDebug("match and is_last");
            break;
        }
        smd++;
    }
    return true;
}

static int DetectEngineInspectRulePayloadMatches(
     DetectEngineThreadCtx *det_ctx,
     const DetectEnginePktInspectionEngine *engine,
     const Signature *s, Packet *p, uint8_t *alert_flags)
{
    SCEnter();

    DetectEngineCtx *de_ctx = det_ctx->de_ctx;

    KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_PMATCH);
    /* if we have stream msgs, inspect against those first,
     * but not for a "dsize" signature */
    if (s->flags & SIG_FLAG_REQUIRE_STREAM) {
        int pmatch = 0;
        if (p->flags & PKT_DETECT_HAS_STREAMDATA) {
            pmatch = DetectEngineInspectStreamPayload(de_ctx, det_ctx, s, p->flow, p);
            if (pmatch) {
                det_ctx->flags |= DETECT_ENGINE_THREAD_CTX_STREAM_CONTENT_MATCH;
                *alert_flags |= PACKET_ALERT_FLAG_STREAM_MATCH;
            }
        }
        /* no match? then inspect packet payload */
        if (pmatch == 0) {
            SCLogDebug("no match in stream, fall back to packet payload");

            /* skip if we don't have to inspect the packet and segment was
             * added to stream */
            if (!(s->flags & SIG_FLAG_REQUIRE_PACKET) && (p->flags & PKT_STREAM_ADD)) {
                return false;
            }
            if (DetectEngineInspectPacketPayload(de_ctx, det_ctx, s, p->flow, p) != 1) {
                return false;
            }
        }
    } else {
        if (DetectEngineInspectPacketPayload(de_ctx, det_ctx, s, p->flow, p) != 1) {
            return false;
        }
    }
    return true;
}

bool DetectEnginePktInspectionRun(ThreadVars *tv,
        DetectEngineThreadCtx *det_ctx, const Signature *s,
        Flow *f, Packet *p,
        uint8_t *alert_flags)
{
    SCEnter();

    for (DetectEnginePktInspectionEngine *e = s->pkt_inspect; e != NULL; e = e->next) {
        if (e->v1.Callback(det_ctx, e, s, p, alert_flags) == false) {
            SCLogDebug("sid %u: e %p Callback returned false", s->id, e);
            return false;
        }
        SCLogDebug("sid %u: e %p Callback returned true", s->id, e);
    }

    SCLogDebug("sid %u: returning true", s->id);
    return true;
}

/**
 * \param data pointer to SigMatchData. Allowed to be NULL.
 */
static int DetectEnginePktInspectionAppend(Signature *s, InspectionBufferPktInspectFunc Callback,
        SigMatchData *data, const int list_id)
{
    DetectEnginePktInspectionEngine *e = SCCalloc(1, sizeof(*e));
    if (e == NULL)
        return -1;

    e->mpm = s->init_data->mpm_sm_list == list_id;
    DEBUG_VALIDATE_BUG_ON(list_id < 0 || list_id > UINT16_MAX);
    e->sm_list = (uint16_t)list_id;
    e->sm_list_base = (uint16_t)list_id;
    e->v1.Callback = Callback;
    e->smd = data;

    if (s->pkt_inspect == NULL) {
        s->pkt_inspect = e;
    } else {
        DetectEnginePktInspectionEngine *a = s->pkt_inspect;
        while (a->next != NULL) {
            a = a->next;
        }
        a->next = e;
    }
    return 0;
}

int DetectEnginePktInspectionSetup(Signature *s)
{
    /* only handle PMATCH here if we're not an app inspect rule */
    if (s->sm_arrays[DETECT_SM_LIST_PMATCH] && (s->init_data->init_flags & SIG_FLAG_INIT_STATE_MATCH) == 0) {
        if (DetectEnginePktInspectionAppend(
                    s, DetectEngineInspectRulePayloadMatches, NULL, DETECT_SM_LIST_PMATCH) < 0)
            return -1;
        SCLogDebug("sid %u: DetectEngineInspectRulePayloadMatches appended", s->id);
    }

    if (s->sm_arrays[DETECT_SM_LIST_MATCH]) {
        if (DetectEnginePktInspectionAppend(
                    s, DetectEngineInspectRulePacketMatches, NULL, DETECT_SM_LIST_MATCH) < 0)
            return -1;
        SCLogDebug("sid %u: DetectEngineInspectRulePacketMatches appended", s->id);
    }

    return 0;
}

/* code to control the main thread to do a reload */

enum DetectEngineSyncState {
    IDLE,   /**< ready to start a reload */
    RELOAD, /**< command main thread to do the reload */
};


typedef struct DetectEngineSyncer_ {
    SCMutex m;
    enum DetectEngineSyncState state;
} DetectEngineSyncer;

static DetectEngineSyncer detect_sync = { SCMUTEX_INITIALIZER, IDLE };

/* tell main to start reloading */
int DetectEngineReloadStart(void)
{
    int r = 0;
    SCMutexLock(&detect_sync.m);
    if (detect_sync.state == IDLE) {
        detect_sync.state = RELOAD;
    } else {
        r = -1;
    }
    SCMutexUnlock(&detect_sync.m);
    return r;
}

/* main thread checks this to see if it should start */
int DetectEngineReloadIsStart(void)
{
    int r = 0;
    SCMutexLock(&detect_sync.m);
    if (detect_sync.state == RELOAD) {
        r = 1;
    }
    SCMutexUnlock(&detect_sync.m);
    return r;
}

/* main thread sets done when it's done */
void DetectEngineReloadSetIdle(void)
{
    SCMutexLock(&detect_sync.m);
    detect_sync.state = IDLE;
    SCMutexUnlock(&detect_sync.m);
}

/* caller loops this until it returns 1 */
int DetectEngineReloadIsIdle(void)
{
    int r = 0;
    SCMutexLock(&detect_sync.m);
    if (detect_sync.state == IDLE) {
        r = 1;
    }
    SCMutexUnlock(&detect_sync.m);
    return r;
}

/** \brief Do the content inspection & validation for a signature
 *
 *  \param de_ctx Detection engine context
 *  \param det_ctx Detection engine thread context
 *  \param s Signature to inspect
 *  \param sm SigMatch to inspect
 *  \param f Flow
 *  \param flags app layer flags
 *  \param state App layer state
 *
 *  \retval 0 no match
 *  \retval 1 match
 */
uint8_t DetectEngineInspectGenericList(const DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const Signature *s, const SigMatchData *smd, Flow *f,
        const uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    SCLogDebug("running match functions, sm %p", smd);
    if (smd != NULL) {
        while (1) {
            int match = 0;
            KEYWORD_PROFILING_START;
            match = sigmatch_table[smd->type].
                AppLayerTxMatch(det_ctx, f, flags, alstate, txv, s, smd->ctx);
            KEYWORD_PROFILING_END(det_ctx, smd->type, (match == 1));
            if (match == 0)
                return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
            if (match == 2) {
                return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
            }

            if (smd->is_last)
                break;
            smd++;
        }
    }

    return DETECT_ENGINE_INSPECT_SIG_MATCH;
}


/**
 * \brief Do the content inspection & validation for a signature
 *
 * \param de_ctx Detection engine context
 * \param det_ctx Detection engine thread context
 * \param s Signature to inspect
 * \param f Flow
 * \param flags app layer flags
 * \param state App layer state
 *
 * \retval 0 no match.
 * \retval 1 match.
 * \retval 2 Sig can't match.
 */
uint8_t DetectEngineInspectBufferGeneric(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine, const Signature *s, Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id)
{
    const int list_id = engine->sm_list;
    SCLogDebug("running inspect on %d", list_id);

    const bool eof = (AppLayerParserGetStateProgress(f->proto, f->alproto, txv, flags) > engine->progress);

    SCLogDebug("list %d mpm? %s transforms %p",
            engine->sm_list, engine->mpm ? "true" : "false", engine->v2.transforms);

    /* if prefilter didn't already run, we need to consider transformations */
    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    const InspectionBuffer *buffer = engine->v2.GetData(det_ctx, transforms,
            f, flags, txv, list_id);
    if (unlikely(buffer == NULL)) {
        return eof ? DETECT_ENGINE_INSPECT_SIG_CANT_MATCH :
                     DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;
    const uint64_t offset = buffer->inspect_offset;

    uint8_t ci_flags = eof ? DETECT_CI_FLAGS_END : 0;
    ci_flags |= (offset == 0 ? DETECT_CI_FLAGS_START : 0);
    ci_flags |= buffer->flags;

    det_ctx->discontinue_matching = 0;
    det_ctx->buffer_offset = 0;
    det_ctx->inspection_recursion_counter = 0;

    /* Inspect all the uricontents fetched on each
     * transaction at the app layer */
    int r = DetectEngineContentInspection(de_ctx, det_ctx,
                                          s, engine->smd,
                                          NULL, f,
                                          (uint8_t *)data, data_len, offset, ci_flags,
                                          DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
    if (r == 1) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    } else {
        return eof ? DETECT_ENGINE_INSPECT_SIG_CANT_MATCH :
                     DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }
}

/**
 * \brief Do the content inspection & validation for a signature
 *
 * \param de_ctx Detection engine context
 * \param det_ctx Detection engine thread context
 * \param s Signature to inspect
 * \param p Packet
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
int DetectEngineInspectPktBufferGeneric(
        DetectEngineThreadCtx *det_ctx,
        const DetectEnginePktInspectionEngine *engine,
        const Signature *s, Packet *p, uint8_t *_alert_flags)
{
    const int list_id = engine->sm_list;
    SCLogDebug("running inspect on %d", list_id);

    SCLogDebug("list %d transforms %p",
            engine->sm_list, engine->v1.transforms);

    /* if prefilter didn't already run, we need to consider transformations */
    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v1.transforms;
    }

    const InspectionBuffer *buffer = engine->v1.GetData(det_ctx, transforms, p,
            list_id);
    if (unlikely(buffer == NULL)) {
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;
    const uint64_t offset = 0;

    uint8_t ci_flags = DETECT_CI_FLAGS_START|DETECT_CI_FLAGS_END;
    ci_flags |= buffer->flags;

    det_ctx->discontinue_matching = 0;
    det_ctx->buffer_offset = 0;
    det_ctx->inspection_recursion_counter = 0;

    /* Inspect all the uricontents fetched on each
     * transaction at the app layer */
    int r = DetectEngineContentInspection(det_ctx->de_ctx, det_ctx,
                                          s, engine->smd,
                                          p, p->flow,
                                          (uint8_t *)data, data_len, offset, ci_flags,
                                          DETECT_ENGINE_CONTENT_INSPECTION_MODE_HEADER);
    if (r == 1) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    } else {
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }
}


/* nudge capture loops to wake up */
static void BreakCapture(void)
{
    SCMutexLock(&tv_root_lock);
    for (ThreadVars *tv = tv_root[TVT_PPT]; tv != NULL; tv = tv->next) {
        if ((tv->tmm_flags & TM_FLAG_RECEIVE_TM) == 0) {
            continue;
        }
        /* find the correct slot */
        for (TmSlot *s = tv->tm_slots; s != NULL; s = s->slot_next) {
            if (suricata_ctl_flags != 0) {
                SCMutexUnlock(&tv_root_lock);
                return;
            }

            TmModule *tm = TmModuleGetById(s->tm_id);
            if (!(tm->flags & TM_FLAG_RECEIVE_TM)) {
                continue;
            }

            /* signal capture method that we need a packet. */
            TmThreadsSetFlag(tv, THV_CAPTURE_INJECT_PKT);
            /* if the method supports it, BreakLoop. Otherwise we rely on
             * the capture method's recv timeout */
            if (tm->PktAcqLoop && tm->PktAcqBreakLoop) {
                tm->PktAcqBreakLoop(tv, SC_ATOMIC_GET(s->slot_data));
            }
            break;
        }
    }
    SCMutexUnlock(&tv_root_lock);
}

/** \internal
 *  \brief inject a pseudo packet into each detect thread that doesn't use the
 *         new det_ctx yet
 */
static void InjectPackets(ThreadVars **detect_tvs,
                          DetectEngineThreadCtx **new_det_ctx,
                          int no_of_detect_tvs)
{
    /* inject a fake packet if the detect thread isn't using the new ctx yet,
     * this speeds up the process */
    for (int i = 0; i < no_of_detect_tvs; i++) {
        if (SC_ATOMIC_GET(new_det_ctx[i]->so_far_used_by_detect) != 1) {
            if (detect_tvs[i]->inq != NULL) {
                Packet *p = PacketGetFromAlloc();
                if (p != NULL) {
                    p->flags |= PKT_PSEUDO_STREAM_END;
                    PKT_SET_SRC(p, PKT_SRC_DETECT_RELOAD_FLUSH);
                    PacketQueue *q = detect_tvs[i]->inq->pq;
                    SCMutexLock(&q->mutex_q);
                    PacketEnqueue(q, p);
                    SCCondSignal(&q->cond_q);
                    SCMutexUnlock(&q->mutex_q);
                }
            }
        }
    }
}

/** \internal
 *  \brief Update detect threads with new detect engine
 *
 *  Atomically update each detect thread with a new thread context
 *  that is associated to the new detection engine(s).
 *
 *  If called in unix socket mode, it's possible that we don't have
 *  detect threads yet.
 *
 *  \retval -1 error
 *  \retval 0 no detection threads
 *  \retval 1 successful reload
 */
static int DetectEngineReloadThreads(DetectEngineCtx *new_de_ctx)
{
    SCEnter();
    uint32_t i = 0;

    /* count detect threads in use */
    uint32_t no_of_detect_tvs = TmThreadCountThreadsByTmmFlags(TM_FLAG_DETECT_TM);
    /* can be zero in unix socket mode */
    if (no_of_detect_tvs == 0) {
        return 0;
    }

    /* prepare swap structures */
    DetectEngineThreadCtx *old_det_ctx[no_of_detect_tvs];
    DetectEngineThreadCtx *new_det_ctx[no_of_detect_tvs];
    ThreadVars *detect_tvs[no_of_detect_tvs];
    memset(old_det_ctx, 0x00, (no_of_detect_tvs * sizeof(DetectEngineThreadCtx *)));
    memset(new_det_ctx, 0x00, (no_of_detect_tvs * sizeof(DetectEngineThreadCtx *)));
    memset(detect_tvs, 0x00, (no_of_detect_tvs * sizeof(ThreadVars *)));

    /* start the process of swapping detect threads ctxs */

    /* get reference to tv's and setup new_det_ctx array */
    SCMutexLock(&tv_root_lock);
    for (ThreadVars *tv = tv_root[TVT_PPT]; tv != NULL; tv = tv->next) {
        if ((tv->tmm_flags & TM_FLAG_DETECT_TM) == 0) {
            continue;
        }
        for (TmSlot *s = tv->tm_slots; s != NULL; s = s->slot_next) {
            TmModule *tm = TmModuleGetById(s->tm_id);
            if (!(tm->flags & TM_FLAG_DETECT_TM)) {
                continue;
            }

            if (suricata_ctl_flags != 0) {
                SCMutexUnlock(&tv_root_lock);
                goto error;
            }

            old_det_ctx[i] = FlowWorkerGetDetectCtxPtr(SC_ATOMIC_GET(s->slot_data));
            detect_tvs[i] = tv;

            new_det_ctx[i] = DetectEngineThreadCtxInitForReload(tv, new_de_ctx, 1);
            if (new_det_ctx[i] == NULL) {
                SCLogError(SC_ERR_LIVE_RULE_SWAP, "Detect engine thread init "
                           "failure in live rule swap.  Let's get out of here");
                SCMutexUnlock(&tv_root_lock);
                goto error;
            }
            SCLogDebug("live rule swap created new det_ctx - %p and de_ctx "
                       "- %p\n", new_det_ctx[i], new_de_ctx);
            i++;
            break;
        }
    }
    BUG_ON(i != no_of_detect_tvs);

    /* atomically replace the det_ctx data */
    i = 0;
    for (ThreadVars *tv = tv_root[TVT_PPT]; tv != NULL; tv = tv->next) {
        if ((tv->tmm_flags & TM_FLAG_DETECT_TM) == 0) {
            continue;
        }
        for (TmSlot *s = tv->tm_slots; s != NULL; s = s->slot_next) {
            TmModule *tm = TmModuleGetById(s->tm_id);
            if (!(tm->flags & TM_FLAG_DETECT_TM)) {
                continue;
            }
            SCLogDebug("swapping new det_ctx - %p with older one - %p",
                       new_det_ctx[i], SC_ATOMIC_GET(s->slot_data));
            FlowWorkerReplaceDetectCtx(SC_ATOMIC_GET(s->slot_data), new_det_ctx[i++]);
            break;
        }
    }
    SCMutexUnlock(&tv_root_lock);

    /* threads now all have new data, however they may not have started using
     * it and may still use the old data */

    SCLogDebug("Live rule swap has swapped %d old det_ctx's with new ones, "
               "along with the new de_ctx", no_of_detect_tvs);

    InjectPackets(detect_tvs, new_det_ctx, no_of_detect_tvs);

    for (i = 0; i < no_of_detect_tvs; i++) {
        int break_out = 0;
        usleep(1000);
        while (SC_ATOMIC_GET(new_det_ctx[i]->so_far_used_by_detect) != 1) {
            if (suricata_ctl_flags != 0) {
                break_out = 1;
                break;
            }

            BreakCapture();
            usleep(1000);
        }
        if (break_out)
            break;
        SCLogDebug("new_det_ctx - %p used by detect engine", new_det_ctx[i]);
    }

    /* this is to make sure that if someone initiated shutdown during a live
     * rule swap, the live rule swap won't clean up the old det_ctx and
     * de_ctx, till all detect threads have stopped working and sitting
     * silently after setting RUNNING_DONE flag and while waiting for
     * THV_DEINIT flag */
    if (i != no_of_detect_tvs) { // not all threads we swapped
        for (ThreadVars *tv = tv_root[TVT_PPT]; tv != NULL; tv = tv->next) {
            if ((tv->tmm_flags & TM_FLAG_DETECT_TM) == 0) {
                continue;
            }

            while (!TmThreadsCheckFlag(tv, THV_RUNNING_DONE)) {
                usleep(100);
            }
        }
    }

    /* free all the ctxs */
    for (i = 0; i < no_of_detect_tvs; i++) {
        SCLogDebug("Freeing old_det_ctx - %p used by detect",
                   old_det_ctx[i]);
        DetectEngineThreadCtxDeinit(NULL, old_det_ctx[i]);
    }

    SRepReloadComplete();

    return 1;

 error:
    for (i = 0; i < no_of_detect_tvs; i++) {
        if (new_det_ctx[i] != NULL)
            DetectEngineThreadCtxDeinit(NULL, new_det_ctx[i]);
    }
    return -1;
}

static DetectEngineCtx *DetectEngineCtxInitReal(enum DetectEngineType type, const char *prefix)
{
    DetectEngineCtx *de_ctx = SCMalloc(sizeof(DetectEngineCtx));
    if (unlikely(de_ctx == NULL))
        goto error;

    memset(de_ctx,0,sizeof(DetectEngineCtx));
    memset(&de_ctx->sig_stat, 0, sizeof(SigFileLoaderStat));
    TAILQ_INIT(&de_ctx->sig_stat.failed_sigs);
    de_ctx->sigerror = NULL;
    de_ctx->type = type;

    if (type == DETECT_ENGINE_TYPE_DD_STUB || type == DETECT_ENGINE_TYPE_MT_STUB) {
        de_ctx->version = DetectEngineGetVersion();
        SCLogDebug("stub %u with version %u", type, de_ctx->version);
        return de_ctx;
    }

    if (prefix != NULL) {
        strlcpy(de_ctx->config_prefix, prefix, sizeof(de_ctx->config_prefix));
    }

    if (ConfGetBool("engine.init-failure-fatal", (int *)&(de_ctx->failure_fatal)) != 1) {
        SCLogDebug("ConfGetBool could not load the value.");
    }

    de_ctx->mpm_matcher = PatternMatchDefaultMatcher();
    de_ctx->spm_matcher = SinglePatternMatchDefaultMatcher();
    SCLogConfig("pattern matchers: MPM: %s, SPM: %s",
        mpm_table[de_ctx->mpm_matcher].name,
        spm_table[de_ctx->spm_matcher].name);

    de_ctx->spm_global_thread_ctx = SpmInitGlobalThreadCtx(de_ctx->spm_matcher);
    if (de_ctx->spm_global_thread_ctx == NULL) {
        SCLogDebug("Unable to alloc SpmGlobalThreadCtx.");
        goto error;
    }

    if (DetectEngineCtxLoadConf(de_ctx) == -1) {
        goto error;
    }

    SigGroupHeadHashInit(de_ctx);
    MpmStoreInit(de_ctx);
    ThresholdHashInit(de_ctx);
    DetectParseDupSigHashInit(de_ctx);
    DetectAddressMapInit(de_ctx);
    DetectMetadataHashInit(de_ctx);
    DetectBufferTypeSetupDetectEngine(de_ctx);
    DetectEngineInitializeFastPatternList(de_ctx);

    /* init iprep... ignore errors for now */
    (void)SRepInit(de_ctx);

    SCClassConfLoadClassficationConfigFile(de_ctx, NULL);
    if (SCRConfLoadReferenceConfigFile(de_ctx, NULL) < 0) {
        if (RunmodeGetCurrent() == RUNMODE_CONF_TEST)
            goto error;
    }

    if (ActionInitConfig() < 0) {
        goto error;
    }

    de_ctx->version = DetectEngineGetVersion();
    VarNameStoreSetupStaging(de_ctx->version);
    SCLogDebug("dectx with version %u", de_ctx->version);
    return de_ctx;
error:
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }
    return NULL;

}

DetectEngineCtx *DetectEngineCtxInitStubForMT(void)
{
    return DetectEngineCtxInitReal(DETECT_ENGINE_TYPE_MT_STUB, NULL);
}

DetectEngineCtx *DetectEngineCtxInitStubForDD(void)
{
    return DetectEngineCtxInitReal(DETECT_ENGINE_TYPE_DD_STUB, NULL);
}

DetectEngineCtx *DetectEngineCtxInit(void)
{
    return DetectEngineCtxInitReal(DETECT_ENGINE_TYPE_NORMAL, NULL);
}

DetectEngineCtx *DetectEngineCtxInitWithPrefix(const char *prefix)
{
    if (prefix == NULL || strlen(prefix) == 0)
        return DetectEngineCtxInit();
    else
        return DetectEngineCtxInitReal(DETECT_ENGINE_TYPE_NORMAL, prefix);
}

static void DetectEngineCtxFreeThreadKeywordData(DetectEngineCtx *de_ctx)
{
    HashListTableFree(de_ctx->keyword_hash);
}

static void DetectEngineCtxFreeFailedSigs(DetectEngineCtx *de_ctx)
{
    SigString *item = NULL;
    SigString *sitem;

    TAILQ_FOREACH_SAFE(item, &de_ctx->sig_stat.failed_sigs, next, sitem) {
        SCFree(item->filename);
        SCFree(item->sig_str);
        if (item->sig_error) {
            SCFree(item->sig_error);
        }
        TAILQ_REMOVE(&de_ctx->sig_stat.failed_sigs, item, next);
        SCFree(item);
    }
}

/**
 * \brief Free a DetectEngineCtx::
 *
 * \param de_ctx DetectEngineCtx:: to be freed
 */
void DetectEngineCtxFree(DetectEngineCtx *de_ctx)
{

    if (de_ctx == NULL)
        return;

#ifdef PROFILING
    if (de_ctx->profile_ctx != NULL) {
        SCProfilingRuleDestroyCtx(de_ctx->profile_ctx);
        de_ctx->profile_ctx = NULL;
    }
    if (de_ctx->profile_keyword_ctx != NULL) {
        SCProfilingKeywordDestroyCtx(de_ctx);//->profile_keyword_ctx);
//        de_ctx->profile_keyword_ctx = NULL;
    }
    if (de_ctx->profile_sgh_ctx != NULL) {
        SCProfilingSghDestroyCtx(de_ctx);
    }
    SCProfilingPrefilterDestroyCtx(de_ctx);
#endif

    /* Normally the hashes are freed elsewhere, but
     * to be sure look at them again here.
     */
    SigGroupHeadHashFree(de_ctx);
    MpmStoreFree(de_ctx);
    DetectParseDupSigHashFree(de_ctx);
    SCSigSignatureOrderingModuleCleanup(de_ctx);
    ThresholdContextDestroy(de_ctx);
    SigCleanSignatures(de_ctx);
    if (de_ctx->sig_array)
        SCFree(de_ctx->sig_array);

    DetectEngineFreeFastPatternList(de_ctx);
    SCClassConfDeInitContext(de_ctx);
    SCRConfDeInitContext(de_ctx);

    SigGroupCleanup(de_ctx);

    SpmDestroyGlobalThreadCtx(de_ctx->spm_global_thread_ctx);

    MpmFactoryDeRegisterAllMpmCtxProfiles(de_ctx);

    DetectEngineCtxFreeThreadKeywordData(de_ctx);
    SRepDestroy(de_ctx);
    DetectEngineCtxFreeFailedSigs(de_ctx);

    DetectAddressMapFree(de_ctx);
    DetectMetadataHashFree(de_ctx);

    /* if we have a config prefix, remove the config from the tree */
    if (strlen(de_ctx->config_prefix) > 0) {
        /* remove config */
        ConfNode *node = ConfGetNode(de_ctx->config_prefix);
        if (node != NULL) {
            ConfNodeRemove(node); /* frees node */
        }
#if 0
        ConfDump();
#endif
    }

    DetectPortCleanupList(de_ctx, de_ctx->tcp_whitelist);
    DetectPortCleanupList(de_ctx, de_ctx->udp_whitelist);

    DetectBufferTypeFreeDetectEngine(de_ctx);
    /* freed our var name hash */
    VarNameStoreFree(de_ctx->version);

    SCFree(de_ctx);
    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();
}

/** \brief  Function that load DetectEngineCtx config for grouping sigs
 *          used by the engine
 *  \retval 0 if no config provided, 1 if config was provided
 *          and loaded successfully
 */
static int DetectEngineCtxLoadConf(DetectEngineCtx *de_ctx)
{
    uint8_t profile = ENGINE_PROFILE_MEDIUM;
    const char *max_uniq_toclient_groups_str = NULL;
    const char *max_uniq_toserver_groups_str = NULL;
    const char *sgh_mpm_context = NULL;
    const char *de_ctx_profile = NULL;

    (void)ConfGet("detect.profile", &de_ctx_profile);
    (void)ConfGet("detect.sgh-mpm-context", &sgh_mpm_context);

    ConfNode *de_ctx_custom = ConfGetNode("detect-engine");
    ConfNode *opt = NULL;

    if (de_ctx_custom != NULL) {
        TAILQ_FOREACH(opt, &de_ctx_custom->head, next) {
            if (de_ctx_profile == NULL) {
                if (opt->val && strcmp(opt->val, "profile") == 0) {
                    de_ctx_profile = opt->head.tqh_first->val;
                }
            }

            if (sgh_mpm_context == NULL) {
                if (opt->val && strcmp(opt->val, "sgh-mpm-context") == 0) {
                    sgh_mpm_context = opt->head.tqh_first->val;
                }
            }
        }
    }

    if (de_ctx_profile != NULL) {
        if (strcmp(de_ctx_profile, "low") == 0 ||
            strcmp(de_ctx_profile, "lowest") == 0) {        // legacy
            profile = ENGINE_PROFILE_LOW;
        } else if (strcmp(de_ctx_profile, "medium") == 0) {
            profile = ENGINE_PROFILE_MEDIUM;
        } else if (strcmp(de_ctx_profile, "high") == 0 ||
                   strcmp(de_ctx_profile, "highest") == 0) { // legacy
            profile = ENGINE_PROFILE_HIGH;
        } else if (strcmp(de_ctx_profile, "custom") == 0) {
            profile = ENGINE_PROFILE_CUSTOM;
        } else {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                    "invalid value for detect.profile: '%s'. "
                    "Valid options: low, medium, high and custom.",
                    de_ctx_profile);
            return -1;
        }

        SCLogDebug("Profile for detection engine groups is \"%s\"", de_ctx_profile);
    } else {
        SCLogDebug("Profile for detection engine groups not provided "
                   "at suricata.yaml. Using default (\"medium\").");
    }

    /* detect-engine.sgh-mpm-context option parsing */
    if (sgh_mpm_context == NULL || strcmp(sgh_mpm_context, "auto") == 0) {
        /* for now, since we still haven't implemented any intelligence into
         * understanding the patterns and distributing mpm_ctx across sgh */
        if (de_ctx->mpm_matcher == MPM_AC || de_ctx->mpm_matcher == MPM_AC_KS ||
#ifdef BUILD_HYPERSCAN
            de_ctx->mpm_matcher == MPM_HS ||
#endif
            de_ctx->mpm_matcher == MPM_AC_BS) {
            de_ctx->sgh_mpm_ctx_cnf = ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE;
        } else {
            de_ctx->sgh_mpm_ctx_cnf = ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL;
        }
    } else {
        if (strcmp(sgh_mpm_context, "single") == 0) {
            de_ctx->sgh_mpm_ctx_cnf = ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE;
        } else if (strcmp(sgh_mpm_context, "full") == 0) {
            de_ctx->sgh_mpm_ctx_cnf = ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL;
        } else {
           SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "You have supplied an "
                      "invalid conf value for detect-engine.sgh-mpm-context-"
                      "%s", sgh_mpm_context);
           exit(EXIT_FAILURE);
        }
    }

    if (run_mode == RUNMODE_UNITTEST) {
        de_ctx->sgh_mpm_ctx_cnf = ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL;
    }

    /* parse profile custom-values */
    opt = NULL;
    switch (profile) {
        case ENGINE_PROFILE_LOW:
            de_ctx->max_uniq_toclient_groups = 15;
            de_ctx->max_uniq_toserver_groups = 25;
            break;

        case ENGINE_PROFILE_HIGH:
            de_ctx->max_uniq_toclient_groups = 75;
            de_ctx->max_uniq_toserver_groups = 75;
            break;

        case ENGINE_PROFILE_CUSTOM:
            (void)ConfGet("detect.custom-values.toclient-groups",
                    &max_uniq_toclient_groups_str);
            (void)ConfGet("detect.custom-values.toserver-groups",
                    &max_uniq_toserver_groups_str);

            if (de_ctx_custom != NULL) {
                TAILQ_FOREACH(opt, &de_ctx_custom->head, next) {
                    if (opt->val && strcmp(opt->val, "custom-values") == 0) {
                        if (max_uniq_toclient_groups_str == NULL) {
                            max_uniq_toclient_groups_str = (char *)ConfNodeLookupChildValue
                                (opt->head.tqh_first, "toclient-sp-groups");
                        }
                        if (max_uniq_toclient_groups_str == NULL) {
                            max_uniq_toclient_groups_str = (char *)ConfNodeLookupChildValue
                                (opt->head.tqh_first, "toclient-groups");
                        }
                        if (max_uniq_toserver_groups_str == NULL) {
                            max_uniq_toserver_groups_str = (char *)ConfNodeLookupChildValue
                                (opt->head.tqh_first, "toserver-dp-groups");
                        }
                        if (max_uniq_toserver_groups_str == NULL) {
                            max_uniq_toserver_groups_str = (char *)ConfNodeLookupChildValue
                                (opt->head.tqh_first, "toserver-groups");
                        }
                    }
                }
            }
            if (max_uniq_toclient_groups_str != NULL) {
                if (StringParseUint16(&de_ctx->max_uniq_toclient_groups, 10,
                            (uint16_t)strlen(max_uniq_toclient_groups_str),
                            (const char *)max_uniq_toclient_groups_str) <= 0) {
                    de_ctx->max_uniq_toclient_groups = 20;

                    SCLogWarning(SC_ERR_SIZE_PARSE, "parsing '%s' for "
                            "toclient-groups failed, using %u",
                            max_uniq_toclient_groups_str,
                            de_ctx->max_uniq_toclient_groups);
                }
            } else {
                de_ctx->max_uniq_toclient_groups = 20;
            }
            SCLogConfig("toclient-groups %u", de_ctx->max_uniq_toclient_groups);

            if (max_uniq_toserver_groups_str != NULL) {
                if (StringParseUint16(&de_ctx->max_uniq_toserver_groups, 10,
                            (uint16_t)strlen(max_uniq_toserver_groups_str),
                            (const char *)max_uniq_toserver_groups_str) <= 0) {
                    de_ctx->max_uniq_toserver_groups = 40;

                    SCLogWarning(SC_ERR_SIZE_PARSE, "parsing '%s' for "
                            "toserver-groups failed, using %u",
                            max_uniq_toserver_groups_str,
                            de_ctx->max_uniq_toserver_groups);
                }
            } else {
                de_ctx->max_uniq_toserver_groups = 40;
            }
            SCLogConfig("toserver-groups %u", de_ctx->max_uniq_toserver_groups);
            break;

        /* Default (or no config provided) is profile medium */
        case ENGINE_PROFILE_MEDIUM:
        case ENGINE_PROFILE_UNKNOWN:
        default:
            de_ctx->max_uniq_toclient_groups = 20;
            de_ctx->max_uniq_toserver_groups = 40;
            break;
    }

    intmax_t value = 0;
    if (ConfGetInt("detect.inspection-recursion-limit", &value) == 1)
    {
        if (value >= 0 && value <= INT_MAX) {
            de_ctx->inspection_recursion_limit = (int)value;
        }

    /* fall back to old config parsing */
    } else {
        ConfNode *insp_recursion_limit_node = NULL;
        char *insp_recursion_limit = NULL;

        if (de_ctx_custom != NULL) {
            opt = NULL;
            TAILQ_FOREACH(opt, &de_ctx_custom->head, next) {
                if (opt->val && strcmp(opt->val, "inspection-recursion-limit") != 0)
                    continue;

                insp_recursion_limit_node = ConfNodeLookupChild(opt, opt->val);
                if (insp_recursion_limit_node == NULL) {
                    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Error retrieving conf "
                            "entry for detect-engine:inspection-recursion-limit");
                    break;
                }
                insp_recursion_limit = insp_recursion_limit_node->val;
                SCLogDebug("Found detect-engine.inspection-recursion-limit - %s:%s",
                        insp_recursion_limit_node->name, insp_recursion_limit_node->val);
                break;
            }

            if (insp_recursion_limit != NULL) {
                if (StringParseInt32(&de_ctx->inspection_recursion_limit, 10,
                                     0, (const char *)insp_recursion_limit) < 0) {
                    SCLogWarning(SC_ERR_INVALID_VALUE, "Invalid value for "
                                 "detect-engine.inspection-recursion-limit: %s "
                                 "resetting to %d", insp_recursion_limit,
                                 DETECT_ENGINE_DEFAULT_INSPECTION_RECURSION_LIMIT);
                    de_ctx->inspection_recursion_limit =
                        DETECT_ENGINE_DEFAULT_INSPECTION_RECURSION_LIMIT;
                }
            } else {
                de_ctx->inspection_recursion_limit =
                    DETECT_ENGINE_DEFAULT_INSPECTION_RECURSION_LIMIT;
            }
        }
    }

    if (de_ctx->inspection_recursion_limit == 0)
        de_ctx->inspection_recursion_limit = -1;

    SCLogDebug("de_ctx->inspection_recursion_limit: %d",
               de_ctx->inspection_recursion_limit);

    /* parse port grouping whitelisting settings */

    const char *ports = NULL;
    (void)ConfGet("detect.grouping.tcp-whitelist", &ports);
    if (ports) {
        SCLogConfig("grouping: tcp-whitelist %s", ports);
    } else {
        ports = "53, 80, 139, 443, 445, 1433, 3306, 3389, 6666, 6667, 8080";
        SCLogConfig("grouping: tcp-whitelist (default) %s", ports);

    }
    if (DetectPortParse(de_ctx, &de_ctx->tcp_whitelist, ports) != 0) {
        SCLogWarning(SC_ERR_INVALID_YAML_CONF_ENTRY, "'%s' is not a valid value "
                "for detect.grouping.tcp-whitelist", ports);
    }
    DetectPort *x = de_ctx->tcp_whitelist;
    for ( ; x != NULL;  x = x->next) {
        if (x->port != x->port2) {
            SCLogWarning(SC_ERR_INVALID_YAML_CONF_ENTRY, "'%s' is not a valid value "
                "for detect.grouping.tcp-whitelist: only single ports allowed", ports);
            DetectPortCleanupList(de_ctx, de_ctx->tcp_whitelist);
            de_ctx->tcp_whitelist = NULL;
            break;
        }
    }

    ports = NULL;
    (void)ConfGet("detect.grouping.udp-whitelist", &ports);
    if (ports) {
        SCLogConfig("grouping: udp-whitelist %s", ports);
    } else {
        ports = "53, 135, 5060";
        SCLogConfig("grouping: udp-whitelist (default) %s", ports);

    }
    if (DetectPortParse(de_ctx, &de_ctx->udp_whitelist, ports) != 0) {
        SCLogWarning(SC_ERR_INVALID_YAML_CONF_ENTRY, "'%s' is not a valid value "
                "forr detect.grouping.udp-whitelist", ports);
    }
    for (x = de_ctx->udp_whitelist; x != NULL;  x = x->next) {
        if (x->port != x->port2) {
            SCLogWarning(SC_ERR_INVALID_YAML_CONF_ENTRY, "'%s' is not a valid value "
                "for detect.grouping.udp-whitelist: only single ports allowed", ports);
            DetectPortCleanupList(de_ctx, de_ctx->udp_whitelist);
            de_ctx->udp_whitelist = NULL;
            break;
        }
    }

    de_ctx->prefilter_setting = DETECT_PREFILTER_MPM;
    const char *pf_setting = NULL;
    if (ConfGet("detect.prefilter.default", &pf_setting) == 1 && pf_setting) {
        if (strcasecmp(pf_setting, "mpm") == 0) {
            de_ctx->prefilter_setting = DETECT_PREFILTER_MPM;
        } else if (strcasecmp(pf_setting, "auto") == 0) {
            de_ctx->prefilter_setting = DETECT_PREFILTER_AUTO;
        }
    }
    switch (de_ctx->prefilter_setting) {
        case DETECT_PREFILTER_MPM:
            SCLogConfig("prefilter engines: MPM");
            break;
        case DETECT_PREFILTER_AUTO:
            SCLogConfig("prefilter engines: MPM and keywords");
            break;
    }

    return 0;
}

/*
 * getting & (re)setting the internal sig i
 */

//inline uint32_t DetectEngineGetMaxSigId(DetectEngineCtx *de_ctx)
//{
//    return de_ctx->signum;
//}

void DetectEngineResetMaxSigId(DetectEngineCtx *de_ctx)
{
    de_ctx->signum = 0;
}

static int DetectEngineThreadCtxInitGlobalKeywords(DetectEngineThreadCtx *det_ctx)
{
    const DetectEngineMasterCtx *master = &g_master_de_ctx;

    if (master->keyword_id > 0) {
        // coverity[suspicious_sizeof : FALSE]
        det_ctx->global_keyword_ctxs_array = (void **)SCCalloc(master->keyword_id, sizeof(void *));
        if (det_ctx->global_keyword_ctxs_array == NULL) {
            SCLogError(SC_ERR_DETECT_PREPARE, "setting up thread local detect ctx");
            return TM_ECODE_FAILED;
        }
        det_ctx->global_keyword_ctxs_size = master->keyword_id;

        const DetectEngineThreadKeywordCtxItem *item = master->keyword_list;
        while (item) {
            det_ctx->global_keyword_ctxs_array[item->id] = item->InitFunc(item->data);
            if (det_ctx->global_keyword_ctxs_array[item->id] == NULL) {
                SCLogError(SC_ERR_DETECT_PREPARE, "setting up thread local detect ctx "
                        "for keyword \"%s\" failed", item->name);
                return TM_ECODE_FAILED;
            }
            item = item->next;
        }
    }
    return TM_ECODE_OK;
}

static void DetectEngineThreadCtxDeinitGlobalKeywords(DetectEngineThreadCtx *det_ctx)
{
    if (det_ctx->global_keyword_ctxs_array == NULL ||
        det_ctx->global_keyword_ctxs_size == 0) {
        return;
    }

    const DetectEngineMasterCtx *master = &g_master_de_ctx;
    if (master->keyword_id > 0) {
        const DetectEngineThreadKeywordCtxItem *item = master->keyword_list;
        while (item) {
            if (det_ctx->global_keyword_ctxs_array[item->id] != NULL)
                item->FreeFunc(det_ctx->global_keyword_ctxs_array[item->id]);

            item = item->next;
        }
        det_ctx->global_keyword_ctxs_size = 0;
        SCFree(det_ctx->global_keyword_ctxs_array);
        det_ctx->global_keyword_ctxs_array = NULL;
    }
}

static int DetectEngineThreadCtxInitKeywords(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx)
{
    if (de_ctx->keyword_id > 0) {
        // coverity[suspicious_sizeof : FALSE]
        det_ctx->keyword_ctxs_array = SCMalloc(de_ctx->keyword_id * sizeof(void *));
        if (det_ctx->keyword_ctxs_array == NULL) {
            SCLogError(SC_ERR_DETECT_PREPARE, "setting up thread local detect ctx");
            return TM_ECODE_FAILED;
        }

        memset(det_ctx->keyword_ctxs_array, 0x00, de_ctx->keyword_id * sizeof(void *));

        det_ctx->keyword_ctxs_size = de_ctx->keyword_id;

        HashListTableBucket *hb = HashListTableGetListHead(de_ctx->keyword_hash);
        for (; hb != NULL; hb = HashListTableGetListNext(hb)) {
            DetectEngineThreadKeywordCtxItem *item = HashListTableGetListData(hb);

            det_ctx->keyword_ctxs_array[item->id] = item->InitFunc(item->data);
            if (det_ctx->keyword_ctxs_array[item->id] == NULL) {
                SCLogError(SC_ERR_DETECT_PREPARE, "setting up thread local detect ctx "
                        "for keyword \"%s\" failed", item->name);
                return TM_ECODE_FAILED;
            }
        }
    }
    return TM_ECODE_OK;
}

static void DetectEngineThreadCtxDeinitKeywords(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx)
{
    if (de_ctx->keyword_id > 0) {
        HashListTableBucket *hb = HashListTableGetListHead(de_ctx->keyword_hash);
        for (; hb != NULL; hb = HashListTableGetListNext(hb)) {
            DetectEngineThreadKeywordCtxItem *item = HashListTableGetListData(hb);

            if (det_ctx->keyword_ctxs_array[item->id] != NULL)
                item->FreeFunc(det_ctx->keyword_ctxs_array[item->id]);
        }
        det_ctx->keyword_ctxs_size = 0;
        SCFree(det_ctx->keyword_ctxs_array);
        det_ctx->keyword_ctxs_array = NULL;
    }
}

/** NOTE: master MUST be locked before calling this */
static TmEcode DetectEngineThreadCtxInitForMT(ThreadVars *tv, DetectEngineThreadCtx *det_ctx)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    DetectEngineTenantMapping *map_array = NULL;
    uint32_t map_array_size = 0;
    uint32_t map_cnt = 0;
    uint32_t max_tenant_id = 0;
    DetectEngineCtx *list = master->list;
    HashTable *mt_det_ctxs_hash = NULL;

    if (master->tenant_selector == TENANT_SELECTOR_UNKNOWN) {
        SCLogError(SC_ERR_MT_NO_SELECTOR, "no tenant selector set: "
                                          "set using multi-detect.selector");
        return TM_ECODE_FAILED;
    }

    uint32_t tcnt = 0;
    while (list) {
        if (list->tenant_id > max_tenant_id)
            max_tenant_id = list->tenant_id;

        list = list->next;
        tcnt++;
    }

    mt_det_ctxs_hash = HashTableInit(tcnt * 2, TenantIdHash, TenantIdCompare, TenantIdFree);
    if (mt_det_ctxs_hash == NULL) {
        goto error;
    }

    if (tcnt == 0) {
        SCLogInfo("no tenants left, or none registered yet");
    } else {
        max_tenant_id++;

        DetectEngineTenantMapping *map = master->tenant_mapping_list;
        while (map) {
            map_cnt++;
            map = map->next;
        }

        if (map_cnt > 0) {
            map_array_size = map_cnt + 1;

            map_array = SCCalloc(map_array_size, sizeof(*map_array));
            if (map_array == NULL)
                goto error;

            /* fill the array */
            map_cnt = 0;
            map = master->tenant_mapping_list;
            while (map) {
                if (map_cnt >= map_array_size) {
                    goto error;
                }
                map_array[map_cnt].traffic_id = map->traffic_id;
                map_array[map_cnt].tenant_id = map->tenant_id;
                map_cnt++;
                map = map->next;
            }

        }

        /* set up hash for tenant lookup */
        list = master->list;
        while (list) {
            SCLogDebug("tenant-id %u", list->tenant_id);
            if (list->tenant_id != 0) {
                DetectEngineThreadCtx *mt_det_ctx = DetectEngineThreadCtxInitForReload(tv, list, 0);
                if (mt_det_ctx == NULL)
                    goto error;
                if (HashTableAdd(mt_det_ctxs_hash, mt_det_ctx, 0) != 0) {
                    goto error;
                }
            }
            list = list->next;
        }
    }

    det_ctx->mt_det_ctxs_hash = mt_det_ctxs_hash;
    mt_det_ctxs_hash = NULL;

    det_ctx->mt_det_ctxs_cnt = max_tenant_id;

    det_ctx->tenant_array = map_array;
    det_ctx->tenant_array_size = map_array_size;

    switch (master->tenant_selector) {
        case TENANT_SELECTOR_UNKNOWN:
            SCLogDebug("TENANT_SELECTOR_UNKNOWN");
            break;
        case TENANT_SELECTOR_VLAN:
            det_ctx->TenantGetId = DetectEngineTentantGetIdFromVlanId;
            SCLogDebug("TENANT_SELECTOR_VLAN");
            break;
        case TENANT_SELECTOR_LIVEDEV:
            det_ctx->TenantGetId = DetectEngineTentantGetIdFromLivedev;
            SCLogDebug("TENANT_SELECTOR_LIVEDEV");
            break;
        case TENANT_SELECTOR_DIRECT:
            det_ctx->TenantGetId = DetectEngineTentantGetIdFromPcap;
            SCLogDebug("TENANT_SELECTOR_DIRECT");
            break;
    }

    return TM_ECODE_OK;
error:
    if (map_array != NULL)
        SCFree(map_array);
    if (mt_det_ctxs_hash != NULL)
        HashTableFree(mt_det_ctxs_hash);

    return TM_ECODE_FAILED;
}

/** \internal
 *  \brief Helper for DetectThread setup functions
 */
static TmEcode ThreadCtxDoInit (DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx)
{
    PatternMatchThreadPrepare(&det_ctx->mtc, de_ctx->mpm_matcher);
    PatternMatchThreadPrepare(&det_ctx->mtcs, de_ctx->mpm_matcher);
    PatternMatchThreadPrepare(&det_ctx->mtcu, de_ctx->mpm_matcher);

    PmqSetup(&det_ctx->pmq);

    det_ctx->spm_thread_ctx = SpmMakeThreadCtx(de_ctx->spm_global_thread_ctx);
    if (det_ctx->spm_thread_ctx == NULL) {
        return TM_ECODE_FAILED;
    }

    /* sized to the max of our sgh settings. A max setting of 0 implies that all
     * sgh's have: sgh->non_pf_store_cnt == 0 */
    if (de_ctx->non_pf_store_cnt_max > 0) {
        det_ctx->non_pf_id_array =  SCCalloc(de_ctx->non_pf_store_cnt_max, sizeof(SigIntId));
        BUG_ON(det_ctx->non_pf_id_array == NULL);
    }

    /* IP-ONLY */
    DetectEngineIPOnlyThreadInit(de_ctx,&det_ctx->io_ctx);

    /* DeState */
    if (de_ctx->sig_array_len > 0) {
        det_ctx->match_array_len = de_ctx->sig_array_len;
        det_ctx->match_array = SCMalloc(det_ctx->match_array_len * sizeof(Signature *));
        if (det_ctx->match_array == NULL) {
            return TM_ECODE_FAILED;
        }
        memset(det_ctx->match_array, 0,
               det_ctx->match_array_len * sizeof(Signature *));

        RuleMatchCandidateTxArrayInit(det_ctx, de_ctx->sig_array_len);
    }

    /* Alert processing queue */
    AlertQueueInit(det_ctx);

    /* byte_extract storage */
    det_ctx->byte_values = SCMalloc(sizeof(*det_ctx->byte_values) *
                                  (de_ctx->byte_extract_max_local_id + 1));
    if (det_ctx->byte_values == NULL) {
        return TM_ECODE_FAILED;
    }

    /* Allocate space for base64 decoded data. */
    if (de_ctx->base64_decode_max_len) {
        det_ctx->base64_decoded = SCMalloc(de_ctx->base64_decode_max_len);
        if (det_ctx->base64_decoded == NULL) {
            return TM_ECODE_FAILED;
        }
        det_ctx->base64_decoded_len_max = de_ctx->base64_decode_max_len;
        det_ctx->base64_decoded_len = 0;
    }

    det_ctx->inspect.buffers_size = de_ctx->buffer_type_id;
    det_ctx->inspect.buffers = SCCalloc(det_ctx->inspect.buffers_size, sizeof(InspectionBuffer));
    if (det_ctx->inspect.buffers == NULL) {
        return TM_ECODE_FAILED;
    }
    det_ctx->inspect.to_clear_queue = SCCalloc(det_ctx->inspect.buffers_size, sizeof(uint32_t));
    if (det_ctx->inspect.to_clear_queue == NULL) {
        return TM_ECODE_FAILED;
    }
    det_ctx->inspect.to_clear_idx = 0;

    det_ctx->multi_inspect.buffers_size = de_ctx->buffer_type_id;
    det_ctx->multi_inspect.buffers = SCCalloc(det_ctx->multi_inspect.buffers_size, sizeof(InspectionBufferMultipleForList));
    if (det_ctx->multi_inspect.buffers == NULL) {
        return TM_ECODE_FAILED;
    }
    det_ctx->multi_inspect.to_clear_queue = SCCalloc(det_ctx->multi_inspect.buffers_size, sizeof(uint32_t));
    if (det_ctx->multi_inspect.to_clear_queue == NULL) {
        return TM_ECODE_FAILED;
    }
    det_ctx->multi_inspect.to_clear_idx = 0;


    DetectEngineThreadCtxInitKeywords(de_ctx, det_ctx);
    DetectEngineThreadCtxInitGlobalKeywords(det_ctx);
#ifdef PROFILING
    SCProfilingRuleThreadSetup(de_ctx->profile_ctx, det_ctx);
    SCProfilingKeywordThreadSetup(de_ctx->profile_keyword_ctx, det_ctx);
    SCProfilingPrefilterThreadSetup(de_ctx->profile_prefilter_ctx, det_ctx);
    SCProfilingSghThreadSetup(de_ctx->profile_sgh_ctx, det_ctx);
#endif
    SC_ATOMIC_INIT(det_ctx->so_far_used_by_detect);

    return TM_ECODE_OK;
}

/** \brief initialize thread specific detection engine context
 *
 *  \note there is a special case when using delayed detect. In this case the
 *        function is called twice per thread. The first time the rules are not
 *        yet loaded. de_ctx->delayed_detect_initialized will be 0. The 2nd
 *        time they will be loaded. de_ctx->delayed_detect_initialized will be 1.
 *        This is needed to do the per thread counter registration before the
 *        packet runtime starts. In delayed detect mode, the first call will
 *        return a NULL ptr through the data ptr.
 *
 *  \param tv ThreadVars for this thread
 *  \param initdata pointer to de_ctx
 *  \param data[out] pointer to store our thread detection ctx
 *
 *  \retval TM_ECODE_OK if all went well
 *  \retval TM_ECODE_FAILED on serious errors
 */
TmEcode DetectEngineThreadCtxInit(ThreadVars *tv, void *initdata, void **data)
{
    DetectEngineThreadCtx *det_ctx = SCMalloc(sizeof(DetectEngineThreadCtx));
    if (unlikely(det_ctx == NULL))
        return TM_ECODE_FAILED;
    memset(det_ctx, 0, sizeof(DetectEngineThreadCtx));

    det_ctx->tv = tv;
    det_ctx->de_ctx = DetectEngineGetCurrent();
    if (det_ctx->de_ctx == NULL) {
#ifdef UNITTESTS
        if (RunmodeIsUnittests()) {
            det_ctx->de_ctx = (DetectEngineCtx *)initdata;
        } else {
            DetectEngineThreadCtxDeinit(tv, det_ctx);
            return TM_ECODE_FAILED;
        }
#else
        DetectEngineThreadCtxDeinit(tv, det_ctx);
        return TM_ECODE_FAILED;
#endif
    }

    if (det_ctx->de_ctx->type == DETECT_ENGINE_TYPE_NORMAL ||
        det_ctx->de_ctx->type == DETECT_ENGINE_TYPE_TENANT)
    {
        if (ThreadCtxDoInit(det_ctx->de_ctx, det_ctx) != TM_ECODE_OK) {
            DetectEngineThreadCtxDeinit(tv, det_ctx);
            return TM_ECODE_FAILED;
        }
    }

    /** alert counter setup */
    det_ctx->counter_alerts = StatsRegisterCounter("detect.alert", tv);
    det_ctx->counter_alerts_overflow = StatsRegisterCounter("detect.alert_queue_overflow", tv);
    det_ctx->counter_alerts_suppressed = StatsRegisterCounter("detect.alerts_suppressed", tv);
#ifdef PROFILING
    det_ctx->counter_mpm_list = StatsRegisterAvgCounter("detect.mpm_list", tv);
    det_ctx->counter_nonmpm_list = StatsRegisterAvgCounter("detect.nonmpm_list", tv);
    det_ctx->counter_fnonmpm_list = StatsRegisterAvgCounter("detect.fnonmpm_list", tv);
    det_ctx->counter_match_list = StatsRegisterAvgCounter("detect.match_list", tv);
#endif

    if (DetectEngineMultiTenantEnabled()) {
        if (DetectEngineThreadCtxInitForMT(tv, det_ctx) != TM_ECODE_OK) {
            DetectEngineThreadCtxDeinit(tv, det_ctx);
            return TM_ECODE_FAILED;
        }
    }

    /* pass thread data back to caller */
    *data = (void *)det_ctx;

    return TM_ECODE_OK;
}

/**
 * \internal
 * \brief initialize a det_ctx for reload cases
 * \param new_de_ctx the new detection engine
 * \param mt flag to indicate if MT should be set up for this det_ctx
 *           this should only be done for the 'root' det_ctx
 *
 * \retval det_ctx detection engine thread ctx or NULL in case of error
 */
DetectEngineThreadCtx *DetectEngineThreadCtxInitForReload(
        ThreadVars *tv, DetectEngineCtx *new_de_ctx, int mt)
{
    DetectEngineThreadCtx *det_ctx = SCMalloc(sizeof(DetectEngineThreadCtx));
    if (unlikely(det_ctx == NULL))
        return NULL;
    memset(det_ctx, 0, sizeof(DetectEngineThreadCtx));

    det_ctx->tenant_id = new_de_ctx->tenant_id;
    det_ctx->tv = tv;
    det_ctx->de_ctx = DetectEngineReference(new_de_ctx);
    if (det_ctx->de_ctx == NULL) {
        SCFree(det_ctx);
        return NULL;
    }

    /* most of the init happens here */
    if (det_ctx->de_ctx->type == DETECT_ENGINE_TYPE_NORMAL ||
        det_ctx->de_ctx->type == DETECT_ENGINE_TYPE_TENANT)
    {
        if (ThreadCtxDoInit(det_ctx->de_ctx, det_ctx) != TM_ECODE_OK) {
            DetectEngineDeReference(&det_ctx->de_ctx);
            SCFree(det_ctx);
            return NULL;
        }
    }

    /** alert counter setup */
    det_ctx->counter_alerts = StatsRegisterCounter("detect.alert", tv);
#ifdef PROFILING
    uint16_t counter_mpm_list = StatsRegisterAvgCounter("detect.mpm_list", tv);
    uint16_t counter_nonmpm_list = StatsRegisterAvgCounter("detect.nonmpm_list", tv);
    uint16_t counter_fnonmpm_list = StatsRegisterAvgCounter("detect.fnonmpm_list", tv);
    uint16_t counter_match_list = StatsRegisterAvgCounter("detect.match_list", tv);
    det_ctx->counter_mpm_list = counter_mpm_list;
    det_ctx->counter_nonmpm_list = counter_nonmpm_list;
    det_ctx->counter_fnonmpm_list = counter_fnonmpm_list;
    det_ctx->counter_match_list = counter_match_list;
#endif

    if (mt && DetectEngineMultiTenantEnabled()) {
        if (DetectEngineThreadCtxInitForMT(tv, det_ctx) != TM_ECODE_OK) {
            DetectEngineDeReference(&det_ctx->de_ctx);
            SCFree(det_ctx);
            return NULL;
        }
    }

    return det_ctx;
}

static void DetectEngineThreadCtxFree(DetectEngineThreadCtx *det_ctx)
{
#if  DEBUG
    SCLogDebug("PACKET PKT_STREAM_ADD: %"PRIu64, det_ctx->pkt_stream_add_cnt);

    SCLogDebug("PAYLOAD MPM %"PRIu64"/%"PRIu64, det_ctx->payload_mpm_cnt, det_ctx->payload_mpm_size);
    SCLogDebug("STREAM  MPM %"PRIu64"/%"PRIu64, det_ctx->stream_mpm_cnt, det_ctx->stream_mpm_size);

    SCLogDebug("PAYLOAD SIG %"PRIu64"/%"PRIu64, det_ctx->payload_persig_cnt, det_ctx->payload_persig_size);
    SCLogDebug("STREAM  SIG %"PRIu64"/%"PRIu64, det_ctx->stream_persig_cnt, det_ctx->stream_persig_size);
#endif

    if (det_ctx->tenant_array != NULL) {
        SCFree(det_ctx->tenant_array);
        det_ctx->tenant_array = NULL;
    }

#ifdef PROFILING
    SCProfilingRuleThreadCleanup(det_ctx);
    SCProfilingKeywordThreadCleanup(det_ctx);
    SCProfilingPrefilterThreadCleanup(det_ctx);
    SCProfilingSghThreadCleanup(det_ctx);
#endif

    DetectEngineIPOnlyThreadDeinit(&det_ctx->io_ctx);

    /** \todo get rid of this static */
    if (det_ctx->de_ctx != NULL) {
        PatternMatchThreadDestroy(&det_ctx->mtc, det_ctx->de_ctx->mpm_matcher);
        PatternMatchThreadDestroy(&det_ctx->mtcs, det_ctx->de_ctx->mpm_matcher);
        PatternMatchThreadDestroy(&det_ctx->mtcu, det_ctx->de_ctx->mpm_matcher);
    }

    PmqFree(&det_ctx->pmq);

    if (det_ctx->spm_thread_ctx != NULL) {
        SpmDestroyThreadCtx(det_ctx->spm_thread_ctx);
    }

    if (det_ctx->non_pf_id_array != NULL)
        SCFree(det_ctx->non_pf_id_array);

    if (det_ctx->match_array != NULL)
        SCFree(det_ctx->match_array);

    RuleMatchCandidateTxArrayFree(det_ctx);

    AlertQueueFree(det_ctx);

    if (det_ctx->byte_values != NULL)
        SCFree(det_ctx->byte_values);

    /* Decoded base64 data. */
    if (det_ctx->base64_decoded != NULL) {
        SCFree(det_ctx->base64_decoded);
    }

    if (det_ctx->inspect.buffers) {
        for (uint32_t i = 0; i < det_ctx->inspect.buffers_size; i++) {
            InspectionBufferFree(&det_ctx->inspect.buffers[i]);
        }
        SCFree(det_ctx->inspect.buffers);
    }
    if (det_ctx->inspect.to_clear_queue) {
        SCFree(det_ctx->inspect.to_clear_queue);
    }
    if (det_ctx->multi_inspect.buffers) {
        for (uint32_t i = 0; i < det_ctx->multi_inspect.buffers_size; i++) {
            InspectionBufferMultipleForList *fb = &det_ctx->multi_inspect.buffers[i];
            for (uint32_t x = 0; x < fb->size; x++) {
                InspectionBufferFree(&fb->inspection_buffers[x]);
            }
            SCFree(fb->inspection_buffers);
        }
        SCFree(det_ctx->multi_inspect.buffers);
    }
    if (det_ctx->multi_inspect.to_clear_queue) {
        SCFree(det_ctx->multi_inspect.to_clear_queue);
    }

    DetectEngineThreadCtxDeinitGlobalKeywords(det_ctx);
    if (det_ctx->de_ctx != NULL) {
        DetectEngineThreadCtxDeinitKeywords(det_ctx->de_ctx, det_ctx);
#ifdef UNITTESTS
        if (!RunmodeIsUnittests() || det_ctx->de_ctx->ref_cnt > 0)
            DetectEngineDeReference(&det_ctx->de_ctx);
#else
        DetectEngineDeReference(&det_ctx->de_ctx);
#endif
    }

    AppLayerDecoderEventsFreeEvents(&det_ctx->decoder_events);

    SCFree(det_ctx);
}

TmEcode DetectEngineThreadCtxDeinit(ThreadVars *tv, void *data)
{
    DetectEngineThreadCtx *det_ctx = (DetectEngineThreadCtx *)data;

    if (det_ctx == NULL) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "argument \"data\" NULL");
        return TM_ECODE_OK;
    }

    if (det_ctx->mt_det_ctxs_hash != NULL) {
        HashTableFree(det_ctx->mt_det_ctxs_hash);
        det_ctx->mt_det_ctxs_hash = NULL;
    }
    DetectEngineThreadCtxFree(det_ctx);

    return TM_ECODE_OK;
}

void DetectEngineThreadCtxInfo(ThreadVars *t, DetectEngineThreadCtx *det_ctx)
{
    /* XXX */
    PatternMatchThreadPrint(&det_ctx->mtc, det_ctx->de_ctx->mpm_matcher);
    PatternMatchThreadPrint(&det_ctx->mtcu, det_ctx->de_ctx->mpm_matcher);
}

static uint32_t DetectKeywordCtxHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    DetectEngineThreadKeywordCtxItem *ctx = data;
    const char *name = ctx->name;
    uint64_t hash = StringHashDjb2((const uint8_t *)name, strlen(name)) + (uint64_t)ctx->data;
    hash %= ht->array_size;
    return hash;
}

static char DetectKeywordCtxCompareFunc(void *data1, uint16_t len1, void *data2, uint16_t len2)
{
    DetectEngineThreadKeywordCtxItem *ctx1 = data1;
    DetectEngineThreadKeywordCtxItem *ctx2 = data2;
    const char *name1 = ctx1->name;
    const char *name2 = ctx2->name;
    return (strcmp(name1, name2) == 0 && ctx1->data == ctx2->data);
}

static void DetectKeywordCtxFreeFunc(void *ptr)
{
    SCFree(ptr);
}

/** \brief Register Thread keyword context Funcs
 *
 *  \param de_ctx detection engine to register in
 *  \param name keyword name for error printing
 *  \param InitFunc function ptr
 *  \param data keyword init data to pass to Func. Can be NULL.
 *  \param FreeFunc function ptr
 *  \param mode 0 normal (ctx per keyword instance) 1 shared (one ctx per det_ct)
 *
 *  \retval id for retrieval of ctx at runtime
 *  \retval -1 on error
 *
 *  \note make sure "data" remains valid and it free'd elsewhere. It's
 *        recommended to store it in the keywords global ctx so that
 *        it's freed when the de_ctx is freed.
 */
int DetectRegisterThreadCtxFuncs(DetectEngineCtx *de_ctx, const char *name, void *(*InitFunc)(void *), void *data, void (*FreeFunc)(void *), int mode)
{
    BUG_ON(de_ctx == NULL || InitFunc == NULL || FreeFunc == NULL);

    if (de_ctx->keyword_hash == NULL) {
        de_ctx->keyword_hash = HashListTableInit(4096, // TODO
                DetectKeywordCtxHashFunc, DetectKeywordCtxCompareFunc, DetectKeywordCtxFreeFunc);
        BUG_ON(de_ctx->keyword_hash == NULL);
    }

    if (mode) {
        DetectEngineThreadKeywordCtxItem search = { .data = data, .name = name };

        DetectEngineThreadKeywordCtxItem *item =
                HashListTableLookup(de_ctx->keyword_hash, (void *)&search, 0);
        if (item)
            return item->id;

        /* fall through */
    }

    DetectEngineThreadKeywordCtxItem *item = SCCalloc(1, sizeof(DetectEngineThreadKeywordCtxItem));
    if (unlikely(item == NULL))
        return -1;

    item->InitFunc = InitFunc;
    item->FreeFunc = FreeFunc;
    item->data = data;
    item->name = name;
    item->id = de_ctx->keyword_id++;

    if (HashListTableAdd(de_ctx->keyword_hash, (void *)item, 0) < 0) {
        SCFree(item);
        return -1;
    }
    return item->id;
}

/** \brief Remove Thread keyword context registration
 *
 *  \param de_ctx detection engine to deregister from
 *  \param det_ctx detection engine thread context to deregister from
 *  \param data keyword init data to pass to Func. Can be NULL.
 *  \param name keyword name for error printing
 *
 *  \retval 1 Item unregistered
 *  \retval 0 otherwise
 *
 *  \note make sure "data" remains valid and it free'd elsewhere. It's
 *        recommended to store it in the keywords global ctx so that
 *        it's freed when the de_ctx is freed.
 */
int DetectUnregisterThreadCtxFuncs(DetectEngineCtx *de_ctx, void *data, const char *name)
{
    /* might happen if we call this before a call to *Register* */
    if (de_ctx->keyword_hash == NULL)
        return 1;
    DetectEngineThreadKeywordCtxItem remove = { .data = data, .name = name };
    if (HashListTableRemove(de_ctx->keyword_hash, (void *)&remove, 0) == 0)
        return 1;
    return 0;
}
/** \brief Retrieve thread local keyword ctx by id
 *
 *  \param det_ctx detection engine thread ctx to retrieve the ctx from
 *  \param id id of the ctx returned by DetectRegisterThreadCtxInitFunc at
 *            keyword init.
 *
 *  \retval ctx or NULL on error
 */
void *DetectThreadCtxGetKeywordThreadCtx(DetectEngineThreadCtx *det_ctx, int id)
{
    if (id < 0 || id > det_ctx->keyword_ctxs_size || det_ctx->keyword_ctxs_array == NULL)
        return NULL;

    return det_ctx->keyword_ctxs_array[id];
}


/** \brief Register Thread keyword context Funcs (Global)
 *
 *  IDs stay static over reloads and between tenants
 *
 *  \param name keyword name for error printing
 *  \param InitFunc function ptr
 *  \param FreeFunc function ptr
 *
 *  \retval id for retrieval of ctx at runtime
 *  \retval -1 on error
 */
int DetectRegisterThreadCtxGlobalFuncs(const char *name,
        void *(*InitFunc)(void *), void *data, void (*FreeFunc)(void *))
{
    int id;
    BUG_ON(InitFunc == NULL || FreeFunc == NULL);

    DetectEngineMasterCtx *master = &g_master_de_ctx;

    /* if already registered, return existing id */
    DetectEngineThreadKeywordCtxItem *item = master->keyword_list;
    while (item != NULL) {
        if (strcmp(name, item->name) == 0) {
            id = item->id;
            return id;
        }

        item = item->next;
    }

    item = SCCalloc(1, sizeof(*item));
    if (unlikely(item == NULL)) {
        return -1;
    }
    item->InitFunc = InitFunc;
    item->FreeFunc = FreeFunc;
    item->name = name;
    item->data = data;

    item->next = master->keyword_list;
    master->keyword_list = item;
    item->id = master->keyword_id++;

    id = item->id;
    return id;
}

/** \brief Retrieve thread local keyword ctx by id
 *
 *  \param det_ctx detection engine thread ctx to retrieve the ctx from
 *  \param id id of the ctx returned by DetectRegisterThreadCtxInitFunc at
 *            keyword init.
 *
 *  \retval ctx or NULL on error
 */
void *DetectThreadCtxGetGlobalKeywordThreadCtx(DetectEngineThreadCtx *det_ctx, int id)
{
    if (id < 0 || id > det_ctx->global_keyword_ctxs_size ||
        det_ctx->global_keyword_ctxs_array == NULL) {
        return NULL;
    }

    return det_ctx->global_keyword_ctxs_array[id];
}

/** \brief Check if detection is enabled
 *  \retval bool true or false */
int DetectEngineEnabled(void)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);

    if (master->list == NULL) {
        SCMutexUnlock(&master->lock);
        return 0;
    }

    SCMutexUnlock(&master->lock);
    return 1;
}

uint32_t DetectEngineGetVersion(void)
{
    uint32_t version;
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);
    version = master->version;
    SCMutexUnlock(&master->lock);
    return version;
}

void DetectEngineBumpVersion(void)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);
    master->version++;
    SCLogDebug("master version now %u", master->version);
    SCMutexUnlock(&master->lock);
}

DetectEngineCtx *DetectEngineGetCurrent(void)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);

    DetectEngineCtx *de_ctx = master->list;
    while (de_ctx) {
        if (de_ctx->type == DETECT_ENGINE_TYPE_NORMAL ||
            de_ctx->type == DETECT_ENGINE_TYPE_DD_STUB ||
            de_ctx->type == DETECT_ENGINE_TYPE_MT_STUB)
        {
            de_ctx->ref_cnt++;
            SCLogDebug("de_ctx %p ref_cnt %u", de_ctx, de_ctx->ref_cnt);
            SCMutexUnlock(&master->lock);
            return de_ctx;
        }
        de_ctx = de_ctx->next;
    }

    SCMutexUnlock(&master->lock);
    return NULL;
}

DetectEngineCtx *DetectEngineReference(DetectEngineCtx *de_ctx)
{
    if (de_ctx == NULL)
        return NULL;
    de_ctx->ref_cnt++;
    return de_ctx;
}

/** TODO locking? Not needed if this is a one time setting at startup */
int DetectEngineMultiTenantEnabled(void)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    return (master->multi_tenant_enabled);
}

/** \internal
 *  \brief load a tenant from a yaml file
 *
 *  \param tenant_id the tenant id by which the config is known
 *  \param filename full path of a yaml file
 *  \param loader_id id of loader thread or -1
 *
 *  \retval 0 ok
 *  \retval -1 failed
 */
static int DetectEngineMultiTenantLoadTenant(uint32_t tenant_id, const char *filename, int loader_id)
{
    DetectEngineCtx *de_ctx = NULL;
    char prefix[64];

    snprintf(prefix, sizeof(prefix), "multi-detect.%u", tenant_id);

#ifdef OS_WIN32
    struct _stat st;
    if(_stat(filename, &st) != 0) {
#else
    struct stat st;
    if(stat(filename, &st) != 0) {
#endif /* OS_WIN32 */
        SCLogError(SC_ERR_FOPEN, "failed to stat file %s", filename);
        goto error;
    }

    de_ctx = DetectEngineGetByTenantId(tenant_id);
    if (de_ctx != NULL) {
        SCLogError(SC_ERR_MT_DUPLICATE_TENANT, "tenant %u already registered",
                tenant_id);
        DetectEngineDeReference(&de_ctx);
        goto error;
    }

    ConfNode *node = ConfGetNode(prefix);
    if (node == NULL) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "failed to properly setup yaml %s", filename);
        goto error;
    }

    de_ctx = DetectEngineCtxInitWithPrefix(prefix);
    if (de_ctx == NULL) {
        SCLogError(SC_ERR_INITIALIZATION, "initializing detection engine "
                "context failed.");
        goto error;
    }
    SCLogDebug("de_ctx %p with prefix %s", de_ctx, de_ctx->config_prefix);

    de_ctx->type = DETECT_ENGINE_TYPE_TENANT;
    de_ctx->tenant_id = tenant_id;
    de_ctx->loader_id = loader_id;

    if (SigLoadSignatures(de_ctx, NULL, 0) < 0) {
        SCLogError(SC_ERR_NO_RULES_LOADED, "Loading signatures failed.");
        goto error;
    }

    DetectEngineAddToMaster(de_ctx);

    return 0;

error:
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }
    return -1;
}

static int DetectEngineMultiTenantReloadTenant(uint32_t tenant_id, const char *filename, int reload_cnt)
{
    DetectEngineCtx *old_de_ctx = DetectEngineGetByTenantId(tenant_id);
    if (old_de_ctx == NULL) {
        SCLogError(SC_ERR_INITIALIZATION, "tenant detect engine not found");
        return -1;
    }

    char prefix[64];
    snprintf(prefix, sizeof(prefix), "multi-detect.%u.reload.%d", tenant_id, reload_cnt);
    reload_cnt++;
    SCLogDebug("prefix %s", prefix);

    if (ConfYamlLoadFileWithPrefix(filename, prefix) != 0) {
        SCLogError(SC_ERR_INITIALIZATION,"failed to load yaml");
        goto error;
    }

    ConfNode *node = ConfGetNode(prefix);
    if (node == NULL) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "failed to properly setup yaml %s", filename);
        goto error;
    }

    DetectEngineCtx *new_de_ctx = DetectEngineCtxInitWithPrefix(prefix);
    if (new_de_ctx == NULL) {
        SCLogError(SC_ERR_INITIALIZATION, "initializing detection engine "
                "context failed.");
        goto error;
    }
    SCLogDebug("de_ctx %p with prefix %s", new_de_ctx, new_de_ctx->config_prefix);

    new_de_ctx->type = DETECT_ENGINE_TYPE_TENANT;
    new_de_ctx->tenant_id = tenant_id;
    new_de_ctx->loader_id = old_de_ctx->loader_id;

    if (SigLoadSignatures(new_de_ctx, NULL, 0) < 0) {
        SCLogError(SC_ERR_NO_RULES_LOADED, "Loading signatures failed.");
        goto error;
    }

    DetectEngineAddToMaster(new_de_ctx);

    /* move to free list */
    DetectEngineMoveToFreeList(old_de_ctx);
    DetectEngineDeReference(&old_de_ctx);
    return 0;

error:
    DetectEngineDeReference(&old_de_ctx);
    return -1;
}


typedef struct TenantLoaderCtx_ {
    uint32_t tenant_id;
    int reload_cnt; /**< used by reload */
    const char *yaml;
} TenantLoaderCtx;

static int DetectLoaderFuncLoadTenant(void *vctx, int loader_id)
{
    TenantLoaderCtx *ctx = (TenantLoaderCtx *)vctx;

    SCLogDebug("loader %d", loader_id);
    if (DetectEngineMultiTenantLoadTenant(ctx->tenant_id, ctx->yaml, loader_id) != 0) {
        return -1;
    }
    return 0;
}

static int DetectLoaderSetupLoadTenant(uint32_t tenant_id, const char *yaml)
{
    TenantLoaderCtx *t = SCCalloc(1, sizeof(*t));
    if (t == NULL)
        return -ENOMEM;

    t->tenant_id = tenant_id;
    t->yaml = yaml;

    return DetectLoaderQueueTask(-1, DetectLoaderFuncLoadTenant, t);
}

static int DetectLoaderFuncReloadTenant(void *vctx, int loader_id)
{
    TenantLoaderCtx *ctx = (TenantLoaderCtx *)vctx;

    SCLogDebug("loader_id %d", loader_id);

    if (DetectEngineMultiTenantReloadTenant(ctx->tenant_id, ctx->yaml, ctx->reload_cnt) != 0) {
        return -1;
    }
    return 0;
}

static int DetectLoaderSetupReloadTenant(uint32_t tenant_id, const char *yaml, int reload_cnt)
{
    DetectEngineCtx *old_de_ctx = DetectEngineGetByTenantId(tenant_id);
    if (old_de_ctx == NULL)
        return -ENOENT;
    int loader_id = old_de_ctx->loader_id;
    DetectEngineDeReference(&old_de_ctx);

    TenantLoaderCtx *t = SCCalloc(1, sizeof(*t));
    if (t == NULL)
        return -ENOMEM;

    t->tenant_id = tenant_id;
    t->yaml = yaml;
    t->reload_cnt = reload_cnt;

    SCLogDebug("loader_id %d", loader_id);

    return DetectLoaderQueueTask(loader_id, DetectLoaderFuncReloadTenant, t);
}

/** \brief Load a tenant and wait for loading to complete
 */
int DetectEngineLoadTenantBlocking(uint32_t tenant_id, const char *yaml)
{
    int r = DetectLoaderSetupLoadTenant(tenant_id, yaml);
    if (r < 0)
        return r;

    if (DetectLoadersSync() != 0)
        return -1;

    return 0;
}

/** \brief Reload a tenant and wait for loading to complete
 */
int DetectEngineReloadTenantBlocking(uint32_t tenant_id, const char *yaml, int reload_cnt)
{
    int r = DetectLoaderSetupReloadTenant(tenant_id, yaml, reload_cnt);
    if (r < 0)
        return r;

    if (DetectLoadersSync() != 0)
        return -1;

    return 0;
}

static int DetectEngineMultiTenantSetupLoadLivedevMappings(const ConfNode *mappings_root_node,
        bool failure_fatal)
{
    ConfNode *mapping_node = NULL;

    int mapping_cnt = 0;
    if (mappings_root_node != NULL) {
        TAILQ_FOREACH(mapping_node, &mappings_root_node->head, next) {
            ConfNode *tenant_id_node = ConfNodeLookupChild(mapping_node, "tenant-id");
            if (tenant_id_node == NULL)
                goto bad_mapping;
            ConfNode *device_node = ConfNodeLookupChild(mapping_node, "device");
            if (device_node == NULL)
                goto bad_mapping;

            uint32_t tenant_id = 0;
            if (StringParseUint32(&tenant_id, 10, (uint16_t)strlen(tenant_id_node->val),
                        tenant_id_node->val) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "tenant-id  "
                        "of %s is invalid", tenant_id_node->val);
                goto bad_mapping;
            }

            const char *dev = device_node->val;
            LiveDevice *ld = LiveGetDevice(dev);
            if (ld == NULL) {
                SCLogWarning(SC_ERR_MT_NO_MAPPING, "device %s not found", dev);
                goto bad_mapping;
            }

            if (ld->tenant_id_set) {
                SCLogWarning(SC_ERR_MT_NO_MAPPING, "device %s already mapped to tenant-id %u",
                        dev, ld->tenant_id);
                goto bad_mapping;
            }

            ld->tenant_id = tenant_id;
            ld->tenant_id_set = true;

            if (DetectEngineTentantRegisterLivedev(tenant_id, ld->id) != 0) {
                goto error;
            }

            SCLogConfig("device %s connected to tenant-id %u", dev, tenant_id);
            mapping_cnt++;
            continue;

        bad_mapping:
            if (failure_fatal)
                goto error;
        }
    }
    SCLogConfig("%d device - tenant-id mappings defined", mapping_cnt);
    return mapping_cnt;

error:
    return 0;
}

static int DetectEngineMultiTenantSetupLoadVlanMappings(const ConfNode *mappings_root_node,
        bool failure_fatal)
{
    ConfNode *mapping_node = NULL;

    int mapping_cnt = 0;
    if (mappings_root_node != NULL) {
        TAILQ_FOREACH(mapping_node, &mappings_root_node->head, next) {
            ConfNode *tenant_id_node = ConfNodeLookupChild(mapping_node, "tenant-id");
            if (tenant_id_node == NULL)
                goto bad_mapping;
            ConfNode *vlan_id_node = ConfNodeLookupChild(mapping_node, "vlan-id");
            if (vlan_id_node == NULL)
                goto bad_mapping;

            uint32_t tenant_id = 0;
            if (StringParseUint32(&tenant_id, 10, (uint16_t)strlen(tenant_id_node->val),
                        tenant_id_node->val) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "tenant-id  "
                        "of %s is invalid", tenant_id_node->val);
                goto bad_mapping;
            }

            uint16_t vlan_id = 0;
            if (StringParseUint16(
                        &vlan_id, 10, (uint16_t)strlen(vlan_id_node->val), vlan_id_node->val) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "vlan-id  "
                        "of %s is invalid", vlan_id_node->val);
                goto bad_mapping;
            }
            if (vlan_id == 0 || vlan_id >= 4095) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "vlan-id  "
                        "of %s is invalid. Valid range 1-4094.", vlan_id_node->val);
                goto bad_mapping;
            }

            if (DetectEngineTentantRegisterVlanId(tenant_id, vlan_id) != 0) {
                goto error;
            }
            SCLogConfig("vlan %u connected to tenant-id %u", vlan_id, tenant_id);
            mapping_cnt++;
            continue;

        bad_mapping:
            if (failure_fatal)
                goto error;
        }
    }
    return mapping_cnt;

error:
    return 0;
}

/**
 *  \brief setup multi-detect / multi-tenancy
 *
 *  See if MT is enabled. If so, setup the selector, tenants and mappings.
 *  Tenants and mappings are optional, and can also dynamically be added
 *  and removed from the unix socket.
 */
int DetectEngineMultiTenantSetup(void)
{
    enum DetectEngineTenantSelectors tenant_selector = TENANT_SELECTOR_UNKNOWN;
    DetectEngineMasterCtx *master = &g_master_de_ctx;

    int unix_socket = ConfUnixSocketIsEnable();

    int failure_fatal = 0;
    (void)ConfGetBool("engine.init-failure-fatal", &failure_fatal);

    int enabled = 0;
    (void)ConfGetBool("multi-detect.enabled", &enabled);
    if (enabled == 1) {
        DetectLoadersInit();
        TmModuleDetectLoaderRegister();
        DetectLoaderThreadSpawn();
        TmThreadContinueDetectLoaderThreads();

        SCMutexLock(&master->lock);
        master->multi_tenant_enabled = 1;

        const char *handler = NULL;
        if (ConfGet("multi-detect.selector", &handler) == 1) {
            SCLogConfig("multi-tenant selector type %s", handler);

            if (strcmp(handler, "vlan") == 0) {
                tenant_selector = master->tenant_selector = TENANT_SELECTOR_VLAN;

                int vlanbool = 0;
                if ((ConfGetBool("vlan.use-for-tracking", &vlanbool)) == 1 && vlanbool == 0) {
                    SCLogError(SC_ERR_INVALID_VALUE, "vlan tracking is disabled, "
                            "can't use multi-detect selector 'vlan'");
                    SCMutexUnlock(&master->lock);
                    goto error;
                }

            } else if (strcmp(handler, "direct") == 0) {
                tenant_selector = master->tenant_selector = TENANT_SELECTOR_DIRECT;
            } else if (strcmp(handler, "device") == 0) {
                tenant_selector = master->tenant_selector = TENANT_SELECTOR_LIVEDEV;
                if (EngineModeIsIPS()) {
                    SCLogWarning(SC_ERR_MT_NO_MAPPING,
                            "multi-tenant 'device' mode not supported for IPS");
                    SCMutexUnlock(&master->lock);
                    goto error;
                }

            } else {
                SCLogError(SC_ERR_INVALID_VALUE, "unknown value %s "
                                                 "multi-detect.selector", handler);
                SCMutexUnlock(&master->lock);
                goto error;
            }
        }
        SCMutexUnlock(&master->lock);
        SCLogConfig("multi-detect is enabled (multi tenancy). Selector: %s", handler);

        /* traffic -- tenant mappings */
        ConfNode *mappings_root_node = ConfGetNode("multi-detect.mappings");

        if (tenant_selector == TENANT_SELECTOR_VLAN) {
            int mapping_cnt = DetectEngineMultiTenantSetupLoadVlanMappings(mappings_root_node,
                    failure_fatal);
            if (mapping_cnt == 0) {
                /* no mappings are valid when we're in unix socket mode,
                 * they can be added on the fly. Otherwise warn/error
                 * depending on failure_fatal */

                if (unix_socket) {
                    SCLogNotice("no tenant traffic mappings defined, "
                            "tenants won't be used until mappings are added");
                } else {
                    if (failure_fatal) {
                        SCLogError(SC_ERR_MT_NO_MAPPING, "no multi-detect mappings defined");
                        goto error;
                    } else {
                        SCLogWarning(SC_ERR_MT_NO_MAPPING, "no multi-detect mappings defined");
                    }
                }
            }
        } else if (tenant_selector == TENANT_SELECTOR_LIVEDEV) {
            int mapping_cnt = DetectEngineMultiTenantSetupLoadLivedevMappings(mappings_root_node,
                    failure_fatal);
            if (mapping_cnt == 0) {
                if (failure_fatal) {
                    SCLogError(SC_ERR_MT_NO_MAPPING, "no multi-detect mappings defined");
                    goto error;
                } else {
                    SCLogWarning(SC_ERR_MT_NO_MAPPING, "no multi-detect mappings defined");
                }
            }
        }

        /* tenants */
        ConfNode *tenants_root_node = ConfGetNode("multi-detect.tenants");
        ConfNode *tenant_node = NULL;

        if (tenants_root_node != NULL) {
            TAILQ_FOREACH(tenant_node, &tenants_root_node->head, next) {
                ConfNode *id_node = ConfNodeLookupChild(tenant_node, "id");
                if (id_node == NULL) {
                    goto bad_tenant;
                }
                ConfNode *yaml_node = ConfNodeLookupChild(tenant_node, "yaml");
                if (yaml_node == NULL) {
                    goto bad_tenant;
                }

                uint32_t tenant_id = 0;
                if (StringParseUint32(
                            &tenant_id, 10, (uint16_t)strlen(id_node->val), id_node->val) < 0) {
                    SCLogError(SC_ERR_INVALID_ARGUMENT, "tenant_id  "
                            "of %s is invalid", id_node->val);
                    goto bad_tenant;
                }
                SCLogDebug("tenant id: %u, %s", tenant_id, yaml_node->val);

                /* setup the yaml in this loop so that it's not done by the loader
                 * threads. ConfYamlLoadFileWithPrefix is not thread safe. */
                char prefix[64];
                snprintf(prefix, sizeof(prefix), "multi-detect.%u", tenant_id);
                if (ConfYamlLoadFileWithPrefix(yaml_node->val, prefix) != 0) {
                    SCLogError(SC_ERR_CONF_YAML_ERROR, "failed to load yaml %s", yaml_node->val);
                    goto bad_tenant;
                }

                int r = DetectLoaderSetupLoadTenant(tenant_id, yaml_node->val);
                if (r < 0) {
                    /* error logged already */
                    goto bad_tenant;
                }
                continue;

            bad_tenant:
                if (failure_fatal)
                    goto error;
            }
        }

        /* wait for our loaders to complete their tasks */
        if (DetectLoadersSync() != 0) {
            goto error;
        }

        VarNameStoreActivateStaging();

    } else {
        SCLogDebug("multi-detect not enabled (multi tenancy)");
    }
    return 0;
error:
    return -1;
}

static uint32_t DetectEngineTentantGetIdFromVlanId(const void *ctx, const Packet *p)
{
    const DetectEngineThreadCtx *det_ctx = ctx;
    uint32_t x = 0;
    uint32_t vlan_id = 0;

    if (p->vlan_idx == 0)
        return 0;

    vlan_id = p->vlan_id[0];

    if (det_ctx == NULL || det_ctx->tenant_array == NULL || det_ctx->tenant_array_size == 0)
        return 0;

    /* not very efficient, but for now we're targeting only limited amounts.
     * Can use hash/tree approach later. */
    for (x = 0; x < det_ctx->tenant_array_size; x++) {
        if (det_ctx->tenant_array[x].traffic_id == vlan_id)
            return det_ctx->tenant_array[x].tenant_id;
    }

    return 0;
}

static uint32_t DetectEngineTentantGetIdFromLivedev(const void *ctx, const Packet *p)
{
    const DetectEngineThreadCtx *det_ctx = ctx;
    const LiveDevice *ld = p->livedev;

    if (ld == NULL || det_ctx == NULL)
        return 0;

    SCLogDebug("using tenant-id %u for packet on device %s", ld->tenant_id, ld->dev);
    return ld->tenant_id;
}

static int DetectEngineTentantRegisterSelector(enum DetectEngineTenantSelectors selector,
                                           uint32_t tenant_id, uint32_t traffic_id)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);

    if (!(master->tenant_selector == TENANT_SELECTOR_UNKNOWN || master->tenant_selector == selector)) {
        SCLogInfo("conflicting selector already set");
        SCMutexUnlock(&master->lock);
        return -1;
    }

    DetectEngineTenantMapping *m = master->tenant_mapping_list;
    while (m) {
        if (m->traffic_id == traffic_id) {
            SCLogInfo("traffic id already registered");
            SCMutexUnlock(&master->lock);
            return -1;
        }
        m = m->next;
    }

    DetectEngineTenantMapping *map = SCCalloc(1, sizeof(*map));
    if (map == NULL) {
        SCLogInfo("memory fail");
        SCMutexUnlock(&master->lock);
        return -1;
    }
    map->traffic_id = traffic_id;
    map->tenant_id = tenant_id;

    map->next = master->tenant_mapping_list;
    master->tenant_mapping_list = map;

    master->tenant_selector = selector;

    SCLogDebug("tenant handler %u %u %u registered", selector, tenant_id, traffic_id);
    SCMutexUnlock(&master->lock);
    return 0;
}

static int DetectEngineTentantUnregisterSelector(enum DetectEngineTenantSelectors selector,
                                           uint32_t tenant_id, uint32_t traffic_id)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);

    if (master->tenant_mapping_list == NULL) {
        SCMutexUnlock(&master->lock);
        return -1;
    }

    DetectEngineTenantMapping *prev = NULL;
    DetectEngineTenantMapping *map = master->tenant_mapping_list;
    while (map) {
        if (map->traffic_id == traffic_id &&
            map->tenant_id == tenant_id)
        {
            if (prev != NULL)
                prev->next = map->next;
            else
                master->tenant_mapping_list = map->next;

            map->next = NULL;
            SCFree(map);
            SCLogInfo("tenant handler %u %u %u unregistered", selector, tenant_id, traffic_id);
            SCMutexUnlock(&master->lock);
            return 0;
        }
        prev = map;
        map = map->next;
    }

    SCMutexUnlock(&master->lock);
    return -1;
}

int DetectEngineTentantRegisterLivedev(uint32_t tenant_id, int device_id)
{
    return DetectEngineTentantRegisterSelector(TENANT_SELECTOR_LIVEDEV, tenant_id, (uint32_t)device_id);
}

int DetectEngineTentantRegisterVlanId(uint32_t tenant_id, uint16_t vlan_id)
{
    return DetectEngineTentantRegisterSelector(TENANT_SELECTOR_VLAN, tenant_id, (uint32_t)vlan_id);
}

int DetectEngineTentantUnregisterVlanId(uint32_t tenant_id, uint16_t vlan_id)
{
    return DetectEngineTentantUnregisterSelector(TENANT_SELECTOR_VLAN, tenant_id, (uint32_t)vlan_id);
}

int DetectEngineTentantRegisterPcapFile(uint32_t tenant_id)
{
    SCLogInfo("registering %u %d 0", TENANT_SELECTOR_DIRECT, tenant_id);
    return DetectEngineTentantRegisterSelector(TENANT_SELECTOR_DIRECT, tenant_id, 0);
}

int DetectEngineTentantUnregisterPcapFile(uint32_t tenant_id)
{
    SCLogInfo("unregistering %u %d 0", TENANT_SELECTOR_DIRECT, tenant_id);
    return DetectEngineTentantUnregisterSelector(TENANT_SELECTOR_DIRECT, tenant_id, 0);
}

static uint32_t DetectEngineTentantGetIdFromPcap(const void *ctx, const Packet *p)
{
    return p->pcap_v.tenant_id;
}

DetectEngineCtx *DetectEngineGetByTenantId(uint32_t tenant_id)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);

    if (master->list == NULL) {
        SCMutexUnlock(&master->lock);
        return NULL;
    }

    DetectEngineCtx *de_ctx = master->list;
    while (de_ctx) {
        if (de_ctx->type == DETECT_ENGINE_TYPE_TENANT &&
                de_ctx->tenant_id == tenant_id)
        {
            de_ctx->ref_cnt++;
            break;
        }

        de_ctx = de_ctx->next;
    }

    SCMutexUnlock(&master->lock);
    return de_ctx;
}

void DetectEngineDeReference(DetectEngineCtx **de_ctx)
{
    BUG_ON((*de_ctx)->ref_cnt == 0);
    (*de_ctx)->ref_cnt--;
    *de_ctx = NULL;
}

static int DetectEngineAddToList(DetectEngineCtx *instance)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;

    if (instance == NULL)
        return -1;

    if (master->list == NULL) {
        master->list = instance;
    } else {
        instance->next = master->list;
        master->list = instance;
    }

    return 0;
}

int DetectEngineAddToMaster(DetectEngineCtx *de_ctx)
{
    int r;

    if (de_ctx == NULL)
        return -1;

    SCLogDebug("adding de_ctx %p to master", de_ctx);

    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);
    r = DetectEngineAddToList(de_ctx);
    SCMutexUnlock(&master->lock);
    return r;
}

int DetectEngineMoveToFreeList(DetectEngineCtx *de_ctx)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;

    SCMutexLock(&master->lock);
    DetectEngineCtx *instance = master->list;
    if (instance == NULL) {
        SCMutexUnlock(&master->lock);
        return -1;
    }

    /* remove from active list */
    if (instance == de_ctx) {
        master->list = instance->next;
    } else {
        DetectEngineCtx *prev = instance;
        instance = instance->next; /* already checked first element */

        while (instance) {
            DetectEngineCtx *next = instance->next;

            if (instance == de_ctx) {
                prev->next = instance->next;
                break;
            }

            prev = instance;
            instance = next;
        }
        if (instance == NULL) {
            SCMutexUnlock(&master->lock);
            return -1;
        }
    }

    /* instance is now detached from list */
    instance->next = NULL;

    /* add to free list */
    if (master->free_list == NULL) {
        master->free_list = instance;
    } else {
        instance->next = master->free_list;
        master->free_list = instance;
    }
    SCLogDebug("detect engine %p moved to free list (%u refs)", de_ctx, de_ctx->ref_cnt);

    SCMutexUnlock(&master->lock);
    return 0;
}

void DetectEnginePruneFreeList(void)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);

    DetectEngineCtx *prev = NULL;
    DetectEngineCtx *instance = master->free_list;
    while (instance) {
        DetectEngineCtx *next = instance->next;

        SCLogDebug("detect engine %p has %u ref(s)", instance, instance->ref_cnt);

        if (instance->ref_cnt == 0) {
            if (prev == NULL) {
                master->free_list = next;
            } else {
                prev->next = next;
            }

            SCLogDebug("freeing detect engine %p", instance);
            DetectEngineCtxFree(instance);
            instance = NULL;
        }

        prev = instance;
        instance = next;
    }
    SCMutexUnlock(&master->lock);
}

static int reloads = 0;

/** \brief Reload the detection engine
 *
 *  \param filename YAML file to load for the detect config
 *
 *  \retval -1 error
 *  \retval 0 ok
 */
int DetectEngineReload(const SCInstance *suri)
{
    DetectEngineCtx *new_de_ctx = NULL;
    DetectEngineCtx *old_de_ctx = NULL;

    char prefix[128];
    memset(prefix, 0, sizeof(prefix));

    SCLogNotice("rule reload starting");

    if (suri->conf_filename != NULL) {
        snprintf(prefix, sizeof(prefix), "detect-engine-reloads.%d", reloads++);
        if (ConfYamlLoadFileWithPrefix(suri->conf_filename, prefix) != 0) {
            SCLogError(SC_ERR_CONF_YAML_ERROR, "failed to load yaml %s",
                    suri->conf_filename);
            return -1;
        }

        ConfNode *node = ConfGetNode(prefix);
        if (node == NULL) {
            SCLogError(SC_ERR_CONF_YAML_ERROR, "failed to properly setup yaml %s",
                    suri->conf_filename);
            return -1;
        }
#if 0
        ConfDump();
#endif
    }

    /* get a reference to the current de_ctx */
    old_de_ctx = DetectEngineGetCurrent();
    if (old_de_ctx == NULL)
        return -1;
    SCLogDebug("get ref to old_de_ctx %p", old_de_ctx);
    DatasetReload();

    /* only reload a regular 'normal' and 'delayed detect stub' detect engines */
    if (!(old_de_ctx->type == DETECT_ENGINE_TYPE_NORMAL ||
          old_de_ctx->type == DETECT_ENGINE_TYPE_DD_STUB))
    {
        DetectEngineDeReference(&old_de_ctx);
        SCLogNotice("rule reload complete");
        return -1;
    }

    /* get new detection engine */
    new_de_ctx = DetectEngineCtxInitWithPrefix(prefix);
    if (new_de_ctx == NULL) {
        SCLogError(SC_ERR_INITIALIZATION, "initializing detection engine "
                "context failed.");
        DetectEngineDeReference(&old_de_ctx);
        return -1;
    }
    if (SigLoadSignatures(new_de_ctx,
                          suri->sig_file, suri->sig_file_exclusive) != 0) {
        DetectEngineCtxFree(new_de_ctx);
        DetectEngineDeReference(&old_de_ctx);
        return -1;
    }
    SCLogDebug("set up new_de_ctx %p", new_de_ctx);

    /* add to master */
    DetectEngineAddToMaster(new_de_ctx);

    /* move to old free list */
    DetectEngineMoveToFreeList(old_de_ctx);
    DetectEngineDeReference(&old_de_ctx);

    SCLogDebug("going to reload the threads to use new_de_ctx %p", new_de_ctx);
    /* update the threads */
    DetectEngineReloadThreads(new_de_ctx);
    SCLogDebug("threads now run new_de_ctx %p", new_de_ctx);

    /* walk free list, freeing the old_de_ctx */
    DetectEnginePruneFreeList();

    DatasetPostReloadCleanup();

    DetectEngineBumpVersion();

    SCLogDebug("old_de_ctx should have been freed");

    SCLogNotice("rule reload complete");
    return 0;
}

static uint32_t TenantIdHash(HashTable *h, void *data, uint16_t data_len)
{
    DetectEngineThreadCtx *det_ctx = (DetectEngineThreadCtx *)data;
    return det_ctx->tenant_id % h->array_size;
}

static char TenantIdCompare(void *d1, uint16_t d1_len, void *d2, uint16_t d2_len)
{
    DetectEngineThreadCtx *det1 = (DetectEngineThreadCtx *)d1;
    DetectEngineThreadCtx *det2 = (DetectEngineThreadCtx *)d2;
    return (det1->tenant_id == det2->tenant_id);
}

static void TenantIdFree(void *d)
{
    DetectEngineThreadCtxFree(d);
}

int DetectEngineMTApply(void)
{
    DetectEngineMasterCtx *master = &g_master_de_ctx;
    SCMutexLock(&master->lock);

    if (master->tenant_selector == TENANT_SELECTOR_UNKNOWN) {
        SCLogInfo("error, no tenant selector");
        SCMutexUnlock(&master->lock);
        return -1;
    }

    DetectEngineCtx *stub_de_ctx = NULL;
    DetectEngineCtx *list = master->list;
    for ( ; list != NULL; list = list->next) {
        SCLogDebug("list %p tenant %u", list, list->tenant_id);

        if (list->type == DETECT_ENGINE_TYPE_NORMAL ||
            list->type == DETECT_ENGINE_TYPE_MT_STUB ||
            list->type == DETECT_ENGINE_TYPE_DD_STUB)
        {
            stub_de_ctx = list;
            break;
        }
    }
    if (stub_de_ctx == NULL) {
        stub_de_ctx = DetectEngineCtxInitStubForMT();
        if (stub_de_ctx == NULL) {
            SCMutexUnlock(&master->lock);
            return -1;
        }

        if (master->list == NULL) {
            master->list = stub_de_ctx;
        } else {
            stub_de_ctx->next = master->list;
            master->list = stub_de_ctx;
        }
    }

    /* update the threads */
    SCLogDebug("MT reload starting");
    DetectEngineReloadThreads(stub_de_ctx);
    SCLogDebug("MT reload done");

    SCMutexUnlock(&master->lock);

    /* walk free list, freeing the old_de_ctx */
    DetectEnginePruneFreeList();

    SCLogDebug("old_de_ctx should have been freed");
    return 0;
}

static int g_parse_metadata = 0;

void DetectEngineSetParseMetadata(void)
{
    g_parse_metadata = 1;
}

void DetectEngineUnsetParseMetadata(void)
{
    g_parse_metadata = 0;
}

int DetectEngineMustParseMetadata(void)
{
    return g_parse_metadata;
}

const char *DetectSigmatchListEnumToString(enum DetectSigmatchListEnum type)
{
    switch (type) {
        case DETECT_SM_LIST_MATCH:
            return "packet";
        case DETECT_SM_LIST_PMATCH:
            return "packet/stream payload";

        case DETECT_SM_LIST_TMATCH:
            return "tag";

        case DETECT_SM_LIST_BASE64_DATA:
            return "base64_data";

        case DETECT_SM_LIST_POSTMATCH:
            return "post-match";

        case DETECT_SM_LIST_SUPPRESS:
            return "suppress";
        case DETECT_SM_LIST_THRESHOLD:
            return "threshold";

        case DETECT_SM_LIST_MAX:
            return "max (internal)";
    }
    return "error";
}

/* events api */
void DetectEngineSetEvent(DetectEngineThreadCtx *det_ctx, uint8_t e)
{
    AppLayerDecoderEventsSetEventRaw(&det_ctx->decoder_events, e);
    det_ctx->events++;
}

AppLayerDecoderEvents *DetectEngineGetEvents(DetectEngineThreadCtx *det_ctx)
{
    return det_ctx->decoder_events;
}

int DetectEngineGetEventInfo(const char *event_name, int *event_id,
                             AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, det_ctx_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "det_ctx's enum map table.",  event_name);
        /* this should be treated as fatal */
        return -1;
    }
    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

/*************************************Unittest*********************************/

#ifdef UNITTESTS

static int DetectEngineInitYamlConf(const char *conf)
{
    ConfCreateContextBackup();
    ConfInit();
    return ConfYamlLoadString(conf, strlen(conf));
}

static void DetectEngineDeInitYamlConf(void)
{
    ConfDeInit();
    ConfRestoreContextBackup();

    return;
}

static int DetectEngineTest01(void)
{
    const char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: medium\n"
        "  - custom-values:\n"
        "      toclient_src_groups: 2\n"
        "      toclient_dst_groups: 2\n"
        "      toclient_sp_groups: 2\n"
        "      toclient_dp_groups: 3\n"
        "      toserver_src_groups: 2\n"
        "      toserver_dst_groups: 4\n"
        "      toserver_sp_groups: 2\n"
        "      toserver_dp_groups: 25\n"
        "  - inspection-recursion-limit: 0\n";

    FAIL_IF(DetectEngineInitYamlConf(conf) == -1);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FAIL_IF_NOT(de_ctx->inspection_recursion_limit == -1);

    DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    PASS;
}

static int DetectEngineTest02(void)
{
    const char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: medium\n"
        "  - custom-values:\n"
        "      toclient_src_groups: 2\n"
        "      toclient_dst_groups: 2\n"
        "      toclient_sp_groups: 2\n"
        "      toclient_dp_groups: 3\n"
        "      toserver_src_groups: 2\n"
        "      toserver_dst_groups: 4\n"
        "      toserver_sp_groups: 2\n"
        "      toserver_dp_groups: 25\n"
        "  - inspection-recursion-limit:\n";

    FAIL_IF(DetectEngineInitYamlConf(conf) == -1);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FAIL_IF_NOT(
            de_ctx->inspection_recursion_limit == DETECT_ENGINE_DEFAULT_INSPECTION_RECURSION_LIMIT);

    DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    PASS;
}

static int DetectEngineTest03(void)
{
    const char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: medium\n"
        "  - custom-values:\n"
        "      toclient_src_groups: 2\n"
        "      toclient_dst_groups: 2\n"
        "      toclient_sp_groups: 2\n"
        "      toclient_dp_groups: 3\n"
        "      toserver_src_groups: 2\n"
        "      toserver_dst_groups: 4\n"
        "      toserver_sp_groups: 2\n"
        "      toserver_dp_groups: 25\n";

    FAIL_IF(DetectEngineInitYamlConf(conf) == -1);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FAIL_IF_NOT(
            de_ctx->inspection_recursion_limit == DETECT_ENGINE_DEFAULT_INSPECTION_RECURSION_LIMIT);

    DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    PASS;
}

static int DetectEngineTest04(void)
{
    const char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: medium\n"
        "  - custom-values:\n"
        "      toclient_src_groups: 2\n"
        "      toclient_dst_groups: 2\n"
        "      toclient_sp_groups: 2\n"
        "      toclient_dp_groups: 3\n"
        "      toserver_src_groups: 2\n"
        "      toserver_dst_groups: 4\n"
        "      toserver_sp_groups: 2\n"
        "      toserver_dp_groups: 25\n"
        "  - inspection-recursion-limit: 10\n";

    FAIL_IF(DetectEngineInitYamlConf(conf) == -1);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FAIL_IF_NOT(de_ctx->inspection_recursion_limit == 10);

    DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    PASS;
}

static int DetectEngineTest08(void)
{
    const char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: custom\n"
        "  - custom-values:\n"
        "      toclient-groups: 23\n"
        "      toserver-groups: 27\n";

    FAIL_IF(DetectEngineInitYamlConf(conf) == -1);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FAIL_IF_NOT(de_ctx->max_uniq_toclient_groups == 23);
    FAIL_IF_NOT(de_ctx->max_uniq_toserver_groups == 27);

    DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    PASS;
}

/** \test bug 892 bad values */
static int DetectEngineTest09(void)
{
    const char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: custom\n"
        "  - custom-values:\n"
        "      toclient-groups: BA\n"
        "      toserver-groups: BA\n"
        "  - inspection-recursion-limit: 10\n";

    FAIL_IF(DetectEngineInitYamlConf(conf) == -1);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FAIL_IF_NOT(de_ctx->max_uniq_toclient_groups == 20);
    FAIL_IF_NOT(de_ctx->max_uniq_toserver_groups == 40);

    DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    PASS;
}

#endif

void DetectEngineRegisterTests()
{
#ifdef UNITTESTS
    UtRegisterTest("DetectEngineTest01", DetectEngineTest01);
    UtRegisterTest("DetectEngineTest02", DetectEngineTest02);
    UtRegisterTest("DetectEngineTest03", DetectEngineTest03);
    UtRegisterTest("DetectEngineTest04", DetectEngineTest04);
    UtRegisterTest("DetectEngineTest08", DetectEngineTest08);
    UtRegisterTest("DetectEngineTest09", DetectEngineTest09);
#endif
    return;
}
