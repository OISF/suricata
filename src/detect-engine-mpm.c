/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 *
 * Multi pattern matcher
 */

#include "suricata-common.h"
#ifdef DEBUG
#include "util-print.h"
#include "util-debug.h"
#include "util-enum.h"
#include "stream.h"
#include "detect-flow.h"
#include "flow-var.h"
#include "flow.h"
#include "detect-udphdr.h"
#include "detect-tcphdr.h"
#include "conf.h"
#include "util-memcpy.h"
#include "util-mpm.h"
#include "detect-parse.h"
#include "detect-engine-iponly.h"
#include "detect-engine-siggroup.h"
#include "detect.h"
#include "decode.h"
#include "app-layer-protos.h"
#include "suricata.h"
#endif

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "util-memcmp.h"
#include "detect-fast-pattern.h"

#include "detect-content.h"

#include "detect-engine-payload.h"

#include "util-misc.h"
#include "util-validate.h"
#include "util-hash-string.h"

const char *builtin_mpms[] = {
    "toserver TCP packet",
    "toclient TCP packet",
    "toserver TCP stream",
    "toclient TCP stream",
    "toserver UDP packet",
    "toclient UDP packet",
    "other IP packet",

    NULL };

/* Registry for mpm keywords
 *
 * Keywords are registered at engine start up
 */

static DetectBufferMpmRegistery *g_mpm_list[DETECT_BUFFER_MPM_TYPE_SIZE] = { NULL, NULL, NULL };
static int g_mpm_list_cnt[DETECT_BUFFER_MPM_TYPE_SIZE] = { 0, 0, 0 };

/** \brief register a MPM engine
 *
 *  \note to be used at start up / registration only. Errors are fatal.
 */
void DetectAppLayerMpmRegister2(const char *name,
        int direction, int priority,
        int (*PrefilterRegister)(DetectEngineCtx *de_ctx,
            SigGroupHead *sgh, MpmCtx *mpm_ctx,
            const DetectBufferMpmRegistery *mpm_reg, int list_id),
        InspectionBufferGetDataPtr GetData,
        AppProto alproto, int tx_min_progress)
{
    SCLogDebug("registering %s/%d/%d/%p/%p/%u/%d", name, direction, priority,
            PrefilterRegister, GetData, alproto, tx_min_progress);

    BUG_ON(tx_min_progress >= 48);

    if (PrefilterRegister == PrefilterGenericMpmRegister && GetData == NULL) {
        // must register GetData with PrefilterGenericMpmRegister
        abort();
    }

    DetectBufferTypeSupportsMpm(name);
    DetectBufferTypeSupportsTransformations(name);
    int sm_list = DetectBufferTypeGetByName(name);
    if (sm_list == -1) {
        FatalError(SC_ERR_INITIALIZATION,
                "MPM engine registration for %s failed", name);
    }

    DetectBufferMpmRegistery *am = SCCalloc(1, sizeof(*am));
    BUG_ON(am == NULL);
    am->name = name;
    snprintf(am->pname, sizeof(am->pname), "%s", am->name);
    am->direction = direction;
    DEBUG_VALIDATE_BUG_ON(sm_list < 0 || sm_list > INT16_MAX);
    am->sm_list = (int16_t)sm_list;
    am->sm_list_base = (int16_t)sm_list;
    am->priority = priority;
    am->type = DETECT_BUFFER_MPM_TYPE_APP;

    am->PrefilterRegisterWithListId = PrefilterRegister;
    am->app_v2.GetData = GetData;
    am->app_v2.alproto = alproto;
    am->app_v2.tx_min_progress = tx_min_progress;

    if (g_mpm_list[DETECT_BUFFER_MPM_TYPE_APP] == NULL) {
        g_mpm_list[DETECT_BUFFER_MPM_TYPE_APP] = am;
    } else {
        DetectBufferMpmRegistery *t = g_mpm_list[DETECT_BUFFER_MPM_TYPE_APP];
        while (t->next != NULL) {
            t = t->next;
        }

        t->next = am;
        am->id = t->id + 1;
    }
    g_mpm_list_cnt[DETECT_BUFFER_MPM_TYPE_APP]++;

    SupportFastPatternForSigMatchList(sm_list, priority);
}

/** \brief copy a mpm engine from parent_id, add in transforms */
void DetectAppLayerMpmRegisterByParentId(DetectEngineCtx *de_ctx,
        const int id, const int parent_id,
        DetectEngineTransforms *transforms)
{
    SCLogDebug("registering %d/%d", id, parent_id);

    DetectBufferMpmRegistery *t = de_ctx->app_mpms_list;
    while (t) {
        if (t->sm_list == parent_id) {
            DetectBufferMpmRegistery *am = SCCalloc(1, sizeof(*am));
            BUG_ON(am == NULL);
            am->name = t->name;
            am->direction = t->direction;
            DEBUG_VALIDATE_BUG_ON(id < 0 || id > INT16_MAX);
            am->sm_list = (uint16_t)id; // use new id
            am->sm_list_base = t->sm_list;
            am->type = DETECT_BUFFER_MPM_TYPE_APP;
            am->PrefilterRegisterWithListId = t->PrefilterRegisterWithListId;
            am->app_v2.GetData = t->app_v2.GetData;
            am->app_v2.alproto = t->app_v2.alproto;
            am->app_v2.tx_min_progress = t->app_v2.tx_min_progress;
            am->priority = t->priority;
            am->sgh_mpm_context = t->sgh_mpm_context;
            am->sgh_mpm_context = MpmFactoryRegisterMpmCtxProfile(de_ctx, am->name, am->sm_list);
            am->next = t->next;
            if (transforms) {
                memcpy(&am->transforms, transforms, sizeof(*transforms));

                /* create comma separated string of the names of the
                 * transforms and then shorten it if necessary. Finally
                 * use it to construct the 'profile' name for the engine */
                char xforms[1024] = "";
                for (int i = 0; i < transforms->cnt; i++) {
                    char ttstr[64];
                    (void)snprintf(ttstr,sizeof(ttstr), "%s,",
                            sigmatch_table[transforms->transforms[i].transform].name);
                    strlcat(xforms, ttstr, sizeof(xforms));
                }
                xforms[strlen(xforms)-1] = '\0';

                size_t space = sizeof(am->pname) - strlen(am->name) - 3;
                char toprint[space + 1];
                memset(toprint, 0x00, space + 1);
                if (space < strlen(xforms)) {
                    ShortenString(xforms, toprint, space, '~');
                } else {
                    strlcpy(toprint, xforms,sizeof(toprint));
                }
                (void)snprintf(am->pname, sizeof(am->pname), "%s#%d (%s)",
                        am->name, id, toprint);
            } else {
                (void)snprintf(am->pname, sizeof(am->pname), "%s#%d",
                        am->name, id);
            }
            am->id = de_ctx->app_mpms_list_cnt++;

            DetectEngineRegisterFastPatternForId(de_ctx, am->sm_list, am->priority);
            t->next = am;
            SCLogDebug("copied mpm registration for %s id %u "
                    "with parent %u and GetData %p",
                    t->name, id, parent_id, am->app_v2.GetData);
            t = am;
        }
        t = t->next;
    }
}

void DetectMpmInitializeAppMpms(DetectEngineCtx *de_ctx)
{
    const DetectBufferMpmRegistery *list = g_mpm_list[DETECT_BUFFER_MPM_TYPE_APP];
    DetectBufferMpmRegistery *toadd = de_ctx->app_mpms_list;
    while (list != NULL) {
        DetectBufferMpmRegistery *n = SCCalloc(1, sizeof(*n));
        BUG_ON(n == NULL);

        *n = *list;
        n->next = NULL;

        if (toadd == NULL) {
            toadd = n;
            de_ctx->app_mpms_list = n;
        } else {
            toadd->next = n;
            toadd = toadd->next;
        }

        /* default to whatever the global setting is */
        int shared = (de_ctx->sgh_mpm_ctx_cnf == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE);

        /* see if we use a unique or shared mpm ctx for this type */
        int confshared = 0;
        char confstring[256] = "detect.mpm.";
        strlcat(confstring, n->name, sizeof(confstring));
        strlcat(confstring, ".shared", sizeof(confstring));
        if (ConfGetBool(confstring, &confshared) == 1)
            shared = confshared;

        if (shared == 0) {
            if (!(de_ctx->flags & DE_QUIET)) {
                SCLogPerf("using unique mpm ctx' for %s", n->name);
            }
            n->sgh_mpm_context = MPM_CTX_FACTORY_UNIQUE_CONTEXT;
        } else {
            if (!(de_ctx->flags & DE_QUIET)) {
                SCLogPerf("using shared mpm ctx' for %s", n->name);
            }
            n->sgh_mpm_context = MpmFactoryRegisterMpmCtxProfile(de_ctx, n->name, n->sm_list);
        }

        list = list->next;
    }
    de_ctx->app_mpms_list_cnt = g_mpm_list_cnt[DETECT_BUFFER_MPM_TYPE_APP];
    SCLogDebug("mpm: de_ctx app_mpms_list %p %u",
            de_ctx->app_mpms_list, de_ctx->app_mpms_list_cnt);
}

/**
 *  \brief initialize mpm contexts for applayer buffers that are in
 *         "single or "shared" mode.
 */
int DetectMpmPrepareAppMpms(DetectEngineCtx *de_ctx)
{
    int r = 0;
    const DetectBufferMpmRegistery *am = de_ctx->app_mpms_list;
    while (am != NULL) {
        int dir = (am->direction == SIG_FLAG_TOSERVER) ? 1 : 0;

        if (am->sgh_mpm_context != MPM_CTX_FACTORY_UNIQUE_CONTEXT)
        {
            MpmCtx *mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, am->sgh_mpm_context, dir);
            if (mpm_ctx != NULL) {
                if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
                    r |= mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
                }
            }
        }
        am = am->next;
    }
    return r;
}

/** \brief register a MPM engine
 *
 *  \note to be used at start up / registration only. Errors are fatal.
 */
void DetectFrameMpmRegister(const char *name, int direction, int priority,
        int (*PrefilterRegister)(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
                const DetectBufferMpmRegistery *mpm_reg, int list_id),
        AppProto alproto, uint8_t type)
{
    SCLogDebug("registering %s/%d/%p/%s/%u", name, priority, PrefilterRegister,
            AppProtoToString(alproto), type);

    DetectBufferTypeSupportsMpm(name);
    DetectBufferTypeSupportsFrames(name);
    DetectBufferTypeSupportsTransformations(name);
    int sm_list = DetectBufferTypeGetByName(name);
    if (sm_list < 0 || sm_list > UINT16_MAX) {
        FatalError(SC_ERR_INITIALIZATION, "MPM engine registration for %s failed", name);
    }

    DetectBufferMpmRegistery *am = SCCalloc(1, sizeof(*am));
    BUG_ON(am == NULL);
    am->name = name;
    snprintf(am->pname, sizeof(am->pname), "%s", am->name);
    am->sm_list = (uint16_t)sm_list;
    am->direction = direction;
    am->priority = priority;
    am->type = DETECT_BUFFER_MPM_TYPE_FRAME;

    am->PrefilterRegisterWithListId = PrefilterRegister;
    am->frame_v1.alproto = alproto;
    am->frame_v1.type = type;
    SCLogDebug("type %u", type);
    SCLogDebug("am type %u", am->frame_v1.type);

    if (g_mpm_list[DETECT_BUFFER_MPM_TYPE_FRAME] == NULL) {
        g_mpm_list[DETECT_BUFFER_MPM_TYPE_FRAME] = am;
    } else {
        DetectBufferMpmRegistery *t = g_mpm_list[DETECT_BUFFER_MPM_TYPE_FRAME];
        while (t->next != NULL) {
            t = t->next;
        }
        t->next = am;
        am->id = t->id + 1;
    }
    g_mpm_list_cnt[DETECT_BUFFER_MPM_TYPE_FRAME]++;

    SupportFastPatternForSigMatchList(sm_list, priority);
    SCLogDebug("%s/%d done", name, sm_list);
}

/** \brief copy a mpm engine from parent_id, add in transforms */
void DetectFrameMpmRegisterByParentId(DetectEngineCtx *de_ctx, const int id, const int parent_id,
        DetectEngineTransforms *transforms)
{
    SCLogDebug("registering %d/%d", id, parent_id);

    DetectBufferMpmRegistery *t = de_ctx->frame_mpms_list;
    while (t) {
        if (t->sm_list == parent_id) {
            DetectBufferMpmRegistery *am = SCCalloc(1, sizeof(*am));
            BUG_ON(am == NULL);
            am->name = t->name;
            snprintf(am->pname, sizeof(am->pname), "%s#%d", am->name, id);
            DEBUG_VALIDATE_BUG_ON(id < 0 || id > UINT16_MAX);
            am->sm_list = (uint16_t)id; // use new id
            am->sm_list_base = t->sm_list;
            am->type = DETECT_BUFFER_MPM_TYPE_FRAME;
            am->PrefilterRegisterWithListId = t->PrefilterRegisterWithListId;
            am->frame_v1 = t->frame_v1;
            SCLogDebug("am type %u", am->frame_v1.type);
            am->priority = t->priority;
            am->direction = t->direction;
            am->sgh_mpm_context = t->sgh_mpm_context;
            am->next = t->next;
            if (transforms) {
                memcpy(&am->transforms, transforms, sizeof(*transforms));
            }
            am->id = de_ctx->frame_mpms_list_cnt++;

            DetectEngineRegisterFastPatternForId(de_ctx, am->sm_list, am->priority);
            t->next = am;
            SCLogDebug("copied mpm registration for %s id %u "
                       "with parent %u",
                    t->name, id, parent_id);
            t = am;
        }
        t = t->next;
    }
}

void DetectEngineFrameMpmRegister(DetectEngineCtx *de_ctx, const char *name, int direction,
        int priority,
        int (*PrefilterRegister)(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
                const DetectBufferMpmRegistery *mpm_reg, int list_id),
        AppProto alproto, uint8_t type)
{
    SCLogDebug("registering %s/%d/%p/%s/%u", name, priority, PrefilterRegister,
            AppProtoToString(alproto), type);

    const int sm_list = DetectEngineBufferTypeRegister(de_ctx, name);
    if (sm_list < 0 || sm_list > UINT16_MAX) {
        FatalError(SC_ERR_INITIALIZATION, "MPM engine registration for %s failed", name);
    }

    DetectEngineBufferTypeSupportsMpm(de_ctx, name);
    DetectEngineBufferTypeSupportsFrames(de_ctx, name);
    DetectEngineBufferTypeSupportsTransformations(de_ctx, name);

    DetectBufferMpmRegistery *am = SCCalloc(1, sizeof(*am));
    BUG_ON(am == NULL);
    am->name = name;
    snprintf(am->pname, sizeof(am->pname), "%s", am->name);
    am->sm_list = (uint16_t)sm_list;
    am->direction = direction;
    am->priority = priority;
    am->type = DETECT_BUFFER_MPM_TYPE_FRAME;

    am->PrefilterRegisterWithListId = PrefilterRegister;
    am->frame_v1.alproto = alproto;
    am->frame_v1.type = type;

    // TODO is it ok to do this here?

    /* default to whatever the global setting is */
    int shared = (de_ctx->sgh_mpm_ctx_cnf == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE);
    /* see if we use a unique or shared mpm ctx for this type */
    int confshared = 0;
    if (ConfGetBool("detect.mpm.frame.shared", &confshared) == 1)
        shared = confshared;

    if (shared == 0) {
        am->sgh_mpm_context = MPM_CTX_FACTORY_UNIQUE_CONTEXT;
    } else {
        am->sgh_mpm_context = MpmFactoryRegisterMpmCtxProfile(de_ctx, am->name, am->sm_list);
    }

    if (de_ctx->frame_mpms_list == NULL) {
        de_ctx->frame_mpms_list = am;
    } else {
        DetectBufferMpmRegistery *t = de_ctx->frame_mpms_list;
        while (t->next != NULL) {
            t = t->next;
        }

        t->next = am;
    }
    de_ctx->frame_mpms_list_cnt++;

    DetectEngineRegisterFastPatternForId(de_ctx, sm_list, priority);
    SCLogDebug("%s/%d done", name, sm_list);
}

void DetectMpmInitializeFrameMpms(DetectEngineCtx *de_ctx)
{
    const DetectBufferMpmRegistery *list = g_mpm_list[DETECT_BUFFER_MPM_TYPE_FRAME];
    while (list != NULL) {
        DetectBufferMpmRegistery *n = SCCalloc(1, sizeof(*n));
        BUG_ON(n == NULL);

        *n = *list;
        n->next = NULL;

        if (de_ctx->frame_mpms_list == NULL) {
            de_ctx->frame_mpms_list = n;
        } else {
            DetectBufferMpmRegistery *t = de_ctx->frame_mpms_list;
            while (t->next != NULL) {
                t = t->next;
            }

            t->next = n;
        }

        /* default to whatever the global setting is */
        int shared = (de_ctx->sgh_mpm_ctx_cnf == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE);

        /* see if we use a unique or shared mpm ctx for this type */
        int confshared = 0;
        char confstring[256] = "detect.mpm.";
        strlcat(confstring, n->name, sizeof(confstring));
        strlcat(confstring, ".shared", sizeof(confstring));
        if (ConfGetBool(confstring, &confshared) == 1)
            shared = confshared;

        if (shared == 0) {
            if (!(de_ctx->flags & DE_QUIET)) {
                SCLogPerf("using unique mpm ctx' for %s", n->name);
            }
            n->sgh_mpm_context = MPM_CTX_FACTORY_UNIQUE_CONTEXT;
        } else {
            if (!(de_ctx->flags & DE_QUIET)) {
                SCLogPerf("using shared mpm ctx' for %s", n->name);
            }
            n->sgh_mpm_context = MpmFactoryRegisterMpmCtxProfile(de_ctx, n->name, n->sm_list);
        }

        list = list->next;
    }
    de_ctx->frame_mpms_list_cnt = g_mpm_list_cnt[DETECT_BUFFER_MPM_TYPE_FRAME];
    SCLogDebug("mpm: de_ctx frame_mpms_list %p %u", de_ctx->frame_mpms_list,
            de_ctx->frame_mpms_list_cnt);
}

/**
 *  \brief initialize mpm contexts for applayer buffers that are in
 *         "single or "shared" mode.
 */
int DetectMpmPrepareFrameMpms(DetectEngineCtx *de_ctx)
{
    SCLogDebug("preparing frame mpm");
    int r = 0;
    const DetectBufferMpmRegistery *am = de_ctx->frame_mpms_list;
    while (am != NULL) {
        SCLogDebug("am %p %s sgh_mpm_context %d", am, am->name, am->sgh_mpm_context);
        SCLogDebug("%s", am->name);
        if (am->sgh_mpm_context != MPM_CTX_FACTORY_UNIQUE_CONTEXT) {
            int dir = (am->direction == SIG_FLAG_TOSERVER) ? 1 : 0;
            MpmCtx *mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, am->sgh_mpm_context, dir);
            SCLogDebug("%s: %d mpm_Ctx %p", am->name, r, mpm_ctx);
            if (mpm_ctx != NULL) {
                if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
                    r |= mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
                    SCLogDebug("%s: %d", am->name, r);
                }
            }
        }
        am = am->next;
    }
    return r;
}

/** \brief register a MPM engine
 *
 *  \note to be used at start up / registration only. Errors are fatal.
 */
void DetectPktMpmRegister(const char *name,
        int priority,
        int (*PrefilterRegister)(DetectEngineCtx *de_ctx,
            SigGroupHead *sgh, MpmCtx *mpm_ctx,
            const DetectBufferMpmRegistery *mpm_reg, int list_id),
        InspectionBufferGetPktDataPtr GetData)
{
    SCLogDebug("registering %s/%d/%p/%p", name, priority,
            PrefilterRegister, GetData);

    if (PrefilterRegister == PrefilterGenericMpmPktRegister && GetData == NULL) {
        // must register GetData with PrefilterGenericMpmRegister
        abort();
    }

    DetectBufferTypeSupportsMpm(name);
    DetectBufferTypeSupportsTransformations(name);
    int sm_list = DetectBufferTypeGetByName(name);
    if (sm_list == -1) {
        FatalError(SC_ERR_INITIALIZATION,
                "MPM engine registration for %s failed", name);
    }

    DetectBufferMpmRegistery *am = SCCalloc(1, sizeof(*am));
    BUG_ON(am == NULL);
    am->name = name;
    snprintf(am->pname, sizeof(am->pname), "%s", am->name);
    DEBUG_VALIDATE_BUG_ON(sm_list < 0 || sm_list > INT16_MAX);
    am->sm_list = (uint16_t)sm_list;
    am->priority = priority;
    am->type = DETECT_BUFFER_MPM_TYPE_PKT;

    am->PrefilterRegisterWithListId = PrefilterRegister;
    am->pkt_v1.GetData = GetData;

    if (g_mpm_list[DETECT_BUFFER_MPM_TYPE_PKT] == NULL) {
        g_mpm_list[DETECT_BUFFER_MPM_TYPE_PKT] = am;
    } else {
        DetectBufferMpmRegistery *t = g_mpm_list[DETECT_BUFFER_MPM_TYPE_PKT];
        while (t->next != NULL) {
            t = t->next;
        }
        t->next = am;
        am->id = t->id + 1;
    }
    g_mpm_list_cnt[DETECT_BUFFER_MPM_TYPE_PKT]++;

    SupportFastPatternForSigMatchList(sm_list, priority);
    SCLogDebug("%s/%d done", name, sm_list);
}

/** \brief copy a mpm engine from parent_id, add in transforms */
void DetectPktMpmRegisterByParentId(DetectEngineCtx *de_ctx,
        const int id, const int parent_id,
        DetectEngineTransforms *transforms)
{
    SCLogDebug("registering %d/%d", id, parent_id);

    DetectBufferMpmRegistery *t = de_ctx->pkt_mpms_list;
    while (t) {
        if (t->sm_list == parent_id) {
            DetectBufferMpmRegistery *am = SCCalloc(1, sizeof(*am));
            BUG_ON(am == NULL);
            am->name = t->name;
            snprintf(am->pname, sizeof(am->pname), "%s#%d", am->name, id);
            DEBUG_VALIDATE_BUG_ON(id < 0 || id > INT16_MAX);
            am->sm_list = (uint16_t)id; // use new id
            am->sm_list_base = t->sm_list;
            am->type = DETECT_BUFFER_MPM_TYPE_PKT;
            am->PrefilterRegisterWithListId = t->PrefilterRegisterWithListId;
            am->pkt_v1.GetData = t->pkt_v1.GetData;
            am->priority = t->priority;
            am->sgh_mpm_context = t->sgh_mpm_context;
            am->next = t->next;
            if (transforms) {
                memcpy(&am->transforms, transforms, sizeof(*transforms));
            }
            am->id = de_ctx->pkt_mpms_list_cnt++;

            DetectEngineRegisterFastPatternForId(de_ctx, am->sm_list, am->priority);
            t->next = am;
            SCLogDebug("copied mpm registration for %s id %u "
                    "with parent %u and GetData %p",
                    t->name, id, parent_id, am->pkt_v1.GetData);
            t = am;
        }
        t = t->next;
    }
}

void DetectMpmInitializePktMpms(DetectEngineCtx *de_ctx)
{
    const DetectBufferMpmRegistery *list = g_mpm_list[DETECT_BUFFER_MPM_TYPE_PKT];
    while (list != NULL) {
        DetectBufferMpmRegistery *n = SCCalloc(1, sizeof(*n));
        BUG_ON(n == NULL);

        *n = *list;
        n->next = NULL;

        if (de_ctx->pkt_mpms_list == NULL) {
            de_ctx->pkt_mpms_list = n;
        } else {
            DetectBufferMpmRegistery *t = de_ctx->pkt_mpms_list;
            while (t->next != NULL) {
                t = t->next;
            }

            t->next = n;
        }

        /* default to whatever the global setting is */
        int shared = (de_ctx->sgh_mpm_ctx_cnf == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE);

        /* see if we use a unique or shared mpm ctx for this type */
        int confshared = 0;
        char confstring[256] = "detect.mpm.";
        strlcat(confstring, n->name, sizeof(confstring));
        strlcat(confstring, ".shared", sizeof(confstring));
        if (ConfGetBool(confstring, &confshared) == 1)
            shared = confshared;

        if (shared == 0) {
            if (!(de_ctx->flags & DE_QUIET)) {
                SCLogPerf("using unique mpm ctx' for %s", n->name);
            }
            n->sgh_mpm_context = MPM_CTX_FACTORY_UNIQUE_CONTEXT;
        } else {
            if (!(de_ctx->flags & DE_QUIET)) {
                SCLogPerf("using shared mpm ctx' for %s", n->name);
            }
            n->sgh_mpm_context = MpmFactoryRegisterMpmCtxProfile(de_ctx, n->name, n->sm_list);
        }

        list = list->next;
    }
    de_ctx->pkt_mpms_list_cnt = g_mpm_list_cnt[DETECT_BUFFER_MPM_TYPE_PKT];
    SCLogDebug("mpm: de_ctx pkt_mpms_list %p %u",
            de_ctx->pkt_mpms_list, de_ctx->pkt_mpms_list_cnt);
}

/**
 *  \brief initialize mpm contexts for applayer buffers that are in
 *         "single or "shared" mode.
 */
int DetectMpmPreparePktMpms(DetectEngineCtx *de_ctx)
{
    SCLogDebug("preparing pkt mpm");
    int r = 0;
    const DetectBufferMpmRegistery *am = de_ctx->pkt_mpms_list;
    while (am != NULL) {
        SCLogDebug("%s", am->name);
        if (am->sgh_mpm_context != MPM_CTX_FACTORY_UNIQUE_CONTEXT)
        {
            MpmCtx *mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, am->sgh_mpm_context, 0);
            if (mpm_ctx != NULL) {
                if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
                    r |= mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
                    SCLogDebug("%s: %d", am->name, r);
                }
            }
        }
        am = am->next;
    }
    return r;
}

static int32_t SetupBuiltinMpm(DetectEngineCtx *de_ctx, const char *name)
{
    /* default to whatever the global setting is */
    int shared = (de_ctx->sgh_mpm_ctx_cnf == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE);

    /* see if we use a unique or shared mpm ctx for this type */
    int confshared = 0;
    char confstring[256] = "detect.mpm.";
    strlcat(confstring, name, sizeof(confstring));
    strlcat(confstring, ".shared", sizeof(confstring));
    if (ConfGetBool(confstring, &confshared) == 1)
        shared = confshared;

    int32_t ctx;
    if (shared == 0) {
        ctx = MPM_CTX_FACTORY_UNIQUE_CONTEXT;
        SCLogPerf("using unique mpm ctx' for %s", name);
    } else {
        ctx = MpmFactoryRegisterMpmCtxProfile(de_ctx, name, DETECT_SM_LIST_PMATCH);
        SCLogPerf("using shared mpm ctx' for %s", name);
    }
    return ctx;
}

void DetectMpmInitializeBuiltinMpms(DetectEngineCtx *de_ctx)
{
    de_ctx->sgh_mpm_context_proto_tcp_packet = SetupBuiltinMpm(de_ctx, "tcp-packet");
    de_ctx->sgh_mpm_context_stream = SetupBuiltinMpm(de_ctx, "tcp-stream");

    de_ctx->sgh_mpm_context_proto_udp_packet = SetupBuiltinMpm(de_ctx, "udp-packet");
    de_ctx->sgh_mpm_context_proto_other_packet = SetupBuiltinMpm(de_ctx, "other-ip");
}

/**
 *  \brief initialize mpm contexts for builtin buffers that are in
 *         "single or "shared" mode.
 */
int DetectMpmPrepareBuiltinMpms(DetectEngineCtx *de_ctx)
{
    int r = 0;
    MpmCtx *mpm_ctx = NULL;

    if (de_ctx->sgh_mpm_context_proto_tcp_packet != MPM_CTX_FACTORY_UNIQUE_CONTEXT) {
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_tcp_packet, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            r |= mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_tcp_packet, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            r |= mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
    }

    if (de_ctx->sgh_mpm_context_proto_udp_packet != MPM_CTX_FACTORY_UNIQUE_CONTEXT) {
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_udp_packet, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            r |= mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_udp_packet, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            r |= mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
    }

    if (de_ctx->sgh_mpm_context_proto_other_packet != MPM_CTX_FACTORY_UNIQUE_CONTEXT) {
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_other_packet, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            r |= mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
    }

    if (de_ctx->sgh_mpm_context_stream != MPM_CTX_FACTORY_UNIQUE_CONTEXT) {
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_stream, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            r |= mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_stream, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            r |= mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
    }

    return r;
}

/**
 *  \brief check if a signature has patterns that are to be inspected
 *         against a packets payload (as opposed to the stream payload)
 *
 *  \param s signature
 *
 *  \retval 1 true
 *  \retval 0 false
 */
int SignatureHasPacketContent(const Signature *s)
{
    SCEnter();

    if (s == NULL) {
        SCReturnInt(0);
    }

    if (!(s->proto.proto[IPPROTO_TCP / 8] & 1 << (IPPROTO_TCP % 8))) {
        SCReturnInt(1);
    }

    if ((s->init_data != NULL && s->init_data->smlists[DETECT_SM_LIST_PMATCH] == NULL) ||
        (s->init_data == NULL && s->sm_arrays[DETECT_SM_LIST_PMATCH] == NULL))
    {
        SCLogDebug("no mpm");
        SCReturnInt(0);
    }

    if (!(s->flags & SIG_FLAG_REQUIRE_PACKET)) {
        SCReturnInt(0);
    }

    SCReturnInt(1);
}

/**
 *  \brief check if a signature has patterns that are to be inspected
 *         against the stream payload (as opposed to the individual packets
 *         payload(s))
 *
 *  \param s signature
 *
 *  \retval 1 true
 *  \retval 0 false
 */
int SignatureHasStreamContent(const Signature *s)
{
    SCEnter();

    if (s == NULL) {
        SCReturnInt(0);
    }

    if (!(s->proto.proto[IPPROTO_TCP / 8] & 1 << (IPPROTO_TCP % 8))) {
        SCReturnInt(0);
    }

    if ((s->init_data != NULL && s->init_data->smlists[DETECT_SM_LIST_PMATCH] == NULL) ||
        (s->init_data == NULL && s->sm_arrays[DETECT_SM_LIST_PMATCH] == NULL))
    {
        SCLogDebug("no mpm");
        SCReturnInt(0);
    }

    if (!(s->flags & SIG_FLAG_REQUIRE_STREAM)) {
        SCReturnInt(0);
    }

    SCReturnInt(1);
}


/**
 *  \brief  Function to return the multi pattern matcher algorithm to be
 *          used by the engine, based on the mpm-algo setting in yaml
 *          Use the default mpm if none is specified in the yaml file.
 *
 *  \retval mpm algo value
 */
uint8_t PatternMatchDefaultMatcher(void)
{
    const char *mpm_algo;
    uint8_t mpm_algo_val = mpm_default_matcher;

    /* Get the mpm algo defined in config file by the user */
    if ((ConfGet("mpm-algo", &mpm_algo)) == 1) {
        if (mpm_algo != NULL) {
#if __BYTE_ORDER == __BIG_ENDIAN
            if (strcmp(mpm_algo, "ac-ks") == 0) {
                FatalError(SC_ERR_FATAL, "ac-ks does "
                           "not work on big endian systems at this time.");
            }
#endif
            if (strcmp("auto", mpm_algo) == 0) {
                goto done;
            }
            for (uint8_t u = 0; u < MPM_TABLE_SIZE; u++) {
                if (mpm_table[u].name == NULL)
                    continue;

                if (strcmp(mpm_table[u].name, mpm_algo) == 0) {
                    mpm_algo_val = u;
                    goto done;
                }
            }

#ifndef BUILD_HYPERSCAN
            if ((strcmp(mpm_algo, "hs") == 0)) {
                FatalError(SC_ERR_INVALID_VALUE, "Hyperscan (hs) support for mpm-algo is "
                        "not compiled into Suricata.");
            }
#endif
        }
        FatalError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid mpm algo supplied "
                "in the yaml conf file: \"%s\"", mpm_algo);
    }

 done:
    return mpm_algo_val;
}

void PatternMatchDestroy(MpmCtx *mpm_ctx, uint16_t mpm_matcher)
{
    SCLogDebug("mpm_ctx %p, mpm_matcher %"PRIu16"", mpm_ctx, mpm_matcher);
    mpm_table[mpm_matcher].DestroyCtx(mpm_ctx);
}

void PatternMatchThreadPrint(MpmThreadCtx *mpm_thread_ctx, uint16_t mpm_matcher)
{
    SCLogDebug("mpm_thread_ctx %p, mpm_matcher %"PRIu16" defunct", mpm_thread_ctx, mpm_matcher);
    //mpm_table[mpm_matcher].PrintThreadCtx(mpm_thread_ctx);
}
void PatternMatchThreadDestroy(MpmThreadCtx *mpm_thread_ctx, uint16_t mpm_matcher)
{
    SCLogDebug("mpm_thread_ctx %p, mpm_matcher %"PRIu16"", mpm_thread_ctx, mpm_matcher);
    if (mpm_table[mpm_matcher].DestroyThreadCtx != NULL)
        mpm_table[mpm_matcher].DestroyThreadCtx(NULL, mpm_thread_ctx);
}
void PatternMatchThreadPrepare(MpmThreadCtx *mpm_thread_ctx, uint16_t mpm_matcher)
{
    SCLogDebug("mpm_thread_ctx %p, type %"PRIu16, mpm_thread_ctx, mpm_matcher);
    MpmInitThreadCtx(mpm_thread_ctx, mpm_matcher);
}

/** \brief Predict a strength value for patterns
 *
 *  Patterns with high character diversity score higher.
 *  Alpha chars score not so high
 *  Other printable + a few common codes a little higher
 *  Everything else highest.
 *  Longer patterns score better than short patters.
 *
 *  \param pat pattern
 *  \param patlen length of the pattern
 *
 *  \retval s pattern score
 */
uint32_t PatternStrength(uint8_t *pat, uint16_t patlen)
{
    uint8_t a[256];
    memset(&a, 0 ,sizeof(a));

    uint32_t s = 0;
    uint16_t u = 0;
    for (u = 0; u < patlen; u++) {
        if (a[pat[u]] == 0) {
            if (isalpha(pat[u]))
                s += 3;
            else if (isprint(pat[u]) || pat[u] == 0x00 || pat[u] == 0x01 || pat[u] == 0xFF)
                s += 4;
            else
                s += 6;

            a[pat[u]] = 1;
        } else {
            s++;
        }
    }

    return s;
}

static void PopulateMpmHelperAddPattern(MpmCtx *mpm_ctx,
                                        const DetectContentData *cd,
                                        const Signature *s, uint8_t flags,
                                        int chop)
{
    uint16_t pat_offset = cd->offset;
    uint16_t pat_depth = cd->depth;

    /* recompute offset/depth to cope with chop */
    if (chop && (pat_depth || pat_offset)) {
        pat_offset += cd->fp_chop_offset;
        if (pat_depth) {
            pat_depth -= cd->content_len;
            pat_depth += cd->fp_chop_offset + cd->fp_chop_len;
        }
    }

    /* We have to effectively "wild card" values that will be coming from
     * byte_extract variables
     */
    if (cd->flags & (DETECT_CONTENT_DEPTH_VAR | DETECT_CONTENT_OFFSET_VAR)) {
        pat_depth = pat_offset = 0;
    }

    if (cd->flags & DETECT_CONTENT_NOCASE) {
        if (chop) {
            MpmAddPatternCI(mpm_ctx,
                            cd->content + cd->fp_chop_offset, cd->fp_chop_len,
                            pat_offset, pat_depth,
                            cd->id, s->num, flags|MPM_PATTERN_CTX_OWNS_ID);
        } else {
            MpmAddPatternCI(mpm_ctx,
                            cd->content, cd->content_len,
                            pat_offset, pat_depth,
                            cd->id, s->num, flags|MPM_PATTERN_CTX_OWNS_ID);
        }
    } else {
        if (chop) {
            MpmAddPatternCS(mpm_ctx,
                            cd->content + cd->fp_chop_offset, cd->fp_chop_len,
                            pat_offset, pat_depth,
                            cd->id, s->num, flags|MPM_PATTERN_CTX_OWNS_ID);
        } else {
            MpmAddPatternCS(mpm_ctx,
                            cd->content, cd->content_len,
                            pat_offset, pat_depth,
                            cd->id, s->num, flags|MPM_PATTERN_CTX_OWNS_ID);
        }
    }

    return;
}

#define SGH_PROTO(sgh, p) ((sgh)->init->protos[(p)] == 1)
#define SGH_DIRECTION_TS(sgh) ((sgh)->init->direction & SIG_FLAG_TOSERVER)
#define SGH_DIRECTION_TC(sgh) ((sgh)->init->direction & SIG_FLAG_TOCLIENT)

static void SetMpm(Signature *s, SigMatch *mpm_sm, const int mpm_sm_list)
{
    if (s == NULL || mpm_sm == NULL)
        return;

    DetectContentData *cd = (DetectContentData *)mpm_sm->ctx;
    if (cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
        if (DETECT_CONTENT_IS_SINGLE(cd) &&
                !(cd->flags & DETECT_CONTENT_NEGATED) &&
                !(cd->flags & DETECT_CONTENT_REPLACE) &&
                cd->content_len == cd->fp_chop_len)
        {
            cd->flags |= DETECT_CONTENT_NO_DOUBLE_INSPECTION_REQUIRED;
        }
    } else {
        if (DETECT_CONTENT_IS_SINGLE(cd) &&
                !(cd->flags & DETECT_CONTENT_NEGATED) &&
                !(cd->flags & DETECT_CONTENT_REPLACE))
        {
            cd->flags |= DETECT_CONTENT_NO_DOUBLE_INSPECTION_REQUIRED;
        }
    }
    cd->flags |= DETECT_CONTENT_MPM;
    s->init_data->mpm_sm_list = mpm_sm_list;
    s->init_data->mpm_sm = mpm_sm;
    return;
}

static SigMatch *GetMpmForList(const Signature *s, const int list, SigMatch *mpm_sm,
    uint16_t max_len, bool skip_negated_content)
{
    for (SigMatch *sm = s->init_data->smlists[list]; sm != NULL; sm = sm->next) {
        if (sm->type != DETECT_CONTENT)
            continue;

        const DetectContentData *cd = (DetectContentData *)sm->ctx;
        /* skip_negated_content is only set if there's absolutely no
         * non-negated content present in the sig */
        if ((cd->flags & DETECT_CONTENT_NEGATED) && skip_negated_content)
            continue;
        if (cd->content_len != max_len)
            continue;

        if (mpm_sm == NULL) {
            mpm_sm = sm;
        } else {
            DetectContentData *data1 = (DetectContentData *)sm->ctx;
            DetectContentData *data2 = (DetectContentData *)mpm_sm->ctx;
            uint32_t ls = PatternStrength(data1->content, data1->content_len);
            uint32_t ss = PatternStrength(data2->content, data2->content_len);
            if (ls > ss) {
                mpm_sm = sm;
            } else if (ls == ss) {
                /* if 2 patterns are of equal strength, we pick the longest */
                if (data1->content_len > data2->content_len)
                    mpm_sm = sm;
            } else {
                SCLogDebug("sticking with mpm_sm");
            }
        }
    }
    return mpm_sm;
}

void RetrieveFPForSig(const DetectEngineCtx *de_ctx, Signature *s)
{
    if (s->init_data->mpm_sm != NULL)
        return;

    SigMatch *sm = NULL;
    const int nlists = s->init_data->smlists_array_size;
    int nn_sm_list[nlists];
    int n_sm_list[nlists];
    memset(nn_sm_list, 0, nlists * sizeof(int));
    memset(n_sm_list, 0, nlists * sizeof(int));
    int count_nn_sm_list = 0;
    int count_n_sm_list = 0;

    /* inspect rule to see if we have the fast_pattern reg to
     * force using a sig, otherwise keep stats about the patterns */
    for (int list_id = DETECT_SM_LIST_PMATCH; list_id < nlists; list_id++) {
        if (s->init_data->smlists[list_id] == NULL)
            continue;

        if (list_id == DETECT_SM_LIST_POSTMATCH || list_id == DETECT_SM_LIST_TMATCH ||
                list_id == DETECT_SM_LIST_SUPPRESS || list_id == DETECT_SM_LIST_THRESHOLD)
            continue;

        if (!FastPatternSupportEnabledForSigMatchList(de_ctx, list_id))
            continue;

        for (sm = s->init_data->smlists[list_id]; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

            const DetectContentData *cd = (DetectContentData *)sm->ctx;
            /* fast_pattern set in rule, so using this pattern */
            if ((cd->flags & DETECT_CONTENT_FAST_PATTERN)) {
                SetMpm(s, sm, list_id);
                return;
            }

            if (cd->flags & DETECT_CONTENT_NEGATED) {
                n_sm_list[list_id] = 1;
                count_n_sm_list++;
            } else {
                nn_sm_list[list_id] = 1;
                count_nn_sm_list++;
            }
        }
    }

    /* prefer normal not-negated over negated */
    int *curr_sm_list = NULL;
    int skip_negated_content = 1;
    if (count_nn_sm_list > 0) {
        curr_sm_list = nn_sm_list;
    } else if (count_n_sm_list > 0) {
        curr_sm_list = n_sm_list;
        skip_negated_content = 0;
    } else {
        return;
    }

    int final_sm_list[nlists];
    memset(&final_sm_list, 0, (nlists * sizeof(int)));

    int count_final_sm_list = 0;
    int priority;

    const SCFPSupportSMList *tmp = de_ctx->fp_support_smlist_list;
    while (tmp != NULL) {
        for (priority = tmp->priority;
             tmp != NULL && priority == tmp->priority;
             tmp = tmp->next)
        {
            SCLogDebug("tmp->list_id %d tmp->priority %d", tmp->list_id, tmp->priority);
            if (tmp->list_id >= nlists)
                continue;
            if (curr_sm_list[tmp->list_id] == 0)
                continue;
            final_sm_list[count_final_sm_list++] = tmp->list_id;
        }
        if (count_final_sm_list != 0)
            break;
    }

    BUG_ON(count_final_sm_list == 0);

    uint16_t max_len = 0;
    for (int i = 0; i < count_final_sm_list; i++) {
        if (final_sm_list[i] >= (int)s->init_data->smlists_array_size)
            continue;

        for (sm = s->init_data->smlists[final_sm_list[i]]; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

            const DetectContentData *cd = (DetectContentData *)sm->ctx;
            /* skip_negated_content is only set if there's absolutely no
             * non-negated content present in the sig */
            if ((cd->flags & DETECT_CONTENT_NEGATED) && skip_negated_content)
                continue;
            if (max_len < cd->content_len)
                max_len = cd->content_len;
        }
    }

    SigMatch *mpm_sm = NULL;
    int mpm_sm_list = -1;
    for (int i = 0; i < count_final_sm_list; i++) {
        if (final_sm_list[i] >= (int)s->init_data->smlists_array_size)
            continue;

        /* GetMpmForList may keep `mpm_sm` the same, so track if it changed */
        SigMatch *prev_mpm_sm = mpm_sm;
        mpm_sm = GetMpmForList(s, final_sm_list[i], mpm_sm, max_len, skip_negated_content);
        if (mpm_sm != prev_mpm_sm) {
            mpm_sm_list = final_sm_list[i];
        }
    }

#ifdef DEBUG
    if (mpm_sm != NULL) {
        BUG_ON(mpm_sm_list == -1);
        int check_list = SigMatchListSMBelongsTo(s, mpm_sm);
        BUG_ON(check_list != mpm_sm_list);
    }
#endif
    /* assign to signature */
    SetMpm(s, mpm_sm, mpm_sm_list);
    return;
}

/** \internal
 *  \brief The hash function for MpmStore
 *
 *  \param ht      Pointer to the hash table.
 *  \param data    Pointer to the MpmStore.
 *  \param datalen Not used in our case.
 *
 *  \retval hash The generated hash value.
 */
static uint32_t MpmStoreHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    const MpmStore *ms = (MpmStore *)data;
    uint32_t hash = 0;
    uint32_t b = 0;

    for (b = 0; b < ms->sid_array_size; b++)
        hash += ms->sid_array[b];

    return hash % ht->array_size;
}

/**
 * \brief The Compare function for MpmStore
 *
 * \param data1 Pointer to the first MpmStore.
 * \param len1  Not used.
 * \param data2 Pointer to the second MpmStore.
 * \param len2  Not used.
 *
 * \retval 1 If the 2 MpmStores sent as args match.
 * \retval 0 If the 2 MpmStores sent as args do not match.
 */
static char MpmStoreCompareFunc(void *data1, uint16_t len1, void *data2,
                                uint16_t len2)
{
    const MpmStore *ms1 = (MpmStore *)data1;
    const MpmStore *ms2 = (MpmStore *)data2;

    if (ms1->sid_array_size != ms2->sid_array_size)
        return 0;

    if (ms1->buffer != ms2->buffer)
        return 0;

    if (ms1->direction != ms2->direction)
        return 0;

    if (ms1->sm_list != ms2->sm_list)
        return 0;

    if (SCMemcmp(ms1->sid_array, ms2->sid_array,
                 ms1->sid_array_size) != 0)
    {
        return 0;
    }

    return 1;
}

static void MpmStoreFreeFunc(void *ptr)
{
    MpmStore *ms = ptr;
    if (ms != NULL) {
        if (ms->mpm_ctx != NULL && !(ms->mpm_ctx->flags & MPMCTX_FLAGS_GLOBAL))
        {
            SCLogDebug("destroying mpm_ctx %p", ms->mpm_ctx);
            mpm_table[ms->mpm_ctx->mpm_type].DestroyCtx(ms->mpm_ctx);
            SCFree(ms->mpm_ctx);
        }
        ms->mpm_ctx = NULL;

        SCFree(ms->sid_array);
        SCFree(ms);
    }
}

/**
 * \brief Initializes the MpmStore mpm hash table to be used by the detection
 *        engine context.
 *
 * \param de_ctx Pointer to the detection engine context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int MpmStoreInit(DetectEngineCtx *de_ctx)
{
    de_ctx->mpm_hash_table = HashListTableInit(4096,
                                               MpmStoreHashFunc,
                                               MpmStoreCompareFunc,
                                               MpmStoreFreeFunc);
    if (de_ctx->mpm_hash_table == NULL)
        goto error;

    return 0;

error:
    return -1;
}

/**
 * \brief Adds a MpmStore to the detection engine context MpmStore
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the MpmStore.
 *
 * \retval ret 0 on Successfully adding the argument sgh; -1 on failure.
 */
static int MpmStoreAdd(DetectEngineCtx *de_ctx, MpmStore *s)
{
    int ret = HashListTableAdd(de_ctx->mpm_hash_table, (void *)s, 0);
    return ret;
}

/**
 * \brief Used to lookup a MpmStore from the MpmStore
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sgh    Pointer to the MpmStore.
 *
 * \retval rsgh On success a pointer to the MpmStore if the MpmStore is
 *              found in the hash table; NULL on failure.
 */
static MpmStore *MpmStoreLookup(DetectEngineCtx *de_ctx, MpmStore *s)
{
    MpmStore *rs = HashListTableLookup(de_ctx->mpm_hash_table,
                                             (void *)s, 0);
    return rs;
}

static const DetectBufferMpmRegistery *GetByMpmStore(const DetectEngineCtx *de_ctx,
        const MpmStore *ms)
{
    const DetectBufferMpmRegistery *am = de_ctx->app_mpms_list;
    while (am != NULL) {
        if (ms->sm_list == am->sm_list &&
            ms->direction == am->direction) {
            return am;
        }
        am = am->next;
    }
    am = de_ctx->pkt_mpms_list;
    while (am != NULL) {
        if (ms->sm_list == am->sm_list) {
            return am;
        }
        am = am->next;
    }
    return NULL;
}

void MpmStoreReportStats(const DetectEngineCtx *de_ctx)
{
    HashListTableBucket *htb = NULL;

    uint32_t stats[MPMB_MAX] = {0};
    int app_mpms_cnt = de_ctx->buffer_type_id;
    uint32_t appstats[app_mpms_cnt + 1];    // +1 to silence scan-build
    memset(&appstats, 0x00, sizeof(appstats));
    int pkt_mpms_cnt = de_ctx->buffer_type_id;
    uint32_t pktstats[pkt_mpms_cnt + 1];    // +1 to silence scan-build
    memset(&pktstats, 0x00, sizeof(pktstats));
    int frame_mpms_cnt = de_ctx->buffer_type_id;
    uint32_t framestats[frame_mpms_cnt + 1]; // +1 to silence scan-build
    memset(&framestats, 0x00, sizeof(framestats));

    for (htb = HashListTableGetListHead(de_ctx->mpm_hash_table);
            htb != NULL;
            htb = HashListTableGetListNext(htb))
    {
        const MpmStore *ms = (MpmStore *)HashListTableGetListData(htb);
        if (ms == NULL || ms->mpm_ctx == NULL) {
            continue;
        }
        if (ms->buffer < MPMB_MAX)
            stats[ms->buffer]++;
        else if (ms->sm_list != DETECT_SM_LIST_PMATCH) {
            const DetectBufferMpmRegistery *am = GetByMpmStore(de_ctx, ms);
            if (am != NULL) {
                switch (am->type) {
                    case DETECT_BUFFER_MPM_TYPE_PKT:
                        SCLogDebug("%s: %u patterns. Min %u, Max %u. Ctx %p",
                                am->name,
                                ms->mpm_ctx->pattern_cnt,
                                ms->mpm_ctx->minlen, ms->mpm_ctx->maxlen,
                                ms->mpm_ctx);
                        pktstats[am->sm_list]++;
                        break;
                    case DETECT_BUFFER_MPM_TYPE_APP:
                        SCLogDebug("%s %s: %u patterns. Min %u, Max %u. Ctx %p",
                                am->name,
                                am->direction == SIG_FLAG_TOSERVER ? "toserver":"toclient",
                                ms->mpm_ctx->pattern_cnt,
                                ms->mpm_ctx->minlen, ms->mpm_ctx->maxlen,
                                ms->mpm_ctx);
                        appstats[am->sm_list]++;
                        break;
                    case DETECT_BUFFER_MPM_TYPE_FRAME:
                        SCLogDebug("%s: %u patterns. Min %u, Max %u. Ctx %p", am->name,
                                ms->mpm_ctx->pattern_cnt, ms->mpm_ctx->minlen, ms->mpm_ctx->maxlen,
                                ms->mpm_ctx);
                        framestats[am->sm_list]++;
                        break;
                    case DETECT_BUFFER_MPM_TYPE_SIZE:
                        break;
                }
            }
        }
    }

    if (!(de_ctx->flags & DE_QUIET)) {
        for (int x = 0; x < MPMB_MAX; x++) {
            SCLogPerf("Builtin MPM \"%s\": %u", builtin_mpms[x], stats[x]);
        }
        const DetectBufferMpmRegistery *am = de_ctx->app_mpms_list;
        while (am != NULL) {
            if (appstats[am->sm_list] > 0) {
                const char *name = am->name;
                const char *direction = am->direction == SIG_FLAG_TOSERVER ? "toserver" : "toclient";
                SCLogPerf("AppLayer MPM \"%s %s (%s)\": %u", direction, name,
                        AppProtoToString(am->app_v2.alproto), appstats[am->sm_list]);
            }
            am = am->next;
        }
        const DetectBufferMpmRegistery *pm = de_ctx->pkt_mpms_list;
        while (pm != NULL) {
            if (pktstats[pm->sm_list] > 0) {
                const char *name = pm->name;
                SCLogPerf("Pkt MPM \"%s\": %u", name, pktstats[pm->sm_list]);
            }
            pm = pm->next;
        }
        const DetectBufferMpmRegistery *um = de_ctx->frame_mpms_list;
        while (um != NULL) {
            if (framestats[um->sm_list] > 0) {
                const char *name = um->name;
                SCLogPerf("Frame MPM \"%s\": %u", name, framestats[um->sm_list]);
            }
            um = um->next;
        }
    }
}

/**
 * \brief Frees the hash table - DetectEngineCtx->mpm_hash_table, allocated by
 *        MpmStoreInit() function.
 *
 * \param de_ctx Pointer to the detection engine context.
 */
void MpmStoreFree(DetectEngineCtx *de_ctx)
{
    if (de_ctx->mpm_hash_table == NULL)
        return;

    HashListTableFree(de_ctx->mpm_hash_table);
    de_ctx->mpm_hash_table = NULL;
    return;
}

static void MpmStoreSetup(const DetectEngineCtx *de_ctx, MpmStore *ms)
{
    const Signature *s = NULL;
    uint32_t sig;
    int dir = 0;

    if (ms->buffer != MPMB_MAX) {
        BUG_ON(ms->sm_list != DETECT_SM_LIST_PMATCH);

        switch (ms->buffer) {
            /* TS is 1 */
            case MPMB_TCP_PKT_TS:
            case MPMB_TCP_STREAM_TS:
            case MPMB_UDP_TS:
                dir = 1;
                break;

                /* TC is 0 */
            default:
            case MPMB_UDP_TC:
            case MPMB_TCP_STREAM_TC:
            case MPMB_TCP_PKT_TC:
            case MPMB_OTHERIP:          /**< use 0 for other */
                dir = 0;
                break;
        }
    } else {
        BUG_ON(ms->sm_list == DETECT_SM_LIST_PMATCH);

        if (ms->direction == SIG_FLAG_TOSERVER)
            dir = 1;
        else
            dir = 0;
    }

    ms->mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, ms->sgh_mpm_context, dir);
    if (ms->mpm_ctx == NULL) {
        return;
    }

    MpmInitCtx(ms->mpm_ctx, de_ctx->mpm_matcher);

    /* add the patterns */
    for (sig = 0; sig < (ms->sid_array_size * 8); sig++) {
        if (ms->sid_array[sig / 8] & (1 << (sig % 8))) {
            s = de_ctx->sig_array[sig];
            if (s == NULL)
                continue;
            if ((s->flags & ms->direction) == 0) {
                SCLogDebug("s->flags %x ms->direction %x", s->flags, ms->direction);
                continue;
            }
            if (s->init_data->mpm_sm == NULL)
                continue;
            int list = s->init_data->mpm_sm_list;
            if (list < 0)
                continue;
            if (list != ms->sm_list)
                continue;

            SCLogDebug("adding %u", s->id);

            const DetectContentData *cd = (DetectContentData *)s->init_data->mpm_sm->ctx;

            int skip = 0;
            /* negated logic: if mpm match can't be used to be sure about this
             * pattern, we have to inspect the rule fully regardless of mpm
             * match. So in this case there is no point of adding it at all.
             * The non-mpm list entry for the sig will make sure the sig is
             * inspected. */
            if ((cd->flags & DETECT_CONTENT_NEGATED) &&
                !(DETECT_CONTENT_MPM_IS_CONCLUSIVE(cd)))
            {
                skip = 1;
                SCLogDebug("not adding negated mpm as it's not 'single'");
            }

            if (!skip) {
                PopulateMpmHelperAddPattern(ms->mpm_ctx,
                        cd, s, 0, (cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP));
            }
        }
    }

    if (ms->mpm_ctx->pattern_cnt == 0) {
        MpmFactoryReClaimMpmCtx(de_ctx, ms->mpm_ctx);
        ms->mpm_ctx = NULL;
    } else {
        if (ms->sgh_mpm_context == MPM_CTX_FACTORY_UNIQUE_CONTEXT) {
            if (mpm_table[ms->mpm_ctx->mpm_type].Prepare != NULL) {
                mpm_table[ms->mpm_ctx->mpm_type].Prepare(ms->mpm_ctx);
            }
        }
    }
}


/** \brief Get MpmStore for a built-in buffer type
 *
 */
MpmStore *MpmStorePrepareBuffer(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
                                enum MpmBuiltinBuffers buf)
{
    const Signature *s = NULL;
    uint32_t sig;
    uint32_t cnt = 0;
    int direction = 0;
    uint32_t max_sid = DetectEngineGetMaxSigId(de_ctx) / 8 + 1;
    uint8_t sids_array[max_sid];
    memset(sids_array, 0x00, max_sid);
    int sgh_mpm_context = 0;
    int sm_list = DETECT_SM_LIST_PMATCH;

    switch (buf) {
        case MPMB_TCP_PKT_TS:
        case MPMB_TCP_PKT_TC:
            sgh_mpm_context = de_ctx->sgh_mpm_context_proto_tcp_packet;
            break;
        case MPMB_TCP_STREAM_TS:
        case MPMB_TCP_STREAM_TC:
            sgh_mpm_context = de_ctx->sgh_mpm_context_stream;
            break;
        case MPMB_UDP_TS:
        case MPMB_UDP_TC:
            sgh_mpm_context = de_ctx->sgh_mpm_context_proto_udp_packet;
            break;
        case MPMB_OTHERIP:
            sgh_mpm_context = de_ctx->sgh_mpm_context_proto_other_packet;
            break;
        default:
            break;
    }

    switch(buf) {
        case MPMB_TCP_PKT_TS:
        case MPMB_TCP_STREAM_TS:
        case MPMB_UDP_TS:
            direction = SIG_FLAG_TOSERVER;
            break;

        case MPMB_TCP_PKT_TC:
        case MPMB_TCP_STREAM_TC:
        case MPMB_UDP_TC:
            direction = SIG_FLAG_TOCLIENT;
            break;

        case MPMB_OTHERIP:
            direction = (SIG_FLAG_TOCLIENT|SIG_FLAG_TOSERVER);
            break;

        case MPMB_MAX:
            BUG_ON(1);
            break;
    }

    for (sig = 0; sig < sgh->init->sig_cnt; sig++) {
        s = sgh->init->match_array[sig];
        if (s == NULL)
            continue;

        if (s->init_data->mpm_sm == NULL)
            continue;

        int list = s->init_data->mpm_sm_list;
        if (list < 0)
            continue;

        if (list != DETECT_SM_LIST_PMATCH)
            continue;

        switch (buf) {
            case MPMB_TCP_PKT_TS:
            case MPMB_TCP_PKT_TC:
                if (SignatureHasPacketContent(s) == 1)
                {
                    sids_array[s->num / 8] |= 1 << (s->num % 8);
                    cnt++;
                }
                break;
            case MPMB_TCP_STREAM_TS:
            case MPMB_TCP_STREAM_TC:
                if (SignatureHasStreamContent(s) == 1)
                {
                    sids_array[s->num / 8] |= 1 << (s->num % 8);
                    cnt++;
                }
                break;
            case MPMB_UDP_TS:
            case MPMB_UDP_TC:
                sids_array[s->num / 8] |= 1 << (s->num % 8);
                cnt++;
                break;
            case MPMB_OTHERIP:
                sids_array[s->num / 8] |= 1 << (s->num % 8);
                cnt++;
                break;
            default:
                break;
        }
    }

    if (cnt == 0)
        return NULL;

    MpmStore lookup = { sids_array, max_sid, direction, buf, sm_list, 0, NULL};

    MpmStore *result = MpmStoreLookup(de_ctx, &lookup);
    if (result == NULL) {
        MpmStore *copy = SCCalloc(1, sizeof(MpmStore));
        if (copy == NULL)
            return NULL;
        uint8_t *sids = SCCalloc(1, max_sid);
        if (sids == NULL) {
            SCFree(copy);
            return NULL;
        }

        memcpy(sids, sids_array, max_sid);
        copy->sid_array = sids;
        copy->sid_array_size = max_sid;
        copy->buffer = buf;
        copy->direction = direction;
        copy->sm_list = sm_list;
        copy->sgh_mpm_context = sgh_mpm_context;

        MpmStoreSetup(de_ctx, copy);
        MpmStoreAdd(de_ctx, copy);
        return copy;
    } else {
        return result;
    }
}

struct SidsArray {
    uint8_t *sids_array;
    uint32_t sids_array_size;
    /* indicates this has an active engine */
    bool active;

    enum DetectBufferMpmType type;
};

static MpmStore *MpmStorePrepareBufferAppLayer(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        const DetectBufferMpmRegistery *am, const struct SidsArray *sa)
{
    SCLogDebug("handling %s direction %s for list %d", am->name,
            am->direction == SIG_FLAG_TOSERVER ? "toserver" : "toclient",
            am->sm_list);

    if (sa->active == false || sa->sids_array_size == 0 || sa->sids_array == NULL)
        return NULL;

    MpmStore lookup = { sa->sids_array, sa->sids_array_size, am->direction, MPMB_MAX, am->sm_list,
        0, NULL };
    SCLogDebug("am->direction %d am->sm_list %d",
            am->direction, am->sm_list);

    MpmStore *result = MpmStoreLookup(de_ctx, &lookup);
    if (result == NULL) {
        SCLogDebug("new unique mpm for %s %s", am->name,
                am->direction == SIG_FLAG_TOSERVER ? "toserver" : "toclient");

        MpmStore *copy = SCCalloc(1, sizeof(MpmStore));
        if (copy == NULL)
            return NULL;
        uint8_t *sids = SCCalloc(1, sa->sids_array_size);
        if (sids == NULL) {
            SCFree(copy);
            return NULL;
        }

        memcpy(sids, sa->sids_array, sa->sids_array_size);
        copy->sid_array = sids;
        copy->sid_array_size = sa->sids_array_size;
        copy->buffer = MPMB_MAX;
        copy->direction = am->direction;
        copy->sm_list = am->sm_list;
        copy->sgh_mpm_context = am->sgh_mpm_context;

        MpmStoreSetup(de_ctx, copy);
        MpmStoreAdd(de_ctx, copy);
        return copy;
    } else {
        SCLogDebug("using existing mpm %p", result);
        return result;
    }
    return NULL;
}

static MpmStore *MpmStorePrepareBufferPkt(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        const DetectBufferMpmRegistery *am, const struct SidsArray *sa)
{
    SCLogDebug("handling %s for list %d", am->name,
            am->sm_list);

    if (sa->active == false || sa->sids_array_size == 0 || sa->sids_array == NULL)
        return NULL;

    MpmStore lookup = { sa->sids_array, sa->sids_array_size, SIG_FLAG_TOSERVER | SIG_FLAG_TOCLIENT,
        MPMB_MAX, am->sm_list, 0, NULL };
    SCLogDebug("am->sm_list %d", am->sm_list);

    MpmStore *result = MpmStoreLookup(de_ctx, &lookup);
    if (result == NULL) {
        SCLogDebug("new unique mpm for %s", am->name);

        MpmStore *copy = SCCalloc(1, sizeof(MpmStore));
        if (copy == NULL)
            return NULL;
        uint8_t *sids = SCCalloc(1, sa->sids_array_size);
        if (sids == NULL) {
            SCFree(copy);
            return NULL;
        }

        memcpy(sids, sa->sids_array, sa->sids_array_size);
        copy->sid_array = sids;
        copy->sid_array_size = sa->sids_array_size;
        copy->buffer = MPMB_MAX;
        copy->direction = SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT;
        copy->sm_list = am->sm_list;
        copy->sgh_mpm_context = am->sgh_mpm_context;

        MpmStoreSetup(de_ctx, copy);
        MpmStoreAdd(de_ctx, copy);
        return copy;
    } else {
        SCLogDebug("using existing mpm %p", result);
        return result;
    }
    return NULL;
}

static MpmStore *MpmStorePrepareBufferFrame(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        const DetectBufferMpmRegistery *am, const struct SidsArray *sa)
{
    SCLogDebug("handling %s for list %d", am->name, am->sm_list);

    if (sa->active == false || sa->sids_array_size == 0 || sa->sids_array == NULL)
        return NULL;

    MpmStore lookup = { sa->sids_array, sa->sids_array_size, am->direction, MPMB_MAX, am->sm_list,
        0, NULL };
    SCLogDebug("am->sm_list %d", am->sm_list);

    MpmStore *result = MpmStoreLookup(de_ctx, &lookup);
    if (result == NULL) {
        SCLogDebug("new unique mpm for %s", am->name);

        MpmStore *copy = SCCalloc(1, sizeof(MpmStore));
        if (copy == NULL)
            return NULL;
        uint8_t *sids = SCCalloc(1, sa->sids_array_size);
        if (sids == NULL) {
            SCFree(copy);
            return NULL;
        }

        memcpy(sids, sa->sids_array, sa->sids_array_size);
        copy->sid_array = sids;
        copy->sid_array_size = sa->sids_array_size;
        copy->buffer = MPMB_MAX;
        copy->direction = am->direction;
        copy->sm_list = am->sm_list;
        copy->sgh_mpm_context = am->sgh_mpm_context;

        MpmStoreSetup(de_ctx, copy);
        MpmStoreAdd(de_ctx, copy);
        return copy;
    } else {
        SCLogDebug("using existing mpm %p", result);
        return result;
    }
    return NULL;
}

static void SetRawReassemblyFlag(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    const Signature *s = NULL;
    uint32_t sig;

    for (sig = 0; sig < sgh->init->sig_cnt; sig++) {
        s = sgh->init->match_array[sig];
        if (s == NULL)
            continue;

        if (SignatureHasStreamContent(s) == 1) {
            sgh->flags |= SIG_GROUP_HEAD_HAVERAWSTREAM;
            SCLogDebug("rule group %p has SIG_GROUP_HEAD_HAVERAWSTREAM set", sgh);
            return;
        }
    }
    SCLogDebug("rule group %p does NOT have SIG_GROUP_HEAD_HAVERAWSTREAM set", sgh);
}

static void PrepareMpms(DetectEngineCtx *de_ctx, SigGroupHead *sh)
{
    const int max_buffer_id = de_ctx->buffer_type_id + 1;
    struct SidsArray sids[max_buffer_id][2];
    memset(sids, 0, sizeof(sids));
    const uint32_t max_sid = DetectEngineGetMaxSigId(de_ctx) / 8 + 1;

    /* flag the list+directions we have engines for as active */
    for (DetectBufferMpmRegistery *a = de_ctx->pkt_mpms_list; a != NULL; a = a->next) {
        struct SidsArray *sa = &sids[a->sm_list][0];
        sa->active = true;
        sa->type = a->type;
    }
    for (DetectBufferMpmRegistery *a = de_ctx->frame_mpms_list; a != NULL; a = a->next) {
        sids[a->sm_list][0].type = a->type;
        if ((a->direction == SIG_FLAG_TOSERVER) && SGH_DIRECTION_TS(sh)) {
            struct SidsArray *sa = &sids[a->sm_list][0];
            sa->active = true;
        }
        if ((a->direction == SIG_FLAG_TOCLIENT) && SGH_DIRECTION_TC(sh)) {
            struct SidsArray *sa = &sids[a->sm_list][1];
            sa->active = true;
        }
    }
    for (DetectBufferMpmRegistery *a = de_ctx->app_mpms_list; a != NULL; a = a->next) {
        sids[a->sm_list][0].type = a->type;
        if ((a->direction == SIG_FLAG_TOSERVER) && SGH_DIRECTION_TS(sh)) {
            struct SidsArray *sa = &sids[a->sm_list][0];
            sa->active = true;
        }
        if ((a->direction == SIG_FLAG_TOCLIENT) && SGH_DIRECTION_TC(sh)) {
            struct SidsArray *sa = &sids[a->sm_list][1];
            sa->active = true;
        }
    }

    for (uint32_t sig = 0; sig < sh->init->sig_cnt; sig++) {
        const Signature *s = sh->init->match_array[sig];
        if (s == NULL)
            continue;
        if (s->init_data->mpm_sm == NULL)
            continue;
        const int list = s->init_data->mpm_sm_list;
        if (list < 0)
            continue;
        if (list == DETECT_SM_LIST_PMATCH)
            continue;

        switch (sids[list][0].type) {
            /* app/frame engines are direction aware */
            case DETECT_BUFFER_MPM_TYPE_FRAME:
            case DETECT_BUFFER_MPM_TYPE_APP:
                if (s->flags & SIG_FLAG_TOSERVER) {
                    struct SidsArray *sa = &sids[list][0];
                    if (sa->active) {
                        if (sa->sids_array == NULL) {
                            sa->sids_array = SCCalloc(1, max_sid);
                            sa->sids_array_size = max_sid;
                            BUG_ON(sa->sids_array == NULL); // TODO
                        }
                        sa->sids_array[s->num / 8] |= 1 << (s->num % 8);
                    }
                }
                if (s->flags & SIG_FLAG_TOCLIENT) {
                    struct SidsArray *sa = &sids[list][1];
                    if (sa->active) {
                        if (sa->sids_array == NULL) {
                            sa->sids_array = SCCalloc(1, max_sid);
                            sa->sids_array_size = max_sid;
                            BUG_ON(sa->sids_array == NULL); // TODO
                        }
                        sa->sids_array[s->num / 8] |= 1 << (s->num % 8);
                    }
                }
                break;
            /* pkt engines are directionless, so only use index 0 */
            case DETECT_BUFFER_MPM_TYPE_PKT: {
                struct SidsArray *sa = &sids[list][0];
                if (sa->active) {
                    if (sa->sids_array == NULL) {
                        sa->sids_array = SCCalloc(1, max_sid);
                        sa->sids_array_size = max_sid;
                        BUG_ON(sa->sids_array == NULL); // TODO
                    }
                    sa->sids_array[s->num / 8] |= 1 << (s->num % 8);
                }
                break;
            }
            default:
                abort();
                break;
        }
    }

    sh->init->app_mpms = SCCalloc(de_ctx->app_mpms_list_cnt, sizeof(MpmCtx *));
    BUG_ON(sh->init->app_mpms == NULL);

    sh->init->pkt_mpms = SCCalloc(de_ctx->pkt_mpms_list_cnt, sizeof(MpmCtx *));
    BUG_ON(sh->init->pkt_mpms == NULL);

    sh->init->frame_mpms = SCCalloc(de_ctx->frame_mpms_list_cnt, sizeof(MpmCtx *));
    BUG_ON(sh->init->frame_mpms == NULL);

    for (DetectBufferMpmRegistery *a = de_ctx->pkt_mpms_list; a != NULL; a = a->next) {
        struct SidsArray *sa = &sids[a->sm_list][0];

        MpmStore *mpm_store = MpmStorePrepareBufferPkt(de_ctx, sh, a, sa);
        if (mpm_store != NULL) {
            sh->init->pkt_mpms[a->id] = mpm_store->mpm_ctx;

            SCLogDebug("a %p a->name %s a->reg->PrefilterRegisterWithListId %p "
                    "mpm_store->mpm_ctx %p", a, a->name,
                    a->PrefilterRegisterWithListId, mpm_store->mpm_ctx);

            /* if we have just certain types of negated patterns,
             * mpm_ctx can be NULL */
            if (a->PrefilterRegisterWithListId && mpm_store->mpm_ctx) {
                BUG_ON(a->PrefilterRegisterWithListId(de_ctx,
                            sh, mpm_store->mpm_ctx,
                            a, a->sm_list) != 0);
                SCLogDebug("mpm %s %d set up", a->name, a->sm_list);
            }
        }
    }
    for (DetectBufferMpmRegistery *a = de_ctx->frame_mpms_list; a != NULL; a = a->next) {
        if ((a->direction == SIG_FLAG_TOSERVER && SGH_DIRECTION_TS(sh)) ||
                (a->direction == SIG_FLAG_TOCLIENT && SGH_DIRECTION_TC(sh))) {
            const int dir = a->direction == SIG_FLAG_TOCLIENT;
            struct SidsArray *sa = &sids[a->sm_list][dir];

            SCLogDebug("a %s direction %d PrefilterRegisterWithListId %p", a->name, a->direction,
                    a->PrefilterRegisterWithListId);
            MpmStore *mpm_store = MpmStorePrepareBufferFrame(de_ctx, sh, a, sa);
            if (mpm_store != NULL) {
                sh->init->frame_mpms[a->id] = mpm_store->mpm_ctx;

                SCLogDebug("a %p a->name %s a->reg->PrefilterRegisterWithListId %p "
                           "mpm_store->mpm_ctx %p",
                        a, a->name, a->PrefilterRegisterWithListId, mpm_store->mpm_ctx);

                /* if we have just certain types of negated patterns,
                 * mpm_ctx can be NULL */
                SCLogDebug("mpm_store %p mpm_ctx %p", mpm_store, mpm_store->mpm_ctx);
                if (a->PrefilterRegisterWithListId && mpm_store->mpm_ctx) {
                    BUG_ON(a->PrefilterRegisterWithListId(
                                   de_ctx, sh, mpm_store->mpm_ctx, a, a->sm_list) != 0);
                    SCLogDebug("mpm %s %d set up", a->name, a->sm_list);
                }
            }
        }
    }
    for (DetectBufferMpmRegistery *a = de_ctx->app_mpms_list; a != NULL; a = a->next) {
        if ((a->direction == SIG_FLAG_TOSERVER && SGH_DIRECTION_TS(sh)) ||
                (a->direction == SIG_FLAG_TOCLIENT && SGH_DIRECTION_TC(sh))) {
            const int dir = a->direction == SIG_FLAG_TOCLIENT;
            struct SidsArray *sa = &sids[a->sm_list][dir];

            MpmStore *mpm_store = MpmStorePrepareBufferAppLayer(de_ctx, sh, a, sa);
            if (mpm_store != NULL) {
                sh->init->app_mpms[a->id] = mpm_store->mpm_ctx;

                SCLogDebug("a %p a->name %s a->PrefilterRegisterWithListId %p "
                           "mpm_store->mpm_ctx %p",
                        a, a->name, a->PrefilterRegisterWithListId, mpm_store->mpm_ctx);

                /* if we have just certain types of negated patterns,
                 * mpm_ctx can be NULL */
                if (a->PrefilterRegisterWithListId && mpm_store->mpm_ctx) {
                    BUG_ON(a->PrefilterRegisterWithListId(
                                   de_ctx, sh, mpm_store->mpm_ctx, a, a->sm_list) != 0);
                    SCLogDebug("mpm %s %d set up", a->name, a->sm_list);
                }
            }
        }
    }

    /* free temp sig arrays */
    for (int i = 0; i < max_buffer_id; i++) {
        struct SidsArray *sa;
        sa = &sids[i][0];
        if (sa->sids_array != NULL)
            SCFree(sa->sids_array);
        sa = &sids[i][1];
        if (sa->sids_array != NULL)
            SCFree(sa->sids_array);
    }
}

/** \brief Prepare the pattern matcher ctx in a sig group head.
 *
 */
int PatternMatchPrepareGroup(DetectEngineCtx *de_ctx, SigGroupHead *sh)
{
    MpmStore *mpm_store = NULL;
    if (SGH_PROTO(sh, IPPROTO_TCP)) {
        if (SGH_DIRECTION_TS(sh)) {
            mpm_store = MpmStorePrepareBuffer(de_ctx, sh, MPMB_TCP_PKT_TS);
            if (mpm_store != NULL) {
                PrefilterPktPayloadRegister(de_ctx, sh, mpm_store->mpm_ctx);
            }

            mpm_store = MpmStorePrepareBuffer(de_ctx, sh, MPMB_TCP_STREAM_TS);
            if (mpm_store != NULL) {
                PrefilterPktStreamRegister(de_ctx, sh, mpm_store->mpm_ctx);
            }

            SetRawReassemblyFlag(de_ctx, sh);
        }
        if (SGH_DIRECTION_TC(sh)) {
            mpm_store = MpmStorePrepareBuffer(de_ctx, sh, MPMB_TCP_PKT_TC);
            if (mpm_store != NULL) {
                PrefilterPktPayloadRegister(de_ctx, sh, mpm_store->mpm_ctx);
            }

            mpm_store = MpmStorePrepareBuffer(de_ctx, sh, MPMB_TCP_STREAM_TC);
            if (mpm_store != NULL) {
                PrefilterPktStreamRegister(de_ctx, sh, mpm_store->mpm_ctx);
            }

            SetRawReassemblyFlag(de_ctx, sh);
       }
    } else if (SGH_PROTO(sh, IPPROTO_UDP)) {
        if (SGH_DIRECTION_TS(sh)) {
            mpm_store = MpmStorePrepareBuffer(de_ctx, sh, MPMB_UDP_TS);
            if (mpm_store != NULL) {
                PrefilterPktPayloadRegister(de_ctx, sh, mpm_store->mpm_ctx);
            }
        }
        if (SGH_DIRECTION_TC(sh)) {
            mpm_store = MpmStorePrepareBuffer(de_ctx, sh, MPMB_UDP_TC);
            if (mpm_store != NULL) {
                PrefilterPktPayloadRegister(de_ctx, sh, mpm_store->mpm_ctx);
            }
        }
    } else {
        mpm_store = MpmStorePrepareBuffer(de_ctx, sh, MPMB_OTHERIP);
        if (mpm_store != NULL) {
            PrefilterPktPayloadRegister(de_ctx, sh, mpm_store->mpm_ctx);
        }
    }

    PrepareMpms(de_ctx, sh);
    return 0;
}

static inline uint32_t ContentFlagsForHash(const DetectContentData *cd)
{
    return cd->flags & (DETECT_CONTENT_NOCASE | DETECT_CONTENT_OFFSET | DETECT_CONTENT_DEPTH |
                               DETECT_CONTENT_NEGATED | DETECT_CONTENT_ENDS_WITH);
}

/** \internal
 *  \brief The hash function for Pattern. Hashes pattern after chop is applied.
 *
 *  \param ht      Pointer to the hash table.
 *  \param data    Pointer to the Pattern.
 *  \param datalen Not used in our case.
 *
 *  \retval hash The generated hash value.
 */
static uint32_t PatternChopHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    const DetectPatternTracker *p = (DetectPatternTracker *)data;
    uint32_t hash = p->sm_list + ContentFlagsForHash(p->cd);
    uint16_t content_len = p->cd->content_len;
    const uint8_t *content = p->cd->content;
    if (p->cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
        content += p->cd->fp_chop_offset;
        content_len = p->cd->fp_chop_len;
    }
    hash += StringHashDjb2(content, content_len);
    return hash % ht->array_size;
}

/** \internal
 *  \brief The hash function for Pattern. Ignores chop.
 *
 *  \param ht      Pointer to the hash table.
 *  \param data    Pointer to the Pattern.
 *  \param datalen Not used in our case.
 *
 *  \retval hash The generated hash value.
 */
static uint32_t PatternNoChopHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    const DetectPatternTracker *p = (DetectPatternTracker *)data;
    uint32_t hash = p->sm_list + ContentFlagsForHash(p->cd);
    hash += StringHashDjb2(p->cd->content, p->cd->content_len);
    return hash % ht->array_size;
}

/**
 * \brief The Compare function for Pattern. Compares patterns after chop is applied.
 *
 * \param data1 Pointer to the first Pattern.
 * \param len1  Not used.
 * \param data2 Pointer to the second Pattern.
 * \param len2  Not used.
 *
 * \retval 1 If the 2 Patterns sent as args match.
 * \retval 0 If the 2 Patterns sent as args do not match.
 */
static char PatternChopCompareFunc(void *data1, uint16_t len1, void *data2, uint16_t len2)
{
    const DetectPatternTracker *p1 = (DetectPatternTracker *)data1;
    const DetectPatternTracker *p2 = (DetectPatternTracker *)data2;

    if (p1->sm_list != p2->sm_list)
        return 0;

    if (ContentFlagsForHash(p1->cd) != ContentFlagsForHash(p2->cd))
        return 0;

    uint16_t p1_content_len = p1->cd->content_len;
    uint8_t *p1_content = p1->cd->content;
    if (p1->cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
        p1_content += p1->cd->fp_chop_offset;
        p1_content_len = p1->cd->fp_chop_len;
    }
    uint16_t p2_content_len = p2->cd->content_len;
    uint8_t *p2_content = p2->cd->content;
    if (p2->cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
        p2_content += p2->cd->fp_chop_offset;
        p2_content_len = p2->cd->fp_chop_len;
    }

    if (p1_content_len != p2_content_len)
        return 0;

    if (memcmp(p1_content, p2_content, p1_content_len) != 0) {
        return 0;
    }

    return 1;
}

/**
 * \brief The Compare function for Pattern. Ignores chop settings
 *
 * \param data1 Pointer to the first Pattern.
 * \param len1  Not used.
 * \param data2 Pointer to the second Pattern.
 * \param len2  Not used.
 *
 * \retval 1 If the 2 Patterns sent as args match.
 * \retval 0 If the 2 Patterns sent as args do not match.
 */
static char PatternNoChopCompareFunc(void *data1, uint16_t len1, void *data2, uint16_t len2)
{
    const DetectPatternTracker *p1 = (DetectPatternTracker *)data1;
    const DetectPatternTracker *p2 = (DetectPatternTracker *)data2;

    if (p1->sm_list != p2->sm_list)
        return 0;

    if (ContentFlagsForHash(p1->cd) != ContentFlagsForHash(p2->cd))
        return 0;

    if (p1->cd->content_len != p2->cd->content_len)
        return 0;

    if (memcmp(p1->cd->content, p2->cd->content, p1->cd->content_len) != 0) {
        return 0;
    }

    return 1;
}

static void PatternFreeFunc(void *ptr)
{
    SCFree(ptr);
}

/**
 * \brief Figure out the FP and their respective content ids for all the
 *        sigs in the engine.
 *
 * \param de_ctx Detection engine context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int DetectSetFastPatternAndItsId(DetectEngineCtx *de_ctx)
{
    uint32_t cnt = 0;
    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        if (s->flags & SIG_FLAG_PREFILTER)
            continue;

        RetrieveFPForSig(de_ctx, s);
        if (s->init_data->mpm_sm != NULL) {
            s->flags |= SIG_FLAG_PREFILTER;
            cnt++;
        }
    }
    /* no mpm rules */
    if (cnt == 0)
        return 0;

    HashListTable *ht =
            HashListTableInit(4096, PatternChopHashFunc, PatternChopCompareFunc, PatternFreeFunc);
    BUG_ON(ht == NULL);
    PatIntId max_id = 0;

    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        if (s->init_data->mpm_sm == NULL)
            continue;

        const int sm_list = s->init_data->mpm_sm_list;
        BUG_ON(sm_list == -1);

        DetectContentData *cd = (DetectContentData *)s->init_data->mpm_sm->ctx;

        DetectPatternTracker lookup = { .cd = cd, .sm_list = sm_list, .cnt = 0, .mpm = 0 };
        DetectPatternTracker *res = HashListTableLookup(ht, &lookup, 0);
        if (res) {
            res->cnt++;
            res->mpm += ((cd->flags & DETECT_CONTENT_MPM) != 0);

            cd->id = res->cd->id;
            SCLogDebug("%u: res id %u cnt %u", s->id, res->cd->id, res->cnt);
        } else {
            DetectPatternTracker *add = SCCalloc(1, sizeof(*add));
            BUG_ON(add == NULL);
            add->cd = cd;
            add->sm_list = sm_list;
            add->cnt = 1;
            add->mpm = ((cd->flags & DETECT_CONTENT_MPM) != 0);
            HashListTableAdd(ht, (void *)add, 0);

            cd->id = max_id++;
            SCLogDebug("%u: add id %u cnt %u", s->id, add->cd->id, add->cnt);
        }
    }

    de_ctx->max_fp_id = max_id;

    HashListTableFree(ht);

    return 0;
}

/** \brief add all patterns on our stats hash
 *  Used to fill the hash later used by DumpPatterns()
 *  \note sets up the hash table on first call
 */
void EngineAnalysisAddAllRulePatterns(DetectEngineCtx *de_ctx, const Signature *s)
{
    if (de_ctx->pattern_hash_table == NULL) {
        de_ctx->pattern_hash_table = HashListTableInit(
                4096, PatternNoChopHashFunc, PatternNoChopCompareFunc, PatternFreeFunc);
        BUG_ON(de_ctx->pattern_hash_table == NULL);
    }
    if (s->sm_arrays[DETECT_SM_LIST_PMATCH]) {
        SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_PMATCH];
        do {
            switch (smd->type) {
                case DETECT_CONTENT: {
                    const DetectContentData *cd = (const DetectContentData *)smd->ctx;
                    DetectPatternTracker lookup = {
                        .cd = cd, .sm_list = DETECT_SM_LIST_PMATCH, .cnt = 0, .mpm = 0
                    };
                    DetectPatternTracker *res =
                            HashListTableLookup(de_ctx->pattern_hash_table, &lookup, 0);
                    if (res) {
                        res->cnt++;
                        res->mpm += ((cd->flags & DETECT_CONTENT_MPM) != 0);
                    } else {
                        DetectPatternTracker *add = SCCalloc(1, sizeof(*add));
                        BUG_ON(add == NULL);
                        add->cd = cd;
                        add->sm_list = DETECT_SM_LIST_PMATCH;
                        add->cnt = 1;
                        add->mpm = ((cd->flags & DETECT_CONTENT_MPM) != 0);
                        HashListTableAdd(de_ctx->pattern_hash_table, (void *)add, 0);
                    }
                    break;
                }
            }
            if (smd->is_last)
                break;
            smd++;
        } while (1);
    }

    const DetectEngineAppInspectionEngine *app = s->app_inspect;
    for (; app != NULL; app = app->next) {
        SigMatchData *smd = app->smd;
        do {
            switch (smd->type) {
                case DETECT_CONTENT: {
                    const DetectContentData *cd = (const DetectContentData *)smd->ctx;

                    DetectPatternTracker lookup = {
                        .cd = cd, .sm_list = app->sm_list, .cnt = 0, .mpm = 0
                    };
                    DetectPatternTracker *res =
                            HashListTableLookup(de_ctx->pattern_hash_table, &lookup, 0);
                    if (res) {
                        res->cnt++;
                        res->mpm += ((cd->flags & DETECT_CONTENT_MPM) != 0);
                    } else {
                        DetectPatternTracker *add = SCCalloc(1, sizeof(*add));
                        BUG_ON(add == NULL);
                        add->cd = cd;
                        add->sm_list = app->sm_list;
                        add->cnt = 1;
                        add->mpm = ((cd->flags & DETECT_CONTENT_MPM) != 0);
                        HashListTableAdd(de_ctx->pattern_hash_table, (void *)add, 0);
                    }
                    break;
                }
            }
            if (smd->is_last)
                break;
            smd++;
        } while (1);
    }
    const DetectEnginePktInspectionEngine *pkt = s->pkt_inspect;
    for (; pkt != NULL; pkt = pkt->next) {
        SigMatchData *smd = pkt->smd;
        do {
            if (smd == NULL) {
                BUG_ON(!(pkt->sm_list < DETECT_SM_LIST_DYNAMIC_START));
                smd = s->sm_arrays[pkt->sm_list];
            }
            switch (smd->type) {
                case DETECT_CONTENT: {
                    const DetectContentData *cd = (const DetectContentData *)smd->ctx;

                    DetectPatternTracker lookup = {
                        .cd = cd, .sm_list = pkt->sm_list, .cnt = 0, .mpm = 0
                    };
                    DetectPatternTracker *res =
                            HashListTableLookup(de_ctx->pattern_hash_table, &lookup, 0);
                    if (res) {
                        res->cnt++;
                        res->mpm += ((cd->flags & DETECT_CONTENT_MPM) != 0);
                    } else {
                        DetectPatternTracker *add = SCCalloc(1, sizeof(*add));
                        BUG_ON(add == NULL);
                        add->cd = cd;
                        add->sm_list = pkt->sm_list;
                        add->cnt = 1;
                        add->mpm = ((cd->flags & DETECT_CONTENT_MPM) != 0);
                        HashListTableAdd(de_ctx->pattern_hash_table, (void *)add, 0);
                    }
                    break;
                }
            }
            if (smd->is_last)
                break;
            smd++;
        } while (1);
    }
    const DetectEngineFrameInspectionEngine *frame = s->frame_inspect;
    for (; frame != NULL; frame = frame->next) {
        SigMatchData *smd = frame->smd;
        do {
            if (smd == NULL) {
                BUG_ON(!(frame->sm_list < DETECT_SM_LIST_DYNAMIC_START));
                smd = s->sm_arrays[frame->sm_list];
            }
            switch (smd->type) {
                case DETECT_CONTENT: {
                    const DetectContentData *cd = (const DetectContentData *)smd->ctx;

                    DetectPatternTracker lookup = {
                        .cd = cd, .sm_list = frame->sm_list, .cnt = 0, .mpm = 0
                    };
                    DetectPatternTracker *res =
                            HashListTableLookup(de_ctx->pattern_hash_table, &lookup, 0);
                    if (res) {
                        res->cnt++;
                        res->mpm += ((cd->flags & DETECT_CONTENT_MPM) != 0);
                    } else {
                        DetectPatternTracker *add = SCCalloc(1, sizeof(*add));
                        BUG_ON(add == NULL);
                        add->cd = cd;
                        add->sm_list = frame->sm_list;
                        add->cnt = 1;
                        add->mpm = ((cd->flags & DETECT_CONTENT_MPM) != 0);
                        HashListTableAdd(de_ctx->pattern_hash_table, (void *)add, 0);
                    }
                    break;
                }
            }
            if (smd->is_last)
                break;
            smd++;
        } while (1);
    }
}
