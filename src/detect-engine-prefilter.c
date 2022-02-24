/* Copyright (C) 2016-2021 Open Information Security Foundation
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
 *
 * Prefilter engine
 *
 * Prefilter engines have as purpose to check for a critical common part of
 * a set of rules. If the condition is present in the traffic, the rules
 * will have to be inspected individually. Otherwise, the rules can be
 * skipped.
 *
 * The best example of this is the MPM. From each rule take a pattern and
 * add it to the MPM state machine. Inspect that in one step and only
 * individually inspect the rules that had a match in MPM.
 *
 * This prefilter API is designed to abstract this logic so that it becomes
 * easier to add other types of prefilters.
 *
 * The prefilter engines are structured as a simple list of engines. Each
 * engine checks for a condition using it's callback function and private
 * data. It then adds the rule match candidates to the PrefilterRuleStore
 * structure.
 *
 * After the engines have run the resulting list of match candidates is
 * sorted by the rule id's so that the individual inspection happens in
 * the correct order.
 */

#include "suricata-common.h"
#include "suricata.h"

#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-mpm.h"
#include "detect-engine-frame.h"

#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "util-profiling.h"
#include "util-validate.h"

static int PrefilterStoreGetId(DetectEngineCtx *de_ctx,
        const char *name, void (*FreeFunc)(void *));
static const PrefilterStore *PrefilterStoreGetStore(const DetectEngineCtx *de_ctx,
        const uint32_t id);

static inline void QuickSortSigIntId(SigIntId *sids, uint32_t n)
{
    if (n < 2)
        return;
    SigIntId p = sids[n / 2];
    SigIntId *l = sids;
    SigIntId *r = sids + n - 1;
    while (l <= r) {
        if (*l < p)
            l++;
        else if (*r > p)
            r--;
        else {
            SigIntId t = *l;
            *l = *r;
            *r = t;
            l++;
            r--;
        }
    }
    QuickSortSigIntId(sids, r - sids + 1);
    QuickSortSigIntId(l, sids + n - l);
}

/**
 * \brief run prefilter engines on a transaction
 */
void DetectRunPrefilterTx(DetectEngineThreadCtx *det_ctx,
        const SigGroupHead *sgh,
        Packet *p,
        const uint8_t ipproto,
        const uint8_t flow_flags,
        const AppProto alproto,
        void *alstate,
        DetectTransaction *tx)
{
    /* reset rule store */
    det_ctx->pmq.rule_id_array_cnt = 0;

    SCLogDebug("packet %" PRIu64 " tx %p progress %d tx->prefilter_flags %" PRIx64, p->pcap_cnt,
            tx->tx_ptr, tx->tx_progress, tx->prefilter_flags);

    PrefilterEngine *engine = sgh->tx_engines;
    do {
        if (engine->alproto != alproto)
            goto next;
        if (engine->ctx.tx_min_progress > tx->tx_progress)
            break;
        if (tx->tx_progress > engine->ctx.tx_min_progress) {
            if (tx->prefilter_flags & BIT_U64(engine->ctx.tx_min_progress)) {
                goto next;
            }
        }

        PREFILTER_PROFILING_START;
        engine->cb.PrefilterTx(det_ctx, engine->pectx,
                p, p->flow, tx->tx_ptr, tx->tx_id, flow_flags);
        PREFILTER_PROFILING_END(det_ctx, engine->gid);

        if (tx->tx_progress > engine->ctx.tx_min_progress && engine->is_last_for_progress) {
            tx->prefilter_flags |= BIT_U64(engine->ctx.tx_min_progress);
        }
    next:
        if (engine->is_last)
            break;
        engine++;
    } while (1);

    /* Sort the rule list to lets look at pmq.
     * NOTE due to merging of 'stream' pmqs we *MAY* have duplicate entries */
    if (likely(det_ctx->pmq.rule_id_array_cnt > 1)) {
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_SORT1);
        QuickSortSigIntId(det_ctx->pmq.rule_id_array, det_ctx->pmq.rule_id_array_cnt);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_SORT1);
    }
}

void Prefilter(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh,
        Packet *p, const uint8_t flags)
{
    SCEnter();
#if 0
    /* TODO review this check */
    SCLogDebug("sgh %p frame_engines %p", sgh, sgh->frame_engines);
    if (p->proto == IPPROTO_TCP && sgh->frame_engines && p->flow &&
            p->flow->alproto != ALPROTO_UNKNOWN && p->flow->alparser != NULL) {
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_RECORD);
        PrefilterFrames(det_ctx, sgh, p, flags, p->flow->alproto);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_RECORD);
    }
#endif
    if (sgh->pkt_engines) {
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_PKT);
        /* run packet engines */
        PrefilterEngine *engine = sgh->pkt_engines;
        do {
            PREFILTER_PROFILING_START;
            engine->cb.Prefilter(det_ctx, p, engine->pectx);
            PREFILTER_PROFILING_END(det_ctx, engine->gid);

            if (engine->is_last)
                break;
            engine++;
        } while (1);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_PKT);
    }

    /* run payload inspecting engines */
    if (sgh->payload_engines &&
        (p->payload_len || (p->flags & PKT_DETECT_HAS_STREAMDATA)) &&
        !(p->flags & PKT_NOPAYLOAD_INSPECTION))
    {
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_PAYLOAD);
        PrefilterEngine *engine = sgh->payload_engines;
        while (1) {
            PREFILTER_PROFILING_START;
            engine->cb.Prefilter(det_ctx, p, engine->pectx);
            PREFILTER_PROFILING_END(det_ctx, engine->gid);

            if (engine->is_last)
                break;
            engine++;
        }
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_PAYLOAD);
    }

    /* Sort the rule list to lets look at pmq.
     * NOTE due to merging of 'stream' pmqs we *MAY* have duplicate entries */
    if (likely(det_ctx->pmq.rule_id_array_cnt > 1)) {
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_SORT1);
        QuickSortSigIntId(det_ctx->pmq.rule_id_array, det_ctx->pmq.rule_id_array_cnt);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_SORT1);
    }
    SCReturn;
}

int PrefilterAppendEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        void (*PrefilterFunc)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx),
        void *pectx, void (*FreeFunc)(void *pectx),
        const char *name)
{
    if (sgh == NULL || PrefilterFunc == NULL || pectx == NULL)
        return -1;

    PrefilterEngineList *e = SCMallocAligned(sizeof(*e), CLS);
    if (e == NULL)
        return -1;
    memset(e, 0x00, sizeof(*e));

    e->Prefilter = PrefilterFunc;
    e->pectx = pectx;
    e->Free = FreeFunc;

    if (sgh->init->pkt_engines == NULL) {
        sgh->init->pkt_engines = e;
    } else {
        PrefilterEngineList *t = sgh->init->pkt_engines;
        while (t->next != NULL) {
            t = t->next;
        }

        t->next = e;
        e->id = t->id + 1;
    }

    e->name = name;
    e->gid = PrefilterStoreGetId(de_ctx, e->name, e->Free);
    return 0;
}

int PrefilterAppendPayloadEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        void (*PrefilterFunc)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx),
        void *pectx, void (*FreeFunc)(void *pectx),
        const char *name)
{
    if (sgh == NULL || PrefilterFunc == NULL || pectx == NULL)
        return -1;

    PrefilterEngineList *e = SCMallocAligned(sizeof(*e), CLS);
    if (e == NULL)
        return -1;
    memset(e, 0x00, sizeof(*e));

    e->Prefilter = PrefilterFunc;
    e->pectx = pectx;
    e->Free = FreeFunc;

    if (sgh->init->payload_engines == NULL) {
        sgh->init->payload_engines = e;
    } else {
        PrefilterEngineList *t = sgh->init->payload_engines;
        while (t->next != NULL) {
            t = t->next;
        }

        t->next = e;
        e->id = t->id + 1;
    }

    e->name = name;
    e->gid = PrefilterStoreGetId(de_ctx, e->name, e->Free);
    return 0;
}

int PrefilterAppendTxEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        void (*PrefilterTxFunc)(DetectEngineThreadCtx *det_ctx, const void *pectx,
            Packet *p, Flow *f, void *tx,
            const uint64_t idx, const uint8_t flags),
        AppProto alproto, int tx_min_progress,
        void *pectx, void (*FreeFunc)(void *pectx),
        const char *name)
{
    if (sgh == NULL || PrefilterTxFunc == NULL || pectx == NULL)
        return -1;

    PrefilterEngineList *e = SCMallocAligned(sizeof(*e), CLS);
    if (e == NULL)
        return -1;
    memset(e, 0x00, sizeof(*e));

    e->PrefilterTx = PrefilterTxFunc;
    e->pectx = pectx;
    e->alproto = alproto;
    e->tx_min_progress = tx_min_progress;
    e->Free = FreeFunc;

    if (sgh->init->tx_engines == NULL) {
        sgh->init->tx_engines = e;
    } else {
        PrefilterEngineList *t = sgh->init->tx_engines;
        while (t->next != NULL) {
            t = t->next;
        }

        t->next = e;
        e->id = t->id + 1;
    }

    e->name = name;
    e->gid = PrefilterStoreGetId(de_ctx, e->name, e->Free);
    return 0;
}

int PrefilterAppendFrameEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        PrefilterFrameFn PrefilterFrameFunc, AppProto alproto, uint8_t frame_type, void *pectx,
        void (*FreeFunc)(void *pectx), const char *name)
{
    if (sgh == NULL || PrefilterFrameFunc == NULL || pectx == NULL)
        return -1;

    PrefilterEngineList *e = SCMallocAligned(sizeof(*e), CLS);
    if (e == NULL)
        return -1;
    memset(e, 0x00, sizeof(*e));

    e->frame_type = frame_type;
    e->alproto = alproto;
    e->PrefilterFrame = PrefilterFrameFunc;
    e->pectx = pectx;
    e->Free = FreeFunc;

    if (sgh->init->frame_engines == NULL) {
        sgh->init->frame_engines = e;
    } else {
        PrefilterEngineList *t = sgh->init->frame_engines;
        while (t->next != NULL) {
            t = t->next;
        }

        t->next = e;
        e->id = t->id + 1;
    }

    e->name = name;
    e->gid = PrefilterStoreGetId(de_ctx, e->name, e->Free);
    return 0;
}

static void PrefilterFreeEngineList(PrefilterEngineList *e)
{
    if (e->Free && e->pectx) {
        e->Free(e->pectx);
    }
    SCFreeAligned(e);
}

void PrefilterFreeEnginesList(PrefilterEngineList *list)
{
    PrefilterEngineList *t = list;

    while (t != NULL) {
        PrefilterEngineList *next = t->next;
        PrefilterFreeEngineList(t);
        t = next;
    }
}

static void PrefilterFreeEngines(const DetectEngineCtx *de_ctx, PrefilterEngine *list)
{
    PrefilterEngine *t = list;

    while (1) {
        const PrefilterStore *s = PrefilterStoreGetStore(de_ctx, t->gid);
        if (s && s->FreeFunc && t->pectx) {
            s->FreeFunc(t->pectx);
        }

        if (t->is_last)
            break;
        t++;
    }
    SCFreeAligned(list);
}

void PrefilterCleanupRuleGroup(const DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    if (sgh->pkt_engines) {
        PrefilterFreeEngines(de_ctx, sgh->pkt_engines);
        sgh->pkt_engines = NULL;
    }
    if (sgh->payload_engines) {
        PrefilterFreeEngines(de_ctx, sgh->payload_engines);
        sgh->payload_engines = NULL;
    }
    if (sgh->tx_engines) {
        PrefilterFreeEngines(de_ctx, sgh->tx_engines);
        sgh->tx_engines = NULL;
    }
    if (sgh->frame_engines) {
        PrefilterFreeEngines(de_ctx, sgh->frame_engines);
        sgh->frame_engines = NULL;
    }
}

static int PrefilterSetupRuleGroupSortHelper(const void *a, const void *b)
{
    const PrefilterEngine *s0 = a;
    const PrefilterEngine *s1 = b;
    if (s1->ctx.tx_min_progress == s0->ctx.tx_min_progress) {
        if (s1->alproto == s0->alproto) {
            return s0->local_id > s1->local_id ? 1 : -1;
        } else {
            return s0->alproto > s1->alproto ? 1 : -1;
        }
    } else {
        return s0->ctx.tx_min_progress > s1->ctx.tx_min_progress ? 1 : -1;
    }
}

void PrefilterSetupRuleGroup(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    int r = PatternMatchPrepareGroup(de_ctx, sgh);
    if (r != 0) {
        FatalError(SC_ERR_INITIALIZATION, "failed to set up pattern matching");
    }

    /* set up engines if needed - when prefilter is set to auto we run
     * all engines, otherwise only those that have been forced by the
     * prefilter keyword. */
    const enum DetectEnginePrefilterSetting setting = de_ctx->prefilter_setting;
    for (int i = 0; i < DETECT_TBLSIZE; i++)
    {
        if (sigmatch_table[i].SetupPrefilter != NULL &&
                (setting == DETECT_PREFILTER_AUTO ||
                 de_ctx->sm_types_prefilter[i]))
        {
            sigmatch_table[i].SetupPrefilter(de_ctx, sgh);
        }
    }

    /* we have lists of engines in sgh->init now. Lets setup the
     * match arrays */
    PrefilterEngineList *el;
    if (sgh->init->pkt_engines != NULL) {
        uint32_t cnt = 0;
        for (el = sgh->init->pkt_engines ; el != NULL; el = el->next) {
            cnt++;
            de_ctx->prefilter_maxid = MAX(de_ctx->prefilter_maxid, el->gid);
        }
        sgh->pkt_engines = SCMallocAligned(cnt * sizeof(PrefilterEngine), CLS);
        if (sgh->pkt_engines == NULL) {
            return;
        }
        memset(sgh->pkt_engines, 0x00, (cnt * sizeof(PrefilterEngine)));

        PrefilterEngine *e = sgh->pkt_engines;
        for (el = sgh->init->pkt_engines ; el != NULL; el = el->next) {
            e->local_id = el->id;
            e->cb.Prefilter = el->Prefilter;
            e->pectx = el->pectx;
            el->pectx = NULL; // e now owns the ctx
            e->gid = el->gid;
            if (el->next == NULL) {
                e->is_last = TRUE;
            }
            e++;
        }
    }
    if (sgh->init->payload_engines != NULL) {
        uint32_t cnt = 0;
        for (el = sgh->init->payload_engines ; el != NULL; el = el->next) {
            cnt++;
            de_ctx->prefilter_maxid = MAX(de_ctx->prefilter_maxid, el->gid);
        }
        sgh->payload_engines = SCMallocAligned(cnt * sizeof(PrefilterEngine), CLS);
        if (sgh->payload_engines == NULL) {
            return;
        }
        memset(sgh->payload_engines, 0x00, (cnt * sizeof(PrefilterEngine)));

        PrefilterEngine *e = sgh->payload_engines;
        for (el = sgh->init->payload_engines ; el != NULL; el = el->next) {
            e->local_id = el->id;
            e->cb.Prefilter = el->Prefilter;
            e->pectx = el->pectx;
            el->pectx = NULL; // e now owns the ctx
            e->gid = el->gid;
            if (el->next == NULL) {
                e->is_last = TRUE;
            }
            e++;
        }
    }
    if (sgh->init->tx_engines != NULL) {
        uint32_t cnt = 0;
        for (el = sgh->init->tx_engines ; el != NULL; el = el->next) {
            cnt++;
            de_ctx->prefilter_maxid = MAX(de_ctx->prefilter_maxid, el->gid);
        }
        sgh->tx_engines = SCMallocAligned(cnt * sizeof(PrefilterEngine), CLS);
        if (sgh->tx_engines == NULL) {
            return;
        }
        memset(sgh->tx_engines, 0x00, (cnt * sizeof(PrefilterEngine)));

        uint32_t local_id = 0;
        PrefilterEngine *e = sgh->tx_engines;
        for (el = sgh->init->tx_engines ; el != NULL; el = el->next) {
            e->local_id = local_id++;
            e->alproto = el->alproto;
            e->ctx.tx_min_progress = el->tx_min_progress;
            e->cb.PrefilterTx = el->PrefilterTx;
            e->pectx = el->pectx;
            el->pectx = NULL; // e now owns the ctx
            e->gid = el->gid;
            e++;
        }

        /* sort by tx_min_progress, then alproto, then local_id */
        qsort(sgh->tx_engines, local_id, sizeof(PrefilterEngine),
                PrefilterSetupRuleGroupSortHelper);
        sgh->tx_engines[local_id - 1].is_last = true;
        sgh->tx_engines[local_id - 1].is_last_for_progress = true;

        PrefilterEngine *engine;

        /* per alproto to set is_last_for_progress per alproto because the inspect
         * loop skips over engines that are not the correct alproto */
        for (AppProto a = 1; a < ALPROTO_FAILED; a++) {
            int last_tx_progress = 0;
            bool last_tx_progress_set = false;
            PrefilterEngine *prev_engine = NULL;
            engine = sgh->tx_engines;
            do {
                BUG_ON(engine->ctx.tx_min_progress < last_tx_progress);
                if (engine->alproto == a) {
                    if (last_tx_progress_set && engine->ctx.tx_min_progress > last_tx_progress) {
                        if (prev_engine) {
                            prev_engine->is_last_for_progress = true;
                        }
                    }

                    last_tx_progress_set = true;
                    prev_engine = engine;
                } else {
                    if (prev_engine) {
                        prev_engine->is_last_for_progress = true;
                    }
                }
                last_tx_progress = engine->ctx.tx_min_progress;
                if (engine->is_last)
                    break;
                engine++;
            } while (1);
        }
#ifdef DEBUG
        SCLogDebug("sgh %p", sgh);
        engine = sgh->tx_engines;
        do {
            SCLogDebug("engine: gid %u alproto %s tx_min_progress %d is_last %s "
                       "is_last_for_progress %s",
                    engine->gid, AppProtoToString(engine->alproto), engine->ctx.tx_min_progress,
                    engine->is_last ? "true" : "false",
                    engine->is_last_for_progress ? "true" : "false");
            if (engine->is_last)
                break;
            engine++;
        } while (1);
#endif
    }
    if (sgh->init->frame_engines != NULL) {
        uint32_t cnt = 0;
        for (el = sgh->init->frame_engines; el != NULL; el = el->next) {
            cnt++;
            de_ctx->prefilter_maxid = MAX(de_ctx->prefilter_maxid, el->gid);
        }
        sgh->frame_engines = SCMallocAligned(cnt * sizeof(PrefilterEngine), CLS);
        if (sgh->frame_engines == NULL) {
            return;
        }
        memset(sgh->frame_engines, 0x00, (cnt * sizeof(PrefilterEngine)));

        PrefilterEngine *e = sgh->frame_engines;
        for (el = sgh->init->frame_engines; el != NULL; el = el->next) {
            e->local_id = el->id;
            e->ctx.frame_type = el->frame_type;
            e->cb.PrefilterFrame = el->PrefilterFrame;
            e->alproto = el->alproto;
            e->pectx = el->pectx;
            el->pectx = NULL; // e now owns the ctx
            e->gid = el->gid;
            if (el->next == NULL) {
                e->is_last = TRUE;
            }
            e++;
        }
    }
}

/* hash table for assigning a unique id to each engine type. */

static uint32_t PrefilterStoreHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    PrefilterStore *ctx = data;

    uint32_t hash = strlen(ctx->name);
    uint16_t u;

    for (u = 0; u < strlen(ctx->name); u++) {
        hash += ctx->name[u];
    }

    hash %= ht->array_size;
    return hash;
}

static char PrefilterStoreCompareFunc(void *data1, uint16_t len1,
                                      void *data2, uint16_t len2)
{
    PrefilterStore *ctx1 = data1;
    PrefilterStore *ctx2 = data2;
    return (strcmp(ctx1->name, ctx2->name) == 0);
}

static void PrefilterStoreFreeFunc(void *ptr)
{
    SCFree(ptr);
}

void PrefilterDeinit(DetectEngineCtx *de_ctx)
{
    if (de_ctx->prefilter_hash_table != NULL) {
        HashListTableFree(de_ctx->prefilter_hash_table);
    }
}

void PrefilterInit(DetectEngineCtx *de_ctx)
{
    BUG_ON(de_ctx->prefilter_hash_table != NULL);

    de_ctx->prefilter_hash_table = HashListTableInit(256,
            PrefilterStoreHashFunc,
            PrefilterStoreCompareFunc,
            PrefilterStoreFreeFunc);
    BUG_ON(de_ctx->prefilter_hash_table == NULL);
}

static int PrefilterStoreGetId(DetectEngineCtx *de_ctx,
        const char *name, void (*FreeFunc)(void *))
{
    PrefilterStore ctx = { name, FreeFunc, 0 };

    BUG_ON(de_ctx->prefilter_hash_table == NULL);

    SCLogDebug("looking up %s", name);

    PrefilterStore *rctx = HashListTableLookup(de_ctx->prefilter_hash_table, (void *)&ctx, 0);
    if (rctx != NULL) {
        return rctx->id;
    }

    PrefilterStore *actx = SCCalloc(1, sizeof(*actx));
    if (actx == NULL) {
        return -1;
    }

    actx->name = name;
    actx->FreeFunc = FreeFunc;
    actx->id = de_ctx->prefilter_id++;
    SCLogDebug("prefilter engine %s has profile id %u", actx->name, actx->id);

    int ret = HashListTableAdd(de_ctx->prefilter_hash_table, actx, 0);
    if (ret != 0) {
        SCFree(actx);
        return -1;
    }

    int r = actx->id;
    return r;
}

/** \warning slow */
static const PrefilterStore *PrefilterStoreGetStore(const DetectEngineCtx *de_ctx,
        const uint32_t id)
{

    const PrefilterStore *store = NULL;
    if (de_ctx->prefilter_hash_table != NULL) {
        HashListTableBucket *hb = HashListTableGetListHead(de_ctx->prefilter_hash_table);
        for ( ; hb != NULL; hb = HashListTableGetListNext(hb)) {
            PrefilterStore *ctx = HashListTableGetListData(hb);
            if (ctx->id == id) {
                store = ctx;
                break;
            }
        }
    }
    return store;
}

#ifdef PROFILING
const char *PrefilterStoreGetName(const uint32_t id)
{
    return NULL;
}
#endif

#include "util-print.h"

typedef struct PrefilterMpmCtx {
    int list_id;
    InspectionBufferGetDataPtr GetData;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmCtx;

/** \brief Generic Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterMpm(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmCtx *ctx = (const PrefilterMpmCtx *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    SCLogDebug("running on list %d", ctx->list_id);

    InspectionBuffer *buffer = ctx->GetData(det_ctx, ctx->transforms,
            f, flags, txv, ctx->list_id);
    if (buffer == NULL)
        return;

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;

    SCLogDebug("mpm'ing buffer:");
    //PrintRawDataFp(stdout, data, data_len);

    if (data != NULL && data_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, data, data_len);
    }
}

static void PrefilterGenericMpmFree(void *ptr)
{
    SCFree(ptr);
}

int PrefilterGenericMpmRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id)
{
    SCEnter();
    PrefilterMpmCtx *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->GetData = mpm_reg->app_v2.GetData;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    int r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterMpm,
        mpm_reg->app_v2.alproto, mpm_reg->app_v2.tx_min_progress,
        pectx, PrefilterGenericMpmFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
    }
    return r;
}

/* generic mpm for pkt engines */

typedef struct PrefilterMpmPktCtx {
    int list_id;
    InspectionBufferGetPktDataPtr GetData;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmPktCtx;

/** \brief Generic Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterMpmPkt(DetectEngineThreadCtx *det_ctx,
        Packet *p, const void *pectx)
{
    SCEnter();

    const PrefilterMpmPktCtx *ctx = (const PrefilterMpmPktCtx *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    SCLogDebug("running on list %d", ctx->list_id);

    InspectionBuffer *buffer = ctx->GetData(det_ctx, ctx->transforms,
            p, ctx->list_id);
    if (buffer == NULL)
        return;

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;

    SCLogDebug("mpm'ing buffer:");
    //PrintRawDataFp(stdout, data, data_len);

    if (data != NULL && data_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, data, data_len);
    }
}

static void PrefilterMpmPktFree(void *ptr)
{
    SCFree(ptr);
}

int PrefilterGenericMpmPktRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id)
{
    SCEnter();
    PrefilterMpmPktCtx *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->GetData = mpm_reg->pkt_v1.GetData;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    int r = PrefilterAppendEngine(de_ctx, sgh, PrefilterMpmPkt,
        pectx, PrefilterMpmPktFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
    }
    return r;
}
