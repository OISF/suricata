/* Copyright (C) 2016 Open Information Security Foundation
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

#include "detect-engine-prefilter.h"
#include "detect-engine-mpm.h"

#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "util-profiling.h"

typedef struct PrefilterStore_ {
    const char *name;
    void (*FreeFunc)(void *);
    uint32_t id;
} PrefilterStore;

static int PrefilterStoreGetId(const char *name, void (*FreeFunc)(void *));
static const PrefilterStore *PrefilterStoreGetStore(const uint32_t id);

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

static inline void PrefilterTx(DetectEngineThreadCtx *det_ctx,
        const SigGroupHead *sgh, Packet *p, const uint8_t flags)
{
    SCEnter();

    const AppProto alproto = p->flow->alproto;
    const uint8_t ipproto = p->proto;

    if (!(AppLayerParserProtocolIsTxAware(ipproto, alproto)))
        SCReturn;

    void *alstate = p->flow->alstate;
    uint64_t idx = AppLayerParserGetTransactionInspectId(p->flow->alparser, flags);
    const uint64_t total_txs = AppLayerParserGetTxCnt(p->flow, alstate);

    /* HACK test HTTP state here instead of in each engine */
    if (alproto == ALPROTO_HTTP) {
        HtpState *htp_state = (HtpState *)alstate;
        if (unlikely(htp_state->connp == NULL)) {
            SCLogDebug("no HTTP connp");
            SCReturn;
        }
    }

    /* run our engines against each tx */
    for (; idx < total_txs; idx++) {
        void *tx = AppLayerParserGetTx(ipproto, alproto, alstate, idx);
        if (tx == NULL)
            continue;

        uint64_t mpm_ids = AppLayerParserGetTxMpmIDs(ipproto, alproto, tx);
        const int tx_progress = AppLayerParserGetStateProgress(ipproto, alproto, tx, flags);
        SCLogDebug("tx %p progress %d", tx, tx_progress);

        PrefilterEngine *engine = sgh->tx_engines;
        do {
            if (engine->alproto != alproto)
                goto next;
            if (engine->tx_min_progress > tx_progress)
                goto next;
            if (tx_progress > engine->tx_min_progress) {
                if (mpm_ids & (1<<(engine->gid))) {
                    goto next;
                }
            }

            PROFILING_PREFILTER_START(p);
            engine->cb.PrefilterTx(det_ctx, engine->pectx,
                    p, p->flow, tx, idx, flags);
            PROFILING_PREFILTER_END(p, engine->gid);

            if (tx_progress > engine->tx_min_progress) {
                mpm_ids |= (1<<(engine->gid));
            }
        next:
            if (engine->is_last)
                break;
            engine++;
        } while (1);

        if (mpm_ids != 0) {
            //SCLogNotice("tx %p Mpm IDs: %"PRIx64, tx, mpm_ids);
            AppLayerParserSetTxMpmIDs(ipproto, alproto, tx, mpm_ids);
        }
    }
}

void Prefilter(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh,
        Packet *p, const uint8_t flags, const bool has_state)
{
    SCEnter();

    PROFILING_PREFILTER_RESET(p, det_ctx->de_ctx->prefilter_maxid);

    if (sgh->pkt_engines) {
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_PKT);
        /* run packet engines */
        PrefilterEngine *engine = sgh->pkt_engines;
        do {
            PROFILING_PREFILTER_START(p);
            engine->cb.Prefilter(det_ctx, p, engine->pectx);
            PROFILING_PREFILTER_END(p, engine->gid);

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
            PROFILING_PREFILTER_START(p);
            engine->cb.Prefilter(det_ctx, p, engine->pectx);
            PROFILING_PREFILTER_END(p, engine->gid);

            if (engine->is_last)
                break;
            engine++;
        }
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_PAYLOAD);
    }

    /* run tx engines */
    if (((p->proto == IPPROTO_TCP && p->flowflags & FLOW_PKT_ESTABLISHED) || p->proto != IPPROTO_TCP) && has_state) {
        if (sgh->tx_engines != NULL && p->flow != NULL &&
                p->flow->alproto != ALPROTO_UNKNOWN && p->flow->alstate != NULL)
        {
            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_TX);
            PrefilterTx(det_ctx, sgh, p, flags);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_TX);
        }
    }

    /* Sort the rule list to lets look at pmq.
     * NOTE due to merging of 'stream' pmqs we *MAY* have duplicate entries */
    if (likely(det_ctx->pmq.rule_id_array_cnt > 1)) {
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_SORT1);
        QuickSortSigIntId(det_ctx->pmq.rule_id_array, det_ctx->pmq.rule_id_array_cnt);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_SORT1);
    }
}

int PrefilterAppendEngine(SigGroupHead *sgh,
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
    e->gid = PrefilterStoreGetId(e->name, e->Free);
    return 0;
}

int PrefilterAppendPayloadEngine(SigGroupHead *sgh,
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
    e->gid = PrefilterStoreGetId(e->name, e->Free);
    return 0;
}

int PrefilterAppendTxEngine(SigGroupHead *sgh,
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
    e->gid = PrefilterStoreGetId(e->name, e->Free);
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

static void PrefilterFreeEngines(PrefilterEngine *list)
{
    PrefilterEngine *t = list;

    while (1) {
        const PrefilterStore *s = PrefilterStoreGetStore(t->gid);
        if (s && s->FreeFunc && t->pectx) {
            s->FreeFunc(t->pectx);
        }

        if (t->is_last)
            break;
        t++;
    }
    SCFreeAligned(list);
}

void PrefilterCleanupRuleGroup(SigGroupHead *sgh)
{
    if (sgh->pkt_engines) {
        PrefilterFreeEngines(sgh->pkt_engines);
        sgh->pkt_engines = NULL;
    }
    if (sgh->payload_engines) {
        PrefilterFreeEngines(sgh->payload_engines);
        sgh->payload_engines = NULL;
    }
    if (sgh->tx_engines) {
        PrefilterFreeEngines(sgh->tx_engines);
        sgh->tx_engines = NULL;
    }
}

void PrefilterSetupRuleGroup(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    BUG_ON(PatternMatchPrepareGroup(de_ctx, sgh) != 0);

    if (de_ctx->prefilter_setting == DETECT_PREFILTER_AUTO) {
        int i = 0;
        for (i = 0; i < DETECT_TBLSIZE; i++)
        {
            if (sigmatch_table[i].SetupPrefilter != NULL) {
                sigmatch_table[i].SetupPrefilter(sgh);
            }
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
            e->id = el->id;
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
            e->id = el->id;
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

        PrefilterEngine *e = sgh->tx_engines;
        for (el = sgh->init->tx_engines ; el != NULL; el = el->next) {
            e->id = el->id;
            e->alproto = el->alproto;
            e->tx_min_progress = el->tx_min_progress;
            e->cb.PrefilterTx = el->PrefilterTx;
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

static SCMutex g_prefilter_mutex = SCMUTEX_INITIALIZER;
static uint32_t g_prefilter_id = 0;
static HashListTable *g_prefilter_hash_table = NULL;

static void PrefilterDeinit(void)
{
    SCMutexLock(&g_prefilter_mutex);
    BUG_ON(g_prefilter_hash_table == NULL);
    HashListTableFree(g_prefilter_hash_table);
    SCMutexUnlock(&g_prefilter_mutex);
}

static void PrefilterInit(void)
{
    SCMutexLock(&g_prefilter_mutex);
    BUG_ON(g_prefilter_hash_table != NULL);

    g_prefilter_hash_table = HashListTableInit(256,
            PrefilterStoreHashFunc,
            PrefilterStoreCompareFunc,
            PrefilterStoreFreeFunc);
    BUG_ON(g_prefilter_hash_table == NULL);
    atexit(PrefilterDeinit);
    SCMutexUnlock(&g_prefilter_mutex);
}

static int PrefilterStoreGetId(const char *name, void (*FreeFunc)(void *))
{
    PrefilterStore ctx = { name, FreeFunc, 0 };

    if (g_prefilter_hash_table == NULL) {
        PrefilterInit();
    }

    SCLogDebug("looking up %s", name);

    SCMutexLock(&g_prefilter_mutex);
    PrefilterStore *rctx = HashListTableLookup(g_prefilter_hash_table, (void *)&ctx, 0);
    if (rctx != NULL) {
        SCMutexUnlock(&g_prefilter_mutex);
        return rctx->id;
    }

    PrefilterStore *actx = SCCalloc(1, sizeof(*actx));
    if (actx == NULL) {
        SCMutexUnlock(&g_prefilter_mutex);
        return -1;
    }

    actx->name = name;
    actx->FreeFunc = FreeFunc;
    actx->id = g_prefilter_id++;
    SCLogDebug("prefilter engine %s has profile id %u", actx->name, actx->id);

    int ret = HashListTableAdd(g_prefilter_hash_table, actx, 0);
    if (ret != 0) {
        SCMutexUnlock(&g_prefilter_mutex);
        SCFree(actx);
        return -1;
    }

    int r = actx->id;
    SCMutexUnlock(&g_prefilter_mutex);
    return r;
}

/** \warning slow */
static const PrefilterStore *PrefilterStoreGetStore(const uint32_t id)
{
    const PrefilterStore *store = NULL;
    SCMutexLock(&g_prefilter_mutex);
    if (g_prefilter_hash_table != NULL) {
        HashListTableBucket *hb = HashListTableGetListHead(g_prefilter_hash_table);
        for ( ; hb != NULL; hb = HashListTableGetListNext(hb)) {
            PrefilterStore *ctx = HashListTableGetListData(hb);
            if (ctx->id == id) {
                store = ctx;
                break;
            }
        }
    }
    SCMutexUnlock(&g_prefilter_mutex);
    return store;
}

#ifdef PROFILING
/** \warning slow */
const char *PrefilterStoreGetName(const uint32_t id)
{
    const char *name = NULL;
    SCMutexLock(&g_prefilter_mutex);
    if (g_prefilter_hash_table != NULL) {
        HashListTableBucket *hb = HashListTableGetListHead(g_prefilter_hash_table);
        for ( ; hb != NULL; hb = HashListTableGetListNext(hb)) {
            PrefilterStore *ctx = HashListTableGetListData(hb);
            if (ctx->id == id) {
                name = ctx->name;
                break;
            }
        }
    }
    SCMutexUnlock(&g_prefilter_mutex);
    return name;
}
#endif
