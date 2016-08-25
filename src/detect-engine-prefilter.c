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

#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "util-profiling.h"

#ifdef PROFILING
static int PrefilterStoreGetId(const char *name);
#endif

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
    const uint64_t total_txs = AppLayerParserGetTxCnt(ipproto, alproto, alstate);

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

        const int tx_progress = AppLayerParserGetStateProgress(ipproto, alproto, tx, flags);
        SCLogDebug("tx %p progress %d", tx, tx_progress);

        PrefilterEngine *engine = sgh->tx_engines;
        do {
            if (engine->alproto != alproto)
                goto next;
            if (engine->tx_min_progress > tx_progress)
                goto next;

            PROFILING_PREFILTER_START(p);
            engine->PrefilterTx(det_ctx, engine->pectx,
                    p, p->flow, tx, idx, flags);
            PROFILING_PREFILTER_END(p, engine->profile_id);
        next:
            engine = engine->next;
        } while (engine);
    }
}

void Prefilter(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh,
        Packet *p, const uint8_t flags, int has_state)
{
    SCEnter();

    PROFILING_PREFILTER_RESET(p, det_ctx->de_ctx->profile_prefilter_maxid);

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_PKT);
    /* run packet engines */
    PrefilterEngine *engine = sgh->pkt_engines;
    while (engine) {
        PROFILING_PREFILTER_START(p);
        engine->Prefilter(det_ctx, p, engine->pectx);
        PROFILING_PREFILTER_END(p, engine->profile_id);

        engine = engine->next;
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_PKT);

    /* run payload inspecting engines */
    if ((p->payload_len > 0 || det_ctx->smsg != NULL) && !(p->flags & PKT_NOPAYLOAD_INSPECTION)) {
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_PAYLOAD);
        engine = sgh->payload_engines;
        while (engine) {
            PROFILING_PREFILTER_START(p);
            engine->Prefilter(det_ctx, p, engine->pectx);
            PROFILING_PREFILTER_END(p, engine->profile_id);

            engine = engine->next;
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
}

int PrefilterAppendEngine(SigGroupHead *sgh,
        void (*Prefilter)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx),
        void *pectx, void (*FreeFunc)(void *pectx),
        const char *name)
{
    if (sgh == NULL || Prefilter == NULL || pectx == NULL)
        return -1;

    PrefilterEngine *e = SCMallocAligned(sizeof(*e), CLS);
    if (e == NULL)
        return -1;
    memset(e, 0x00, sizeof(*e));

    e->Prefilter = Prefilter;
    e->pectx = pectx;
    e->Free = FreeFunc;

    if (sgh->pkt_engines == NULL) {
        sgh->pkt_engines = e;
    } else {
        PrefilterEngine *t = sgh->pkt_engines;
        while (t->next != NULL) {
            t = t->next;
        }

        t->next = e;
        e->id = t->id + 1;
    }

#ifdef PROFILING
    sgh->engines_cnt = e->id;
    e->name = name;
    e->profile_id = PrefilterStoreGetId(e->name);
#endif
    return 0;
}

int PrefilterAppendPayloadEngine(SigGroupHead *sgh,
        void (*Prefilter)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx),
        void *pectx, void (*FreeFunc)(void *pectx),
        const char *name)
{
    if (sgh == NULL || Prefilter == NULL || pectx == NULL)
        return -1;

    PrefilterEngine *e = SCMallocAligned(sizeof(*e), CLS);
    if (e == NULL)
        return -1;
    memset(e, 0x00, sizeof(*e));

    e->Prefilter = Prefilter;
    e->pectx = pectx;
    e->Free = FreeFunc;

    if (sgh->payload_engines == NULL) {
        sgh->payload_engines = e;
    } else {
        PrefilterEngine *t = sgh->payload_engines;
        while (t->next != NULL) {
            t = t->next;
        }

        t->next = e;
        e->id = t->id + 1;
    }

#ifdef PROFILING
    sgh->engines_cnt = e->id;
    e->name = name;
    e->profile_id = PrefilterStoreGetId(e->name);
#endif
    return 0;
}

int PrefilterAppendTxEngine(SigGroupHead *sgh,
        void (*PrefilterTx)(DetectEngineThreadCtx *det_ctx, const void *pectx,
            Packet *p, Flow *f, void *tx,
            const uint64_t idx, const uint8_t flags),
        AppProto alproto, int tx_min_progress,
        void *pectx, void (*FreeFunc)(void *pectx),
        const char *name)
{
    if (sgh == NULL || PrefilterTx == NULL || pectx == NULL)
        return -1;

    PrefilterEngine *e = SCMallocAligned(sizeof(*e), CLS);
    if (e == NULL)
        return -1;
    memset(e, 0x00, sizeof(*e));

    e->PrefilterTx = PrefilterTx;
    e->pectx = pectx;
    e->alproto = alproto;
    e->tx_min_progress = tx_min_progress;
    e->Free = FreeFunc;

    if (sgh->tx_engines == NULL) {
        sgh->tx_engines = e;
    } else {
        PrefilterEngine *t = sgh->tx_engines;
        while (t->next != NULL) {
            t = t->next;
        }

        t->next = e;
        e->id = t->id + 1;
    }
#ifdef PROFILING
    sgh->tx_engines_cnt = e->id;
    e->name = name;
    e->profile_id = PrefilterStoreGetId(e->name);
#endif
    return 0;
}

static void PrefilterFreeEngine(PrefilterEngine *e)
{
    if (e->Free) {
        e->Free(e->pectx);
    }
    SCFreeAligned(e);
}

void PrefilterFreeEngines(PrefilterEngine *list)
{
    PrefilterEngine *t = list;

    while (t != NULL) {
        PrefilterEngine *next = t->next;
        PrefilterFreeEngine(t);
        t = next;
    }
}

#ifdef PROFILING
/* hash table for assigning a unique id to each engine type. */

typedef struct PrefilterStore_ {
    const char *name;
    uint32_t id;
} PrefilterStore;

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

static int PrefilterStoreGetId(const char *name)
{
    PrefilterStore ctx = { name, 0 };

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
#endif /* PROFILING */
