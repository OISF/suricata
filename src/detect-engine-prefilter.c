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

            engine->PrefilterTx(det_ctx, engine->pectx,
                    p, p->flow, tx, idx, flags);
        next:
            engine = engine->next;
        } while (engine);
    }
}

void Prefilter(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh,
        Packet *p, const uint8_t flags, int has_state)
{
    SCEnter();

    /* run packet engines */
    PrefilterEngine *engine = sgh->engines;
    while (engine) {
        engine->Prefilter(det_ctx, p, engine->pectx);
        engine = engine->next;
    }

    /* run tx engines */
    if (((p->proto == IPPROTO_TCP && p->flowflags & FLOW_PKT_ESTABLISHED) || p->proto != IPPROTO_TCP) && has_state) {
        if (sgh->tx_engines != NULL && p->flow != NULL &&
                p->flow->alproto != ALPROTO_UNKNOWN && p->flow->alstate != NULL)
        {
            PrefilterTx(det_ctx, sgh, p, flags);
        }
    }
}

int PrefilterAppendEngine(SigGroupHead *sgh,
        void (*Prefilter)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx),
        void *pectx, void (*FreeFunc)(void *pectx))
{
    if (sgh == NULL || Prefilter == NULL || pectx == NULL)
        return -1;

    PrefilterEngine *e = SCCalloc(1, sizeof(*e));
    if (e == NULL)
        return -1;

    e->Prefilter = Prefilter;
    e->pectx = pectx;
    e->Free = FreeFunc;

    if (sgh->engines == NULL) {
        sgh->engines = e;
        return 0;
    }

    PrefilterEngine *t = sgh->engines;
    while (t->next != NULL) {
        t = t->next;
    }

    t->next = e;
    e->id = t->id + 1;
    return 0;
}

int PrefilterAppendTxEngine(SigGroupHead *sgh,
        void (*PrefilterTx)(DetectEngineThreadCtx *det_ctx, const void *pectx,
            Packet *p, Flow *f, void *tx,
            const uint64_t idx, const uint8_t flags),
        AppProto alproto, int tx_min_progress,
        void *pectx, void (*FreeFunc)(void *pectx))
{
    if (sgh == NULL || PrefilterTx == NULL || pectx == NULL)
        return -1;

    PrefilterEngine *e = SCCalloc(1, sizeof(*e));
    if (e == NULL)
        return -1;

    e->PrefilterTx = PrefilterTx;
    e->pectx = pectx;
    e->alproto = alproto;
    e->tx_min_progress = tx_min_progress;
    e->Free = FreeFunc;

    if (sgh->tx_engines == NULL) {
        sgh->tx_engines = e;
        return 0;
    }

    PrefilterEngine *t = sgh->tx_engines;
    while (t->next != NULL) {
        t = t->next;
    }

    t->next = e;
    e->id = t->id + 1;
    return 0;
}

static void PrefilterFreeEngine(PrefilterEngine *e)
{
    if (e->Free) {
        e->Free(e->pectx);
    }
    SCFree(e);
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
