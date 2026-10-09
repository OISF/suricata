/* Copyright (C) 2016-2025 Open Information Security Foundation
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
#ifdef UNITTESTS
#include "util-unittest.h"
#endif
#include "detect-engine-mpm.h"
#include "detect-engine-frame.h"
#include "detect-engine-uint.h"

#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "util-profiling.h"
#include "util-validate.h"
#include "util-hash-string.h"

static int PrefilterStoreGetId(DetectEngineCtx *de_ctx,
        const char *name, void (*FreeFunc)(void *));
static const PrefilterStore *PrefilterStoreGetStore(const DetectEngineCtx *de_ctx,
        const uint32_t id);

enum FwLteGrows {
    LTE_GROWS_NONE, /**< every pattern of the group is final above the hook */
    LTE_GROWS_LIST, /**< the buffer can be rewritten above the hook: inspect */
};

struct PrefilterNonPFDataTx {
    uint32_t size;
    /** some rule of the group has a fast pattern in a buffer that keeps growing
     *  above the hook, so its miss is not final there. */
    enum FwLteGrows lte_grows;
    uint32_t array[];
};

static bool PrefilterLteWindowAdd(
        DetectEngineThreadCtx *det_ctx, const struct PrefilterNonPFDataTx *data);

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
    QuickSortSigIntId(sids, (uint32_t)(r - sids) + 1);
    QuickSortSigIntId(l, (uint32_t)(sids + n - l));
}

/** LTE windows exist for firewall rules only: the `<` hook form is refused for any
 *  other rule, so `tx_max_progress` is set only when the engine groups LTE rules.
 *  Keep the dependency on the engine mode explicit rather than implicit. */
static bool PrefilterEngineIsFwLteWindow(const PrefilterEngine *engine)
{
    /* tx_max_progress doubles as "no bound" and "hooked at progress 0": a rule at the
     * very start has no state below its hook, so the plain run the base does already
     * covers it and a window would only add a per-packet store. */
    if (engine->ctx.app.tx_max_progress == 0)
        return false;
    DEBUG_VALIDATE_BUG_ON(!EngineModeIsFirewall());
    return EngineModeIsFirewall();
}

/**
 * \brief run prefilter engines on a transaction
 *
 * \retval true if an LTE pending window engine was skipped because the tx has
 *         reached the rules hook: the fast pattern decides there, and its miss
 *         is not final yet, so default policies must wait.
 */
bool DetectRunPrefilterTx(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh, Packet *p,
        const uint8_t ipproto, const uint8_t flow_flags, const AppProto alproto, void *alstate,
        DetectTransaction *tx)
{
    /* reset rule store */
    det_ctx->pmq.rule_id_array_cnt = 0;
    det_ctx->fw_lte_window_cnt = 0;
    bool lte_at_hook = false;

    SCLogDebug("packet %" PRIu64 " tx %p id %" PRIu64 " progress %d tx->detect_progress %02x",
            PcapPacketCntGet(p), tx->tx_ptr, tx->tx_id, tx->tx_progress, tx->detect_progress);

    PrefilterEngine *engine = sgh->tx_engines;
    do {
        SCLogDebug("%" PRIu64 ": engine %p for %s progress %u  sub_state %u tx %u",
                PcapPacketCntGet(p), engine, AppProtoToString(engine->alproto),
                engine->ctx.app.tx_min_progress, engine->ctx.app.sub_state, tx->tx_type);

        DEBUG_VALIDATE_BUG_ON(
                AppLayerParserSupportsSubStates(engine->alproto) && engine->ctx.app.sub_state == 0);
        DEBUG_VALIDATE_BUG_ON(!AppLayerParserSupportsSubStates(engine->alproto) &&
                              engine->ctx.app.sub_state != 0);

        if (engine->alproto != ALPROTO_UNKNOWN && engine->ctx.app.sub_state != tx->tx_type) {
            SCLogDebug("%" PRIu64 ": engine %p sub_state %u mismatch with tx %u",
                    PcapPacketCntGet(p), engine, engine->ctx.app.sub_state, tx->tx_type);
            // not for the tx sub state
            goto next;
        }
        // based on flow alproto, and engine, we get right tx_ptr
        void *tx_ptr = DetectGetInnerTx(tx->tx_ptr, alproto, engine->alproto, flow_flags);
        if (tx_ptr == NULL) {
            // incompatible engine->alproto with flow alproto
            goto next;
        }

        if (engine->ctx.app.tx_min_progress != -1) {
            DEBUG_VALIDATE_BUG_ON(engine->alproto == ALPROTO_UNKNOWN);
#ifdef DEBUG
            const char *pname = AppLayerParserGetStateNameById(ipproto, engine->alproto,
                    engine->ctx.app.tx_min_progress,
                    flow_flags & (STREAM_TOSERVER | STREAM_TOCLIENT));
            SCLogDebug("engine %p min_progress %d %s:%s", engine, engine->ctx.app.tx_min_progress,
                    AppProtoToString(engine->alproto), pname);
#endif
            /* if engine needs tx state to be higher, break out. */
            if (engine->ctx.app.tx_min_progress > tx->tx_progress)
                break;
            /* A pending window engine covers LTE rules that have their hook at
             * `bound`. At that state the fast pattern decides which of them match,
             * so the list is left to it; above it the group is retired on its last
             * rule, unless a rule of it can still grow there. */
            const uint8_t bound = engine->ctx.app.tx_max_progress;
            bool run = true;
            if (PrefilterEngineIsFwLteWindow(engine) && tx->tx_progress >= bound) {
                run = false;
                /* only the pending windows carry a bound, so this is the
                 * non-prefilter data */
                const struct PrefilterNonPFDataTx *data = engine->pectx;
                if (tx->tx_progress == bound && tx->tx_progress < tx->tx_end_state) {
                    /* the rules the pattern did not add may still match: keep track of
                     * the group so the walk can act as if it had them in its list */
                    if (PrefilterLteWindowAdd(det_ctx, data)) {
                        lte_at_hook = true;
                    } else {
                        PrefilterAddSids(&det_ctx->pmq, data->array, data->size);
                    }
                } else if (data->size > 0) {
                    /* The last rule can only retire the group if no other rule of it can
                     * match anymore. A protocol which declares sub-states rewrites a buffer
                     * above its hook - an http2 trailer HEADERS frame - so such a group is
                     * still live and its rules go in the list whole; a rule whose pattern
                     * can only arrive from the stream cannot load at an LTE hook (see
                     * DetectFirewallRuleValidate). */
                    if (data->lte_grows == LTE_GROWS_LIST) {
                        PrefilterAddSids(&det_ctx->pmq, data->array, data->size);
                    } else {
                        PrefilterAddSids(&det_ctx->pmq, &data->array[data->size - 1], 1);
                    }
                }
            }
            if (tx->tx_progress > engine->ctx.app.tx_min_progress) {
                SCLogDebug("tx->tx_progress %u > engine->ctx.app.tx_min_progress %d",
                        tx->tx_progress, engine->ctx.app.tx_min_progress);

                /* if state value is at or beyond engine state, we can skip it. It means we ran at
                 * least once already. A run-always engine (stateful keyword) is revisited on
                 * every update, so detect_progress must not skip it. */
                if (!engine->run_always && tx->detect_progress > engine->ctx.app.tx_min_progress) {
                    SCLogDebug("tx already marked progress as beyond engine: %u > %u",
                            tx->detect_progress, engine->ctx.app.tx_min_progress);
                    goto next;
                } else {
                    SCLogDebug("tx->tx_progress %u > engine->ctx.app.tx_min_progress %d: "
                               "tx->detect_progress %u",
                            tx->tx_progress, engine->ctx.app.tx_min_progress, tx->detect_progress);
                }
            }
#ifdef DEBUG
            uint32_t old = det_ctx->pmq.rule_id_array_cnt;
#endif
            if (run) {
                PREFILTER_PROFILING_START(det_ctx);
                engine->cb.PrefilterTx(det_ctx, engine->pectx, p, p->flow, tx_ptr, tx->tx_id,
                        tx->tx_data_ptr, flow_flags);
                PREFILTER_PROFILING_END(det_ctx, engine->gid);
            }
            SCLogDebug("engine %p min_progress %d %s:%s: results %u", engine,
                    engine->ctx.app.tx_min_progress, AppProtoToString(engine->alproto), pname,
                    det_ctx->pmq.rule_id_array_cnt - old);

            if (tx->tx_progress > engine->ctx.app.tx_min_progress && engine->is_last_for_progress &&
                    tx->tx_ptr == tx_ptr) {
                /* track with an offset of one, so that tx->progress 0 complete is tracked
                 * as 1, progress 1 as 2, etc. This is to allow 0 to mean: nothing tracked, even
                 * though a parser may use 0 as a valid value. */
                // tx->tx_ptr == tx_ptr ensures we do not use a dns engine progress
                // to update a HTTP2 tx detect_progress in case of DOH2
                //
                // monotonic: a run-always engine at a lower progress is revisited
                // after the tx moved on, and must not re-enable the engines it
                // already completed
                if (tx->detect_progress < engine->ctx.app.tx_min_progress + 1) {
                    tx->detect_progress = engine->ctx.app.tx_min_progress + 1;
                }
                SCLogDebug("tx->tx_progress %d engine->ctx.app.tx_min_progress %d "
                           "engine->is_last_for_progress %d => tx->detect_progress updated to %02x",
                        tx->tx_progress, engine->ctx.app.tx_min_progress,
                        engine->is_last_for_progress, tx->detect_progress);
            }
        } else {
            DEBUG_VALIDATE_BUG_ON(engine->alproto != ALPROTO_UNKNOWN);
            PREFILTER_PROFILING_START(det_ctx);
            engine->cb.PrefilterTx(det_ctx, engine->pectx, p, p->flow, tx_ptr, tx->tx_id,
                    tx->tx_data_ptr, flow_flags);
            PREFILTER_PROFILING_END(det_ctx, engine->gid);
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
    return lte_at_hook;
}

/** \brief invoke post-rule match "prefilter" engines
 *
 * Invoke prefilter engines that depend on a rule match to run.
 * e.g. the flowbits:set prefilter that adds sids that depend on
 * a flowbit "set" to the match array.
 */
void PrefilterPostRuleMatch(
        DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh, Packet *p, Flow *f)
{
    SCLogDebug("post-rule-match engines %p", sgh->post_rule_match_engines);
    if (sgh->post_rule_match_engines) {
        PrefilterEngine *engine = sgh->post_rule_match_engines;
        do {
            SCLogDebug("running post-rule-match engine");
            PREFILTER_PROFILING_START(det_ctx);
            engine->cb.PrefilterPostRule(det_ctx, engine->pectx, p, f);
            PREFILTER_PROFILING_END(det_ctx, engine->gid);

            if (engine->is_last)
                break;
            engine++;
        } while (1);

        if (det_ctx->pmq.rule_id_array_cnt > 1) {
            QuickSortSigIntId(det_ctx->pmq.rule_id_array, det_ctx->pmq.rule_id_array_cnt);
        }
    }
}

void Prefilter(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh, Packet *p,
        const uint8_t flags, const SignatureMask mask)
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
            /* run engine if:
             * mask matches
             * no hook is used OR hook matches
             */
            if (((engine->ctx.pkt.mask & mask) == engine->ctx.pkt.mask) &&
                    (engine->ctx.pkt.hook == 0 || (p->pkt_hooks & BIT_U16(engine->ctx.pkt.hook)))) {
                PREFILTER_PROFILING_START(det_ctx);
                engine->cb.Prefilter(det_ctx, p, engine->pectx);
                PREFILTER_PROFILING_END(det_ctx, engine->gid);
            }

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
            PREFILTER_PROFILING_START(det_ctx);
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

int PrefilterAppendEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh, PrefilterPktFn PrefilterFunc,
        SignatureMask mask, enum SignatureHookPkt hook, void *pectx, void (*FreeFunc)(void *pectx),
        const char *name)
{
    if (sgh == NULL || PrefilterFunc == NULL || pectx == NULL)
        return -1;

    PrefilterEngineList *e = SCMallocAligned(sizeof(*e), CLS);
    if (e == NULL)
        return -1;
    memset(e, 0x00, sizeof(*e));

    // TODO right now we represent the hook in a u8 in the prefilter engine for space reasons.
    BUG_ON(hook >= 8);

    e->Prefilter = PrefilterFunc;
    e->pectx = pectx;
    e->Free = FreeFunc;
    e->pkt_mask = mask;
    e->pkt_hook = hook;

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
    SCLogDebug("sgh->init->pkt_engines %p", sgh->init->pkt_engines);
    return 0;
}

int PrefilterAppendPayloadEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        PrefilterPktFn PrefilterFunc, void *pectx, void (*FreeFunc)(void *pectx), const char *name)
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

int PrefilterAppendTxEngineSubState(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        PrefilterTxFn PrefilterTxFunc, AppProto alproto, uint8_t sub_state,
        const int8_t tx_min_progress, void *pectx, void (*FreeFunc)(void *pectx), const char *name)
{
    BUG_ON(AppLayerParserSupportsSubStates(alproto) && sub_state == 0);
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
    e->sub_state = sub_state;
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
    SCLogDebug("%s: sub_state %u", name, e->sub_state);
    return 0;
}

int PrefilterAppendTxEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        PrefilterTxFn PrefilterTxFunc, AppProto alproto, const int8_t tx_min_progress, void *pectx,
        void (*FreeFunc)(void *pectx), const char *name)
{
    return PrefilterAppendTxEngineSubState(
            de_ctx, sgh, PrefilterTxFunc, alproto, 0, tx_min_progress, pectx, FreeFunc, name);
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

int PrefilterAppendPostRuleEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        void (*PrefilterPostRuleFunc)(
                DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p, Flow *f),
        void *pectx, void (*FreeFunc)(void *pectx), const char *name)
{
    if (sgh == NULL || PrefilterPostRuleFunc == NULL || pectx == NULL)
        return -1;

    PrefilterEngineList *e = SCMallocAligned(sizeof(*e), CLS);
    if (e == NULL)
        return -1;
    memset(e, 0x00, sizeof(*e));
    e->PrefilterPostRule = PrefilterPostRuleFunc;
    e->pectx = pectx;
    e->Free = FreeFunc;

    if (sgh->init->post_rule_match_engines == NULL) {
        sgh->init->post_rule_match_engines = e;
    } else {
        PrefilterEngineList *t = sgh->init->post_rule_match_engines;
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
    if (sgh->post_rule_match_engines) {
        PrefilterFreeEngines(de_ctx, sgh->post_rule_match_engines);
        sgh->post_rule_match_engines = NULL;
    }
}

static int PrefilterSetupRuleGroupSortHelper(const void *a, const void *b)
{
    const PrefilterEngine *s0 = a;
    const PrefilterEngine *s1 = b;
    if (s1->ctx.app.sub_state == s0->ctx.app.sub_state) {
        if (s1->ctx.app.tx_min_progress == s0->ctx.app.tx_min_progress) {
            if (s1->alproto == s0->alproto) {
                return s0->local_id > s1->local_id ? 1 : -1;
            } else {
                return s0->alproto > s1->alproto ? 1 : -1;
            }
        } else {
            return s0->ctx.app.tx_min_progress > s1->ctx.app.tx_min_progress ? 1 : -1;
        }
    } else {
        return s0->ctx.app.sub_state > s1->ctx.app.sub_state ? 1 : -1;
    }
}

/** prefilter engine data for the non-prefilter engine for the prefilter API */
struct PrefilterNonPFDataSig {
    uint32_t sid : 30;
    uint32_t type : 2; /**< type for `value` field below: 0:alproto 1:dport 2:dsize */
    uint16_t value;
    /* since we have 2 more bytes available due to padding, we can add some additional
     * filters here. */
    union {
        struct {
            SignatureMask sig_mask;
        } pkt;
        struct {
            /* filter for frame type */
            uint8_t type;
        } frame;
        struct {
            uint8_t foo; // TODO unused
        } app;
    };
};

struct PrefilterNonPFData {
    uint32_t size;
    struct PrefilterNonPFDataSig array[];
};

/** \internal
 *  \brief wrapper for use in APIs */
static void PrefilterNonPFDataFree(void *data)
{
    SCFree(data);
}

static void PrefilterTxNonPF(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p, Flow *f,
        void *tx, const uint64_t tx_id, const AppLayerTxData *tx_data, const uint8_t flags)
{
    const struct PrefilterNonPFDataTx *data = (const struct PrefilterNonPFDataTx *)pectx;
    SCLogDebug("adding %u sids", data->size);
    PrefilterAddSids(&det_ctx->pmq, data->array, data->size);
}

static int PrefilterNonPFDataSortU32(const void *a, const void *b)
{
    const uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

/** \brief keep track of a pending window that went silent at its bound. The number
 *         of groups bound at a state is set by the ruleset, so the array grows to
 *         fit: a window that could not be tracked would leave the walk unable to
 *         tell which rule is still pending.
 */
static bool PrefilterLteWindowAdd(
        DetectEngineThreadCtx *det_ctx, const struct PrefilterNonPFDataTx *data)
{
    for (uint32_t w = 0; w < det_ctx->fw_lte_window_cnt; w++) {
        /* the engines of one group can share a set of rules, and the window is
         * merged against itself: a duplicate only costs the merge */
        if (det_ctx->fw_lte_windows[w] == data) {
            return true;
        }
    }
    if (det_ctx->fw_lte_window_cnt == det_ctx->fw_lte_window_size) {
        const uint32_t size =
                det_ctx->fw_lte_window_size == 0 ? 8 : det_ctx->fw_lte_window_size * 2;
        void *ptmp = SCRealloc((void *)det_ctx->fw_lte_windows, size * sizeof(void *));
        if (ptmp == NULL) {
            /* out of memory: tell the caller to keep the group as candidates
             * instead of killing the engine on the packet path */
            return false;
        }
        det_ctx->fw_lte_windows = (const void **)ptmp;
        det_ctx->fw_lte_window_size = size;
    }
    det_ctx->fw_lte_windows[det_ctx->fw_lte_window_cnt++] = data;
    return true;
}

void DetectPrefilterLteWindowFree(DetectEngineThreadCtx *det_ctx)
{
    SCFree((void *)det_ctx->fw_lte_windows);
    det_ctx->fw_lte_windows = NULL;
    det_ctx->fw_lte_window_size = 0;
    det_ctx->fw_lte_window_cnt = 0;
}

static uint32_t LteArrayLowerBound(const uint32_t *a, const uint32_t n_, const uint32_t v)
{
    uint32_t lo = 0, hi = n_;
    while (lo < hi) {
        const uint32_t mid = lo + (hi - lo) / 2;
        if (a[mid] < v)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

static uint32_t LteCandidateLowerBound(
        const RuleMatchCandidateTx *cands, const uint32_t cand_cnt, const uint32_t v)
{
    uint32_t lo = 0, hi = cand_cnt;
    while (lo < hi) {
        const uint32_t mid = lo + (hi - lo) / 2;
        if (cands[mid].id < v)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

/** \brief find the lowest rule of a silenced LTE pending window that is not a
 *         candidate: the fast pattern did not add it, but the tx is not final at
 *         the hook, so it may still match. A walk that had all rules in it would
 *         inspect this one before any rule with a higher iid.
 *  Both arrays are in iid order, so the search enters them at the cursor.
 */
static uint32_t LteWindowFirstMissing(const struct PrefilterNonPFDataTx *data,
        const RuleMatchCandidateTx *cands, const uint32_t cand_cnt, const uint32_t min_iid)
{
    /* both arrays are sorted, so enter them where min_iid lies rather than at the
     * start: a caller that retries past rejected rules would otherwise rewalk
     * everything below the cursor on every retry. */
    uint32_t i = LteArrayLowerBound(data->array, data->size, min_iid);
    while (i < data->size) {
        const uint32_t iid = data->array[i];
        const uint32_t j = LteCandidateLowerBound(cands, cand_cnt, iid);
        if (j == cand_cnt || cands[j].id != iid)
            return iid;
        i++;
    }
    return UINT32_MAX;
}

uint32_t DetectPrefilterLtePendingIid(
        DetectEngineThreadCtx *det_ctx, const uint32_t cand_cnt, const uint32_t min_iid)
{
    uint32_t lowest = UINT32_MAX;
    for (uint32_t i = 0; i < det_ctx->fw_lte_window_cnt; i++) {
        const struct PrefilterNonPFDataTx *data = det_ctx->fw_lte_windows[i];
        lowest =
                MIN(lowest, LteWindowFirstMissing(data, det_ctx->tx_candidates, cand_cnt, min_iid));
    }
    return lowest;
}

#ifdef NONPF_PKT_STATS
static thread_local uint64_t prefilter_pkt_nonpf_called = 0;
static thread_local uint64_t prefilter_pkt_nonpf_mask_fail = 0;
static thread_local uint64_t prefilter_pkt_nonpf_alproto_fail = 0;
static thread_local uint64_t prefilter_pkt_nonpf_dsize_fail = 0;
static thread_local uint64_t prefilter_pkt_nonpf_dport_fail = 0;
static thread_local uint64_t prefilter_pkt_nonpf_sids = 0;
#define NONPF_PKT_STATS_INCR(s) (s)++
#else
#define NONPF_PKT_STATS_INCR(s)
#endif

void PrefilterPktNonPFStatsDump(void)
{
#ifdef NONPF_PKT_STATS
    SCLogDebug("prefilter non-pf: called:%" PRIu64 ", mask_fail:%" PRIu64 ", alproto fail:%" PRIu64
               ", dport fail:%" PRIu64 ", dsize fail:%" PRIu64 ", sids:%" PRIu64
               ", avg sids:%" PRIu64,
            prefilter_pkt_nonpf_called, prefilter_pkt_nonpf_mask_fail,
            prefilter_pkt_nonpf_alproto_fail, prefilter_pkt_nonpf_dport_fail,
            prefilter_pkt_nonpf_dsize_fail, prefilter_pkt_nonpf_sids,
            prefilter_pkt_nonpf_called ? prefilter_pkt_nonpf_sids / prefilter_pkt_nonpf_called : 0);
#endif
}

static void PrefilterPktNonPF(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const uint16_t alproto = p->flow ? p->flow->alproto : ALPROTO_UNKNOWN;
    const SignatureMask mask = p->sig_mask;
    const struct PrefilterNonPFData *data = (const struct PrefilterNonPFData *)pectx;
    SCLogDebug("adding %u sids", data->size);
    NONPF_PKT_STATS_INCR(prefilter_pkt_nonpf_called);
    for (uint32_t i = 0; i < data->size; i++) {
        const struct PrefilterNonPFDataSig *ds = &data->array[i];
        const SignatureMask rule_mask = ds->pkt.sig_mask;
        if ((rule_mask & mask) == rule_mask) {
            switch (ds->type) {
                case 0:
                    if (ds->value == ALPROTO_UNKNOWN || AppProtoEquals(ds->value, alproto)) {
                        const uint32_t sid = ds->sid;
                        PrefilterAddSids(&det_ctx->pmq, &sid, 1);
                        NONPF_PKT_STATS_INCR(prefilter_pkt_nonpf_sids);
                    } else {
                        NONPF_PKT_STATS_INCR(prefilter_pkt_nonpf_alproto_fail);
                    }
                    break;
                case 1:
                    if (ds->value == p->dp) {
                        const uint32_t sid = ds->sid;
                        PrefilterAddSids(&det_ctx->pmq, &sid, 1);
                        NONPF_PKT_STATS_INCR(prefilter_pkt_nonpf_sids);
                    } else {
                        NONPF_PKT_STATS_INCR(prefilter_pkt_nonpf_dport_fail);
                    }
                    break;
                case 2:
                    if (ds->value == p->payload_len) {
                        const uint32_t sid = ds->sid;
                        PrefilterAddSids(&det_ctx->pmq, &sid, 1);
                        NONPF_PKT_STATS_INCR(prefilter_pkt_nonpf_sids);
                    } else {
                        NONPF_PKT_STATS_INCR(prefilter_pkt_nonpf_dsize_fail);
                    }
                    break;
            }
        } else {
            NONPF_PKT_STATS_INCR(prefilter_pkt_nonpf_mask_fail);
        }
    }
}

static void PrefilterPktNonPFHookFlowStart(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (p->flowflags & (FLOW_PKT_TOSERVER_FIRST | FLOW_PKT_TOCLIENT_FIRST)) {
        PrefilterPktNonPF(det_ctx, p, pectx);
    }
}

/** \internal
 *  \brief engine to select the non-prefilter rules for frames
 *  Checks the alproto and type as well.
 *  Direction needs no checking as the rule groups are per direction. */
static void PrefilterFrameNonPF(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        const Frames *frames, const Frame *frame)
{
    DEBUG_VALIDATE_BUG_ON(p->flow == NULL);
    const uint16_t alproto = p->flow->alproto;
    const struct PrefilterNonPFData *data = (const struct PrefilterNonPFData *)pectx;
    SCLogDebug("adding %u sids", data->size);
    for (uint32_t i = 0; i < data->size; i++) {
        const struct PrefilterNonPFDataSig *ds = &data->array[i];
        if (ds->frame.type == frame->type &&
                (ds->value == ALPROTO_UNKNOWN || AppProtoEquals(ds->value, alproto))) {
            const uint32_t sid = ds->sid;
            PrefilterAddSids(&det_ctx->pmq, &sid, 1);
        }
    }
}

/* helper funcs for the non prefilter names hash */

static uint32_t NonPFNamesHash(HashTable *h, void *data, uint16_t _len)
{
    const char *str = data;
    return StringHashDjb2((const uint8_t *)str, (uint16_t)strlen(str)) % h->array_size;
}

static char NonPFNamesCompare(void *data1, uint16_t _len1, void *data2, uint16_t len2)
{
    const char *s1 = data1;
    const char *s2 = data2;
    return StringHashCompareFunc(data1, (uint16_t)strlen(s1), data2, (uint16_t)strlen(s2));
}

static void NonPFNamesFree(void *data)
{
    SCFree(data);
}

/* helper funcs for assembling non-prefilter engines */

struct TxNonPFData {
    AppProto alproto;
    uint8_t sub_state;
    int dir;      /**< 0: toserver, 1: toclient */
    uint8_t progress; /**< progress state value to register at */
    int sig_list; /**< special handling: normally 0, but for special cases (app-layer-state,
                     app-layer-event) use the list id to create separate engines */
    /** the buffer holds a stateful keyword: evaluate its engine on every tx
     *  update (engine progress -1) so a provisional miss can be revisited as
     *  the transaction advances. */
    bool run_always;
    /** LTE pending window bound: the engine goes silent once the tx reaches this
     *  hook, as the fast pattern decides there. 0 means always add the sids. */
    uint8_t lte_hook;
    /** like #lte_hook, but for the group: #FwLteGrows of its rules */
    enum FwLteGrows lte_grows;
    uint32_t sigs_cnt;
    struct PrefilterNonPFDataSig *sigs;
    const char *engine_name; /**< pointer to name owned by DetectEngineCtx::non_pf_engine_names */
};

static uint32_t TxNonPFHash(HashListTable *h, void *data, uint16_t _len)
{
    struct TxNonPFData *d = data;
    return (d->alproto + d->sub_state + d->progress + d->dir + d->sig_list + d->run_always +
                   d->lte_hook) %
           h->array_size;
}

static char TxNonPFCompare(void *data1, uint16_t _len1, void *data2, uint16_t len2)
{
    struct TxNonPFData *d1 = data1;
    struct TxNonPFData *d2 = data2;
    return d1->alproto == d2->alproto && d1->sub_state == d2->sub_state &&
           d1->progress == d2->progress && d1->dir == d2->dir && d1->sig_list == d2->sig_list &&
           d1->run_always == d2->run_always && d1->lte_hook == d2->lte_hook;
}

static void TxNonPFFree(void *data)
{
    struct TxNonPFData *d = data;
    SCFree(d->sigs);
    SCFree(d);
}

/** \internal \brief does the rule's fast pattern keep growing above its hook?
 *  An app hooked rule can only hold patterns from buffers whose engine sits at
 *  the hook progress (`SigValidateCheckBuffers`), so such a buffer is complete
 *  once the tx is past the hook and a miss there is final. One case escapes
 *  that: a protocol which declares sub-states rewrites a buffer above its hook
 *  - an http2 trailer HEADERS frame updates the header buffers. A raw stream
 *  pattern cannot get here: DetectFirewallRuleValidate() refuses an LTE rule
 *  with anything on the payload list. */
static enum FwLteGrows FwLtePatternGrowsAboveBound(const Signature *s)
{
    if (s->init_data->mpm_sm == NULL) {
        /* no fast pattern at all: nothing can bring the rule back into the
         * candidates above the bound, so the group cannot be retired there */
        return LTE_GROWS_LIST;
    }
    if (AppLayerParserSupportsSubStates(s->alproto)) {
        return LTE_GROWS_LIST; /* a frame rewrites the buffer above the hook */
    }
    return LTE_GROWS_NONE;
}

static int TxNonPFAddSig(DetectEngineCtx *de_ctx, HashListTable *tx_engines_hash,
        const AppProto alproto, const uint8_t sub_state, const int dir, const uint8_t progress,
        const int sig_list, const char *name, const Signature *s, const bool run_always,
        const uint8_t lte_hook)
{
    const uint32_t max_sids = DetectEngineGetMaxSigId(de_ctx);

    struct TxNonPFData lookup = {
        .alproto = alproto,
        .sub_state = sub_state,
        .dir = dir,
        .progress = progress,
        .sig_list = sig_list,
        .run_always = run_always,
        .lte_hook = lte_hook,
        .sigs_cnt = 0,
        .sigs = NULL,
        .engine_name = NULL,
    };
    const enum FwLteGrows grows = lte_hook != 0 ? FwLtePatternGrowsAboveBound(s) : LTE_GROWS_NONE;

    struct TxNonPFData *e = HashListTableLookup(tx_engines_hash, &lookup, 0);
    if (e != NULL) {
        e->lte_grows = MAX(e->lte_grows, grows);
        bool found = false;
        // avoid adding same sid multiple times
        for (uint32_t y = 0; y < e->sigs_cnt; y++) {
            if (e->sigs[y].sid == s->iid) {
                found = true;
                break;
            }
        }
        if (!found) {
            BUG_ON(e->sigs_cnt == max_sids);
            e->sigs[e->sigs_cnt].sid = s->iid;
            e->sigs[e->sigs_cnt].value = alproto;
            e->sigs_cnt++;
        }
        return 0;
    }

    struct TxNonPFData *add = SCCalloc(1, sizeof(*add));
    if (add == NULL) {
        return -1;
    }
    add->dir = dir;
    add->sub_state = sub_state;
    add->alproto = alproto;
    add->progress = progress;
    add->sig_list = sig_list;
    add->run_always = run_always;
    add->lte_hook = lte_hook;
    add->lte_grows = grows;
    add->sigs = SCCalloc(max_sids, sizeof(struct PrefilterNonPFDataSig));
    if (add->sigs == NULL) {
        SCFree(add);
        return -1;
    }
    add->sigs_cnt = 0;
    add->sigs[add->sigs_cnt].sid = s->iid;
    add->sigs[add->sigs_cnt].value = alproto;
    add->sigs_cnt++;

    char engine_name[128];
    /* the id-to-name lookup can return null for a state id outside
     * the protocol's table (e.g. the ssh completion state); a null
     * %s argument is UB and would register a "(null)" engine name */
    snprintf(engine_name, sizeof(engine_name), "%s:%s:non_pf:%s", AppProtoToString(alproto),
            name ? name : "unknown", dir == 0 ? "toserver" : "toclient");
    char *engine_name_heap = SCStrdup(engine_name);
    if (engine_name_heap == NULL) {
        SCFree(add->sigs);
        SCFree(add);
        return -1;
    }
    int result = HashTableAdd(
            de_ctx->non_pf_engine_names, engine_name_heap, (uint16_t)strlen(engine_name_heap));
    if (result != 0) {
        SCFree(add->sigs);
        SCFree(add);
        return -1;
    }

    add->engine_name = engine_name_heap;
    SCLogDebug("engine_name_heap %s", engine_name_heap);

    int ret = HashListTableAdd(tx_engines_hash, add, 0);
    if (ret != 0) {
        SCFree(add->sigs);
        SCFree(add);
        return -1;
    }

    return 0;
}

/** \internal
 *  \brief setup non-prefilter rules in special "non-prefilter" engines that are registered in the
 * prefilter logic.
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
static int SetupNonPrefilter(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    const uint32_t max_sids = DetectEngineGetMaxSigId(de_ctx);
    SCLogDebug("max_sids %u", max_sids);
    struct PrefilterNonPFDataSig *pkt_non_pf_array = SCCalloc(max_sids, sizeof(*pkt_non_pf_array));
    if (pkt_non_pf_array == NULL) {
        return -1;
    }
    uint32_t pkt_non_pf_array_size = 0;
    struct PrefilterNonPFDataSig *frame_non_pf_array =
            SCCalloc(max_sids, sizeof(*frame_non_pf_array));
    if (frame_non_pf_array == NULL) {
        SCFree(pkt_non_pf_array);
        return -1;
    }
    uint32_t frame_non_pf_array_size = 0;

    struct PrefilterNonPFDataSig *pkt_hook_flow_start_non_pf_array =
            SCCalloc(max_sids, sizeof(*pkt_hook_flow_start_non_pf_array));
    if (pkt_hook_flow_start_non_pf_array == NULL) {
        SCFree(pkt_non_pf_array);
        SCFree(frame_non_pf_array);
        return -1;
    }
    uint32_t pkt_hook_flow_start_non_pf_array_size = 0;
    SignatureMask pkt_hook_flow_start_mask = 0;
    bool pkt_hook_flow_start_mask_init = false;

    HashListTable *tx_engines_hash =
            HashListTableInit(256, TxNonPFHash, TxNonPFCompare, TxNonPFFree);
    if (tx_engines_hash == NULL) {
        SCFree(pkt_non_pf_array);
        SCFree(pkt_hook_flow_start_non_pf_array);
        SCFree(frame_non_pf_array);
        return -1;
    }

    if (de_ctx->non_pf_engine_names == NULL) {
        de_ctx->non_pf_engine_names =
                HashTableInit(512, NonPFNamesHash, NonPFNamesCompare, NonPFNamesFree);
        if (de_ctx->non_pf_engine_names == NULL) {
            SCFree(pkt_non_pf_array);
            SCFree(pkt_hook_flow_start_non_pf_array);
            SCFree(frame_non_pf_array);
            HashListTableFree(tx_engines_hash);
            return -1;
        }
    }

    SignatureMask pkt_mask = 0;
    bool pkt_mask_init = false;
#ifdef NONPF_PKT_STATS
    uint32_t nonpf_pkt_alproto = 0;
    uint32_t nonpf_pkt_dsize = 0;
    uint32_t nonpf_pkt_dport = 0;
#endif
    const int app_events_list_id = DetectBufferTypeGetByName("app-layer-events");
    SCLogDebug("app_events_list_id %d", app_events_list_id);
    const int app_state_list_id = DetectBufferTypeGetByName("app-layer-state");
    SCLogDebug("app_state_list_id %d", app_state_list_id);
    for (uint32_t sig = 0; sig < sgh->init->sig_cnt; sig++) {
        Signature *s = sgh->init->match_array[sig];
        if (s == NULL)
            continue;
        SCLogDebug("checking sid %u for non-prefilter", s->id);
        /* pf_hook: the rules hook state is covered by a fast pattern or a keyword
         * prefilter engine, so the rule needs no non-prefilter entry there. */
        bool pf_hook = false;
        if (s->init_data->mpm_sm != NULL && (s->flags & SIG_FLAG_MPM_NEG) == 0)
            pf_hook = true;
        if (s->init_data->prefilter_sm != NULL)
            pf_hook = true;
        if ((s->flags & (SIG_FLAG_PREFILTER | SIG_FLAG_MPM_NEG)) == SIG_FLAG_PREFILTER)
            pf_hook = true;
        const bool lte = (s->flags & SIG_FLAG_FW_HOOK_LTE) != 0;
        if (pf_hook && !lte)
            continue;
        SCLogDebug("setting up sid %u for non-prefilter", s->id);

        uint8_t frame_type = 0; /**< only a single type per rule */
        bool tx_non_pf = false;
        bool frame_non_pf = false;
        bool pkt_non_pf = false;

        if (s->init_data->hook.type == SIGNATURE_HOOK_TYPE_PKT &&
                s->init_data->hook.t.pkt.ph == SIGNATURE_HOOK_PKT_FLOW_START) {
            // TODO code duplication with regular pkt case below

            /* for pkt non prefilter, we have some space in the structure,
             * so we can squeeze another filter */
            uint8_t type;
            uint16_t value;
            if ((s->flags & SIG_FLAG_DSIZE) && s->dsize_mode == DETECT_UINT_EQ) {
                SCLogDebug("dsize extra match");
                type = 2;
                value = s->dsize_low;
            } else if (s->dp != NULL && s->dp->next == NULL && s->dp->port == s->dp->port2) {
                type = 1;
                value = s->dp->port;
            } else {
                type = 0;
                value = s->alproto;
            }
            pkt_hook_flow_start_non_pf_array[pkt_hook_flow_start_non_pf_array_size].sid = s->iid;
            pkt_hook_flow_start_non_pf_array[pkt_hook_flow_start_non_pf_array_size].value = value;
            pkt_hook_flow_start_non_pf_array[pkt_hook_flow_start_non_pf_array_size].type = type;
            pkt_hook_flow_start_non_pf_array[pkt_hook_flow_start_non_pf_array_size].pkt.sig_mask =
                    s->mask;
            pkt_hook_flow_start_non_pf_array_size++;

            if (pkt_hook_flow_start_mask_init) {
                pkt_hook_flow_start_mask &= s->mask;
            } else {
                pkt_hook_flow_start_mask = s->mask;
                pkt_hook_flow_start_mask_init = true;
            }

            SCLogDebug("flow_start hook");
            continue; // done for this sig
        }

        /* special case: insert sigs at hook before Signature::app_progress_hook for the HOOK_LTE
         * case: we need a addition per hook to make sure that the sig is called when needed. For
         * hook 0 it could have a preceding rule that makes sure this sig isn't triggered, but then
         * for hook 1 we would need to be called. */
        if (s->flags & SIG_FLAG_FW_HOOK_LTE) {
            /* With a fast pattern the pattern engine is the only one that may drop
             * rules that do not match, so the hook state is left to it: the window
             * covers the states below the hook and the engine bound takes care of
             * the hook and the states above it. Without one the rule needs to be in
             * the list at its hook, as it has always been. A hook of 0 has no state
             * below it to defer, and gating it would leave the rule with neither a
             * window nor an engine. */
            const bool gated = pf_hook && s->app_progress_hook > 0;
            for (uint8_t state = 0; state < s->app_progress_hook; state++) {
                SCLogDebug("handle HOOK %u LTE", state);
                const int dir = (s->flags & SIG_FLAG_TOSERVER) ? 0 : 1;
                const uint8_t sub_state = s->init_data->hook.t.app.sub_state;
                const char *pname = DetectEngineAppHookToName(
                        s->alproto, sub_state, state, dir == 0 ? STREAM_TOSERVER : STREAM_TOCLIENT);
                if (pname == NULL) {
                    goto error;
                }
                const uint8_t direction = dir == 0 ? STREAM_TOSERVER : STREAM_TOCLIENT;
                const int sm_list =
                        DetectEngineAppHookToSmlist(s->alproto, sub_state, state, direction);
                if (TxNonPFAddSig(de_ctx, tx_engines_hash, s->alproto, sub_state, dir, state,
                            sm_list, pname, s, false, gated ? s->app_progress_hook : 0) != 0) {
                    goto error;
                }
                tx_non_pf = true;
            }
            if (gated) {
                /* skip the buffer loop: it would add the rule at the hook
                 * regardless of what the pattern engine made of it */
                SCLogDebug("sid %u: LTE pending window only", s->id);
                continue;
            }
        }

        for (uint32_t x = 0; x < s->init_data->buffer_index; x++) {
            const int list_id = s->init_data->buffers[x].id;
            const DetectBufferType *buf = DetectEngineBufferTypeGetById(de_ctx, list_id);
            if (buf == NULL)
                continue;
            /* for now, exclude app-layer-events, as they are not tied to a specific
             * progress value like other keywords. */
            SCLogDebug("list_id %d buf %p", list_id, buf);
            if (list_id == app_events_list_id)
                continue;
            if (buf->packet) {
                SCLogDebug("packet buf");
                /* packet is handled below */
                pkt_non_pf = true;
            } else if (buf->frame) {
                for (DetectEngineFrameInspectionEngine *f = de_ctx->frame_inspect_engines;
                        f != NULL; f = f->next) {
                    if (!((((s->flags & SIG_FLAG_TOSERVER) != 0 && f->dir == 0) ||
                                  ((s->flags & SIG_FLAG_TOCLIENT) != 0 && f->dir == 1)) &&
                                list_id == (int)f->sm_list &&
                                AppProtoEquals(s->alproto, f->alproto)))
                        continue;

                    SCLogDebug("frame '%s' type %u", buf->name, f->type);
                    frame_type = f->type;
                    frame_non_pf = true;

                    frame_non_pf_array[frame_non_pf_array_size].sid = s->iid;
                    frame_non_pf_array[frame_non_pf_array_size].value = s->alproto;
                    frame_non_pf_array[frame_non_pf_array_size].frame.type = frame_type;
                    frame_non_pf_array_size++;
                    break;
                }

            } else {
                SCLogDebug("x %u list_id %d", x, list_id);
                for (DetectEngineAppInspectionEngine *app = de_ctx->app_inspect_engines;
                        app != NULL; app = app->next) {
                    SCLogDebug("app %p proto %s list_d %d sig dir %0x", app,
                            AppProtoToString(app->alproto), app->sm_list,
                            s->flags & (SIG_FLAG_TOSERVER | SIG_FLAG_TOCLIENT));

                    /* extra strict alproto check for SIGNATURE_HOOK_TYPE_APP,
                     * just like with mpm and per rule app engine. */
                    if (s->init_data->hook.type == SIGNATURE_HOOK_TYPE_APP) {
                        if (!AppProtoEqualsStrict(s->alproto, app->alproto))
                            continue;
                    }

                    /* skip if:
                     * - not in our dir
                     * - not our list
                     * - app proto mismatch. Both sig and app can have proto or unknown */
                    if (!((((s->flags & SIG_FLAG_TOSERVER) != 0 && app->dir == 0) ||
                                  ((s->flags & SIG_FLAG_TOCLIENT) != 0 && app->dir == 1)) &&
                                list_id == (int)app->sm_list &&
                                (s->alproto == ALPROTO_UNKNOWN || app->alproto == ALPROTO_UNKNOWN ||
                                        AppProtoEquals(s->alproto, app->alproto))))
                        continue;

                    int sig_list = 0;
                    if (list_id == app_state_list_id)
                        sig_list = app_state_list_id;
                    /* buffers marked run-always (stateful keywords) must be
                     * revisited as the tx advances. */
                    const bool run_always = buf != NULL && buf->run_always;
                    const uint8_t sub_state = app->sub_state;
                    if (TxNonPFAddSig(de_ctx, tx_engines_hash, app->alproto, sub_state, app->dir,
                                app->progress, sig_list, buf->name, s, run_always, 0) != 0) {
                        goto error;
                    }
                    tx_non_pf = true;
                }
            }
            if (frame_non_pf) {
                // we found a frame, do not look for other buffers
                // which may include the same frame + transform
                // but we only want 1 per signature
                break;
            }
        }
        /* handle hook only rules */
        if (!tx_non_pf && s->init_data->hook.type == SIGNATURE_HOOK_TYPE_APP) {
            const int dir = (s->flags & SIG_FLAG_TOSERVER) ? 0 : 1;
            const char *pname = AppLayerParserGetStateNameById(IPPROTO_TCP, // TODO
                    s->alproto, s->init_data->hook.t.app.app_progress,
                    dir == 0 ? STREAM_TOSERVER : STREAM_TOCLIENT);

            uint8_t sub_state = s->init_data->hook.t.app.sub_state;
            if (TxNonPFAddSig(de_ctx, tx_engines_hash, s->alproto, sub_state, dir,
                        s->init_data->hook.t.app.app_progress, s->init_data->hook.sm_list, pname, s,
                        false, 0) != 0) {
                goto error;
            }
            tx_non_pf = true;
        }
        /* mark as prefiltered as the sig is now part of a engine */
        // s->flags |= SIG_FLAG_PREFILTER;
        //  TODO doesn't work for sigs that are in multiple sgh's

        /* default to pkt if there was no tx or frame match */
        if (!(tx_non_pf || frame_non_pf)) {
            if (!pkt_non_pf) {
                SCLogDebug("not frame, not tx, so pkt");
            }
            pkt_non_pf = true;
        }

        SCLogDebug("setting up sid %u for non-prefilter: %s", s->id,
                tx_non_pf ? "tx engine" : (frame_non_pf ? "frame engine" : "pkt engine"));

        if (pkt_non_pf) {
            /* for pkt non prefilter, we have some space in the structure,
             * so we can squeeze another filter */
            uint8_t type;
            uint16_t value;
            if ((s->flags & SIG_FLAG_DSIZE) && s->dsize_mode == DETECT_UINT_EQ) {
                SCLogDebug("dsize extra match");
                type = 2;
                value = s->dsize_low;
#ifdef NONPF_PKT_STATS
                nonpf_pkt_dsize++;
#endif
            } else if (s->dp != NULL && s->dp->next == NULL && s->dp->port == s->dp->port2) {
                type = 1;
                value = s->dp->port;
#ifdef NONPF_PKT_STATS
                nonpf_pkt_dport++;
#endif
            } else {
                type = 0;
                value = s->alproto;
#ifdef NONPF_PKT_STATS
                nonpf_pkt_alproto++;
#endif
            }

            pkt_non_pf_array[pkt_non_pf_array_size].sid = s->iid;
            pkt_non_pf_array[pkt_non_pf_array_size].value = value;
            pkt_non_pf_array[pkt_non_pf_array_size].type = type;
            pkt_non_pf_array[pkt_non_pf_array_size].pkt.sig_mask = s->mask;
            pkt_non_pf_array_size++;

            if (pkt_mask_init) {
                pkt_mask &= s->mask;
            } else {
                pkt_mask = s->mask;
                pkt_mask_init = true;
            }
            SCLogDebug("s->id %u added", s->id);
        }
    }

    /* for each unique sig set, add an engine */
    for (HashListTableBucket *b = HashListTableGetListHead(tx_engines_hash); b != NULL;
            b = HashListTableGetListNext(b)) {
        struct TxNonPFData *t = HashListTableGetListData(b);
        SCLogDebug("%s engine for %s hook %d has %u non-pf sigs",
                t->dir == 0 ? "toserver" : "toclient", AppProtoToString(t->alproto), t->progress,
                t->sigs_cnt);

        if (((sgh->init->direction & SIG_FLAG_TOSERVER) && t->dir == 1) ||
                ((sgh->init->direction & SIG_FLAG_TOCLIENT) && t->dir == 0)) {
            SCLogDebug("skipped");
            continue;
        }

        DEBUG_VALIDATE_BUG_ON(t->progress > INT8_MAX);
        int8_t engine_progress = (int8_t)t->progress;
        if (t->sig_list == app_state_list_id) {
            /* app-layer-state engines use the -1 "run every update" sentinel;
             * they are proto-agnostic (ALPROTO_UNKNOWN), which that path
             * requires. */
            SCLogDebug("engine %s for state list, run always", t->engine_name);
            engine_progress = -1;
        }

        struct PrefilterNonPFDataTx *data =
                SCCalloc(1, sizeof(*data) + t->sigs_cnt * sizeof(data->array[0]));
        if (data == NULL)
            goto error;
        data->size = t->sigs_cnt;
        data->lte_grows = t->lte_grows;
        for (uint32_t i = 0; i < t->sigs_cnt; i++) {
            data->array[i] = t->sigs[i].sid;
        }
        if (t->lte_hook) {
            /* DetectPrefilterLtePendingIid merges the window against the sorted
             * candidates, so the window has to be in iid order. */
            qsort(data->array, data->size, sizeof(data->array[0]), PrefilterNonPFDataSortU32);
        }
        if (PrefilterAppendTxEngineSubState(de_ctx, sgh, PrefilterTxNonPF, t->alproto, t->sub_state,
                    engine_progress, (void *)data, PrefilterNonPFDataFree, t->engine_name) < 0) {
            SCFree(data);
            goto error;
        }
        if (t->run_always || t->lte_hook) {
            PrefilterEngineList *tail = sgh->init->tx_engines;
            while (tail->next != NULL)
                tail = tail->next;
            if (t->run_always) {
                /* A stateful keyword must be revisited as the tx advances. Keep
                 * its real progress (so the progress bookkeeping runs and the
                 * proto-agnostic -1 invariant holds) and carry an explicit flag. */
                tail->run_always = true;
            }
            if (t->lte_hook) {
                /* LTE pending window: stop adding the sids once the tx reached
                 * the rules hook, where the fast pattern takes over. */
                tail->tx_max_progress = t->lte_hook;
            }
        }
    }
    HashListTableFree(tx_engines_hash);
    tx_engines_hash = NULL;

    if (pkt_non_pf_array_size) {
        SCLogDebug("pkt_non_pf_array_size %u", pkt_non_pf_array_size);
        struct PrefilterNonPFData *data =
                SCCalloc(1, sizeof(*data) + pkt_non_pf_array_size * sizeof(data->array[0]));
        if (data == NULL)
            goto error;
        data->size = pkt_non_pf_array_size;
        memcpy((uint8_t *)&data->array, pkt_non_pf_array,
                pkt_non_pf_array_size * sizeof(data->array[0]));
        enum SignatureHookPkt hook = SIGNATURE_HOOK_PKT_NOT_SET; // TODO review
        if (PrefilterAppendEngine(de_ctx, sgh, PrefilterPktNonPF, pkt_mask, hook, (void *)data,
                    PrefilterNonPFDataFree, "packet:non_pf") < 0) {
            SCFree(data);
            goto error;
        }
    }
    if (pkt_hook_flow_start_non_pf_array_size) {
        struct PrefilterNonPFData *data = SCCalloc(
                1, sizeof(*data) + pkt_hook_flow_start_non_pf_array_size * sizeof(data->array[0]));
        if (data == NULL)
            goto error;
        data->size = pkt_hook_flow_start_non_pf_array_size;
        memcpy((uint8_t *)&data->array, pkt_hook_flow_start_non_pf_array,
                pkt_hook_flow_start_non_pf_array_size * sizeof(data->array[0]));
        SCLogDebug("packet:flow_start:non_pf added with %u rules", data->size);
        enum SignatureHookPkt hook = SIGNATURE_HOOK_PKT_FLOW_START;
        if (PrefilterAppendEngine(de_ctx, sgh,
                    PrefilterPktNonPFHookFlowStart, // TODO no longer needed to have a dedicated
                                                    // callback
                    pkt_hook_flow_start_mask, hook, (void *)data, PrefilterNonPFDataFree,
                    "packet:flow_start:non_pf") < 0) {
            SCFree(data);
            goto error;
        }
    }
    if (frame_non_pf_array_size) {
        SCLogDebug("%u frame non-pf sigs", frame_non_pf_array_size);
        struct PrefilterNonPFData *data =
                SCCalloc(1, sizeof(*data) + frame_non_pf_array_size * sizeof(data->array[0]));
        if (data == NULL)
            goto error;
        data->size = frame_non_pf_array_size;
        memcpy((uint8_t *)&data->array, frame_non_pf_array,
                frame_non_pf_array_size * sizeof(data->array[0]));
        if (PrefilterAppendFrameEngine(de_ctx, sgh, PrefilterFrameNonPF, ALPROTO_UNKNOWN,
                    FRAME_ANY_TYPE, (void *)data, PrefilterNonPFDataFree, "frame:non_pf") < 0) {
            SCFree(data);
            goto error;
        }
    }

    SCFree(pkt_hook_flow_start_non_pf_array);
    pkt_hook_flow_start_non_pf_array = NULL;
    SCFree(pkt_non_pf_array);
    pkt_non_pf_array = NULL;
    SCFree(frame_non_pf_array);
    frame_non_pf_array = NULL;
    return 0;

error:
    if (tx_engines_hash) {
        HashListTableFree(tx_engines_hash);
    }
    SCFree(pkt_hook_flow_start_non_pf_array);
    SCFree(pkt_non_pf_array);
    SCFree(frame_non_pf_array);
    return -1;
}

int PrefilterSetupRuleGroup(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    int r = PatternMatchPrepareGroup(de_ctx, sgh);
    if (r != 0) {
        FatalError("failed to set up pattern matching");
    }

    /* set up engines if needed - when prefilter is set to auto we run
     * all engines, otherwise only those that have been forced by the
     * prefilter keyword. */
    const enum DetectEnginePrefilterSetting setting = de_ctx->prefilter_setting;
    for (int i = 0; i < DETECT_TBLSIZE; i++) {
        if (sigmatch_table[i].SetupPrefilter != NULL &&
                (setting == DETECT_PREFILTER_AUTO || de_ctx->sm_types_prefilter[i])) {
            sigmatch_table[i].SetupPrefilter(de_ctx, sgh);
        }
    }

    if (SetupNonPrefilter(de_ctx, sgh) != 0) {
        return -1;
    }

    /* we have lists of engines in sgh->init now. Lets setup the
     * match arrays */
    PrefilterEngineList *el;
    if (sgh->init->pkt_engines != NULL) {
        SCLogDebug("for %p we have %p", sgh, sgh->init->pkt_engines);
        uint32_t cnt = 0;
        for (el = sgh->init->pkt_engines ; el != NULL; el = el->next) {
            cnt++;
        }
        SCLogDebug("cnt %u", cnt);
        sgh->pkt_engines = SCMallocAligned(cnt * sizeof(PrefilterEngine), CLS);
        if (sgh->pkt_engines == NULL) {
            return -1;
        }
        memset(sgh->pkt_engines, 0x00, (cnt * sizeof(PrefilterEngine)));

        PrefilterEngine *e = sgh->pkt_engines;
        for (el = sgh->init->pkt_engines ; el != NULL; el = el->next) {
            e->local_id = el->id;
            e->cb.Prefilter = el->Prefilter;
            e->ctx.pkt.mask = el->pkt_mask;
            // TODO right now we represent the hook in a u8 in the prefilter engine for space
            // reasons.
            BUG_ON(el->pkt_hook >= 8);
            e->ctx.pkt.hook = (uint8_t)el->pkt_hook;
            e->pectx = el->pectx;
            el->pectx = NULL; // e now owns the ctx
            e->gid = el->gid;
            if (el->next == NULL) {
                e->is_last = true;
            }
            e++;
        }
    }
    if (sgh->init->payload_engines != NULL) {
        uint32_t cnt = 0;
        for (el = sgh->init->payload_engines ; el != NULL; el = el->next) {
            cnt++;
        }
        sgh->payload_engines = SCMallocAligned(cnt * sizeof(PrefilterEngine), CLS);
        if (sgh->payload_engines == NULL) {
            return -1;
        }
        memset(sgh->payload_engines, 0x00, (cnt * sizeof(PrefilterEngine)));

        PrefilterEngine *e = sgh->payload_engines;
        for (el = sgh->init->payload_engines ; el != NULL; el = el->next) {
            e->local_id = el->id;
            e->cb.Prefilter = el->Prefilter;
            e->ctx.pkt.mask = el->pkt_mask;
            // TODO right now we represent the hook in a u8 in the prefilter engine for space
            // reasons.
            BUG_ON(el->pkt_hook >= 8);
            e->ctx.pkt.hook = (uint8_t)el->pkt_hook;
            e->pectx = el->pectx;
            el->pectx = NULL; // e now owns the ctx
            e->gid = el->gid;
            if (el->next == NULL) {
                e->is_last = true;
            }
            e++;
        }
    }
    if (sgh->init->tx_engines != NULL) {
        uint32_t cnt = 0;
        for (el = sgh->init->tx_engines ; el != NULL; el = el->next) {
            cnt++;
        }
        sgh->tx_engines = SCMallocAligned(cnt * sizeof(PrefilterEngine), CLS);
        if (sgh->tx_engines == NULL) {
            return -1;
        }
        memset(sgh->tx_engines, 0x00, (cnt * sizeof(PrefilterEngine)));

        uint16_t local_id = 0;
        PrefilterEngine *e = sgh->tx_engines;
        for (el = sgh->init->tx_engines ; el != NULL; el = el->next) {
            e->local_id = local_id++;
            e->alproto = el->alproto;
            e->ctx.app.tx_min_progress = el->tx_min_progress;
            e->ctx.app.tx_max_progress = el->tx_max_progress;
            e->ctx.app.sub_state = el->sub_state;
            e->run_always = el->run_always;
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
        for (AppProto a = ALPROTO_FAILED + 1; a < g_alproto_max; a++) {
            /* loop over sub-states. Protocols not supporting sub-states
             * will just use 0. */
            const uint8_t max_sub_state = AppLayerParserGetMaxSubState(a);
            for (uint8_t sub = 0; sub <= max_sub_state; sub++) {
                int last_tx_progress = 0;
                bool last_tx_progress_set = false;
                PrefilterEngine *prev_engine = NULL;
                engine = sgh->tx_engines;
                do {
                    if (engine->ctx.app.sub_state == sub) {
                        if (engine->ctx.app.tx_min_progress != -1)
                            BUG_ON(engine->ctx.app.tx_min_progress < last_tx_progress);
                        if (engine->alproto == a) {
                            if (last_tx_progress_set &&
                                    engine->ctx.app.tx_min_progress > last_tx_progress) {
                                if (prev_engine) {
                                    prev_engine->is_last_for_progress = true;
                                }
                            }

                            last_tx_progress_set = true;
                            prev_engine = engine;
                            if (!engine->is_last) {
                                PrefilterEngine *next_engine = engine + 1;
                                engine->is_last_for_progress =
                                        (next_engine->ctx.app.sub_state != sub);
                            }

                        } else {
                            if (prev_engine) {
                                prev_engine->is_last_for_progress = true;
                            }
                        }
                        last_tx_progress = engine->ctx.app.tx_min_progress;
                    }
                    if (engine->is_last)
                        break;
                    engine++;
                } while (1);
            }
        }
#ifdef DEBUG
        SCLogDebug("sgh %p", sgh);
        engine = sgh->tx_engines;
        do {
            SCLogDebug("engine: gid %u alproto %s sub_state %u tx_min_progress %d is_last %s "
                       "is_last_for_progress %s",
                    engine->gid, AppProtoToString(engine->alproto), engine->ctx.app.sub_state,
                    engine->ctx.app.tx_min_progress, engine->is_last ? "true" : "false",
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
        }
        sgh->frame_engines = SCMallocAligned(cnt * sizeof(PrefilterEngine), CLS);
        if (sgh->frame_engines == NULL) {
            return -1;
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
                e->is_last = true;
            }
            e++;
        }
    }

    if (sgh->init->post_rule_match_engines != NULL) {
        uint32_t cnt = 0;
        for (el = sgh->init->post_rule_match_engines; el != NULL; el = el->next) {
            cnt++;
        }
        sgh->post_rule_match_engines = SCMallocAligned(cnt * sizeof(PrefilterEngine), CLS);
        if (sgh->post_rule_match_engines == NULL) {
            return -1;
        }
        memset(sgh->post_rule_match_engines, 0x00, (cnt * sizeof(PrefilterEngine)));

        uint16_t local_id = 0;
        PrefilterEngine *e = sgh->post_rule_match_engines;
        for (el = sgh->init->post_rule_match_engines; el != NULL; el = el->next) {
            e->local_id = local_id++;
            e->cb.PrefilterPostRule = el->PrefilterPostRule;
            e->pectx = el->pectx;
            el->pectx = NULL; // e now owns the ctx
            e->gid = el->gid;
            e->is_last = (el->next == NULL);
            e++;
        }
        SCLogDebug("sgh %p max local_id %u", sgh, local_id);
    }

    return 0;
}

/* hash table for assigning a unique id to each engine type. */

static uint32_t PrefilterStoreHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    PrefilterStore *ctx = data;

    uint32_t hash = (uint32_t)strlen(ctx->name);

    for (size_t u = 0; u < strlen(ctx->name); u++) {
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

#include "util-print.h"

typedef struct PrefilterMpmCtx {
    int list_id;
    union {
        InspectionBufferGetDataPtr GetData;
        InspectionSingleBufferGetDataPtr GetDataSingle;
    };
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmCtx;

/** \brief Generic Mpm prefilter callback for simple InspectionSingleBufferGetDataPtr
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterMpmTxSingle(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const AppLayerTxData *_txd, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmCtx *ctx = (const PrefilterMpmCtx *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    SCLogDebug("running on list %d", ctx->list_id);

    InspectionBuffer *buffer = DetectGetSingleData(
            det_ctx, ctx->transforms, f, flags, txv, ctx->list_id, ctx->GetDataSingle);
    if (buffer == NULL)
        return;

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;

    SCLogDebug("mpm'ing buffer:");
    // PrintRawDataFp(stdout, data, data_len);

    if (data != NULL && data_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(
                mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, data, data_len);
        PREFILTER_PROFILING_ADD_BYTES(det_ctx, data_len);
    }
}

/** \brief Generic Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterMpm(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p, Flow *f,
        void *txv, const uint64_t idx, const AppLayerTxData *_txd, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmCtx *ctx = (const PrefilterMpmCtx *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    SCLogDebug("running on list %d", ctx->list_id);

    InspectionBuffer *buffer = ctx->GetData(det_ctx, ctx->transforms, f, flags, txv, ctx->list_id);
    if (buffer == NULL)
        return;

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;

    SCLogDebug("mpm'ing buffer:");
    //PrintRawDataFp(stdout, data, data_len);

    if (data != NULL && data_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(
                mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, data, data_len);
        PREFILTER_PROFILING_ADD_BYTES(det_ctx, data_len);
    }
}

static void PrefilterGenericMpmFree(void *ptr)
{
    SCFree(ptr);
}

int PrefilterGenericMpmRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    SCEnter();
    PrefilterMpmCtx *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->GetData = mpm_reg->app_v2.GetData;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    SCLogDebug("mpm_reg %s sub_state %u", mpm_reg->name, mpm_reg->app_v2.sub_state);
    int r = PrefilterAppendTxEngineSubState(de_ctx, sgh, PrefilterMpm, mpm_reg->app_v2.alproto,
            mpm_reg->app_v2.sub_state, mpm_reg->app_v2.tx_min_progress, pectx,
            PrefilterGenericMpmFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
    }
    return r;
}

int PrefilterSingleMpmRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    SCEnter();
    PrefilterMpmCtx *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->GetDataSingle = mpm_reg->app_v2.GetDataSingle;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    SCLogDebug("mpm_reg %s sub_state %u", mpm_reg->name, mpm_reg->app_v2.sub_state);
    int r = PrefilterAppendTxEngineSubState(de_ctx, sgh, PrefilterMpmTxSingle,
            mpm_reg->app_v2.alproto, mpm_reg->app_v2.sub_state, mpm_reg->app_v2.tx_min_progress,
            pectx, PrefilterGenericMpmFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
    }
    return r;
}

static void PrefilterMultiGenericMpmFree(void *ptr)
{
    // PrefilterMpmListId
    SCFree(ptr);
}

static void PrefilterMultiMpm(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p, Flow *f,
        void *txv, const uint64_t idx, const AppLayerTxData *_txd, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmListId *ctx = (const PrefilterMpmListId *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    SCLogDebug("running on list %d", ctx->list_id);
    uint32_t local_id = 0;

    do {
        // loop until we get a NULL
        InspectionBuffer *buffer = DetectGetMultiData(
                det_ctx, ctx->transforms, f, flags, txv, ctx->list_id, local_id, ctx->GetData);
        if (buffer == NULL)
            break;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(
                    mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, buffer->inspect, buffer->inspect_len);
            PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
        }

        local_id++;
    } while (1);
}

int PrefilterMultiGenericMpmRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    SCEnter();
    PrefilterMpmListId *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->GetData = mpm_reg->app_v2.GetMultiData;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    SCLogDebug("mpm_reg %s sub_state %u", mpm_reg->name, mpm_reg->app_v2.sub_state);
    int r = PrefilterAppendTxEngineSubState(de_ctx, sgh, PrefilterMultiMpm, mpm_reg->app_v2.alproto,
            mpm_reg->app_v2.sub_state, mpm_reg->app_v2.tx_min_progress, pectx,
            PrefilterMultiGenericMpmFree, mpm_reg->pname);
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
        (void)mpm_table[mpm_ctx->mpm_type].Search(
                mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, data, data_len);
        PREFILTER_PROFILING_ADD_BYTES(det_ctx, data_len);
    }
}

static void PrefilterMpmPktFree(void *ptr)
{
    SCFree(ptr);
}

int PrefilterGenericMpmPktRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    SCEnter();
    PrefilterMpmPktCtx *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->GetData = mpm_reg->pkt_v1.GetData;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    enum SignatureHookPkt hook = SIGNATURE_HOOK_PKT_NOT_SET; // TODO review
    int r = PrefilterAppendEngine(
            de_ctx, sgh, PrefilterMpmPkt, 0, hook, pectx, PrefilterMpmPktFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
    }
    return r;
}

#define QUEUE_STEP 16

void PostRuleMatchWorkQueueAppend(
        DetectEngineThreadCtx *det_ctx, const Signature *s, const int type, const uint32_t value)
{
    if (det_ctx->post_rule_work_queue.q == NULL) {
        det_ctx->post_rule_work_queue.q =
                SCCalloc(1, sizeof(PostRuleMatchWorkQueueItem) * QUEUE_STEP);
        if (det_ctx->post_rule_work_queue.q == NULL) {
            DetectEngineSetEvent(det_ctx, DETECT_EVENT_POST_MATCH_QUEUE_FAILED);
            return;
        }
        det_ctx->post_rule_work_queue.size = QUEUE_STEP;
    } else if (det_ctx->post_rule_work_queue.len == det_ctx->post_rule_work_queue.size) {
        void *ptr = SCRealloc(
                det_ctx->post_rule_work_queue.q, (det_ctx->post_rule_work_queue.size + QUEUE_STEP) *
                                                         sizeof(PostRuleMatchWorkQueueItem));
        if (ptr == NULL) {
            DetectEngineSetEvent(det_ctx, DETECT_EVENT_POST_MATCH_QUEUE_FAILED);
            return;
        }
        det_ctx->post_rule_work_queue.q = ptr;
        det_ctx->post_rule_work_queue.size += QUEUE_STEP;
    }
    det_ctx->post_rule_work_queue.q[det_ctx->post_rule_work_queue.len].sm_type = type;
    det_ctx->post_rule_work_queue.q[det_ctx->post_rule_work_queue.len].value = value;
#ifdef DEBUG
    det_ctx->post_rule_work_queue.q[det_ctx->post_rule_work_queue.len].id = s->iid;
#endif
    det_ctx->post_rule_work_queue.len++;
    SCLogDebug("det_ctx->post_rule_work_queue.len %u", det_ctx->post_rule_work_queue.len);
}

#ifdef UNITTESTS
static struct PrefilterNonPFDataTx *LteWindowTestData(const uint32_t *iids, uint32_t cnt)
{
    struct PrefilterNonPFDataTx *data = SCCalloc(1, sizeof(*data) + cnt * sizeof(data->array[0]));
    if (data == NULL)
        return NULL;
    data->size = cnt;
    for (uint32_t i = 0; i < cnt; i++)
        data->array[i] = iids[i];
    return data;
}

/** \test the pending rule of a LTE window the fast pattern did not add */
static int PrefilterLteWindowTest01(void)
{
    const uint32_t iids[] = { 2, 5, 9, 13 };
    struct PrefilterNonPFDataTx *data = LteWindowTestData(iids, 4);
    FAIL_IF(data == NULL);

    /* the pattern added nothing: the lowest rule of the window is pending */
    FAIL_IF(LteWindowFirstMissing(data, NULL, 0, 0) != 2);

    /* a rule of the window matched, but it is not the lowest one */
    RuleMatchCandidateTx cands[1] = { { .id = 5 } };
    FAIL_IF(LteWindowFirstMissing(data, cands, 1, 0) != 2);

    /* the lowest rule matched, so the miss is the next one */
    cands[0].id = 2;
    FAIL_IF(LteWindowFirstMissing(data, cands, 1, 0) != 5);

    RuleMatchCandidateTx more[3] = { { .id = 2 }, { .id = 5 }, { .id = 9 } };
    FAIL_IF(LteWindowFirstMissing(data, more, 3, 0) != 13);

    /* the window is fully matched: nothing is pending */
    RuleMatchCandidateTx all[4] = { { .id = 2 }, { .id = 5 }, { .id = 9 }, { .id = 13 } };
    FAIL_IF(LteWindowFirstMissing(data, all, 4, 0) != UINT32_MAX);

    /* the candidates also hold rules of other groups, before, between and after */
    RuleMatchCandidateTx mix[5] = { { .id = 1 }, { .id = 2 }, { .id = 6 }, { .id = 9 },
        { .id = 40 } };
    FAIL_IF(LteWindowFirstMissing(data, mix, 5, 0) != 5);

    SCFree(data);
    PASS;
}

/** \test empty and single entry windows */
static int PrefilterLteWindowTest02(void)
{
    struct PrefilterNonPFDataTx *empty = LteWindowTestData(NULL, 0);
    FAIL_IF(empty == NULL);
    FAIL_IF(LteWindowFirstMissing(empty, NULL, 0, 0) != UINT32_MAX);
    SCFree(empty);

    const uint32_t iids[] = { 7 };
    struct PrefilterNonPFDataTx *one = LteWindowTestData(iids, 1);
    FAIL_IF(one == NULL);
    FAIL_IF(LteWindowFirstMissing(one, NULL, 0, 0) != 7);
    FAIL_IF(LteWindowFirstMissing(one, NULL, 0, 8) != UINT32_MAX);
    RuleMatchCandidateTx cand = { .id = 7 };
    FAIL_IF(LteWindowFirstMissing(one, &cand, 1, 0) != UINT32_MAX);
    SCFree(one);
    PASS;
}

/** \test DetectPrefilterLtePendingIid over several windows */
static int PrefilterLteWindowTest03(void)
{
    DetectEngineThreadCtx det_ctx = { 0 };
    Signature sigs[6] = { { 0 } };
    for (uint32_t i = 0; i < 6; i++)
        sigs[i].iid = i;

    const uint32_t a[] = { 1, 3, 5 }, b[] = { 0, 2, 4 };
    struct PrefilterNonPFDataTx *wa = LteWindowTestData(a, 3);
    struct PrefilterNonPFDataTx *wb = LteWindowTestData(b, 3);
    FAIL_IF(wa == NULL || wb == NULL);
    FAIL_IF(wa == wb);

    RuleMatchCandidateTx cands[2] = { { .id = 0 }, { .id = 3 } };
    const void *windows[2] = { wa, wb };
    det_ctx.tx_candidates = cands;
    det_ctx.fw_lte_windows = windows;
    det_ctx.fw_lte_window_size = 2;
    det_ctx.fw_lte_window_cnt = 2;

    /* window b has rule 0, so its first miss is 2; window a misses at 1 */
    FAIL_IF(DetectPrefilterLtePendingIid(&det_ctx, 2, 0) != sigs[1].iid);
    /* the caller takes the next one when a rule turns out to be out of scope */
    FAIL_IF(DetectPrefilterLtePendingIid(&det_ctx, 2, 2) != 2);
    FAIL_IF(DetectPrefilterLtePendingIid(&det_ctx, 2, 3) != 4);
    FAIL_IF(DetectPrefilterLtePendingIid(&det_ctx, 2, 6) != UINT32_MAX);

    /* nothing pending: every rule of every window made the list */
    det_ctx.fw_lte_window_cnt = 0;
    FAIL_IF(DetectPrefilterLtePendingIid(&det_ctx, 2, 0) != UINT32_MAX);

    SCFree(wa);
    SCFree(wb);
    PASS;
}

/** \test more windows than the initial array holds: they all stay tracked */
static int PrefilterLteWindowTest04(void)
{
    DetectEngineThreadCtx det_ctx = { 0 };
    Signature sigs[16] = { { 0 } };
    for (uint32_t i = 0; i < 16; i++)
        sigs[i].iid = i;

    const uint32_t pending[] = { 4, 9 };
    const uint32_t matched[] = { 12 };
    struct PrefilterNonPFDataTx *w0 = LteWindowTestData(pending, 2);
    struct PrefilterNonPFDataTx *w[16] = { 0 };
    FAIL_IF(w0 == NULL);
    PrefilterLteWindowAdd(&det_ctx, w0);
    for (uint32_t i = 0; i < 16; i++) {
        /* distinct sets: the array has to grow past its initial 8 entries */
        w[i] = LteWindowTestData(matched, 1);
        FAIL_IF(w[i] == NULL);
        PrefilterLteWindowAdd(&det_ctx, w[i]);
    }
    FAIL_IF(det_ctx.fw_lte_window_cnt != 17);
    FAIL_IF(det_ctx.fw_lte_window_size != 32);
    /* a window already tracked is not tracked twice: the engines of a group share it */
    PrefilterLteWindowAdd(&det_ctx, w[3]);
    FAIL_IF(det_ctx.fw_lte_window_cnt != 17);

    /* the windows that are fully matched give no pending rule, window 0 misses at 9 */
    RuleMatchCandidateTx cands[2] = { { .id = 4 }, { .id = 12 } };
    det_ctx.tx_candidates = cands;
    FAIL_IF(DetectPrefilterLtePendingIid(&det_ctx, 2, 0) != sigs[9].iid);

    DetectPrefilterLteWindowFree(&det_ctx);
    FAIL_IF(det_ctx.fw_lte_windows != NULL);
    FAIL_IF(det_ctx.fw_lte_window_cnt != 0);
    for (uint32_t i = 0; i < 16; i++) {
        SCFree(w[i]);
    }
    SCFree(w0);
    PASS;
}

/** \test a large window entered at any cursor answers as a linear scan would
 *  (the search enters both arrays where the cursor lies, not at index 0)
 */
static int PrefilterLteWindowTest05(void)
{
    enum { WIN = 256, CAND = 128 };
    uint32_t iids[WIN];
    for (uint32_t i = 0; i < WIN; i++)
        iids[i] = i * 2 + 1;
    struct PrefilterNonPFDataTx *data = LteWindowTestData(iids, WIN);
    FAIL_IF_NULL(data);
    RuleMatchCandidateTx cands[CAND];
    for (uint32_t i = 0; i < CAND; i++)
        cands[i].id = i * 4 + 1;
    for (uint32_t cursor = 0; cursor <= WIN * 2; cursor += 7) {
        uint32_t want = UINT32_MAX;
        for (uint32_t i = 0; i < WIN; i++) {
            if (iids[i] < cursor)
                continue;
            bool in_cands = false;
            for (uint32_t j = 0; j < CAND; j++)
                in_cands |= cands[j].id == iids[i];
            if (!in_cands) {
                want = iids[i];
                break;
            }
        }
        FAIL_IF(LteWindowFirstMissing(data, cands, CAND, cursor) != want);
    }
    SCFree(data);
    PASS;
}

void DetectPrefilterRegisterTests(void)
{
    UtRegisterTest("PrefilterLteWindowTest01", PrefilterLteWindowTest01);
    UtRegisterTest("PrefilterLteWindowTest02", PrefilterLteWindowTest02);
    UtRegisterTest("PrefilterLteWindowTest03", PrefilterLteWindowTest03);
    UtRegisterTest("PrefilterLteWindowTest04", PrefilterLteWindowTest04);
    UtRegisterTest("PrefilterLteWindowTest05", PrefilterLteWindowTest05);
}
#endif /* UNITTESTS */
