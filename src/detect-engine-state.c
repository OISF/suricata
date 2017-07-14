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
 * \defgroup sigstate State support
 *
 * It is possible to do matching on reconstructed applicative flow.
 * This is done by this code. It uses the ::Flow structure to store
 * the list of signatures to match on the reconstructed stream.
 *
 * The Flow::de_state is a ::DetectEngineState structure. This is
 * basically a containter for storage item of type ::DeStateStore.
 * They contains an array of ::DeStateStoreItem which store the
 * state of match for an individual signature identified by
 * DeStateStoreItem::sid.
 *
 * The state is constructed by DeStateDetectStartDetection() which
 * also starts the matching. Work is continued by
 * DeStateDetectContinueDetection().
 *
 * Once a transaction has been analysed DeStateRestartDetection()
 * is used to reset the structures.
 *
 * @{
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * \brief State based signature handling.
 */

#include "suricata-common.h"

#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-engine-state.h"
#include "detect-engine-dcepayload.h"

#include "detect-flowvar.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"
#include "app-layer-smb.h"
#include "app-layer-dcerpc-common.h"
#include "app-layer-dcerpc.h"
#include "app-layer-dns-common.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-profiling.h"

#include "flow-util.h"

/** convert enum to string */
#define CASE_CODE(E)  case E: return #E

/** The DetectEngineThreadCtx::de_state_sig_array contains 2 separate values:
 *  1. the first bit tells the prefilter engine to bypass the rule (or not)
 *  2. the other bits allow 'ContinueDetect' to specify an offset again the
 *     base tx id. This offset will then be used by 'StartDetect' to not
 *     inspect transactions again for the same signature.
 *
 *  The offset in (2) has a max value due to the limited data type. If it is
 *  set to max the code will fall back to a slower path that validates that
 *  we're not adding duplicate rules to the detection state.
 */
#define MAX_STORED_TXID_OFFSET 127

/******** static internal helpers *********/

static inline int StateIsValid(uint16_t alproto, void *alstate)
{
    if (alstate != NULL) {
        if (alproto == ALPROTO_HTTP) {
            HtpState *htp_state = (HtpState *)alstate;
            if (htp_state->conn != NULL) {
                return 1;
            }
        } else {
            return 1;
        }
    }
    return 0;
}

static inline int TxIsLast(uint64_t tx_id, uint64_t total_txs)
{
    if (total_txs - tx_id <= 1)
        return 1;
    return 0;
}

static DeStateStore *DeStateStoreAlloc(void)
{
    DeStateStore *d = SCMalloc(sizeof(DeStateStore));
    if (unlikely(d == NULL))
        return NULL;
    memset(d, 0, sizeof(DeStateStore));

    return d;
}

static int DeStateSearchState(DetectEngineState *state, uint8_t direction, SigIntId num)
{
    DetectEngineStateDirection *dir_state = &state->dir_state[direction & STREAM_TOSERVER ? 0 : 1];
    DeStateStore *tx_store = dir_state->head;
    SigIntId store_cnt;
    SigIntId state_cnt = 0;

    for (; tx_store != NULL; tx_store = tx_store->next) {
        SCLogDebug("tx_store %p", tx_store);
        for (store_cnt = 0;
             store_cnt < DE_STATE_CHUNK_SIZE && state_cnt < dir_state->cnt;
             store_cnt++, state_cnt++)
        {
            DeStateStoreItem *item = &tx_store->store[store_cnt];
            if (item->sid == num) {
                SCLogDebug("sid %u already in state: %p %p %p %u %u, direction %s",
                            num, state, dir_state, tx_store, state_cnt,
                            store_cnt, direction & STREAM_TOSERVER ? "toserver" : "toclient");
                return 1;
            }
        }
    }
    return 0;
}

static void DeStateSignatureAppend(DetectEngineState *state,
        const Signature *s, uint32_t inspect_flags, uint8_t direction)
{
    int jump = 0;
    int i = 0;
    DetectEngineStateDirection *dir_state = &state->dir_state[direction & STREAM_TOSERVER ? 0 : 1];

#ifdef DEBUG_VALIDATION
    BUG_ON(DeStateSearchState(state, direction, s->num));
#endif
    DeStateStore *store = dir_state->head;

    if (store == NULL) {
        store = DeStateStoreAlloc();
        if (store != NULL) {
            dir_state->head = store;
            dir_state->tail = store;
        }
    } else {
        jump = dir_state->cnt / DE_STATE_CHUNK_SIZE;
        for (i = 0; i < jump; i++) {
            store = store->next;
        }
        if (store == NULL) {
            store = DeStateStoreAlloc();
            if (store != NULL) {
                dir_state->tail->next = store;
                dir_state->tail = store;
            }
        }
    }

    if (store == NULL)
        return;

    SigIntId idx = dir_state->cnt++ % DE_STATE_CHUNK_SIZE;
    store->store[idx].sid = s->num;
    store->store[idx].flags = inspect_flags;

    return;
}

static void DeStateStoreFileNoMatchCnt(DetectEngineState *de_state, uint16_t file_no_match, uint8_t direction)
{
    de_state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].filestore_cnt += file_no_match;

    return;
}

static int DeStateStoreFilestoreSigsCantMatch(const SigGroupHead *sgh, DetectEngineState *de_state, uint8_t direction)
{
    if (de_state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].filestore_cnt == sgh->filestore_cnt)
        return 1;
    else
        return 0;
}

DetectEngineState *DetectEngineStateAlloc(void)
{
    DetectEngineState *d = SCMalloc(sizeof(DetectEngineState));
    if (unlikely(d == NULL))
        return NULL;
    memset(d, 0, sizeof(DetectEngineState));

    return d;
}

void DetectEngineStateFree(DetectEngineState *state)
{
    DeStateStore *store;
    DeStateStore *store_next;
    int i = 0;

    for (i = 0; i < 2; i++) {
        store = state->dir_state[i].head;
        while (store != NULL) {
            store_next = store->next;
            SCFree(store);
            store = store_next;
        }
    }
    SCFree(state);

    return;
}

static int HasStoredSigs(const Flow *f, const uint8_t flags)
{
    AppProto alproto = f->alproto;
    void *alstate = FlowGetAppState(f);
    if (!StateIsValid(f->alproto, alstate)) {
        return 0;
    }

    int state = AppLayerParserHasTxDetectState(f->proto, alproto, f->alstate);
    if (state == -ENOSYS) { /* proto doesn't support this API call */
        /* fall through */
    } else if (state == 0) {
        return 0;
    }
    /* if state == 1 we also fall through */

    uint64_t inspect_tx_id = AppLayerParserGetTransactionInspectId(f->alparser, flags);
    uint64_t total_txs = AppLayerParserGetTxCnt(f, alstate);

    for ( ; inspect_tx_id < total_txs; inspect_tx_id++) {
        void *inspect_tx = AppLayerParserGetTx(f->proto, alproto, alstate, inspect_tx_id);
        if (inspect_tx != NULL) {
            DetectEngineState *tx_de_state = AppLayerParserGetTxDetectState(f->proto, alproto, inspect_tx);
            if (tx_de_state == NULL) {
                continue;
            }
            if (tx_de_state->dir_state[flags & STREAM_TOSERVER ? 0 : 1].cnt != 0) {
                SCLogDebug("tx %"PRIu64" has sigs present", inspect_tx_id);
                return 1;
            }
        }
    }
    return 0;
}

/** \brief Check if we need to inspect this state
 *
 *  State needs to be inspected if:
 *   1. state has been updated
 *   2. we already have de_state in progress
 *
 *  \retval 0 no inspectable state
 *  \retval 1 inspectable state
 */
int DeStateFlowHasInspectableState(const Flow *f, const uint8_t flags)
{
    int r = 0;

    if (HasStoredSigs(f, flags)) {
        r = 1;
    } else {
        r = 0;
    }
    return r;
}

static void StoreStateTxHandleFiles(DetectEngineThreadCtx *det_ctx, Flow *f,
                                    DetectEngineState *destate, const uint8_t flags,
                                    const uint64_t tx_id, const uint16_t file_no_match)
{
    SCLogDebug("tx %"PRIu64", file_no_match %u", tx_id, file_no_match);
    DeStateStoreFileNoMatchCnt(destate, file_no_match, flags);
    if (DeStateStoreFilestoreSigsCantMatch(det_ctx->sgh, destate, flags) == 1) {
        FileDisableStoringForTransaction(f, flags & (STREAM_TOCLIENT | STREAM_TOSERVER), tx_id);
    }
}

static void StoreStateTxFileOnly(DetectEngineThreadCtx *det_ctx,
        Flow *f, const uint8_t flags, const uint64_t tx_id, void *tx,
        const uint16_t file_no_match)
{
    DetectEngineState *destate = AppLayerParserGetTxDetectState(f->proto, f->alproto, tx);
    if (destate == NULL) {
        destate = DetectEngineStateAlloc();
        if (destate == NULL)
            return;
        if (AppLayerParserSetTxDetectState(f, f->alstate, tx, destate) < 0) {
            DetectEngineStateFree(destate);
            return;
        }
        SCLogDebug("destate created for %"PRIu64, tx_id);
    }
    StoreStateTxHandleFiles(det_ctx, f, destate, flags, tx_id, file_no_match);
}

/**
 *  \param check_before_add check for duplicates before adding the sig
 */
static void StoreStateTx(DetectEngineThreadCtx *det_ctx,
        Flow *f, const uint8_t flags,
        const uint64_t tx_id, void *tx,
        const Signature *s, const SigMatchData *smd,
        const uint32_t inspect_flags, const uint16_t file_no_match, int check_before_add)
{
    DetectEngineState *destate = AppLayerParserGetTxDetectState(f->proto, f->alproto, tx);
    if (destate == NULL) {
        destate = DetectEngineStateAlloc();
        if (destate == NULL)
            return;
        if (AppLayerParserSetTxDetectState(f, f->alstate, tx, destate) < 0) {
            DetectEngineStateFree(destate);
            return;
        }
        SCLogDebug("destate created for %"PRIu64, tx_id);
    }

    SCLogDebug("file_no_match %u", file_no_match);

    if (check_before_add == 0 || DeStateSearchState(destate, flags, s->num) == 0)
        DeStateSignatureAppend(destate, s, inspect_flags, flags);

    StoreStateTxHandleFiles(det_ctx, f, destate, flags, tx_id, file_no_match);
    SCLogDebug("Stored for TX %"PRIu64, tx_id);
}

int DeStateDetectStartDetection(ThreadVars *tv, DetectEngineCtx *de_ctx,
                                DetectEngineThreadCtx *det_ctx,
                                const Signature *s, Packet *p, Flow *f, uint8_t flags,
                                AppProto alproto)
{
    SCLogDebug("rule %u/%u", s->id, s->num);

    /* TX based matches (inspect engines) */
    void *alstate = FlowGetAppState(f);
    if (unlikely(!StateIsValid(alproto, alstate))) {
        return 0;
    }

    SigMatchData *smd = NULL;
    uint16_t file_no_match = 0;
    uint32_t inspect_flags = 0;
    int alert_cnt = 0;
    uint8_t direction = (flags & STREAM_TOSERVER) ? 0 : 1;
    int check_before_add = 0;

    /* if continue detection already inspected this rule for this tx,
     * continue with the first not-inspected tx */
    uint8_t offset = det_ctx->de_state_sig_array[s->num] & 0xef;
    uint64_t tx_id = AppLayerParserGetTransactionInspectId(f->alparser, flags);
    if (offset > 0) {
        SCLogDebug("using stored_tx_id %"PRIu64" instead of %"PRIu64, tx_id+offset, tx_id);
        tx_id += offset;
    }
    if (offset == MAX_STORED_TXID_OFFSET) {
        check_before_add = 1;
    }

    uint64_t total_txs = AppLayerParserGetTxCnt(f, alstate);
    SCLogDebug("total_txs %"PRIu64, total_txs);

    SCLogDebug("starting: start tx %"PRIu64", packet %"PRIu64, tx_id, p->pcap_cnt);

    det_ctx->stream_already_inspected = false;
    for (; tx_id < total_txs; tx_id++) {
        int total_matches = 0;
        void *tx = AppLayerParserGetTx(f->proto, alproto, alstate, tx_id);
        SCLogDebug("tx %p", tx);
        if (tx == NULL)
            continue;
        det_ctx->tx_id = tx_id;
        det_ctx->tx_id_set = 1;
        det_ctx->p = p;
        int tx_progress = AppLayerParserGetStateProgress(f->proto, alproto, tx, flags);

        /* see if we need to consider the next tx in our decision to add
         * a sig to the 'no inspect array'. */
        int next_tx_no_progress = 0;
        if (!TxIsLast(tx_id, total_txs)) {
            void *next_tx = AppLayerParserGetTx(f->proto, alproto, alstate, tx_id+1);
            if (next_tx != NULL) {
                int c = AppLayerParserGetStateProgress(f->proto, alproto, next_tx, flags);
                if (c == 0) {
                    next_tx_no_progress = 1;
                }
            }
        }

        DetectEngineAppInspectionEngine *engine = s->app_inspect;
        SCLogDebug("engine %p", engine);
        inspect_flags = 0;
        while (engine != NULL) {
            SCLogDebug("engine %p", engine);
            SCLogDebug("inspect_flags %x", inspect_flags);
            if (direction == engine->dir) {
                if (tx_progress < engine->progress) {
                    SCLogDebug("tx progress %d < engine progress %d",
                            tx_progress, engine->progress);
                    break;
                }

                KEYWORD_PROFILING_SET_LIST(det_ctx, engine->sm_list);
                int match = engine->Callback(tv, de_ctx, det_ctx,
                        s, engine->smd, f, flags, alstate, tx, tx_id);
                SCLogDebug("engine %p match %d", engine, match);
                if ((match == DETECT_ENGINE_INSPECT_SIG_NO_MATCH || match == DETECT_ENGINE_INSPECT_SIG_CANT_MATCH)
                        && (engine->mpm)) {
                    SCLogDebug("MPM and not matching, so skip the whole TX");
                    // TODO
                    goto try_next;
                } else
                if (match == DETECT_ENGINE_INSPECT_SIG_MATCH) {
                    inspect_flags |= BIT_U32(engine->id);
                    engine = engine->next;
                    total_matches++;
                    continue;
                } else if (match == DETECT_ENGINE_INSPECT_SIG_MATCH_MORE_FILES) {
                    /* if the file engine matched, but indicated more
                     * files are still in progress, we don't set inspect
                     * flags as these would end inspection for this tx */
                    engine = engine->next;
                    total_matches++;
                    continue;
                } else if (match == DETECT_ENGINE_INSPECT_SIG_CANT_MATCH) {
                    inspect_flags |= DE_STATE_FLAG_SIG_CANT_MATCH;
                    inspect_flags |= BIT_U32(engine->id);
                } else if (match == DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILESTORE) {
                    inspect_flags |= DE_STATE_FLAG_SIG_CANT_MATCH;
                    inspect_flags |= BIT_U32(engine->id);
                    file_no_match++;
                }
                break;
            }
            engine = engine->next;
        }
        SCLogDebug("inspect_flags %x", inspect_flags);
        /* all the engines seem to be exhausted at this point.  If we
         * didn't have a match in one of the engines we would have
         * broken off and engine wouldn't be NULL.  Hence the alert. */
        if (engine == NULL && total_matches > 0) {
            if (!(s->flags & SIG_FLAG_NOALERT)) {
                PacketAlertAppend(det_ctx, s, p, tx_id,
                        PACKET_ALERT_FLAG_STATE_MATCH|PACKET_ALERT_FLAG_TX);
            } else {
                DetectSignatureApplyActions(p, s,
                        PACKET_ALERT_FLAG_STATE_MATCH|PACKET_ALERT_FLAG_TX);
            }
            alert_cnt = 1;
            SCLogDebug("MATCH: tx %"PRIu64" packet %"PRIu64, tx_id, p->pcap_cnt);
        }

        /* if this is the last tx in our list, and it's incomplete: then
         * we store the state so that ContinueDetection knows about it */
        int tx_is_done = (tx_progress >=
                AppLayerParserGetStateProgressCompletionStatus(alproto, flags));

        SCLogDebug("tx %"PRIu64", packet %"PRIu64", rule %u, alert_cnt %u, last tx %d, tx_is_done %d, next_tx_no_progress %d",
                tx_id, p->pcap_cnt, s->num, alert_cnt,
                TxIsLast(tx_id, total_txs), tx_is_done, next_tx_no_progress);

        /* store our state */
        if (!(TxIsLast(tx_id, total_txs)) || !tx_is_done) {
            if (engine == NULL || inspect_flags & DE_STATE_FLAG_SIG_CANT_MATCH) {
                inspect_flags |= DE_STATE_FLAG_FULL_INSPECT;
            }

            /* store */
            StoreStateTx(det_ctx, f, flags, tx_id, tx,
                    s, smd, inspect_flags, file_no_match, check_before_add);
        } else {
            StoreStateTxFileOnly(det_ctx, f, flags, tx_id, tx, file_no_match);
        }
    try_next:
        if (next_tx_no_progress)
            break;
    } /* for */

    det_ctx->tx_id = 0;
    det_ctx->tx_id_set = 0;
    det_ctx->p = NULL;
    return alert_cnt ? 1:0;
}

static int DoInspectItem(ThreadVars *tv,
    DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
    DeStateStoreItem *item, const uint8_t dir_state_flags,
    Packet *p, Flow *f, AppProto alproto, uint8_t flags,
    const uint64_t inspect_tx_id, const uint64_t total_txs,

    uint16_t *file_no_match, int inprogress, // is current tx in progress?
    const int next_tx_no_progress)                // tx after current is still dormant
{
    Signature *s = de_ctx->sig_array[item->sid];
    det_ctx->stream_already_inspected = false;

    SCLogDebug("file_no_match %u, sid %u", *file_no_match, s->id);

    /* check if a sig in state 'full inspect' needs to be reconsidered
     * as the result of a new file in the existing tx */
    if (item->flags & DE_STATE_FLAG_FULL_INSPECT) {
        if (item->flags & (DE_STATE_FLAG_FILE_TC_INSPECT|DE_STATE_FLAG_FILE_TS_INSPECT)) {
            if ((flags & STREAM_TOCLIENT) &&
                    (dir_state_flags & DETECT_ENGINE_STATE_FLAG_FILE_TC_NEW))
            {
                SCLogDebug("~DE_STATE_FLAG_FILE_TC_INSPECT");
                item->flags &= ~DE_STATE_FLAG_FILE_TC_INSPECT;
                item->flags &= ~DE_STATE_FLAG_FULL_INSPECT;
                item->flags &= ~DE_STATE_FLAG_SIG_CANT_MATCH;
            }

            if ((flags & STREAM_TOSERVER) &&
                    (dir_state_flags & DETECT_ENGINE_STATE_FLAG_FILE_TS_NEW))
            {
                SCLogDebug("~DE_STATE_FLAG_FILE_TS_INSPECT");
                item->flags &= ~DE_STATE_FLAG_FILE_TS_INSPECT;
                item->flags &= ~DE_STATE_FLAG_FULL_INSPECT;
                item->flags &= ~DE_STATE_FLAG_SIG_CANT_MATCH;
            }
        }

        if (item->flags & DE_STATE_FLAG_FULL_INSPECT) {
            if (TxIsLast(inspect_tx_id, total_txs) || inprogress || next_tx_no_progress) {
                det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_NO_NEW_STATE;
                SCLogDebug("skip and bypass %u: tx %"PRIu64" packet %"PRIu64, s->id, inspect_tx_id, p->pcap_cnt);
            } else {
                SCLogDebug("just skip: tx %"PRIu64" packet %"PRIu64, inspect_tx_id, p->pcap_cnt);

                /* make sure that if we reinspect this right now from
                 * start detection, we skip this tx we just matched on */
                uint64_t base_tx_id = AppLayerParserGetTransactionInspectId(f->alparser, flags);
                uint64_t offset = (inspect_tx_id + 1) - base_tx_id;
                if (offset > MAX_STORED_TXID_OFFSET)
                    offset = MAX_STORED_TXID_OFFSET;
                det_ctx->de_state_sig_array[item->sid] = (uint8_t)offset;
#ifdef DEBUG_VALIDATION
                BUG_ON(det_ctx->de_state_sig_array[item->sid] & DE_STATE_MATCH_NO_NEW_STATE); // check that we don't set the bit
#endif
                SCLogDebug("storing tx_id %"PRIu64" for this sid", inspect_tx_id + 1);
            }
            return 0;
        }
    }

    /* check if a sig in state 'cant match' needs to be reconsidered
     * as the result of a new file in the existing tx */
    SCLogDebug("item->flags %x", item->flags);
    if (item->flags & DE_STATE_FLAG_SIG_CANT_MATCH) {
        SCLogDebug("DE_STATE_FLAG_SIG_CANT_MATCH");

        if ((flags & STREAM_TOSERVER) &&
                (item->flags & DE_STATE_FLAG_FILE_TS_INSPECT) &&
                (dir_state_flags & DETECT_ENGINE_STATE_FLAG_FILE_TS_NEW))
        {
            SCLogDebug("unset ~DE_STATE_FLAG_FILE_TS_INSPECT ~DE_STATE_FLAG_SIG_CANT_MATCH");
            item->flags &= ~DE_STATE_FLAG_FILE_TS_INSPECT;
            item->flags &= ~DE_STATE_FLAG_SIG_CANT_MATCH;

        } else if ((flags & STREAM_TOCLIENT) &&
                (item->flags & DE_STATE_FLAG_FILE_TC_INSPECT) &&
                (dir_state_flags & DETECT_ENGINE_STATE_FLAG_FILE_TC_NEW))
        {
            SCLogDebug("unset ~DE_STATE_FLAG_FILE_TC_INSPECT ~DE_STATE_FLAG_SIG_CANT_MATCH");
            item->flags &= ~DE_STATE_FLAG_FILE_TC_INSPECT;
            item->flags &= ~DE_STATE_FLAG_SIG_CANT_MATCH;
        } else {
            if (TxIsLast(inspect_tx_id, total_txs) || inprogress || next_tx_no_progress) {
                det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_NO_NEW_STATE;
                SCLogDebug("skip and bypass: tx %"PRIu64" packet %"PRIu64, inspect_tx_id, p->pcap_cnt);
            } else {
                SCLogDebug("just skip: tx %"PRIu64" packet %"PRIu64, inspect_tx_id, p->pcap_cnt);

                /* make sure that if we reinspect this right now from
                 * start detection, we skip this tx we just matched on */
                uint64_t base_tx_id = AppLayerParserGetTransactionInspectId(f->alparser, flags);
                uint64_t offset = (inspect_tx_id + 1) - base_tx_id;
                if (offset > MAX_STORED_TXID_OFFSET)
                    offset = MAX_STORED_TXID_OFFSET;
                det_ctx->de_state_sig_array[item->sid] = (uint8_t)offset;
#ifdef DEBUG_VALIDATION
                BUG_ON(det_ctx->de_state_sig_array[item->sid] & DE_STATE_MATCH_NO_NEW_STATE); // check that we don't set the bit
#endif
                SCLogDebug("storing tx_id %"PRIu64" for this sid", inspect_tx_id + 1);
            }
            return 0;
        }
    }

    uint8_t alert = 0;
    uint32_t inspect_flags = 0;
    int total_matches = 0;

    RULE_PROFILING_START(p);

    void *alstate = FlowGetAppState(f);
    if (!StateIsValid(alproto, alstate)) {
        RULE_PROFILING_END(det_ctx, s, 0, p);
        return -1;
    }

    det_ctx->tx_id = inspect_tx_id;
    det_ctx->tx_id_set = 1;
    det_ctx->p = p;
    SCLogDebug("inspecting: tx %"PRIu64" packet %"PRIu64, inspect_tx_id, p->pcap_cnt);

    uint8_t direction = (flags & STREAM_TOSERVER) ? 0 : 1;
    DetectEngineAppInspectionEngine *engine = s->app_inspect;
    void *inspect_tx = AppLayerParserGetTx(f->proto, alproto, alstate, inspect_tx_id);
    if (inspect_tx == NULL) {
        RULE_PROFILING_END(det_ctx, s, 0, p);
        return -1;
    }
    int tx_progress = AppLayerParserGetStateProgress(f->proto, alproto, inspect_tx, flags);

    while (engine != NULL) {
        if (!(item->flags & BIT_U32(engine->id)) &&
                direction == engine->dir)
        {
            SCLogDebug("inspect_flags %x", inspect_flags);

            if (tx_progress < engine->progress) {
                SCLogDebug("tx progress %d < engine progress %d",
                        tx_progress, engine->progress);
                break;
            }

            KEYWORD_PROFILING_SET_LIST(det_ctx, engine->sm_list);
            int match = engine->Callback(tv, de_ctx, det_ctx,
                    s, engine->smd,
                    f, flags, alstate, inspect_tx, inspect_tx_id);
            if (match == DETECT_ENGINE_INSPECT_SIG_MATCH) {
                inspect_flags |= BIT_U32(engine->id);
                engine = engine->next;
                total_matches++;
                continue;
            } else if (match == DETECT_ENGINE_INSPECT_SIG_MATCH_MORE_FILES) {
                /* if the file engine matched, but indicated more
                 * files are still in progress, we don't set inspect
                 * flags as these would end inspection for this tx */
                engine = engine->next;
                total_matches++;
                continue;
            } else if (match == DETECT_ENGINE_INSPECT_SIG_CANT_MATCH) {
                inspect_flags |= DE_STATE_FLAG_SIG_CANT_MATCH;
                inspect_flags |= BIT_U32(engine->id);
            } else if (match == DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILESTORE) {
                inspect_flags |= DE_STATE_FLAG_SIG_CANT_MATCH;
                inspect_flags |= BIT_U32(engine->id);
                (*file_no_match)++;
            }
            break;
        }
        engine = engine->next;
    }
    SCLogDebug("inspect_flags %x", inspect_flags);
    if (total_matches > 0 && (engine == NULL || inspect_flags & DE_STATE_FLAG_SIG_CANT_MATCH)) {
        if (engine == NULL)
            alert = 1;
        inspect_flags |= DE_STATE_FLAG_FULL_INSPECT;
    }

    item->flags |= inspect_flags;
    /* flag this sig to don't inspect again from the detection loop it if
     * there is no need for it */
    if (TxIsLast(inspect_tx_id, total_txs) || inprogress || next_tx_no_progress) {
        det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_NO_NEW_STATE;
        SCLogDebug("inspected, now bypass: tx %"PRIu64" packet %"PRIu64, inspect_tx_id, p->pcap_cnt);
    } else {
        /* make sure that if we reinspect this right now from
         * start detection, we skip this tx we just matched on */
        uint64_t base_tx_id = AppLayerParserGetTransactionInspectId(f->alparser, flags);
        uint64_t offset = (inspect_tx_id + 1) - base_tx_id;
        if (offset > MAX_STORED_TXID_OFFSET)
            offset = MAX_STORED_TXID_OFFSET;
        det_ctx->de_state_sig_array[item->sid] = (uint8_t)offset;
#ifdef DEBUG_VALIDATION
        BUG_ON(det_ctx->de_state_sig_array[item->sid] & DE_STATE_MATCH_NO_NEW_STATE); // check that we don't set the bit
#endif
        SCLogDebug("storing tx_id %"PRIu64" for this sid", inspect_tx_id + 1);
    }
    RULE_PROFILING_END(det_ctx, s, (alert == 1), p);

    if (alert) {
        SigMatchSignaturesRunPostMatch(tv, de_ctx, det_ctx, p, s);

        if (!(s->flags & SIG_FLAG_NOALERT)) {
            PacketAlertAppend(det_ctx, s, p, inspect_tx_id,
                    PACKET_ALERT_FLAG_STATE_MATCH|PACKET_ALERT_FLAG_TX);
        } else {
            PACKET_UPDATE_ACTION(p, s->action);
        }
        SCLogDebug("MATCH: tx %"PRIu64" packet %"PRIu64, inspect_tx_id, p->pcap_cnt);
    }

    DetectVarProcessList(det_ctx, f, p);
    return 1;
}

void DeStateDetectContinueDetection(ThreadVars *tv, DetectEngineCtx *de_ctx,
                                    DetectEngineThreadCtx *det_ctx,
                                    Packet *p, Flow *f, uint8_t flags,
                                    AppProto alproto)
{
    uint16_t file_no_match = 0;
    SigIntId store_cnt = 0;
    SigIntId state_cnt = 0;
    uint64_t inspect_tx_id = 0;
    uint64_t total_txs = 0;
    uint8_t direction = (flags & STREAM_TOSERVER) ? 0 : 1;

    SCLogDebug("starting continue detection for packet %"PRIu64, p->pcap_cnt);

    void *alstate = FlowGetAppState(f);
    if (!StateIsValid(alproto, alstate)) {
        return;
    }

    inspect_tx_id = AppLayerParserGetTransactionInspectId(f->alparser, flags);
    total_txs = AppLayerParserGetTxCnt(f, alstate);

    for ( ; inspect_tx_id < total_txs; inspect_tx_id++) {
        int inspect_tx_inprogress = 0;
        int next_tx_no_progress = 0;
        void *inspect_tx = AppLayerParserGetTx(f->proto, alproto, alstate, inspect_tx_id);
        if (inspect_tx != NULL) {
            int a = AppLayerParserGetStateProgress(f->proto, alproto, inspect_tx, flags);
            int b = AppLayerParserGetStateProgressCompletionStatus(alproto, flags);
            if (a < b) {
                inspect_tx_inprogress = 1;
            }
            SCLogDebug("tx %"PRIu64" (%"PRIu64") => %s", inspect_tx_id, total_txs,
                    inspect_tx_inprogress ? "in progress" : "done");

            DetectEngineState *tx_de_state = AppLayerParserGetTxDetectState(f->proto, alproto, inspect_tx);
            if (tx_de_state == NULL) {
                SCLogDebug("NO STATE tx %"PRIu64" (%"PRIu64")", inspect_tx_id, total_txs);
                continue;
            }
            DetectEngineStateDirection *tx_dir_state = &tx_de_state->dir_state[direction];
            DeStateStore *tx_store = tx_dir_state->head;

            SCLogDebug("tx_dir_state->filestore_cnt %u", tx_dir_state->filestore_cnt);

            /* see if we need to consider the next tx in our decision to add
             * a sig to the 'no inspect array'. */
            if (!TxIsLast(inspect_tx_id, total_txs)) {
                void *next_inspect_tx = AppLayerParserGetTx(f->proto, alproto, alstate, inspect_tx_id+1);
                if (next_inspect_tx != NULL) {
                    int c = AppLayerParserGetStateProgress(f->proto, alproto, next_inspect_tx, flags);
                    if (c == 0) {
                        next_tx_no_progress = 1;
                    }
                }
            }

            /* Loop through stored 'items' (stateful rules) and inspect them */
            state_cnt = 0;
            for (; tx_store != NULL; tx_store = tx_store->next) {
                SCLogDebug("tx_store %p", tx_store);
                for (store_cnt = 0;
                        store_cnt < DE_STATE_CHUNK_SIZE && state_cnt < tx_dir_state->cnt;
                        store_cnt++, state_cnt++)
                {
                    DeStateStoreItem *item = &tx_store->store[store_cnt];
                    int r = DoInspectItem(tv, de_ctx, det_ctx,
                            item, tx_dir_state->flags,
                            p, f, alproto, flags,
                            inspect_tx_id, total_txs,
                            &file_no_match, inspect_tx_inprogress, next_tx_no_progress);
                    if (r < 0) {
                        SCLogDebug("failed");
                        goto end;
                    }
                }
            }

            tx_dir_state->flags &=
                ~(DETECT_ENGINE_STATE_FLAG_FILE_TS_NEW|DETECT_ENGINE_STATE_FLAG_FILE_TC_NEW);
        }
        /* if the current tx is in progress, we won't advance to any newer
         * tx' just yet. */
        if (inspect_tx_inprogress) {
            SCLogDebug("break out");
            break;
        }
    }

end:
    det_ctx->p = NULL;
    det_ctx->tx_id = 0;
    det_ctx->tx_id_set = 0;
    return;
}
/** \brief update flow's inspection id's
 *
 *  \param f unlocked flow
 *  \param flags direction and disruption flags
 *
 *  \note it is possible that f->alstate, f->alparser are NULL */
void DeStateUpdateInspectTransactionId(Flow *f, const uint8_t flags)
{
    if (f->alparser && f->alstate) {
        AppLayerParserSetTransactionInspectId(f, f->alparser,
                                              f->alstate, flags);
    }
    return;
}

/** \brief Reset de state for active tx'
 *  To be used on detect engine reload.
 *  \param f write LOCKED flow
 */
void DetectEngineStateResetTxs(Flow *f)
{
    void *alstate = FlowGetAppState(f);
    if (!StateIsValid(f->alproto, alstate)) {
        return;
    }

    uint64_t inspect_ts = AppLayerParserGetTransactionInspectId(f->alparser, STREAM_TOCLIENT);
    uint64_t inspect_tc = AppLayerParserGetTransactionInspectId(f->alparser, STREAM_TOSERVER);

    uint64_t inspect_tx_id = MIN(inspect_ts, inspect_tc);

    uint64_t total_txs = AppLayerParserGetTxCnt(f, alstate);

    for ( ; inspect_tx_id < total_txs; inspect_tx_id++) {
        void *inspect_tx = AppLayerParserGetTx(f->proto, f->alproto, alstate, inspect_tx_id);
        if (inspect_tx != NULL) {
            DetectEngineState *tx_de_state = AppLayerParserGetTxDetectState(f->proto, f->alproto, inspect_tx);
            if (tx_de_state == NULL) {
                continue;
            }

            tx_de_state->dir_state[0].cnt = 0;
            tx_de_state->dir_state[0].filestore_cnt = 0;
            tx_de_state->dir_state[0].flags = 0;

            tx_de_state->dir_state[1].cnt = 0;
            tx_de_state->dir_state[1].filestore_cnt = 0;
            tx_de_state->dir_state[1].flags = 0;
        }
    }
}

/*********Unittests*********/

#ifdef UNITTESTS

static int DeStateTest01(void)
{
    SCLogDebug("sizeof(DetectEngineState)\t\t%"PRIuMAX,
            (uintmax_t)sizeof(DetectEngineState));
    SCLogDebug("sizeof(DeStateStore)\t\t\t%"PRIuMAX,
            (uintmax_t)sizeof(DeStateStore));
    SCLogDebug("sizeof(DeStateStoreItem)\t\t%"PRIuMAX"",
            (uintmax_t)sizeof(DeStateStoreItem));

    return 1;
}

static int DeStateTest02(void)
{
    int result = 0;

    DetectEngineState *state = DetectEngineStateAlloc();
    if (state == NULL) {
        printf("d == NULL: ");
        goto end;
    }

    Signature s;
    memset(&s, 0x00, sizeof(s));

    uint8_t direction = STREAM_TOSERVER;

    s.num = 0;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 11;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 22;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 33;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 44;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 55;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 66;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 77;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 88;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 99;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 100;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 111;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 122;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 133;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 144;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 155;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 166;
    DeStateSignatureAppend(state, &s, 0, direction);

    if (state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head == NULL) {
        goto end;
    }

    if (state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[1].sid != 11) {
        goto end;
    }

    if (state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->next == NULL) {
        goto end;
    }

    if (state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[14].sid != 144) {
        goto end;
    }

    if (state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->next->store[0].sid != 155) {
        goto end;
    }

    if (state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->next->store[1].sid != 166) {
        goto end;
    }

    result = 1;
end:
    if (state != NULL) {
        DetectEngineStateFree(state);
    }
    return result;
}

static int DeStateTest03(void)
{
    DetectEngineState *state = DetectEngineStateAlloc();
    FAIL_IF_NULL(state);

    Signature s;
    memset(&s, 0x00, sizeof(s));

    uint8_t direction = STREAM_TOSERVER;

    s.num = 11;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 22;
    DeStateSignatureAppend(state, &s, BIT_U32(DE_STATE_FLAG_BASE), direction);

    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head == NULL);

    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[0].sid != 11);

    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[0].flags & BIT_U32(DE_STATE_FLAG_BASE));

    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[1].sid != 22);

    FAIL_IF(!(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[1].flags & BIT_U32(DE_STATE_FLAG_BASE)));

    DetectEngineStateFree(state);
    PASS;
}

static int DeStateSigTest01(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\n";
    uint8_t httpbuf2[] = "User-Agent: Mozilla/1.0\r\n";
    uint8_t httpbuf3[] = "Cookie: dummy\r\nContent-Length: 10\r\n\r\n";
    uint8_t httpbuf4[] = "Http Body!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"dummy\"; http_cookie; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (2): ");
        goto end;
    }
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("signature matched, but shouldn't have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (http_state != NULL) {
        HTPStateFree(http_state);
    }
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}

/** \test multiple pipelined http transactions */
static int DeStateSigTest02(void)
{
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n";
    uint8_t httpbuf2[] = "User-Agent: Mozilla/1.0\r\nContent-Length: 10\r\n";
    uint8_t httpbuf3[] = "Cookie: dummy\r\n\r\n";
    uint8_t httpbuf4[] = "Http Body!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    uint8_t httpbuf5[] = "GET /?var=val HTTP/1.1\r\n";
    uint8_t httpbuf6[] = "User-Agent: Firefox/1.0\r\n";
    uint8_t httpbuf7[] = "Cookie: dummy2\r\nContent-Length: 10\r\n\r\nHttp Body!";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */
    uint32_t httplen6 = sizeof(httpbuf6) - 1; /* minus the \0 */
    uint32_t httplen7 = sizeof(httpbuf7) - 1; /* minus the \0 */
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flow:to_server; content:\"POST\"; http_method; content:\"/\"; http_uri; content:\"Mozilla\"; http_header; content:\"dummy\"; http_cookie; content:\"body\"; nocase; http_client_body; sid:1; rev:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flow:to_server; content:\"GET\"; http_method; content:\"Firefox\"; http_header; content:\"dummy2\"; http_cookie; sid:2; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, httpbuf1, httplen1);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf2, httplen2);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf3, httplen3);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    p->alerts.cnt = 0;

    void *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, f.alstate, 0);
    FAIL_IF_NULL(tx);

    DetectEngineState *tx_de_state = AppLayerParserGetTxDetectState(IPPROTO_TCP, ALPROTO_HTTP, tx);
    FAIL_IF_NULL(tx_de_state);
    FAIL_IF(tx_de_state->dir_state[0].cnt != 1);
    /* http_header(mpm): 6, uri: 4, method: 7, cookie: 8 */
    uint32_t expected_flags = (BIT_U32(6) | BIT_U32(4) | BIT_U32(7) |BIT_U32(8));
    FAIL_IF(tx_de_state->dir_state[0].head->store[0].flags != expected_flags);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf4, httplen4);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 1)));

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf5, httplen5);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf6, httplen6);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF((PacketAlertCheck(p, 1)) || (PacketAlertCheck(p, 2)));
    p->alerts.cnt = 0;

    SCLogDebug("sending data chunk 7");

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf7, httplen7);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 2)));
    p->alerts.cnt = 0;

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

static int DeStateSigTest03(void)
{
    uint8_t httpbuf1[] = "POST /upload.cgi HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
                         "Content-Length: 215\r\n"
                         "\r\n"
                         "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n"
                         "filecontent\r\n"
                         "-----------------------------277531038314945--";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    ThreadVars th_v;
    TcpSession ssn;
    Flow *f = NULL;
    Packet *p = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(ssn));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (flow:to_server; content:\"POST\"; http_method; content:\"upload.cgi\"; http_uri; filestore; sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP;

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    p->flow = f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(f);
    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP,
                                STREAM_TOSERVER | STREAM_START | STREAM_EOF,
                                httpbuf1,
                                httplen1);
    FLOWLOCK_UNLOCK(f);

    FAIL_IF(r != 0);

    http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    FAIL_IF_NULL(http_state->files_ts);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 1)));

    FLOWLOCK_WRLOCK(f);
    FileContainer *files = AppLayerParserGetFiles(p->flow->proto, p->flow->alproto,
                                                  p->flow->alstate, STREAM_TOSERVER);
    FLOWLOCK_UNLOCK(f);
    FAIL_IF_NULL(files);

    File *file = files->head;
    FAIL_IF_NULL(file);

    FAIL_IF(!(file->flags & FILE_STORE));

    AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreeFlow(f);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(TRUE);
    PASS;
}

static int DeStateSigTest04(void)
{
    uint8_t httpbuf1[] = "POST /upload.cgi HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
                         "Content-Length: 215\r\n"
                         "\r\n"
                         "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n"
                         "filecontent\r\n"
                         "-----------------------------277531038314945--";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    ThreadVars th_v;
    TcpSession ssn;
    int result = 0;
    Flow *f = NULL;
    Packet *p = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(ssn));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"GET\"; http_method; content:\"upload.cgi\"; http_uri; filestore; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP;

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    if (p == NULL)
        goto end;

    p->flow = f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(f);
    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP,
                                STREAM_TOSERVER | STREAM_START | STREAM_EOF,
                                httpbuf1,
                                httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(f);
        goto end;
    }
    FLOWLOCK_UNLOCK(f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    if (http_state->files_ts == NULL) {
        printf("no files in state: ");
        goto end;
    }

    FLOWLOCK_WRLOCK(f);
    FileContainer *files = AppLayerParserGetFiles(p->flow->proto, p->flow->alproto,
                                                  p->flow->alstate, STREAM_TOSERVER);
    if (files == NULL) {
        printf("no stored files: ");
        FLOWLOCK_UNLOCK(f);
        goto end;
    }
    FLOWLOCK_UNLOCK(f);

    File *file = files->head;
    if (file == NULL) {
        printf("no file: ");
        goto end;
    }

    if (file->flags & FILE_STORE) {
        printf("file is set to store, but sig didn't match: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreeFlow(f);

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    StreamTcpFreeConfig(TRUE);
    return result;
}

static int DeStateSigTest05(void)
{
    uint8_t httpbuf1[] = "POST /upload.cgi HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
                         "Content-Length: 215\r\n"
                         "\r\n"
                         "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n"
                         "filecontent\r\n"
                         "-----------------------------277531038314945--";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    ThreadVars th_v;
    TcpSession ssn;
    int result = 0;
    Flow *f = NULL;
    Packet *p = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(ssn));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"GET\"; http_method; content:\"upload.cgi\"; http_uri; filename:\"nomatch\"; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP;

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    if (p == NULL)
        goto end;

    p->flow = f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(f);
    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP,
                                STREAM_TOSERVER | STREAM_START | STREAM_EOF,
                                httpbuf1,
                                httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(f);
        goto end;
    }
    FLOWLOCK_UNLOCK(f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    if (http_state->files_ts == NULL) {
        printf("no files in state: ");
        goto end;
    }

    FLOWLOCK_WRLOCK(f);
    FileContainer *files = AppLayerParserGetFiles(p->flow->proto, p->flow->alproto,
                                                  p->flow->alstate, STREAM_TOSERVER);
    if (files == NULL) {
        printf("no stored files: ");
        FLOWLOCK_UNLOCK(f);
        goto end;
    }
    FLOWLOCK_UNLOCK(f);

    File *file = files->head;
    if (file == NULL) {
        printf("no file: ");
        goto end;
    }

    if (!(file->flags & FILE_NOSTORE)) {
        printf("file is not set to \"no store\": ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreeFlow(f);

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    StreamTcpFreeConfig(TRUE);
    return result;
}

static int DeStateSigTest06(void)
{
    uint8_t httpbuf1[] = "POST /upload.cgi HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
                         "Content-Length: 215\r\n"
                         "\r\n"
                         "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n"
                         "filecontent\r\n"
                         "-----------------------------277531038314945--";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    ThreadVars th_v;
    TcpSession ssn;
    int result = 0;
    Flow *f = NULL;
    Packet *p = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(ssn));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"POST\"; http_method; content:\"upload.cgi\"; http_uri; filename:\"nomatch\"; filestore; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP;

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    if (p == NULL)
        goto end;

    p->flow = f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(f);
    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP,
                                STREAM_TOSERVER | STREAM_START | STREAM_EOF,
                                httpbuf1,
                                httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(f);
        goto end;
    }
    FLOWLOCK_UNLOCK(f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    if (http_state->files_ts == NULL) {
        printf("no files in state: ");
        goto end;
    }

    FLOWLOCK_WRLOCK(f);
    FileContainer *files = AppLayerParserGetFiles(p->flow->proto, p->flow->alproto,
                                                  p->flow->alstate, STREAM_TOSERVER);
    if (files == NULL) {
        printf("no stored files: ");
        FLOWLOCK_UNLOCK(f);
        goto end;
    }
    FLOWLOCK_UNLOCK(f);

    File *file = files->head;
    if (file == NULL) {
        printf("no file: ");
        goto end;
    }

    if (!(file->flags & FILE_NOSTORE)) {
        printf("file is not set to \"no store\": ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreeFlow(f);

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    StreamTcpFreeConfig(TRUE);
    return result;
}

static int DeStateSigTest07(void)
{
    uint8_t httpbuf1[] = "POST /upload.cgi HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
                         "Content-Length: 215\r\n"
                         "\r\n"
                         "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n";

    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "filecontent\r\n"
                         "-----------------------------277531038314945--";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    ThreadVars th_v;
    TcpSession ssn;
    int result = 0;
    Flow *f = NULL;
    Packet *p = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(ssn));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"GET\"; http_method; content:\"upload.cgi\"; http_uri; filestore; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP;

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    if (p == NULL)
        goto end;

    p->flow = f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    SCLogDebug("\n>>>> processing chunk 1 <<<<\n");
    FLOWLOCK_WRLOCK(f);
    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP,
                                STREAM_TOSERVER | STREAM_START, httpbuf1,
                                httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(f);
        goto end;
    }
    FLOWLOCK_UNLOCK(f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 2 size %u <<<<\n", httplen2);
    FLOWLOCK_WRLOCK(f);
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP,
                            STREAM_TOSERVER | STREAM_EOF, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(f);
        goto end;
    }
    FLOWLOCK_UNLOCK(f);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    if (http_state->files_ts == NULL) {
        printf("no files in state: ");
        goto end;
    }

    FLOWLOCK_WRLOCK(f);
    FileContainer *files = AppLayerParserGetFiles(p->flow->proto, p->flow->alproto,
                                                  p->flow->alstate, STREAM_TOSERVER);
    if (files == NULL) {
        printf("no stored files: ");
        FLOWLOCK_UNLOCK(f);
        goto end;
    }
    FLOWLOCK_UNLOCK(f);

    File *file = files->head;
    if (file == NULL) {
        printf("no file: ");
        goto end;
    }

    if (file->flags & FILE_STORE) {
        printf("file is set to store, but sig didn't match: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreeFlow(f);

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    StreamTcpFreeConfig(TRUE);
    return result;
}

#endif

void DeStateRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DeStateTest01", DeStateTest01);
    UtRegisterTest("DeStateTest02", DeStateTest02);
    UtRegisterTest("DeStateTest03", DeStateTest03);
    UtRegisterTest("DeStateSigTest01", DeStateSigTest01);
    UtRegisterTest("DeStateSigTest02", DeStateSigTest02);
    UtRegisterTest("DeStateSigTest03", DeStateSigTest03);
    UtRegisterTest("DeStateSigTest04", DeStateSigTest04);
    UtRegisterTest("DeStateSigTest05", DeStateSigTest05);
    UtRegisterTest("DeStateSigTest06", DeStateSigTest06);
    UtRegisterTest("DeStateSigTest07", DeStateSigTest07);
#endif

    return;
}

/**
 * @}
 */
