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

/******** static internal helpers *********/

static DeStateStore *DeStateStoreAlloc(void)
{
    DeStateStore *d = SCMalloc(sizeof(DeStateStore));
    if (unlikely(d == NULL))
        return NULL;
    memset(d, 0, sizeof(DeStateStore));

    return d;
}

static void DeStateSignatureAppend(DetectEngineState *state, Signature *s,
                                   SigMatch *sm, uint32_t inspect_flags,
                                   uint8_t direction)
{
    int jump = 0;
    int i = 0;
    DetectEngineStateDirection *dir_state = &state->dir_state[direction & STREAM_TOSERVER ? 0 : 1];
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
    store->store[idx].nm = sm;

    return;
}

static void DeStateStoreStateVersion(DetectEngineState *de_state,
                                     uint16_t alversion, uint8_t direction)
{
    de_state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].alversion = alversion;

    return;
}

static void DeStateStoreFileNoMatchCnt(DetectEngineState *de_state, uint16_t file_no_match, uint8_t direction)
{
    de_state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].filestore_cnt += file_no_match;

    return;
}

static int DeStateStoreFilestoreSigsCantMatch(SigGroupHead *sgh, DetectEngineState *de_state, uint8_t direction)
{
    if (de_state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].filestore_cnt == sgh->filestore_cnt)
        return 1;
    else
        return 0;
}

static void DeStateResetFileInspection(Flow *f, AppProto alproto, void *alstate, uint8_t direction)
{
    if (f == NULL || alproto != ALPROTO_HTTP || alstate == NULL || f->de_state == NULL)
        return;

    FLOWLOCK_WRLOCK(f);
    HtpState *htp_state = (HtpState *)alstate;

    if (direction & STREAM_TOSERVER) {
        if (htp_state->flags & HTP_FLAG_NEW_FILE_TX_TS) {
            SCLogDebug("new file in the TS direction");
            htp_state->flags &= ~HTP_FLAG_NEW_FILE_TX_TS;
            f->de_state->dir_state[0].flags |= DETECT_ENGINE_STATE_FLAG_FILE_TS_NEW;
        }
    } else {
        if (htp_state->flags & HTP_FLAG_NEW_FILE_TX_TC) {
            SCLogDebug("new file in the TC direction");
            htp_state->flags &= ~HTP_FLAG_NEW_FILE_TX_TC;
            f->de_state->dir_state[1].flags |= DETECT_ENGINE_STATE_FLAG_FILE_TC_NEW;
        }
    }

    FLOWLOCK_UNLOCK(f);
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

int DeStateFlowHasInspectableState(Flow *f, AppProto alproto, uint16_t alversion, uint8_t flags)
{
    int r = 0;

    SCMutexLock(&f->de_state_m);
    if (f->de_state == NULL || f->de_state->dir_state[flags & STREAM_TOSERVER ? 0 : 1].cnt == 0) {
        if (AppLayerParserProtocolSupportsTxs(f->proto, alproto)) {
            FLOWLOCK_RDLOCK(f);
            if (AppLayerParserGetTransactionInspectId(f->alparser, flags) >= AppLayerParserGetTxCnt(f->proto, alproto, f->alstate))
                r = 2;
            else
                r = 0;
            FLOWLOCK_UNLOCK(f);
        }
    } else if (!(flags & STREAM_EOF) &&
               f->de_state->dir_state[flags & STREAM_TOSERVER ? 0 : 1].alversion == alversion) {
        r = 2;
    } else {
        r = 1;
    }
    SCMutexUnlock(&f->de_state_m);

    return r;
}

int DeStateDetectStartDetection(ThreadVars *tv, DetectEngineCtx *de_ctx,
                                DetectEngineThreadCtx *det_ctx,
                                Signature *s, Packet *p, Flow *f, uint8_t flags,
                                void *alstate, AppProto alproto, uint16_t alversion)
{
    DetectEngineAppInspectionEngine *engine = NULL;
    SigMatch *sm = NULL;
    uint16_t file_no_match = 0;
    uint32_t inspect_flags = 0;

    HtpState *htp_state = NULL;
    SMBState *smb_state = NULL;

    void *tx = NULL;
    uint64_t tx_id = 0;
    uint64_t total_txs = 0;
    int match = 0;
    int store_de_state = 0;
    uint8_t direction = (flags & STREAM_TOSERVER) ? 0 : 1;
    /* this was introduced later to allow protocols that had both app
     * keywords with transaction keywords.  Without this we would
     * assume that we have an alert if engine == NULL */
    int total_matches = 0;

    int alert_cnt = 0;

    if (alstate == NULL)
        goto end;

    if (AppLayerParserProtocolSupportsTxs(f->proto, alproto)) {
        FLOWLOCK_WRLOCK(f);

        if (alproto == ALPROTO_HTTP) {
            htp_state = (HtpState *)alstate;
            if (htp_state->conn == NULL) {
                FLOWLOCK_UNLOCK(f);
                goto end;
            }
        }
        tx_id = AppLayerParserGetTransactionInspectId(f->alparser, flags);
        SCLogDebug("tx_id %"PRIu64, tx_id);
        total_txs = AppLayerParserGetTxCnt(f->proto, alproto, alstate);
        SCLogDebug("total_txs %"PRIu64, total_txs);

        for (; tx_id < total_txs; tx_id++) {
            total_matches = 0;
            tx = AppLayerParserGetTx(f->proto, alproto, alstate, tx_id);
            if (tx == NULL)
                continue;
            engine = app_inspection_engine[FlowGetProtoMapping(f->proto)][alproto][direction];
            inspect_flags = 0;
            while (engine != NULL) {
                if (s->sm_lists[engine->sm_list] != NULL) {
                    KEYWORD_PROFILING_SET_LIST(det_ctx, engine->sm_list);
                    match = engine->Callback(tv, de_ctx, det_ctx, s, f,
                                             flags, alstate,
                                             tx, tx_id);
                    if (match == 1) {
                        inspect_flags |= engine->inspect_flags;
                        engine = engine->next;
                        total_matches++;
                        continue;
                    } else if (match == 2) {
                        inspect_flags |= DE_STATE_FLAG_SIG_CANT_MATCH;
                        inspect_flags |= engine->inspect_flags;
                    } else if (match == 3) {
                        inspect_flags |= DE_STATE_FLAG_SIG_CANT_MATCH;
                        inspect_flags |= engine->inspect_flags;
                        file_no_match++;
                    }
                    break;
                }
                engine = engine->next;
            }
            /* all the engines seem to be exhausted at this point.  If we
             * didn't have a match in one of the engines we would have
             * broken off and engine wouldn't be NULL.  Hence the alert. */
            if (engine == NULL && total_matches > 0) {

                if (!(s->flags & SIG_FLAG_NOALERT)) {
                    PacketAlertAppend(det_ctx, s, p, tx_id,
                            PACKET_ALERT_FLAG_STATE_MATCH|PACKET_ALERT_FLAG_TX);
                } else {
                    PACKET_UPDATE_ACTION(p, s->action);
                }

                alert_cnt = 1;
            }

            if (tx_id == (total_txs - 1)) {
                void *tx = AppLayerParserGetTx(f->proto, alproto, alstate, tx_id);
                if (tx == NULL)
                    continue;
                if (AppLayerParserGetStateProgress(f->proto, alproto, tx, flags) <
                    AppLayerParserGetStateProgressCompletionStatus(f->proto, alproto, flags)) {
                    store_de_state = 1;
                    if (engine == NULL || inspect_flags & DE_STATE_FLAG_SIG_CANT_MATCH)
                        inspect_flags |= DE_STATE_FLAG_FULL_INSPECT;
                }
            }
        } /* for */

        FLOWLOCK_UNLOCK(f);

    } else if (s->sm_lists[DETECT_SM_LIST_DMATCH] != NULL &&
               (alproto == ALPROTO_DCERPC || alproto == ALPROTO_SMB ||
                alproto == ALPROTO_SMB2))
    {
        KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_DMATCH);
        if (alproto == ALPROTO_SMB || alproto == ALPROTO_SMB2) {
            smb_state = (SMBState *)alstate;
            if (smb_state->dcerpc_present &&
                DetectEngineInspectDcePayload(de_ctx, det_ctx, s, f,
                                              flags, &smb_state->dcerpc) == 1) {
                if (!(s->flags & SIG_FLAG_NOALERT)) {
                    PacketAlertAppend(det_ctx, s, p, 0,
                            PACKET_ALERT_FLAG_STATE_MATCH);
                } else {
                    PACKET_UPDATE_ACTION(p, s->action);
                }

                alert_cnt = 1;
            }
        } else {
            if (DetectEngineInspectDcePayload(de_ctx, det_ctx, s, f,
                                              flags, alstate) == 1) {
                alert_cnt = 1;

                if (!(s->flags & SIG_FLAG_NOALERT)) {
                    PacketAlertAppend(det_ctx, s, p, 0,
                            PACKET_ALERT_FLAG_STATE_MATCH);
                } else {
                    PACKET_UPDATE_ACTION(p, s->action);
                }

            }
        }
    }

    sm = s->sm_lists[DETECT_SM_LIST_AMATCH];
    KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_AMATCH);
    for (match = 0; sm != NULL; sm = sm->next) {
        match = 0;
        if (sigmatch_table[sm->type].AppLayerMatch != NULL) {
            if (alproto == ALPROTO_SMB || alproto == ALPROTO_SMB2) {
                smb_state = (SMBState *)alstate;
                if (smb_state->dcerpc_present) {
                    KEYWORD_PROFILING_START;
                    match = sigmatch_table[sm->type].
                        AppLayerMatch(tv, det_ctx, f, flags, &smb_state->dcerpc, s, sm);
                    KEYWORD_PROFILING_END(det_ctx, sm->type, (match > 0));
                }
            } else {
                KEYWORD_PROFILING_START;
                match = sigmatch_table[sm->type].
                    AppLayerMatch(tv, det_ctx, f, flags, alstate, s, sm);
                KEYWORD_PROFILING_END(det_ctx, sm->type, (match > 0));
            }

            if (match == 0)
                break;
            if (match == 2) {
                inspect_flags |= DE_STATE_FLAG_SIG_CANT_MATCH;
                break;
            }
        }
    }
    if (s->sm_lists[DETECT_SM_LIST_AMATCH] != NULL) {
        store_de_state = 1;
        if (sm == NULL || inspect_flags & DE_STATE_FLAG_SIG_CANT_MATCH) {
            if (match == 1) {
                if (!(s->flags & SIG_FLAG_NOALERT)) {
                    PacketAlertAppend(det_ctx, s, p, 0,
                            PACKET_ALERT_FLAG_STATE_MATCH);
                } else {
                    PACKET_UPDATE_ACTION(p, s->action);
                }
                alert_cnt = 1;
            }
            inspect_flags |= DE_STATE_FLAG_FULL_INSPECT;
        }
    }

    if (!store_de_state && file_no_match == 0)
        goto end;

    SCMutexLock(&f->de_state_m);
    if (f->de_state == NULL) {
        f->de_state = DetectEngineStateAlloc();
        if (f->de_state == NULL) {
            SCMutexUnlock(&f->de_state_m);
            goto end;
        }
    }
    if (store_de_state) {
        DeStateSignatureAppend(f->de_state, s, sm, inspect_flags, flags);
        DeStateStoreStateVersion(f->de_state, alversion, flags);
    }
    DeStateStoreFileNoMatchCnt(f->de_state, file_no_match, flags);
    if (DeStateStoreFilestoreSigsCantMatch(det_ctx->sgh, f->de_state, flags) == 1) {
        FLOWLOCK_WRLOCK(f);
        FileDisableStoringForTransaction(f, flags & (STREAM_TOCLIENT | STREAM_TOSERVER),
                                         det_ctx->tx_id);
        FLOWLOCK_UNLOCK(f);
        f->de_state->dir_state[flags & STREAM_TOSERVER ? 0 : 1].flags |= DETECT_ENGINE_STATE_FLAG_FILE_STORE_DISABLED;
    }
    SCMutexUnlock(&f->de_state_m);

 end:
    return alert_cnt ? 1:0;
}

void DeStateDetectContinueDetection(ThreadVars *tv, DetectEngineCtx *de_ctx,
                                    DetectEngineThreadCtx *det_ctx,
                                    Packet *p, Flow *f, uint8_t flags, void *alstate,
                                    AppProto alproto, uint16_t alversion)
{
    SCMutexLock(&f->de_state_m);

    DetectEngineAppInspectionEngine *engine = NULL;
    SigMatch *sm = NULL;
    uint16_t file_no_match = 0;
    uint32_t inspect_flags = 0;

    HtpState *htp_state = NULL;
    SMBState *smb_state = NULL;

    SigIntId store_cnt = 0;
    SigIntId state_cnt = 0;
    int match = 0;
    uint8_t alert = 0;

    DetectEngineStateDirection *dir_state = &f->de_state->dir_state[flags & STREAM_TOSERVER ? 0 : 1];
    DeStateStore *store = dir_state->head;
    void *inspect_tx = NULL;
    uint64_t inspect_tx_id = 0;
    uint64_t total_txs = 0;
    uint8_t alproto_supports_txs = 0;
    uint8_t reset_de_state = 0;
    /* this was introduced later to allow protocols that had both app
     * keywords with transaction keywords.  Without this we would
     * assume that we have an alert if engine == NULL */
    uint8_t total_matches = 0;

    DeStateResetFileInspection(f, alproto, alstate, flags);

    if (AppLayerParserProtocolSupportsTxs(f->proto, alproto)) {
        FLOWLOCK_RDLOCK(f);
        inspect_tx_id = AppLayerParserGetTransactionInspectId(f->alparser, flags);
        total_txs = AppLayerParserGetTxCnt(f->proto, alproto, alstate);
        inspect_tx = AppLayerParserGetTx(f->proto, alproto, alstate, inspect_tx_id);
        if (inspect_tx == NULL) {
            FLOWLOCK_UNLOCK(f);
            SCMutexUnlock(&f->de_state_m);
            return;
        }
        if (AppLayerParserGetStateProgress(f->proto, alproto, inspect_tx, flags) >=
            AppLayerParserGetStateProgressCompletionStatus(f->proto, alproto, flags)) {
            reset_de_state = 1;
        }
        FLOWLOCK_UNLOCK(f);
        alproto_supports_txs = 1;
    }

    for (; store != NULL; store = store->next) {
        for (store_cnt = 0;
             store_cnt < DE_STATE_CHUNK_SIZE && state_cnt < dir_state->cnt;
             store_cnt++, state_cnt++)
        {
            total_matches = 0;
            DeStateStoreItem *item = &store->store[store_cnt];
            Signature *s = de_ctx->sig_array[item->sid];

            if (item->flags & DE_STATE_FLAG_FULL_INSPECT) {
                if (item->flags & (DE_STATE_FLAG_FILE_TC_INSPECT |
                                   DE_STATE_FLAG_FILE_TS_INSPECT)) {
                    if ((flags & STREAM_TOCLIENT) &&
                        (dir_state->flags & DETECT_ENGINE_STATE_FLAG_FILE_TC_NEW))
                    {
                        item->flags &= ~DE_STATE_FLAG_FILE_TC_INSPECT;
                        item->flags &= ~DE_STATE_FLAG_FULL_INSPECT;
                    }

                    if ((flags & STREAM_TOSERVER) &&
                        (dir_state->flags & DETECT_ENGINE_STATE_FLAG_FILE_TS_NEW))
                    {
                        item->flags &= ~DE_STATE_FLAG_FILE_TS_INSPECT;
                        item->flags &= ~DE_STATE_FLAG_FULL_INSPECT;
                    }
                }

                if (item->flags & DE_STATE_FLAG_FULL_INSPECT) {
                    if (alproto_supports_txs) {
                        if ((total_txs - inspect_tx_id) <= 1)
                            det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_NO_NEW_STATE;
                    } else {
                        det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_NO_NEW_STATE;
                    }
                    continue;
                }
            }

            if (item->flags & DE_STATE_FLAG_SIG_CANT_MATCH) {
                if ((flags & STREAM_TOSERVER) &&
                    (item->flags & DE_STATE_FLAG_FILE_TS_INSPECT) &&
                    (dir_state->flags & DETECT_ENGINE_STATE_FLAG_FILE_TS_NEW))
                {
                    item->flags &= ~DE_STATE_FLAG_FILE_TS_INSPECT;
                    item->flags &= ~DE_STATE_FLAG_SIG_CANT_MATCH;
                } else if ((flags & STREAM_TOCLIENT) &&
                           (item->flags & DE_STATE_FLAG_FILE_TC_INSPECT) &&
                           (dir_state->flags & DETECT_ENGINE_STATE_FLAG_FILE_TC_NEW))
                {
                    item->flags &= ~DE_STATE_FLAG_FILE_TC_INSPECT;
                    item->flags &= ~DE_STATE_FLAG_SIG_CANT_MATCH;
                } else {
                    if (alproto_supports_txs) {
                        if ((total_txs - inspect_tx_id) <= 1)
                            det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_NO_NEW_STATE;
                    } else {
                        det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_NO_NEW_STATE;
                    }
                    continue;
                }
            }

            alert = 0;
            inspect_flags = 0;
            match = 0;

            RULE_PROFILING_START(p);

            if (alproto_supports_txs) {
                FLOWLOCK_WRLOCK(f);

                if (alproto == ALPROTO_HTTP) {
                    htp_state = (HtpState *)alstate;
                    if (htp_state->conn == NULL) {
                        FLOWLOCK_UNLOCK(f);
                        RULE_PROFILING_END(det_ctx, s, match, p);
                        goto end;
                    }
                }

                engine = app_inspection_engine[FlowGetProtoMapping(f->proto)][alproto][(flags & STREAM_TOSERVER) ? 0 : 1];
                inspect_tx = AppLayerParserGetTx(f->proto, alproto, alstate, inspect_tx_id);
                if (inspect_tx == NULL) {
                    FLOWLOCK_UNLOCK(f);
                    RULE_PROFILING_END(det_ctx, s, match, p);
                    goto end;
                }
                while (engine != NULL) {
                    if (!(item->flags & engine->inspect_flags) &&
                        s->sm_lists[engine->sm_list] != NULL)
                    {
                        KEYWORD_PROFILING_SET_LIST(det_ctx, engine->sm_list);
                        match = engine->Callback(tv, de_ctx, det_ctx, s, f,
                                                 flags, alstate, inspect_tx, inspect_tx_id);
                        if (match == 1) {
                            inspect_flags |= engine->inspect_flags;
                            engine = engine->next;
                            total_matches++;
                            continue;
                        } else if (match == 2) {
                            inspect_flags |= DE_STATE_FLAG_SIG_CANT_MATCH;
                            inspect_flags |= engine->inspect_flags;
                        } else if (match == 3) {
                            inspect_flags |= DE_STATE_FLAG_SIG_CANT_MATCH;
                            inspect_flags |= engine->inspect_flags;
                            file_no_match++;
                        }
                        break;
                    }
                    engine = engine->next;
                }
                if (total_matches > 0 && (engine == NULL || inspect_flags & DE_STATE_FLAG_SIG_CANT_MATCH)) {
                    if (engine == NULL)
                        alert = 1;
                    inspect_flags |= DE_STATE_FLAG_FULL_INSPECT;
                }

                FLOWLOCK_UNLOCK(f);
            }

            /* count AMATCH matches */
            total_matches = 0;

            KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_AMATCH);
            for (sm = item->nm; sm != NULL; sm = sm->next) {
                if (sigmatch_table[sm->type].AppLayerMatch != NULL)
                {
                    if (alproto == ALPROTO_SMB || alproto == ALPROTO_SMB2) {
                        smb_state = (SMBState *)alstate;
                        if (smb_state->dcerpc_present) {
                            KEYWORD_PROFILING_START;
                            match = sigmatch_table[sm->type].
                                AppLayerMatch(tv, det_ctx, f, flags, &smb_state->dcerpc, s, sm);
                            KEYWORD_PROFILING_END(det_ctx, sm->type, (match > 0));
                        }
                    } else {
                        KEYWORD_PROFILING_START;
                        match = sigmatch_table[sm->type].
                            AppLayerMatch(tv, det_ctx, f, flags, alstate, s, sm);
                        KEYWORD_PROFILING_END(det_ctx, sm->type, (match > 0));
                    }

                    if (match == 0)
                        break;
                    else if (match == 2)
                        inspect_flags |= DE_STATE_FLAG_SIG_CANT_MATCH;
                    else if (match == 1)
                        total_matches++;
                }
            }
            RULE_PROFILING_END(det_ctx, s, match, p);

            if (s->sm_lists[DETECT_SM_LIST_AMATCH] != NULL) {
                if (total_matches > 0 && (sm == NULL || inspect_flags & DE_STATE_FLAG_SIG_CANT_MATCH)) {
                    if (sm == NULL)
                        alert = 1;
                    inspect_flags |= DE_STATE_FLAG_FULL_INSPECT;
                }
                det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_NO_NEW_STATE;
            }

            item->flags |= inspect_flags;
            item->nm = sm;
            if ((total_txs - inspect_tx_id) <= 1)
                det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_NO_NEW_STATE;

            if (alert) {
                SigMatchSignaturesRunPostMatch(tv, de_ctx, det_ctx, p, s);

                if (!(s->flags & SIG_FLAG_NOALERT)) {
                    if (alproto_supports_txs)
                        PacketAlertAppend(det_ctx, s, p, inspect_tx_id,
                                PACKET_ALERT_FLAG_STATE_MATCH|PACKET_ALERT_FLAG_TX);
                    else
                        PacketAlertAppend(det_ctx, s, p, 0,
                                PACKET_ALERT_FLAG_STATE_MATCH);
                } else {
                    PACKET_UPDATE_ACTION(p, s->action);
                }
            }

            DetectFlowvarProcessList(det_ctx, f);
        }
    }

    DeStateStoreStateVersion(f->de_state, alversion, flags);
    DeStateStoreFileNoMatchCnt(f->de_state, file_no_match, flags);

    if (!(dir_state->flags & DETECT_ENGINE_STATE_FLAG_FILE_STORE_DISABLED)) {
        if (DeStateStoreFilestoreSigsCantMatch(det_ctx->sgh, f->de_state, flags) == 1) {
            SCLogDebug("disabling file storage for transaction");

            FLOWLOCK_WRLOCK(f);
            FileDisableStoringForTransaction(f, flags & (STREAM_TOCLIENT|STREAM_TOSERVER),
                                             det_ctx->tx_id);
            FLOWLOCK_UNLOCK(f);

            dir_state->flags |= DETECT_ENGINE_STATE_FLAG_FILE_STORE_DISABLED;
        }
    }

end:
    if (f->de_state != NULL)
        dir_state->flags &= ~DETECT_ENGINE_STATE_FLAG_FILE_TC_NEW;

    if (reset_de_state)
        DetectEngineStateReset(f->de_state, flags);

    SCMutexUnlock(&f->de_state_m);
    return;
}

void DeStateUpdateInspectTransactionId(Flow *f, uint8_t direction)
{
    FLOWLOCK_WRLOCK(f);
    AppLayerParserSetTransactionInspectId(f->alparser, f->proto, f->alproto, f->alstate, direction);
    FLOWLOCK_UNLOCK(f);

    return;
}


void DetectEngineStateReset(DetectEngineState *state, uint8_t direction)
{
    if (state != NULL) {
        if (direction & STREAM_TOSERVER) {
            state->dir_state[0].cnt = 0;
            state->dir_state[0].filestore_cnt = 0;
            state->dir_state[0].flags = 0;
        }
        if (direction & STREAM_TOCLIENT) {
            state->dir_state[1].cnt = 0;
            state->dir_state[1].filestore_cnt = 0;
            state->dir_state[1].flags = 0;
        }
    }

    return;
}

/** \brief get string for match enum */
const char *DeStateMatchResultToString(DeStateMatchResult res)
{
    switch (res) {
        CASE_CODE (DE_STATE_MATCH_NO_NEW_STATE);
        CASE_CODE (DE_STATE_MATCH_HAS_NEW_STATE);
    }

    return NULL;
}

/*********Unittests*********/

#ifdef UNITTESTS
#include "flow-util.h"

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
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 11;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 22;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 33;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 44;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 55;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 66;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 77;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 88;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 99;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 100;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 111;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 122;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 133;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 144;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 155;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 166;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);

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
    int result = 0;

    DetectEngineState *state = DetectEngineStateAlloc();
    if (state == NULL) {
        printf("d == NULL: ");
        goto end;
    }

    Signature s;
    memset(&s, 0x00, sizeof(s));

    uint8_t direction = STREAM_TOSERVER;

    s.num = 11;
    DeStateSignatureAppend(state, &s, NULL, 0, direction);
    s.num = 22;
    DeStateSignatureAppend(state, &s, NULL, DE_STATE_FLAG_URI_INSPECT, direction);

    if (state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head == NULL) {
        goto end;
    }

    if (state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[0].sid != 11) {
        goto end;
    }

    if (state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[0].flags & DE_STATE_FLAG_URI_INSPECT) {
        goto end;
    }

    if (state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[1].sid != 22) {
        goto end;
    }

    if (!(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[1].flags & DE_STATE_FLAG_URI_INSPECT)) {
        goto end;
    }

    result = 1;
end:
    if (state != NULL) {
        DetectEngineStateFree(state);
    }
    return result;
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

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (2): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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
static int DeStateSigTest02(void) {
    int result = 0;
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
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"Mozilla\"; http_header; content:\"dummy\"; http_cookie; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"GET\"; http_method; content:\"Firefox\"; http_header; content:\"dummy2\"; http_cookie; sid:2; rev:1;)");
    if (s == NULL) {
        printf("sig2 parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (2): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("signature matched, but shouldn't have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (5): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf6, httplen6);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if ((PacketAlertCheck(p, 1)) || (PacketAlertCheck(p, 2))) {
        printf("sig 1 alerted (request 2, chunk 6): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCLogDebug("sending data chunk 7");

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf7, httplen7);
    if (r != 0) {
        printf("toserver chunk 7 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 2))) {
        printf("signature 2 didn't match, but should have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
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

static int DeStateSigTest03(void) {
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

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"POST\"; http_method; content:\"upload.cgi\"; http_uri; filestore; sid:1; rev:1;)");
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

    SCMutexLock(&f->m);
    int r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|STREAM_EOF, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert: ");
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

    SCMutexLock(&f->m);
    FileContainer *files = AppLayerParserGetFiles(p->flow->proto, p->flow->alproto,
                                                  p->flow->alstate, STREAM_TOSERVER);
    if (files == NULL) {
        printf("no stored files: ");
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    File *file = files->head;
    if (file == NULL) {
        printf("no file: ");
        goto end;
    }

    if (!(file->flags & FILE_STORE)) {
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

static int DeStateSigTest04(void) {
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

    SCMutexLock(&f->m);
    int r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|STREAM_EOF, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

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

    SCMutexLock(&f->m);
    FileContainer *files = AppLayerParserGetFiles(p->flow->proto, p->flow->alproto,
                                                  p->flow->alstate, STREAM_TOSERVER);
    if (files == NULL) {
        printf("no stored files: ");
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

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

static int DeStateSigTest05(void) {
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

    SCMutexLock(&f->m);
    int r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|STREAM_EOF, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

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

    SCMutexLock(&f->m);
    FileContainer *files = AppLayerParserGetFiles(p->flow->proto, p->flow->alproto,
                                                  p->flow->alstate, STREAM_TOSERVER);
    if (files == NULL) {
        printf("no stored files: ");
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

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

static int DeStateSigTest06(void) {
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

    SCMutexLock(&f->m);
    int r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|STREAM_EOF, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

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

    SCMutexLock(&f->m);
    FileContainer *files = AppLayerParserGetFiles(p->flow->proto, p->flow->alproto,
                                                  p->flow->alstate, STREAM_TOSERVER);
    if (files == NULL) {
        printf("no stored files: ");
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

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

static int DeStateSigTest07(void) {
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
    SCMutexLock(&f->m);
    int r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }

    SCLogDebug("\n>>>> processing chunk 2 size %u <<<<\n", httplen2);
    SCMutexLock(&f->m);
    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

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

    SCMutexLock(&f->m);
    FileContainer *files = AppLayerParserGetFiles(p->flow->proto, p->flow->alproto,
                                                  p->flow->alstate, STREAM_TOSERVER);
    if (files == NULL) {
        printf("no stored files: ");
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

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
    UtRegisterTest("DeStateTest01", DeStateTest01, 1);
    UtRegisterTest("DeStateTest02", DeStateTest02, 1);
    UtRegisterTest("DeStateTest03", DeStateTest03, 1);
    UtRegisterTest("DeStateSigTest01", DeStateSigTest01, 1);
    UtRegisterTest("DeStateSigTest02", DeStateSigTest02, 1);
    UtRegisterTest("DeStateSigTest03", DeStateSigTest03, 1);
    UtRegisterTest("DeStateSigTest04", DeStateSigTest04, 1);
    UtRegisterTest("DeStateSigTest05", DeStateSigTest05, 1);
    UtRegisterTest("DeStateSigTest06", DeStateSigTest06, 1);
    UtRegisterTest("DeStateSigTest07", DeStateSigTest07, 1);
#endif

    return;
}

/**
 * @}
 */
