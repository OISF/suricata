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
 * \defgroup sigstate State support
 *
 * State is stored in the ::DetectEngineState structure. This is
 * basically a containter for storage item of type ::DeStateStore.
 * They contains an array of ::DeStateStoreItem which store the
 * state of match for an individual signature identified by
 * DeStateStoreItem::sid.
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
#include "detect-engine-build.h"

#include "detect-flowvar.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"
#include "app-layer-dcerpc-common.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-profiling.h"

#include "flow-util.h"

/** convert enum to string */
#define CASE_CODE(E)  case E: return #E

static inline int StateIsValid(uint16_t alproto, void *alstate)
{
    if (alstate != NULL) {
        if (alproto == ALPROTO_HTTP1) {
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

static DeStateStore *DeStateStoreAlloc(void)
{
    DeStateStore *d = SCMalloc(sizeof(DeStateStore));
    if (unlikely(d == NULL))
        return NULL;
    memset(d, 0, sizeof(DeStateStore));

    return d;
}

#ifdef DEBUG_VALIDATION
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
#endif

static void DeStateSignatureAppend(DetectEngineState *state,
        const Signature *s, uint32_t inspect_flags, uint8_t direction)
{
    SCEnter();

    DetectEngineStateDirection *dir_state =
            &state->dir_state[(direction & STREAM_TOSERVER) ? 0 : 1];

#ifdef DEBUG_VALIDATION
    BUG_ON(DeStateSearchState(state, direction, s->num));
#endif
    DeStateStore *store = dir_state->tail;
    if (store == NULL) {
        store = DeStateStoreAlloc();
        dir_state->head = store;
        dir_state->cur = store;
        dir_state->tail = store;
    } else if (dir_state->cur) {
        store = dir_state->cur;
    } else {
        store = DeStateStoreAlloc();
        if (store != NULL) {
            dir_state->tail->next = store;
            dir_state->tail = store;
            dir_state->cur = store;
        }
    }
    if (store == NULL)
        SCReturn;

    SigIntId idx = dir_state->cnt % DE_STATE_CHUNK_SIZE;
    store->store[idx].sid = s->num;
    store->store[idx].flags = inspect_flags;
    dir_state->cnt++;
    /* if current chunk is full, progress cur */
    if (dir_state->cnt % DE_STATE_CHUNK_SIZE == 0) {
        dir_state->cur = dir_state->cur->next;
    }

    SCReturn;
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

static void StoreFileNoMatchCnt(DetectEngineState *de_state, uint16_t file_no_match, uint8_t direction)
{
    de_state->dir_state[(direction & STREAM_TOSERVER) ? 0 : 1].filestore_cnt += file_no_match;

    return;
}

static bool StoreFilestoreSigsCantMatch(const SigGroupHead *sgh, const DetectEngineState *de_state, uint8_t direction)
{
    if (de_state->dir_state[(direction & STREAM_TOSERVER) ? 0 : 1].filestore_cnt ==
            sgh->filestore_cnt)
        return true;
    else
        return false;
}

static void StoreStateTxHandleFiles(const SigGroupHead *sgh, Flow *f, DetectEngineState *destate,
        const uint8_t flow_flags, void *tx, const uint64_t tx_id, const uint16_t file_no_match)
{
    SCLogDebug("tx %"PRIu64", file_no_match %u", tx_id, file_no_match);
    StoreFileNoMatchCnt(destate, file_no_match, flow_flags);
    if (StoreFilestoreSigsCantMatch(sgh, destate, flow_flags)) {
        SCLogDebug("filestore sigs can't match");
        FileDisableStoringForTransaction(
                f, flow_flags & (STREAM_TOCLIENT | STREAM_TOSERVER), tx, tx_id);
    } else {
        SCLogDebug("filestore sigs can still match");
    }
}

void DetectRunStoreStateTx(
        const SigGroupHead *sgh,
        Flow *f, void *tx, uint64_t tx_id,
        const Signature *s,
        uint32_t inspect_flags, uint8_t flow_flags,
        const uint16_t file_no_match)
{
    AppLayerTxData *tx_data = AppLayerParserGetTxData(f->proto, f->alproto, tx);
    BUG_ON(tx_data == NULL);
    if (tx_data == NULL) {
        SCLogDebug("No TX data for %" PRIu64, tx_id);
        return;
    }
    if (tx_data->de_state == NULL) {
        tx_data->de_state = DetectEngineStateAlloc();
        if (tx_data->de_state == NULL)
            return;
        SCLogDebug("destate created for %"PRIu64, tx_id);
    }
    DeStateSignatureAppend(tx_data->de_state, s, inspect_flags, flow_flags);
    StoreStateTxHandleFiles(sgh, f, tx_data->de_state, flow_flags, tx, tx_id, file_no_match);

    SCLogDebug("Stored for TX %"PRIu64, tx_id);
}

/** \brief update flow's inspection id's
 *
 *  \param f unlocked flow
 *  \param flags direction and disruption flags
 *  \param tag_txs_as_inspected if true all 'complete' txs will be marked
 *                              'inspected'
 *
 *  \note it is possible that f->alstate, f->alparser are NULL */
void DeStateUpdateInspectTransactionId(Flow *f, const uint8_t flags,
        const bool tag_txs_as_inspected)
{
    if (f->alparser && f->alstate) {
        AppLayerParserSetTransactionInspectId(f, f->alparser,
                                              f->alstate, flags,
                                              tag_txs_as_inspected);
    }
    return;
}

static inline void ResetTxState(DetectEngineState *s)
{
    if (s) {
        s->dir_state[0].cnt = 0;
        s->dir_state[0].filestore_cnt = 0;
        s->dir_state[0].flags = 0;
        /* reset 'cur' back to the list head */
        s->dir_state[0].cur = s->dir_state[0].head;

        s->dir_state[1].cnt = 0;
        s->dir_state[1].filestore_cnt = 0;
        s->dir_state[1].flags = 0;
        /* reset 'cur' back to the list head */
        s->dir_state[1].cur = s->dir_state[1].head;
    }
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
            AppLayerTxData *txd = AppLayerParserGetTxData(f->proto, f->alproto, inspect_tx);
            BUG_ON(txd == NULL);
            if (txd) {
                ResetTxState(txd->de_state);
            }
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
    uint8_t direction = STREAM_TOSERVER;
    DetectEngineState *state = DetectEngineStateAlloc();
    FAIL_IF_NULL(state);
    FAIL_IF_NOT_NULL(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head);

    Signature s;
    memset(&s, 0x00, sizeof(s));

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
    FAIL_IF_NOT(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head ==
                state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].cur);

    s.num = 144;
    DeStateSignatureAppend(state, &s, 0, direction);

    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[14].sid != 144);
    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head ==
            state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].cur);
    FAIL_IF_NOT(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].cur == NULL);

    s.num = 155;
    DeStateSignatureAppend(state, &s, 0, direction);

    FAIL_IF_NOT(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].tail ==
                state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].cur);

    s.num = 166;
    DeStateSignatureAppend(state, &s, 0, direction);

    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head == NULL);
    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[1].sid != 11);
    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->next == NULL);
    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[14].sid != 144);
    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->next->store[0].sid != 155);
    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->next->store[1].sid != 166);

    ResetTxState(state);

    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head == NULL);
    FAIL_IF_NOT(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head ==
                state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].cur);

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
    FAIL_IF_NOT(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head ==
                state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].cur);
    s.num = 144;
    DeStateSignatureAppend(state, &s, 0, direction);
    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[14].sid != 144);
    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head ==
            state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].cur);
    FAIL_IF_NOT(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].tail ==
                state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].cur);
    s.num = 155;
    DeStateSignatureAppend(state, &s, 0, direction);
    s.num = 166;
    DeStateSignatureAppend(state, &s, 0, direction);

    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head == NULL);
    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[1].sid != 11);
    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->next == NULL);
    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->store[14].sid != 144);
    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->next->store[0].sid != 155);
    FAIL_IF(state->dir_state[direction & STREAM_TOSERVER ? 0 : 1].head->next->store[1].sid != 166);

    DetectEngineStateFree(state);

    PASS;
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

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"dummy\"; http_cookie; sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    FAIL_IF_NULL(det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF_NOT(r == 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF_NOT(r == 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    FAIL_IF_NOT(r == 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf4, httplen4);
    FAIL_IF_NOT(r == 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

/** \test multiple pipelined http transactions */
static int DeStateSigTest02(void)
{
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
    FAIL_IF_NULL(alp_tctx);

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
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flow:to_server; content:\"POST\"; http_method; content:\"/\"; http_uri; content:\"Mozilla\"; http_header; content:\"dummy\"; http_cookie; content:\"body\"; nocase; http_client_body; sid:1; rev:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flow:to_server; content:\"GET\"; http_method; content:\"Firefox\"; http_header; content:\"dummy2\"; http_cookie; sid:2; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    FAIL_IF_NULL(det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    void *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f.alstate, 0);
    FAIL_IF_NULL(tx);

    AppLayerTxData *tx_data = AppLayerParserGetTxData(IPPROTO_TCP, ALPROTO_HTTP1, tx);
    FAIL_IF_NULL(tx_data);
    DetectEngineState *tx_de_state = tx_data->de_state;
    FAIL_IF_NULL(tx_de_state);
    FAIL_IF(tx_de_state->dir_state[0].cnt != 1);
    /* http_header(mpm): 5, uri: 3, method: 6, cookie: 7 */
    uint32_t expected_flags = (BIT_U32(5) | BIT_U32(3) | BIT_U32(6) |BIT_U32(7));
    FAIL_IF(tx_de_state->dir_state[0].head->store[0].flags != expected_flags);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf4, httplen4);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 1)));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf5, httplen5);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf6, httplen6);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF((PacketAlertCheck(p, 1)) || (PacketAlertCheck(p, 2)));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf7, httplen7);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 2)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

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
    f->alproto = ALPROTO_HTTP1;

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    p->flow = f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1,
            STREAM_TOSERVER | STREAM_START | STREAM_EOF, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    HtpState *http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    void *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f->alstate, 0);
    FAIL_IF_NULL(tx);
    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    FAIL_IF_NULL(tx_ud);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 1)));

    FileContainer *files = AppLayerParserGetTxFiles(p->flow, tx, STREAM_TOSERVER);
    FAIL_IF_NULL(files);

    File *file = files->head;
    FAIL_IF_NULL(file);

    FAIL_IF(!(file->flags & FILE_STORE));

    AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreeFlow(f);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(ssn));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"GET\"; http_method; content:\"upload.cgi\"; http_uri; filestore; sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    FAIL_IF_NULL(det_ctx);

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    Packet *p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF_NULL(p);
    p->flow = f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1,
            STREAM_TOSERVER | STREAM_START | STREAM_EOF, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    HtpState *http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    void *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f->alstate, 0);
    FAIL_IF_NULL(tx);
    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    FAIL_IF_NULL(tx_ud);

    FileContainer *files = AppLayerParserGetTxFiles(p->flow, tx, STREAM_TOSERVER);
    FAIL_IF_NULL(files);
    File *file = files->head;
    FAIL_IF_NULL(file);

    FAIL_IF(file->flags & FILE_STORE);

    AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreeFlow(f);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    PASS;
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

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(ssn));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"GET\"; http_method; content:\"upload.cgi\"; http_uri; filename:\"nomatch\"; sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    Packet *p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF_NULL(p);
    p->flow = f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1,
            STREAM_TOSERVER | STREAM_START | STREAM_EOF, httpbuf1, httplen1);
    FAIL_IF_NOT(r == 0);
    HtpState *http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    void *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f->alstate, 0);
    FAIL_IF_NULL(tx);
    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    FAIL_IF_NULL(tx_ud);

    FileContainer *files = AppLayerParserGetTxFiles(p->flow, tx, STREAM_TOSERVER);
    FAIL_IF_NULL(files);
    File *file = files->head;
    FAIL_IF_NULL(file);
    FAIL_IF(http_state->state_data.file_flags & FLOWFILE_NO_STORE_TS);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    /* detect will have set FLOWFILE_NO_STORE_TS, but it won't have had
     * an opportunity to be applied to the file itself yet */
    FAIL_IF_NOT(http_state->state_data.file_flags & FLOWFILE_NO_STORE_TS);
    FAIL_IF(file->flags & FILE_NOSTORE);

    AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreeFlow(f);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    PASS;
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

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(ssn));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"POST\"; http_method; content:\"upload.cgi\"; http_uri; filename:\"nomatch\"; filestore; sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    FAIL_IF_NULL(det_ctx);

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    Packet *p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF_NULL(p);
    p->flow = f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1,
            STREAM_TOSERVER | STREAM_START | STREAM_EOF, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    HtpState *http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    void *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f->alstate, 0);
    FAIL_IF_NULL(tx);
    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    FAIL_IF_NULL(tx_ud);

    FileContainer *files = AppLayerParserGetTxFiles(p->flow, tx, STREAM_TOSERVER);
    FAIL_IF_NULL(files);
    File *file = files->head;
    FAIL_IF_NULL(file);
    /* detect will have set FLOWFILE_NO_STORE_TS, but it won't have had
     * an opportunity to be applied to the file itself yet */
    FAIL_IF_NOT(tx_ud->tx_data.file_flags & FLOWFILE_NO_STORE_TS);
    FAIL_IF(file->flags & FILE_NOSTORE);

    AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreeFlow(f);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    PASS;
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

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(ssn));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"GET\"; http_method; content:\"upload.cgi\"; http_uri; filestore; sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    Packet *p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF_NULL(p);
    p->flow = f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_EOF, httpbuf2, httplen2);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    HtpState *http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    void *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f->alstate, 0);
    FAIL_IF_NULL(tx);
    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    FAIL_IF_NULL(tx_ud);

    FileContainer *files = AppLayerParserGetTxFiles(p->flow, tx, STREAM_TOSERVER);
    FAIL_IF_NULL(files);
    File *file = files->head;
    FAIL_IF_NULL(file);
    FAIL_IF(file->flags & FILE_STORE);

    AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreeFlow(f);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    PASS;
}

/**
 * \test multiple files in a tx
 */
static int DeStateSigTest08(void)
{
    uint8_t httpbuf1[] = "POST /upload.cgi HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
                         "Content-Length: 440\r\n"
                         "\r\n"
                         "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"AAAApicture1.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n";

    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "file";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint8_t httpbuf3[] = "content\r\n"
                         "-----------------------------277531038314945\r\n";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */

    uint8_t httpbuf4[] = "Content-Disposition: form-data; name=\"uploadfile_1\"; filename=\"BBBBpicture2.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n"
                         "filecontent2\r\n"
                         "-----------------------------277531038314945--";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */

    ThreadVars th_v;
    TcpSession ssn;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(ssn));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"POST\"; http_method; content:\"upload.cgi\"; http_uri; filename:\"BBBBpicture\"; filestore; sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    Packet *p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF_NULL(p);
    p->flow = f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    /* HTTP request with 1st part of the multipart body */

    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    HtpState *http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    void *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f->alstate, 0);
    FAIL_IF_NULL(tx);
    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    FAIL_IF_NULL(tx_ud);

    FileContainer *files = AppLayerParserGetTxFiles(p->flow, tx, STREAM_TOSERVER);
    FAIL_IF_NULL(files);
    File *file = files->head;
    FAIL_IF_NULL(file);
    FAIL_IF(file->flags & FILE_STORE);

    /* 2nd multipart body file */

    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_EOF, httpbuf4, httplen4);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f->alstate, 0);
    FAIL_IF_NULL(tx);
    tx_ud = htp_tx_get_user_data(tx);
    FAIL_IF_NULL(tx_ud);

    files = AppLayerParserGetTxFiles(p->flow, tx, STREAM_TOSERVER);
    FAIL_IF_NULL(files);
    file = files->head;
    FAIL_IF_NULL(file);
    file = file->next;
    FAIL_IF_NULL(file);
    FAIL_IF_NOT(file->flags & FILE_STORE);

    AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreeFlow(f);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    PASS;
}

/**
 * \test multiple files in a tx. Both files should match
 */
static int DeStateSigTest09(void)
{
    uint8_t httpbuf1[] = "POST /upload.cgi HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
                         "Content-Length: 440\r\n"
                         "\r\n"
                         "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n";

    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "file";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint8_t httpbuf3[] = "content\r\n"
                         "-----------------------------277531038314945\r\n";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */

    uint8_t httpbuf4[] = "Content-Disposition: form-data; name=\"uploadfile_1\"; filename=\"somepicture2.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n"
                         "filecontent2\r\n"
                         "-----------------------------277531038314945--";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */

    ThreadVars th_v;
    TcpSession ssn;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(ssn));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (content:\"POST\"; http_method; content:\"upload.cgi\"; http_uri; filename:\"somepicture\"; filestore; sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    Packet *p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF_NULL(p);
    p->flow = f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    /* HTTP request with 1st part of the multipart body */

    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    HtpState *http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    void *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f->alstate, 0);
    FAIL_IF_NULL(tx);
    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    FAIL_IF_NULL(tx_ud);

    FileContainer *files = AppLayerParserGetTxFiles(p->flow, tx, STREAM_TOSERVER);
    FAIL_IF_NULL(files);
    File *file = files->head;
    FAIL_IF_NULL(file);
    FAIL_IF_NOT(file->flags & FILE_STORE);

    /* 2nd multipart body file */

    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_EOF, httpbuf4, httplen4);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f->alstate, 0);
    FAIL_IF_NULL(tx);
    tx_ud = htp_tx_get_user_data(tx);
    FAIL_IF_NULL(tx_ud);

    files = AppLayerParserGetTxFiles(p->flow, tx, STREAM_TOSERVER);
    FAIL_IF_NULL(files);
    file = files->head;
    FAIL_IF_NULL(file);
    FAIL_IF_NOT(file->flags & FILE_STORE);

    AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreeFlow(f);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    PASS;
}

/**
 * \test multiple files in a tx. Both files should match. No other matches.
 */
static int DeStateSigTest10(void)
{
    uint8_t httpbuf1[] = "POST /upload.cgi HTTP/1.1\r\n"
                         "Host: www.server.lan\r\n"
                         "Content-Type: multipart/form-data; boundary=---------------------------277531038314945\r\n"
                         "Content-Length: 440\r\n"
                         "\r\n"
                         "-----------------------------277531038314945\r\n"
                         "Content-Disposition: form-data; name=\"uploadfile_0\"; filename=\"somepicture1.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n";

    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "file";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint8_t httpbuf3[] = "content\r\n"
                         "-----------------------------277531038314945\r\n";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */

    uint8_t httpbuf4[] = "Content-Disposition: form-data; name=\"uploadfile_1\"; filename=\"somepicture2.jpg\"\r\n"
                         "Content-Type: image/jpeg\r\n"
                         "\r\n"
                         "filecontent2\r\n"
                         "-----------------------------277531038314945--";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */

    ThreadVars th_v;
    TcpSession ssn;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(ssn));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (filename:\"somepicture\"; filestore; sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    Packet *p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF_NULL(p);
    p->flow = f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(true);

    /* HTTP request with 1st part of the multipart body */

    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    HtpState *http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    void *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f->alstate, 0);
    FAIL_IF_NULL(tx);
    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    FAIL_IF_NULL(tx_ud);

    FileContainer *files = AppLayerParserGetTxFiles(p->flow, tx, STREAM_TOSERVER);
    FAIL_IF_NULL(files);
    File *file = files->head;
    FAIL_IF_NULL(file);
    FAIL_IF_NOT(file->flags & FILE_STORE);

    /* 2nd multipart body file */

    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_EOF, httpbuf4, httplen4);
    FAIL_IF(r != 0);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f->alstate, 0);
    FAIL_IF_NULL(tx);
    tx_ud = htp_tx_get_user_data(tx);
    FAIL_IF_NULL(tx_ud);

    files = AppLayerParserGetTxFiles(p->flow, tx, STREAM_TOSERVER);
    FAIL_IF_NULL(files);
    file = files->head;
    FAIL_IF_NULL(file);
    FAIL_IF_NOT(file->flags & FILE_STORE);

    AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreeFlow(f);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    PASS;
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
    UtRegisterTest("DeStateSigTest08", DeStateSigTest08);
    UtRegisterTest("DeStateSigTest09", DeStateSigTest09);
    UtRegisterTest("DeStateSigTest10", DeStateSigTest10);
#endif

    return;
}

/**
 * @}
 */
