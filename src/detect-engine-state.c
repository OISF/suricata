/* Copyright (C) 2007-2010 Open Information Security Foundation
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

#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-engine-state.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"

#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"

#include "util-unittest.h"

#define CASE_CODE(E)  case E: return #E
const char *DeStateMatchResultToString(DeStateMatchResult res)
{
    switch (res) {
        CASE_CODE (DE_STATE_MATCH_FULL);
        CASE_CODE (DE_STATE_MATCH_PARTIAL);
        CASE_CODE (DE_STATE_MATCH_STORED);
        CASE_CODE (DE_STATE_MATCH_NEW);
    }

    return NULL;
}

/**
 *  \brief Alloc a DeStateStore object
 *  \retval d alloc'd object
 */
DeStateStore *DeStateStoreAlloc(void) {
    SCEnter();

    DeStateStore *d = SCMalloc(sizeof(DeStateStore));
    if (d == NULL) {
        SCReturnPtr(NULL, "DeStateStore");
    }
    memset(d, 0x00, sizeof(DeStateStore));

    SCReturnPtr(d, "DeStateStore");
}

/**
 *  \brief free a DeStateStore object (recursively)
 *  \param store DeStateStore object to free
 */
void DeStateStoreFree(DeStateStore *store) {
    SCEnter();

    if (store == NULL) {
        SCReturn;
    }

    if (store->next != NULL) {
        DeStateStoreFree(store->next);
    }

    SCFree(store);
    SCReturn;
}

/**
 *  \brief Alloc a DetectEngineState object
 *  \param d alloc'd object
 */
DetectEngineState *DetectEngineStateAlloc(void) {
    SCEnter();

    DetectEngineState *d = SCMalloc(sizeof(DetectEngineState));
    if (d == NULL) {
        SCReturnPtr(NULL, "DetectEngineState");
    }
    memset(d, 0x00, sizeof(DetectEngineState));

    SCMutexInit(&d->m, NULL);

    SCReturnPtr(d, "DetectEngineState");
}

/**
 *  \brief Free a DetectEngineState object
 *  \param state DetectEngineState object to free
 */
void DetectEngineStateFree(DetectEngineState *state) {
    if (state == NULL)
        return;

    if (state->head != NULL) {
        DeStateStoreFree(state->head);
    }

    SCMutexDestroy(&state->m);

    SCFree(state);
}

/**
 *  \brief reset a DetectEngineState state
 *  \param state LOCKED state
 */
void DetectEngineStateReset(DetectEngineState *state) {
    SCEnter();

    if (state == NULL) {
        SCReturn;
    }

    if (state->head != NULL) {
        DeStateStoreFree(state->head);
    }
    state->head = NULL;
    state->tail = NULL;

    state->cnt = 0;

    SCReturn;
}

/**
 *  \brief update the transaction id
 *  \retval 2 current transaction done, new available
 *  \retval 1 current transaction done, no new (yet)
 *  \retval 0 current transaction is not done yet
 */
int DeStateUpdateInspectTransactionId(Flow *f) {
    SCEnter();

    int r = 0;

    SCMutexLock(&f->m);
    r = AppLayerTransactionUpdateInspectId(f);
    SCMutexUnlock(&f->m);

    SCReturnInt(r);
}

void DeStateSignatureAppend(DetectEngineState *state, Signature *s, SigMatch *sm) {
    DeStateStore *store = state->tail;

    if (store == NULL) {
        store = DeStateStoreAlloc();
        if (store != NULL) {
            state->head = store;
            state->tail = store;
        }
    } else {
        if ((state->cnt % DE_STATE_CHUNK_SIZE) == 0) {
            store = DeStateStoreAlloc();
            if (store != NULL) {
                state->tail->next = store;
                state->tail = store;
            }
        } else {
            store = state->tail;
        }
    }

    if (store == NULL) {
        return;
    }

    SigIntId idx = state->cnt % DE_STATE_CHUNK_SIZE;
    store->store[idx].sid = s->num;
    store->store[idx].flags = 0;
    store->store[idx].nm = sm;
    state->cnt++;

    SCLogDebug("store %p idx %"PRIuMAX" cnt %"PRIuMAX" sig id %"PRIuMAX"",
            store, (uintmax_t)idx, (uintmax_t)state->cnt,
            (uintmax_t)store->store[idx].sid);
}



/*
    on first detection run:

    for each
        (1) app layer signature
        (2a) at least one app layer sm match OR
        (2b) content/uri match AND other app layer sigmatches present

        Cases:
            multiple app layer sm's
            content + uricontent
            content + app layer sm
            uricontent + app layer sm
*/

/** \brief Check if a flow already contains a flow detect state
 *  \retval 1 has state
 *  \retval 0 has no state
 */
int DeStateFlowHasState(Flow *f) {
    SCEnter();
    int r = 0;
    SCMutexLock(&f->m);
    if (f->de_state == NULL || f->de_state->cnt == 0)
        r = 0;
    else
        r = 1;
    SCMutexUnlock(&f->m);
    SCReturnInt(r);
}

/** \brief Match app layer sig list against state. Set up state for non matches
 *         and partial matches.
 *  \retval 1 match
 *  \retval 0 no or partial match
 */
int DeStateDetectStartDetection(ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
        Signature *s, Flow *f, uint8_t flags, void *alstate, uint16_t alproto)
{
    SCEnter();

    SigMatch *sm = s->amatch;
    int match = 0;
    int r = 0;

    for ( ; sm != NULL; sm = sm->next) {
        SCLogDebug("sm %p, sm->next %p", sm, sm->next);

        if (sigmatch_table[sm->type].AppLayerMatch != NULL &&
                alproto == sigmatch_table[sm->type].alproto &&
                alstate != NULL)
        {
            match = sigmatch_table[sm->type].AppLayerMatch(tv, det_ctx, f, flags, alstate, s, sm);
            if (match == 0) {
                break;
            } else if (sm->next == NULL) {
                r = 1;
                sm = NULL; /* set to NULL as we have a match */
                break;
            }
        }
    }

    SCLogDebug("detection done, store results");

    SCMutexLock(&f->m);
    /* match or no match, we store the state anyway
     * "sm" here is either NULL (complete match) or
     * the last SigMatch that didn't match */
    if (f->de_state == NULL) {
        f->de_state = DetectEngineStateAlloc();
    }
    SCMutexUnlock(&f->m);

    if (f->de_state != NULL) {
        SCMutexLock(&f->de_state->m);
        DeStateSignatureAppend(f->de_state, s, sm);
        SCMutexUnlock(&f->de_state->m);
    }

    SCReturnInt(r);
}

/** \brief Continue DeState detection of the signatures stored in the state.
 *
 *  \retval 0 all is good
 */
int DeStateDetectContinueDetection(ThreadVars *tv, DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *alstate, uint16_t alproto)
{
    SCEnter();
    SigIntId cnt = 0;
    SigIntId store_cnt = 0;
    DeStateStore *store = NULL;

    if (f == NULL || alstate == NULL || alproto == ALPROTO_UNKNOWN) {
        return 0;
    }

    SCMutexLock(&f->de_state->m);

    if (f->de_state->cnt == 0)
        goto end;

    /* loop through the stores */
    for (store = f->de_state->head; store != NULL; store = store->next)
    {
        /* loop through the sigs in the stores */
        for (store_cnt = 0;
                store_cnt < DE_STATE_CHUNK_SIZE && cnt < f->de_state->cnt;
                store_cnt++, cnt++)
        {
            DeStateStoreItem *item = &store->store[store_cnt];

            SCLogDebug("internal id of signature to inspect: %"PRIuMAX,
                    (uintmax_t)item->sid);

            Signature *s = de_ctx->sig_array[item->sid];
            SCLogDebug("id of signature to inspect: %"PRIuMAX,
                    (uintmax_t)s->id);

            /* if the sm is NULL, the sig matched already */
            if (item->nm == NULL) {
                SCLogDebug("state detection already matched in a previous run");
                det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_STORED;

                SCLogDebug("signature %"PRIu32" match state %s",
                        s->id, DeStateMatchResultToString(det_ctx->de_state_sig_array[item->sid]));
                continue;
            }

            /* let's continue detection */
            SigMatch *sm;
            for (sm = item->nm; sm != NULL; sm = sm->next) {
                int match = sigmatch_table[sm->type].AppLayerMatch(tv,
                        det_ctx, f, flags, alstate, s, sm);
                if (match == 0) {
                    item->nm = sm;
                    det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_PARTIAL;
                } else if (sm->next == NULL) {
                    /* mark the sig as matched */
                    item->nm = NULL;
                    det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_NEW;
                }
            }

            SCLogDebug("signature %"PRIu32" match state %s",
                    s->id, DeStateMatchResultToString(det_ctx->de_state_sig_array[item->sid]));
        }
    }

end:
    SCMutexUnlock(&f->de_state->m);
    SCReturnInt(0);
}

/**
 *  \brief Restart detection as we're going to inspect a new transaction
 */
int DeStateRestartDetection(ThreadVars *tv, DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *alstate, uint16_t alproto)
{
    SCEnter();

    /* first clear the existing state as it belongs
     * to the previous transaction */
    SCMutexLock(&f->m);
    if (f->de_state != NULL) {
        SCMutexLock(&f->de_state->m);
        DetectEngineStateReset(f->de_state);
        SCMutexUnlock(&f->de_state->m);
    }
    SCMutexUnlock(&f->m);

    SCReturnInt(0);
}

/**
 *  \retval 1 match
 *  \retval 0 no match
 */
int DeStateDetectSignature(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, Signature *s,
        Packet *p, uint8_t flags, void *alstate, uint16_t alproto)
{
    SCEnter();
    int r = 0;

    if (p->flow == NULL) {
        SCReturnInt(0);
    }

    /* if there is already a state, continue the inspection of this
     * signature using that state.
     */
    r = DeStateDetectStartDetection(tv, det_ctx, s, p->flow, flags,
            alstate, alproto);

    SCReturnInt(r);
}

/*
    pseudocode

app_detect() {
    if (no flow state) {
        start_fresh_detect();
    } else {
        continue_where_we_left_off()
    }
}

start_fresh_detect() {
    if (state not updated)
        done;

    for (sigs in app list) {
        add sig to state;

        for (each sigmatch) {
            if (not sigmatch match) {
                store sigmatch ptr;
                break sigmatch loop;
            }

            if (final sigmatch matches)
                set state sm to NULL
        }
    }
}

continue_where_we_left_off() {
    if (state not updated)
        done;

    for (each sig in the state) {
        for (each sm starting at state->sm) {
            if (not sigmatch match) {
                store sigmatch ptr;
                break sigmatch loop;
            }

            if (final sigmatch matches)
                set state sm to NULL
        }
    }
}


 */


#ifdef UNITTESTS
#include "flow-util.h"

static int DeStateTest01(void) {
    SCLogDebug("sizeof(DetectEngineState)\t\t%"PRIuMAX,
            (uintmax_t)sizeof(DetectEngineState));
    SCLogDebug("sizeof(DeStateStore)\t\t\t%"PRIuMAX,
            (uintmax_t)sizeof(DeStateStore));
    SCLogDebug("sizeof(DeStateStoreItem)\t\t%"PRIuMAX"",
            (uintmax_t)sizeof(DeStateStoreItem));
    return 1;
}

static int DeStateTest02(void) {
    int result = 0;

    DetectEngineState *state = DetectEngineStateAlloc();
    if (state == NULL) {
        printf("d == NULL: ");
        goto end;
    }

    Signature s;
    memset(&s, 0x00, sizeof(s));

    s.num = 0;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 11;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 22;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 33;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 44;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 55;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 66;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 77;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 88;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 99;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 100;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 111;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 122;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 133;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 144;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 155;
    DeStateSignatureAppend(state, &s, NULL);
    s.num = 166;
    DeStateSignatureAppend(state, &s, NULL);

    if (state->head == NULL) {
        goto end;
    }

    if (state->head->store[1].sid != 11) {
        goto end;
    }

    if (state->head->next == NULL) {
        goto end;
    }

    if (state->head->next->next == NULL) {
        goto end;
    }

    if (state->head->next->next->next == NULL) {
        goto end;
    }

    if (state->head->next->next->next->next == NULL) {
        goto end;
    }

    if (state->head->next->next->next->store[3].sid != 155) {
        goto end;
    }

    if (state->head->next->next->next->next->store[0].sid != 166) {
        goto end;
    }

    result = 1;
end:
    if (state != NULL) {
        DetectEngineStateFree(state);
    }
    return result;
}

static int DeStateTest03(void) {
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet p;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\n";
    uint8_t httpbuf2[] = "User-Agent: Mozilla/1.0\r\n";
    uint8_t httpbuf3[] = "Cookie: dummy\r\nContent-Length: 10\r\n\r\n";
    uint8_t httpbuf4[] = "Http Body!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

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

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }
    p.alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1)) {
        printf("sig 1 alerted (2): ");
        goto end;
    }
    p.alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (!(PacketAlertCheck(&p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p.alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1)) {
        printf("signature matched, but shouldn't have: ");
        goto end;
    }
    p.alerts.cnt = 0;

    result = 1;
end:
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

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test multiple pipelined http transactions */
static int DeStateTest04(void) {
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet p;
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

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

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

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }
    p.alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1)) {
        printf("sig 1 alerted (2): ");
        goto end;
    }
    p.alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (!(PacketAlertCheck(&p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p.alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1)) {
        printf("signature matched, but shouldn't have: ");
        goto end;
    }
    p.alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1)) {
        printf("sig 1 alerted (5): ");
        goto end;
    }
    p.alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf6, httplen6);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if ((PacketAlertCheck(&p, 1)) || (PacketAlertCheck(&p, 2))) {
        printf("sig 1 alerted (request 2, chunk 6): ");
        goto end;
    }
    p.alerts.cnt = 0;

    SCLogDebug("sending data chunk 7");

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf7, httplen7);
    if (r != 0) {
        printf("toserver chunk 7 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (!(PacketAlertCheck(&p, 2))) {
        printf("signature 2 didn't match, but should have: ");
        goto end;
    }
    p.alerts.cnt = 0;

    result = 1;
end:
    CLEAR_FLOW(&f);

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}
#endif

void DeStateRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DeStateTest01", DeStateTest01, 1);
    UtRegisterTest("DeStateTest02", DeStateTest02, 1);
    UtRegisterTest("DeStateTest03", DeStateTest03, 1);
    UtRegisterTest("DeStateTest04", DeStateTest04, 1);
#endif
}

