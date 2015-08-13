/*
 * Copyright (C) 2014 ANSSI
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * \author Kevin Wong <kwong@solananetworks.com>
 *
 * App-layer parser for ENIP protocol
 *
 */

#include "suricata-common.h"

#include "util-debug.h"
#include "util-byte.h"
#include "util-enum.h"
#include "util-mem.h"
#include "util-misc.h"

#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-enip.h"
#include "detect-cipservice.h"

#include "app-layer-detect-proto.h"

#include "conf.h"
#include "decode.h"



SC_ATOMIC_DECLARE(uint64_t, enip_memuse); /**< byte counter of current memuse */
SC_ATOMIC_DECLARE(uint64_t, enip_memcap_state); /**< counts number of 'rejects' */
SC_ATOMIC_DECLARE(uint64_t, enip_memcap_global); /**< counts number of 'rejects' */

typedef struct ENIPConfig_ {
    uint32_t request_flood;
    uint32_t state_memcap;  /**< memcap in bytes per state */
    uint64_t global_memcap; /**< memcap in bytes globally for parser */
} ENIPConfig;
static ENIPConfig enip_config;


void *ENIPGetTx(void *alstate, uint64_t tx_id)
{
    ENIPState *enip_state = (ENIPState *)alstate;
    ENIPTransaction *tx = NULL;

    /* fast track: try the current tx */
    if (enip_state->curr && enip_state->curr->tx_num == tx_id + 1)
        return enip_state->curr;

    /* fast track:
     * if the prev tx_id is equal to the stored tx ptr, we can
     * use this shortcut to get to the next. */
    if (enip_state->iter) {
        if (tx_id == enip_state->iter->tx_num) {
            tx = TAILQ_NEXT(enip_state->iter, next);
            if (tx && tx->tx_num == tx_id + 1) {
                enip_state->iter = tx;
                return tx;
            }
        }
    }

    /* no luck with the fast tracks, do the full list walk */
    TAILQ_FOREACH(tx, &enip_state->tx_list, next) {
        SCLogDebug("tx->tx_num %u, tx_id %"PRIu64, tx->tx_num, (tx_id+1));
        if ((tx_id+1) != tx->tx_num)
            continue;

        SCLogDebug("returning tx %p", tx);
        enip_state->iter = tx;
        return tx;
    }

    return NULL;
}

uint64_t ENIPGetTxCnt(void *alstate)
{
    ENIPState *enip_state = (ENIPState *)alstate;
    return (uint64_t)enip_state->transaction_max;
}


int ENIPGetAlstateProgress(void *tx, uint8_t direction)
{
    return 1;
}



/** \brief get value for 'complete' status in ENIP
 *
 *  For ENIP we use a simple bool.
 */
int ENIPGetAlstateProgressCompletionStatus(uint8_t direction)
{
    return 1;
}

void ENIPIncrMemcap(uint32_t size, ENIPState *state)
{
    if (state != NULL) {
        state->memuse += size;
    }
    SC_ATOMIC_ADD(enip_memuse, size);
}



void ENIPDecrMemcap(uint32_t size, ENIPState *state)
{
    if (state != NULL) {
        BUG_ON(size > state->memuse); /**< TODO remove later */
        state->memuse -= size;
    }

    BUG_ON(size > SC_ATOMIC_GET(enip_memuse)); /**< TODO remove later */
    (void)SC_ATOMIC_SUB(enip_memuse, size);
}

int ENIPCheckMemcap(uint32_t want, ENIPState *state)
{
    if (state != NULL) {
        if (state->memuse + want > enip_config.state_memcap) {
            SC_ATOMIC_ADD(enip_memcap_state, 1);
          //  ENIPSetEvent(state, ENIP_DECODER_EVENT_STATE_MEMCAP_REACHED);
            return -1;
        }
    }

    if (SC_ATOMIC_GET(enip_memuse) + (uint64_t)want > enip_config.global_memcap) {
        SC_ATOMIC_ADD(enip_memcap_global, 1);
        return -2;
    }

    return 0;
}



void *ENIPStateAlloc(void)
{
    void *s = SCMalloc(sizeof(ENIPState));
    if (unlikely(s == NULL))
        return NULL;

    memset(s, 0, sizeof(ENIPState));

    ENIPState *enip_state = (ENIPState *)s;

    ENIPIncrMemcap(sizeof(ENIPState), enip_state);

    TAILQ_INIT(&enip_state->tx_list);
    return s;
}


/** \internal
 *  \brief Free a ENIP TX
 *  \param tx ENIP TX to free */
static void ENIPTransactionFree(ENIPTransaction *tx, ENIPState *state)
{
    SCEnter();
/*
    ENIPQueryEntry *q = NULL;
    while ((q = TAILQ_FIRST(&tx->query_list))) {
        TAILQ_REMOVE(&tx->query_list, q, next);
        ENIPDecrMemcap((sizeof(ENIPQueryEntry) + q->len), state);
        SCFree(q);
    }

    ENIPAnswerEntry *a = NULL;
    while ((a = TAILQ_FIRST(&tx->answer_list))) {
        TAILQ_REMOVE(&tx->answer_list, a, next);
        ENIPDecrMemcap((sizeof(ENIPAnswerEntry) + a->fqdn_len + a->data_len), state);
        SCFree(a);
    }
    while ((a = TAILQ_FIRST(&tx->authority_list))) {
        TAILQ_REMOVE(&tx->authority_list, a, next);
        ENIPDecrMemcap((sizeof(ENIPAnswerEntry) + a->fqdn_len + a->data_len), state);
        SCFree(a);
    }
*/
    AppLayerDecoderEventsFreeEvents(&tx->decoder_events);

    if (tx->de_state != NULL) {
        DetectEngineStateFree(tx->de_state);
        BUG_ON(state->tx_with_detect_state_cnt == 0);
        state->tx_with_detect_state_cnt--;
    }

    if (state->iter == tx)
        state->iter = NULL;

    ENIPDecrMemcap(sizeof(ENIPTransaction), state);
    SCFree(tx);
    SCReturn;
}



void ENIPStateFree(void *s)
{
    SCEnter();
    if (s) {
        ENIPState *enip_state = (ENIPState *) s;

        ENIPTransaction *tx = NULL;
        while ((tx = TAILQ_FIRST(&enip_state->tx_list))) {
            TAILQ_REMOVE(&enip_state->tx_list, tx, next);
            ENIPTransactionFree(tx, enip_state);
        }

        if (enip_state->buffer != NULL) {
            ENIPDecrMemcap(0xffff, enip_state); /** TODO update if/once we alloc
                                               *  in a smarter way */
            SCFree(enip_state->buffer);
        }

        BUG_ON(enip_state->tx_with_detect_state_cnt > 0);

        ENIPDecrMemcap(sizeof(ENIPState), enip_state);
        BUG_ON(enip_state->memuse > 0);
        SCFree(s);
    }
    SCReturn;
}




/** \internal
 *  \brief Allocate a ENIP TX
 *  \retval tx or NULL */
static ENIPTransaction *ENIPTransactionAlloc(ENIPState *state, const uint16_t tx_id)
{

    if (ENIPCheckMemcap(sizeof(ENIPTransaction), state) < 0)
        return NULL;

    ENIPTransaction *tx = SCMalloc(sizeof(ENIPTransaction));
    if (unlikely(tx == NULL))
        return NULL;

    ENIPIncrMemcap(sizeof(ENIPTransaction), state);

    memset(tx, 0x00, sizeof(ENIPTransaction));

 //   TAILQ_INIT(&tx->query_list);
 //   TAILQ_INIT(&tx->answer_list);
 //   TAILQ_INIT(&tx->authority_list);

    tx->tx_id = tx_id;
    return tx;

}



/**
 *  \brief enip transaction cleanup callback
 */
void ENIPStateTransactionFree(void *state, uint64_t tx_id)
{
    SCEnter();

    ENIPState *enip_state = state;
    ENIPTransaction *tx = NULL;

    SCLogDebug("state %p, id %"PRIu64, enip_state, tx_id);

    TAILQ_FOREACH(tx, &enip_state->tx_list, next) {
        SCLogDebug("tx %p tx->tx_num %u, tx_id %"PRIu64, tx, tx->tx_num, (tx_id+1));
        if ((tx_id+1) < tx->tx_num)
            break;
        else if ((tx_id+1) > tx->tx_num)
            continue;

        if (tx == enip_state->curr)
            enip_state->curr = NULL;

        if (tx->decoder_events != NULL) {
            if (tx->decoder_events->cnt <= enip_state->events)
                enip_state->events -= tx->decoder_events->cnt;
            else
                enip_state->events = 0;
        }

        TAILQ_REMOVE(&enip_state->tx_list, tx, next);
        ENIPTransactionFree(tx, state);
        break;
    }
    SCReturn;
}



int ENIPStateHasTxDetectState(void *alstate)
{
    ENIPState *state = (ENIPState *)alstate;
    return (state->tx_with_detect_state_cnt > 0);
}

DetectEngineState *ENIPGetTxDetectState(void *vtx)
{
    ENIPTransaction *tx = (ENIPTransaction *)vtx;
    return tx->de_state;
}

int ENIPSetTxDetectState(void *alstate, void *vtx, DetectEngineState *s)
{
    ENIPState *state = (ENIPState *)alstate;
    ENIPTransaction *tx = (ENIPTransaction *)vtx;
    state->tx_with_detect_state_cnt++;
    tx->de_state = s;
    return 0;
}


AppLayerDecoderEvents *ENIPGetEvents(void *state, uint64_t id)
{
    ENIPState *enip_state = (ENIPState *)state;
    ENIPTransaction *tx;

    if (enip_state->curr && enip_state->curr->tx_num == (id + 1)) {
        return enip_state->curr->decoder_events;
    }

    TAILQ_FOREACH(tx, &enip_state->tx_list, next) {
        if (tx->tx_num == (id+1))
            return tx->decoder_events;
    }
    return NULL;
}

int ENIPHasEvents(void *state)
{
    ENIPState *enip_state = (ENIPState *)state;
    return (enip_state->events > 0);
}



/** \internal
 *
 * \brief This function is called to retrieve a ENIP
 *
 * \param state     ENIP state structure for the parser
 * \param input     Input line of the command
 * \param input_len Length of the request
 *
 * \retval 1 when the command is parsed, 0 otherwise
 */
static int ENIPParse(Flow *f, void *state,
                              AppLayerParserState *pstate,
                              uint8_t *input, uint32_t input_len,
                              void *local_data)
{
    SCEnter();
    ENIPState         *enip = (ENIPState *) state;
    ENIPTransaction   *tx;

    if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
           SCReturnInt(1);
       } else if (input == NULL || input_len == 0) {
           SCReturnInt(-1);
       }

    printf("ENIPParse input_len %d\n", input_len);


    while (input_len > 0) {
            uint32_t    adu_len = input_len;
            uint8_t     *adu = input;

/*
            if (ModbusParseHeader(modbus, &header, adu, adu_len))
                SCReturnInt(0);

            adu_len = (uint32_t) sizeof(ModbusHeader) + (uint32_t) header.length - 1;
            if (adu_len > input_len)
                SCReturnInt(0);
*/
            /* Allocate a Transaction Context and add it to Transaction list */
            //printf("ENIPParse alloc tx\n");
            tx = ENIPTransactionAlloc(enip, 1);


            if (tx == NULL)
                SCReturnInt(0);
            enip->transaction_max++;
 //           ModbusCheckHeader(modbus, &header);

            /* Store Transaction ID & PDU length */
     //       tx->tx_id   = header.transactionId;
     //       tx->length          = header.length;

            /* Extract MODBUS PDU and fill Transaction Context */
 //           ModbusParseRequestPDU(tx, modbus, adu, adu_len);

            /* Update input line and remaining input length of the command */
            input       += adu_len;
            input_len   -= adu_len;
        }

        SCReturnInt(1);
}


static uint16_t ENIPProbingParser(uint8_t     *input,
                                    uint32_t    input_len,
                                    uint32_t    *offset)
{
    printf("ENIPProbingParser len %d\n", input_len);
    if (input_len < sizeof(ENIPEncapHdr)){
        printf("Length too small to be a ENIP header.\n");
        return ALPROTO_UNKNOWN;
    }

    return ALPROTO_ENIP;
}



/**
 * \brief Function to register the ENIP protocol parsers and other functions
 */
void RegisterENIPParsers(void)
{
    SCEnter();
    char *proto_name = "enip";

    printf("RegisterENIPParsers\n");

    if (AppLayerProtoDetectConfProtoDetectionEnabled("udp", proto_name))
    {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_ENIP, proto_name);

        if (RunmodeIsUnittests())
        {
            AppLayerProtoDetectPPRegister(IPPROTO_UDP, "44818", ALPROTO_ENIP,
                    0, sizeof(ENIPEncapHdr), STREAM_TOSERVER, ENIPProbingParser);

        //    AppLayerProtoDetectPPRegister(IPPROTO_TCP, "44818", ALPROTO_ENIP,
        //            0, sizeof(ENIPEncapHdr), STREAM_TOCLIENT, ENIPProbingParser);

        } else
        {
            printf("RegisterENIPParsers not unit test \n");
            /* if we have no config, we enable the default port 44818 */
            if (!AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP,
                    proto_name, ALPROTO_ENIP, 0, sizeof(ENIPEncapHdr),
                    ENIPProbingParser))
            {
                SCLogWarning(SC_ERR_ENIP_CONFIG, "no ENIP UDP config found, "
                    "enabling ENIP detection on "
                    "port 44818.");

                AppLayerProtoDetectPPRegister(IPPROTO_UDP, "44818",
                        ALPROTO_ENIP, 0, sizeof(ENIPEncapHdr), STREAM_TOSERVER, ENIPProbingParser);
                //    AppLayerProtoDetectPPRegister(IPPROTO_TCP, "44818",
                //            ALPROTO_ENIP, 0, sizeof(ENIPEncapHdr), STREAM_TOCLIENT,
                //            ENIPProbingParser);

            }
        }

    } else
    {
        printf("Protocol detection and parser disabled for %s protocol.",
                proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name))
    {

        printf("RegisterENIPParsers  - AppLayerParserRegisterParser\n");

        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_ENIP, STREAM_TOSERVER, ENIPParse);
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_ENIP, STREAM_TOCLIENT, ENIPParse);

        AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_ENIP, ENIPStateAlloc,
                                          ENIPStateFree);
         AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_ENIP,
                                          ENIPStateTransactionFree);

         AppLayerParserRegisterGetEventsFunc(IPPROTO_UDP, ALPROTO_ENIP, ENIPGetEvents);
         AppLayerParserRegisterHasEventsFunc(IPPROTO_UDP, ALPROTO_ENIP, ENIPHasEvents);
         AppLayerParserRegisterDetectStateFuncs(IPPROTO_UDP, ALPROTO_ENIP,
                                                ENIPStateHasTxDetectState,
                                                ENIPGetTxDetectState, ENIPSetTxDetectState);

         AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_ENIP,
                                     ENIPGetTx);
         AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_ENIP,
                                        ENIPGetTxCnt);
         AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP, ALPROTO_ENIP,
                                                    ENIPGetAlstateProgress);
         AppLayerParserRegisterGetStateProgressCompletionStatus(IPPROTO_UDP, ALPROTO_ENIP,
                                                                ENIPGetAlstateProgressCompletionStatus);

         AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_UDP, ALPROTO_ENIP, STREAM_TOSERVER);
    } else
    {
        SCLogInfo(
                "Parsed disabled for %s protocol. Protocol detection" "still on.",
                proto_name);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_ENIP, ENIPParserRegisterTests);
#endif

    SCReturn;
}

/* UNITTESTS */
#ifdef UNITTESTS
#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"

#include "flow-util.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"




static int ENIPParserTest01(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    int result = 0;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

#endif /* UNITTESTS */

void ENIPParserRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("ENIPParserTest01 -", ENIPParserTest01, 1);

#endif /* UNITTESTS */
}
