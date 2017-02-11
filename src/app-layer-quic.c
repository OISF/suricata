/* Copyright (C) 2015 Open Information Security Foundation
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

/*
 * TODO: Update \author in this file and app-layer-quic.h.
 * TODO: Implement your app-layer logic with unit tests.
 * TODO: Remove SCLogDebug statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * quic application layer detector and parser for learning and
 * quic pruposes.
 *
 * This quic implements a simple application layer for something
 * like the echo protocol running on port 7.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-quic.h"

struct _QuicParserState;
typedef struct _QuicParserState QuicParserState;

extern QuicParserState *r_quic_state_new(void);
extern void r_quic_state_free(QuicParserState *);
extern uint32_t r_quic_probe(uint8_t *input, uint32_t input_len, uint32_t *offset);
extern uint32_t r_quic_parse(uint8_t direction, const unsigned char* value, uint32_t len, QuicParserState*state) __attribute__((warn_unused_result));

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define QUIC_DEFAULT_PORT "443"

/* The minimum size for an echo message. For some protocols this might
 * be the size of a header. */
#define QUIC_MIN_FRAME_LEN 1

/* Enum of app-layer events for an echo protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For echo we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert quic any any -> any any (msg:"SURICATA quic empty message"; \
 *    app-layer-event:quic.empty_message; sid:X; rev:Y;)
 */
enum {
    QUIC_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap quic_decoder_event_table[] = {
    {"EMPTY_MESSAGE", QUIC_DECODER_EVENT_EMPTY_MESSAGE},
};
#if 0
static quicTransaction *quicTxAlloc(quicState *echo)
{
    quicTransaction *tx = SCCalloc(1, sizeof(quicTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = echo->transaction_max++;

    TAILQ_INSERT_TAIL(&echo->tx_list, tx, next);

    return tx;
}
#endif
static void quicTxFree(void *tx)
{
    quicTransaction *quictx = tx;

    if (quictx->request_buffer != NULL) {
        SCFree(quictx->request_buffer);
    }

    if (quictx->response_buffer != NULL) {
        SCFree(quictx->response_buffer);
    }

    AppLayerDecoderEventsFreeEvents(&quictx->decoder_events);

    SCFree(tx);
}

static void *quicStateAlloc(void)
{
//    SCLogNotice("Allocating quic state.");
    return r_quic_state_new();
}

static void quicStateFree(void *state)
{
//    SCLogNotice("Freeing quic state.");
    r_quic_state_free(state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the quicState object.
 * \param tx_id the transaction ID to free.
 */
static void quicStateTxFree(void *state, uint64_t tx_id)
{
    quicState *echo = state;
    quicTransaction *tx = NULL, *ttx;

    SCLogDebug("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &echo->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&echo->tx_list, tx, next);
        quicTxFree(tx);
        return;
    }

    SCLogDebug("Transaction %"PRIu64" not found.", tx_id);
}

static int quicStateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, quic_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "quic enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static AppLayerDecoderEvents *quicGetEvents(void *state, uint64_t tx_id)
{
    quicState *quic_state = state;
    quicTransaction *tx;

    TAILQ_FOREACH(tx, &quic_state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            return tx->decoder_events;
        }
    }

    return NULL;
}

static int quicHasEvents(void *state)
{
    quicState *echo = state;
    return echo->events;
}

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_QUIC if it looks like echo, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto quicProbingParser(uint8_t *input, uint32_t input_len,
    uint32_t *offset)
{
    int r = r_quic_probe(input, input_len, NULL);
    if (r == TRUE) {
//        SCLogNotice("Detected as ALPROTO_QUIC.");
        return ALPROTO_QUIC;
    }

//    SCLogNotice("Protocol not detected as ALPROTO_QUIC: r_quic_probe %d", r);
    return ALPROTO_FAILED;
}

static int quicParseRequest(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    int r = r_quic_parse(0, input, input_len, state);
//    SCLogNotice("r_quic_parse returned %d", r);
    return r;
}

static int quicParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    int r = r_quic_parse(1, input, input_len, state);
//    SCLogNotice("r_quic_parse returned %d", r);
    return r;
}

static uint64_t quicGetTxCnt(void *state)
{
    return 0;
}

static void *quicGetTx(void *state, uint64_t tx_id)
{
    return NULL;
}

static void quicSetTxLogged(void *state, void *vtx, uint32_t logger)
{
}

static int quicGetTxLogged(void *state, void *vtx, uint32_t logger)
{
    return 0;
}

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int quicGetAlstateProgressCompletionStatus(uint8_t direction) {
    return 1;
}

/**
 * \brief Return the state of a transaction in a given direction.
 *
 * In the case of the echo protocol, the existence of a transaction
 * means that the request is done. However, some protocols that may
 * need multiple chunks of data to complete the request may need more
 * than just the existence of a transaction for the request to be
 * considered complete.
 *
 * For the response to be considered done, the response for a request
 * needs to be seen.  The response_done flag is set on response for
 * checking here.
 */
static int quicGetStateProgress(void *tx, uint8_t direction)
{
    return 0;
}

/**
 * \brief ???
 */
static DetectEngineState *quicGetTxDetectState(void *vtx)
{
    return NULL;
}

/**
 * \brief ???
 */
static int quicSetTxDetectState(void *state, void *vtx,
    DetectEngineState *s)
{
    return 0;
}

void RegisterquicParsers(void)
{
    char *proto_name = "quic";

    /* Check if quic UDP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("udp", proto_name)) {

        SCLogDebug("quic UDP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_QUIC, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogDebug("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_UDP, QUIC_DEFAULT_PORT,
                ALPROTO_QUIC, 0, QUIC_MIN_FRAME_LEN, STREAM_TOSERVER,
                quicProbingParser, quicProbingParser);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP,
                    proto_name, ALPROTO_QUIC, 0, QUIC_MIN_FRAME_LEN,
                    quicProbingParser, NULL)) {
                SCLogDebug("No echo app-layer configuration, enabling echo"
                    " detection UDP detection on port %s.",
                    QUIC_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_UDP,
                    QUIC_DEFAULT_PORT, ALPROTO_QUIC, 0,
                    QUIC_MIN_FRAME_LEN, STREAM_TOSERVER,
                    quicProbingParser, quicProbingParser);
            }

        }

    }

    else {
        SCLogDebug("Protocol detecter and parser disabled for quic.");
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name)) {

        SCLogDebug("Registering quic protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new quic flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_QUIC,
            quicStateAlloc, quicStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_QUIC,
            STREAM_TOSERVER, quicParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_QUIC,
            STREAM_TOCLIENT, quicParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_QUIC,
            quicStateTxFree);

        AppLayerParserRegisterLoggerFuncs(IPPROTO_UDP, ALPROTO_QUIC,
            quicGetTxLogged, quicSetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_QUIC,
            quicGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_QUIC,
            quicGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP,
            ALPROTO_QUIC, quicGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_QUIC,
            quicGetTx);

        /* Application layer event handling. */
        AppLayerParserRegisterHasEventsFunc(IPPROTO_UDP, ALPROTO_QUIC,
            quicHasEvents);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_UDP, ALPROTO_QUIC,
            NULL, quicGetTxDetectState, quicSetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_UDP, ALPROTO_QUIC,
            quicStateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_UDP, ALPROTO_QUIC,
            quicGetEvents);
    }
    else {
        SCLogDebug("quic protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_UDP, ALPROTO_QUIC,
        quicParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void quicParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
