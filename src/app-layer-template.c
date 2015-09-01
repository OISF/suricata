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

/**
 * \file Template application layer detector and parser for learning and
 * template pruposes.
 *
 * This template implements a simple application layer for something
 * like the echo protocol running on port 7.
 */

#include "suricata-common.h"
#include "stream.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-template.h"

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define TEMPLATE_DEFAULT_PORT "7"

/* The minimum size for an echo message. For some protocols this might
 * be the size of a header. */
#define TEMPLATE_MIN_FRAME_LEN 1

static TemplateTransaction *TemplateTxAlloc(TemplateState *echo)
{
    TemplateTransaction *tx = SCCalloc(1, sizeof(TemplateTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    /* Increment the states transaction count before assigning the
     * transaction ID. This means the lowest transaction ID will be 1
     * instead of 0.
     *
     * VictorJ: Why? - Other protocols do this, but it doesn't seem
     *    required?
     */
    //echo->transaction_max++;

    tx->tx_id = echo->transaction_max;
    echo->transaction_max++;

    TAILQ_INSERT_TAIL(&echo->tx_list, tx, next);

    return tx;
}

static void TemplateTxFree(void *tx)
{
    SCFree(tx);
}

static void *TemplateStateAlloc(void)
{
    SCLogNotice("Allocating template state.");
    TemplateState *state = SCCalloc(1, sizeof(TemplateState));
    if (unlikely(state == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&state->tx_list);
    return state;
}

static void TemplateStateFree(void *state)
{
    SCLogNotice("Freeing template state.");
    SCFree(state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the TemplateState object.
 * \param tx_id the transaction ID to free.
 */
static void TemplateStateTxFree(void *state, uint64_t tx_id)
{
    TemplateState *echo = state;
    TemplateTransaction *tx = NULL, *ttx;

    SCLogNotice("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &echo->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&echo->tx_list, tx, next);
        TemplateTxFree(tx);
        break;
    }
}

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_TEMPLATE if it looks like echo, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto TemplateProbingParser(uint8_t *input, uint32_t input_len,
    uint32_t *offset)
{
    /* Very simple test - if there is input, this is echo. */
    if (input_len >= TEMPLATE_MIN_FRAME_LEN) {
        SCLogNotice("Detected as ALPROTO_TEMPLATE.");
        return ALPROTO_TEMPLATE;
    }

    SCLogNotice("Protocol not detected as ALPROTO_TEMPLATE.");
    return ALPROTO_UNKNOWN;
}

static int TemplateParseRequest(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    TemplateState *echo = state;

    SCLogNotice("Parsing echo request.");

    /* Normally you would parse out data here and store it in the
     * transcation object, but as this is echo, we'll just record the
     * request data. */

    /* Allocate a transaction. */
    TemplateTransaction *tx = TemplateTxAlloc(echo);
    if (unlikely(tx == NULL)) {
        SCLogNotice("Failed to allocate new Template tx.");
        goto end;
    }
    SCLogNotice("Allocated Template tx %"PRIu64".", tx->tx_id);
    
    /* Make a copy of the request. */
    tx->request_buffer = SCCalloc(1, input_len);
    if (unlikely(tx->request_buffer == NULL)) {
        goto end;
    }
    memcpy(tx->request_buffer, input, input_len);
    tx->request_buffer_len = input_len;

end:    
    return 0;
}

static int TemplateParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    TemplateState *echo = state;
    TemplateTransaction *tx = NULL, *ttx;;
    SCLogNotice("Parsing Template response.");

    /* Look up the existing transaction for this response. In the case
     * of echo, it will be the most recent transaction on the
     * TemplateState object. */

    /* We should just grab the last transaction, but this is to
     * illustrate how you might traverse the transaction list to find
     * the transaction associated with this response. */
    TAILQ_FOREACH(ttx, &echo->tx_list, next) {
        tx = ttx;
    }
    
    if (tx == NULL) {
        SCLogNotice("Failed to find transaction for response on echo state %p.",
            echo);
        goto end;
    }

    SCLogNotice("Found transaction %"PRIu64" for response on echo state %p.",
        tx->tx_id, echo);

    /* Make a copy of the response. */
    tx->response_buffer = SCCalloc(1, input_len);
    if (unlikely(tx->response_buffer == NULL)) {
        goto end;
    }
    memcpy(tx->response_buffer, input, input_len);
    tx->response_buffer_len = input_len;

    tx->response_done = 1;

end:
    return 0;
}

static uint64_t TemplateGetTxCnt(void *state)
{
    TemplateState *echo = state;
    SCLogNotice("Current tx count is %"PRIu64".", echo->transaction_max);
    return echo->transaction_max;
}

static void *TemplateGetTx(void *state, uint64_t tx_id)
{
    TemplateState *echo = state;
    TemplateTransaction *tx;

    SCLogNotice("Requested tx ID %"PRIu64".", tx_id);

    TAILQ_FOREACH(tx, &echo->tx_list, next) {
        if (tx->tx_id == tx_id) {
            SCLogNotice("Transaction %"PRIu64" found, returning tx object %p.",
                tx_id, tx);
            return tx;
        }
    }

    SCLogNotice("Transaction ID %"PRIu64" not found.", tx_id);
    return NULL;
}

/**
 * \brief Called by the application layer.
 *
 * Victor: Please comment on how these relates to GetAlstateProgress.
 */
static int TemplateGetAlstateProgressCompletionStatus(uint8_t direction) {
    if (direction & STREAM_TOCLIENT) {
        SCLogNotice("Direction is TO_CLIENT, returning 2.");
        return 2;
    }
    else {
        SCLogNotice("Direction is TO_SERVER, returning 1.");
        return 1;
    }
}

static int TemplateGetStateProgress(void *tx, uint8_t direction)
{
    TemplateTransaction *echotx = tx;

    SCLogNotice("Transaction progress requested for tx ID %"PRIu64
        ", direction=0x%02x", echotx->tx_id, direction);

    if (direction & STREAM_TOCLIENT) {
        if (echotx->response_done) {
            SCLogNotice("Response is done, returning 2.");
            return 2;
        }
        else {
            /* Victor: Should this return 1 or 0? */
            SCLogNotice("Response is not yet done, returning 0.");
            return 0;
        }
    }
    else {
        /* For echo, just the existence of the transaction means the
         * request is done. */
        SCLogNotice("Request is done, returning 1.");
        return 1;
    }

    return 0;
}

/**
 * \brief ???
 */
static DetectEngineState *TemplateGetTxDetectState(void *vtx)
{
    TemplateTransaction *tx = vtx;
    return tx->de_state;
}

/**
 * \brief ???
 */
static int TemplateSetTxDetectState(void *state, void *vtx,
    DetectEngineState *s)
{
    TemplateTransaction *tx = vtx;
    tx->de_state = s;
    return 0;
}

int TemplateHasEvents(void *state)
{
    TemplateState *echo = state;
    return echo->events;
}

void RegisterTemplateParsers(void)
{
    char *proto_name = "template";

    /* Check if Template TCP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {

        SCLogNotice("Template TCP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_TEMPLATE, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogNotice("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, TEMPLATE_DEFAULT_PORT,
                ALPROTO_TEMPLATE, 0, TEMPLATE_MIN_FRAME_LEN, STREAM_TOSERVER,
                TemplateProbingParser);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_TEMPLATE, 0, TEMPLATE_MIN_FRAME_LEN,
                    TemplateProbingParser)) {
                SCLogNotice("No echo app-layer configuration, enabling echo"
                    " detection TCP detection on port %s.", TEMPLATE_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP, TEMPLATE_DEFAULT_PORT,
                    ALPROTO_TEMPLATE, 0, TEMPLATE_MIN_FRAME_LEN, STREAM_TOSERVER,
                    TemplateProbingParser);
            }

        }

    }

    else {
        SCLogNotice("Protocol detecter and parser disabled for Template.");
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name)) {

        SCLogNotice("Registering Template protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new Template flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_TEMPLATE,
            TemplateStateAlloc, TemplateStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TEMPLATE,
            STREAM_TOSERVER, TemplateParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TEMPLATE, STREAM_TOCLIENT,
            TemplateParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_TEMPLATE,
            TemplateStateTxFree);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_TEMPLATE, TemplateGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(IPPROTO_TCP,
            ALPROTO_TEMPLATE, TemplateGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_TEMPLATE, TemplateGetTx);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_TEMPLATE,
            TemplateGetStateProgress);

        /* Application layer event handling. */
        AppLayerParserRegisterHasEventsFunc(IPPROTO_TCP, ALPROTO_TEMPLATE,
            TemplateHasEvents);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_TEMPLATE,
            NULL, TemplateGetTxDetectState, TemplateSetTxDetectState);

#if 0
        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_DNP3,
            DNP3GetEvents);


        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_DNP3,
            DNP3StateGetEventInfo);
#endif
        
    }
    else {
        SCLogNotice("Template protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_TEMPLATE,
        TemplateParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void TemplateParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
