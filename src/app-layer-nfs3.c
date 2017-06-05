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
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * NFS3 application layer detector and parser for learning and
 * nfs3 pruposes.
 *
 * This nfs3 implements a simple application layer for something
 * like the NFS3 protocol running on port 2049.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-nfs3.h"

#ifndef HAVE_RUST
void RegisterNFS3Parsers(void)
{
}

#else

#include "rust.h"
#include "rust-nfs-nfs3-gen.h"

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define NFS3_DEFAULT_PORT "2049"

/* The minimum size for a RFC message. For some protocols this might
 * be the size of a header. TODO actual min size is likely larger */
#define NFS3_MIN_FRAME_LEN 32

/* Enum of app-layer events for an echo protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For echo we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert nfs3 any any -> any any (msg:"SURICATA NFS3 empty message"; \
 *    app-layer-event:nfs3.empty_message; sid:X; rev:Y;)
 */
enum {
    NFS3_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap nfs3_decoder_event_table[] = {
    {"EMPTY_MESSAGE", NFS3_DECODER_EVENT_EMPTY_MESSAGE},
    { NULL, 0 }
};

static void *NFS3StateAlloc(void)
{
    return rs_nfs3_state_new();
}

static void NFS3StateFree(void *state)
{
    rs_nfs3_state_free(state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the NFS3State object.
 * \param tx_id the transaction ID to free.
 */
static void NFS3StateTxFree(void *state, uint64_t tx_id)
{
    rs_nfs3_state_tx_free(state, tx_id);
}

#if 0
static int NFS3StateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, nfs3_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "nfs3 enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static AppLayerDecoderEvents *NFS3GetEvents(void *state, uint64_t tx_id)
{
    NFS3State *nfs3_state = state;
    NFS3Transaction *tx;

    TAILQ_FOREACH(tx, &nfs3_state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            return tx->decoder_events;
        }
    }

    return NULL;
}

static int NFS3HasEvents(void *state)
{
    NFS3State *echo = state;
    return echo->events;
}
#endif

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_NFS3 if it looks like echo, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto NFS3ProbingParser(uint8_t *input, uint32_t input_len,
    uint32_t *offset)
{
    if (input_len < NFS3_MIN_FRAME_LEN) {
        return ALPROTO_UNKNOWN;
    }

    int8_t r = rs_nfs_probe(input, input_len);
    if (r == 1) {
        return ALPROTO_NFS3;
    } else if (r == -1) {
        return ALPROTO_FAILED;
    }

    SCLogDebug("Protocol not detected as ALPROTO_NFS3.");
    return ALPROTO_UNKNOWN;
}

static int NFS3ParseRequest(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    uint16_t file_flags = FileFlowToFlags(f, STREAM_TOSERVER);
    rs_nfs3_setfileflags(0, state, file_flags);

    return rs_nfs3_parse_request(f, state, pstate, input, input_len, local_data);
}

static int NFS3ParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    uint16_t file_flags = FileFlowToFlags(f, STREAM_TOCLIENT);
    rs_nfs3_setfileflags(1, state, file_flags);

    return rs_nfs3_parse_response(f, state, pstate, input, input_len, local_data);
}

static uint64_t NFS3GetTxCnt(void *state)
{
    return rs_nfs3_state_get_tx_count(state);
}

static void *NFS3GetTx(void *state, uint64_t tx_id)
{
    return rs_nfs3_state_get_tx(state, tx_id);
}

static void NFS3SetTxLogged(void *state, void *vtx, uint32_t logger)
{
    rs_nfs3_tx_set_logged(state, vtx, logger);
}

static int NFS3GetTxLogged(void *state, void *vtx, uint32_t logger)
{
    return rs_nfs3_tx_get_logged(state, vtx, logger);
}

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int NFS3GetAlstateProgressCompletionStatus(uint8_t direction) {
    return rs_nfs3_state_progress_completion_status(direction);
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
static int NFS3GetStateProgress(void *tx, uint8_t direction)
{
    return rs_nfs3_tx_get_alstate_progress(tx, direction);
}

/**
 * \brief get stored tx detect state
 */
static DetectEngineState *NFS3GetTxDetectState(void *vtx)
{
    return rs_nfs3_state_get_tx_detect_state(vtx);
}

/**
 * \brief set store tx detect state
 */
static int NFS3SetTxDetectState(void *state, void *vtx,
    DetectEngineState *s)
{
    rs_nfs3_state_set_tx_detect_state(state, vtx, s);
    return 0;
}

static FileContainer *NFS3GetFiles(void *state, uint8_t direction)
{
    return rs_nfs3_getfiles(direction, state);
}

static StreamingBufferConfig sbcfg = STREAMING_BUFFER_CONFIG_INITIALIZER;
static SuricataFileContext sfc = { &sbcfg };

void RegisterNFS3Parsers(void)
{
    const char *proto_name = "nfs3";

    /* Check if NFS3 TCP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {

        rs_nfs3_init(&sfc);

        SCLogDebug("NFS3 TCP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_NFS3, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogDebug("Unittest mode, registering default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, NFS3_DEFAULT_PORT,
                ALPROTO_NFS3, 0, NFS3_MIN_FRAME_LEN, STREAM_TOSERVER,
                NFS3ProbingParser, NULL);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_NFS3, 0, NFS3_MIN_FRAME_LEN,
                    NFS3ProbingParser, NULL)) {
                SCLogDebug("No NFS3 app-layer configuration, enabling NFS3"
                    " detection TCP detection on port %s.",
                    NFS3_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                    NFS3_DEFAULT_PORT, ALPROTO_NFS3, 0,
                    NFS3_MIN_FRAME_LEN, STREAM_TOSERVER,
                    NFS3ProbingParser, NULL);
            }

        }

    }

    else {
        SCLogDebug("Protocol detecter and parser disabled for NFS3.");
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name))
    {
        SCLogDebug("Registering NFS3 protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new NFS3 flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_NFS3,
            NFS3StateAlloc, NFS3StateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_NFS3,
            STREAM_TOSERVER, NFS3ParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_NFS3,
            STREAM_TOCLIENT, NFS3ParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_NFS3,
            NFS3StateTxFree);

        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_NFS3,
            NFS3GetTxLogged, NFS3SetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_NFS3,
            NFS3GetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_NFS3,
            NFS3GetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP,
            ALPROTO_NFS3, NFS3GetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_NFS3,
            NFS3GetTx);

        AppLayerParserRegisterGetFilesFunc(IPPROTO_TCP, ALPROTO_NFS3, NFS3GetFiles);

        /* Application layer event handling. */
//        AppLayerParserRegisterHasEventsFunc(IPPROTO_TCP, ALPROTO_NFS3,
//            NFS3HasEvents);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_NFS3,
            NULL, NFS3GetTxDetectState, NFS3SetTxDetectState);

//        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_NFS3,
//            NFS3StateGetEventInfo);
//        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_NFS3,
//            NFS3GetEvents);
    }
    else {
        SCLogDebug("NFS3 protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_NFS3,
        NFS3ParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void NFS3ParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}

#endif /* HAVE_RUST */
