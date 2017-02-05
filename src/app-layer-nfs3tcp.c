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
 * TODO: Update \author in this file and app-layer-nfs3tcp.h.
 * TODO: Implement your app-layer logic with unit tests.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Nfs3Tcp application layer detector and parser for learning and
 * nfs3tcp pruposes.
 *
 * This nfs3tcp implements a simple application layer for something
 * like the echo protocol running on port 7.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-nfs3tcp.h"

#include "util-file.h"

#include "util-print.h"
#include "util-byte.h"

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define NFS3TCP_DEFAULT_PORT "2049"

/* The minimum size for an echo message. For some protocols this might
 * be the size of a header. */
#define NFS3TCP_MIN_FRAME_LEN 10

static StreamingBufferConfig sbcfg = STREAMING_BUFFER_CONFIG_INITIALIZER;

struct NfsRustConfig {
    uint32_t magic;
    const StreamingBufferConfig *sbcfg;
    uint32_t magic2;
    File *(*FileOpenFile)(FileContainer *, const StreamingBufferConfig *,
        const uint8_t *name, uint16_t name_len,
        const uint8_t *data, uint32_t data_len, uint16_t flags);
    uint32_t magic3;
    int (*FileCloseFile)(FileContainer *, const uint8_t *data, uint32_t data_len,
            uint16_t flags);
    int (*FileAppendData)(FileContainer *, const uint8_t *data, uint32_t data_len);
    uint32_t magic4;
    void (*FileContainerRecycle)(FileContainer *ffc);
    void (*FilePrune)(FileContainer *ffc);
    uint32_t magic5;
};

static struct NfsRustConfig nfs_rust_config = { 0x1234, &sbcfg, 0x5678,
    FileOpenFile, 0x3333, FileCloseFile, FileAppendData, 0x4444, FileContainerRecycle, FilePrune, 0x1234};

extern int32_t r_nfstcp_init(struct NfsRustConfig *) __attribute__((warn_unused_result));

/* Enum of app-layer events for an echo protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For echo we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert nfs3tcp any any -> any any (msg:"SURICATA Nfs3Tcp empty message"; \
 *    app-layer-event:nfs3tcp.empty_message; sid:X; rev:Y;)
 */
enum {
    NFS3TCP_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap nfs3tcp_decoder_event_table[] = {
    {"EMPTY_MESSAGE", NFS3TCP_DECODER_EVENT_EMPTY_MESSAGE},
};
#if 0
static Nfs3TcpTransaction *Nfs3TcpTxAlloc(Nfs3TcpState *echo)
{
#if 0
    Nfs3TcpTransaction *tx = SCCalloc(1, sizeof(Nfs3TcpTransaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }

    /* Increment the transaction ID on the state each time one is
     * allocated. */
    tx->tx_id = echo->transaction_max++;

    TAILQ_INSERT_TAIL(&echo->tx_list, tx, next);

    return tx;
#endif
    return NULL;
}
static void Nfs3TcpTxFree(void *tx)
{
#if 0
    Nfs3TcpTransaction *nfs3tcptx = tx;

    if (nfs3tcptx->request_buffer != NULL) {
        SCFree(nfs3tcptx->request_buffer);
    }

    if (nfs3tcptx->response_buffer != NULL) {
        SCFree(nfs3tcptx->response_buffer);
    }

    AppLayerDecoderEventsFreeEvents(&nfs3tcptx->decoder_events);

    SCFree(tx);
#endif
}
#endif

static void *Nfs3TcpStateAlloc(void)
{
    SCLogDebug("Allocating nfs3tcp state.");
    void *state = r_nfstcp_state_new();
    return state;
}

static void Nfs3TcpStateFree(void *state)
{
    SCLogDebug("Freeing nfs3tcp state.");
    r_nfstcp_state_free(state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the Nfs3TcpState object.
 * \param tx_id the transaction ID to free.
 */
static void Nfs3TcpStateTxFree(void *state, uint64_t tx_id)
{
#if 0
    Nfs3TcpState *echo = state;
    Nfs3TcpTransaction *tx = NULL, *ttx;

    SCLogNotice("Freeing transaction %"PRIu64, tx_id);

    TAILQ_FOREACH_SAFE(tx, &echo->tx_list, next, ttx) {

        /* Continue if this is not the transaction we are looking
         * for. */
        if (tx->tx_id != tx_id) {
            continue;
        }

        /* Remove and free the transaction. */
        TAILQ_REMOVE(&echo->tx_list, tx, next);
        Nfs3TcpTxFree(tx);
        return;
    }

    SCLogNotice("Transaction %"PRIu64" not found.", tx_id);
#endif
}

static int Nfs3TcpStateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
#if 0
    *event_id = SCMapEnumNameToValue(event_name, nfs3tcp_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "nfs3tcp enum map table.",  event_name);
        /* This should be treated as fatal. */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;
#endif
    return 0;
}

static AppLayerDecoderEvents *Nfs3TcpGetEvents(void *state, uint64_t tx_id)
{
#if 0
    Nfs3TcpState *nfs3tcp_state = state;
    Nfs3TcpTransaction *tx;

    TAILQ_FOREACH(tx, &nfs3tcp_state->tx_list, next) {
        if (tx->tx_id == tx_id) {
            return tx->decoder_events;
        }
    }
#endif
    return NULL;
}

static int Nfs3TcpHasEvents(void *state)
{
#if 0
    Nfs3TcpState *echo = state;
    return echo->events;
#endif
    return 0;
}

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_NFS3TCP if it looks like echo, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto Nfs3TcpProbingParser(uint8_t *input, uint32_t input_len,
    uint32_t *offset)
{
    if (r_nfstcp_probe(input, input_len, offset) == TRUE) {
        SCLogDebug("Detected as ALPROTO_NFS3TCP.");
        return ALPROTO_NFS3TCP;
    }

    SCLogDebug("Protocol not detected as ALPROTO_NFS3TCP.");
    return ALPROTO_UNKNOWN;
}

static int Nfs3TcpParseRequest(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    uint16_t file_flags = FileFlowToFlags(f, STREAM_TOSERVER);
    r_nfstcp_setfileflags(0, state, file_flags);

    int r = r_nfstcp_parse(0, input, input_len, state);
    SCLogDebug("r %d", r);
    return r;
}

static int Nfs3TcpParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    uint16_t file_flags = FileFlowToFlags(f, STREAM_TOCLIENT);
    r_nfstcp_setfileflags(1, state, file_flags);

    int r = r_nfstcp_parse(1, input, input_len, state);
    SCLogDebug("r %d", r);

    Store *data_store = r_nfstcp_getstore(state);
    BUG_ON(!data_store);
    if (data_store != NULL) {
        //SCLogNotice("data_store %p", data_store);

//        uint8_t *data;
//        uint32_t len;
        uint32_t xid;
#if 0
        if (r_getu32(data_store, 2, &xid) == 1) {
            if (r_getdata_map(data_store, 4, xid, &data, &len) == 1) {
                char *c = BytesToString(data, len);
                if (c != NULL) {
//                    SCLogNotice("host %s XID %u", c, xid);
                    SCFree(c);
                }
            }

            Store *nested_store;
            if (r_getstore(data_store, xid, &nested_store) == 1) {
                SCLogNotice("nested_store %p", nested_store);
                uint32_t procedure;
                if (r_getu32(nested_store, 6, &procedure) == 1) {
                    SCLogNotice("nested_store %p XID %u PROCEDURE %u", nested_store, xid, procedure);
                }

                int res = r_dropstore(data_store, xid);
                SCLogNotice("res %d", res);
            }
        }
#endif
        while (r_popfront_u32(data_store, 7, &xid) == 1) {
            Store *nested_store;
            if (r_getstore(data_store, xid, &nested_store) == 1) {
                uint32_t procedure;
                if (r_getu32(nested_store, 6, &procedure) == 1) {
                    if (procedure == 3) {
                        uint8_t *data;
                        uint32_t len;
                        if (r_getdata(nested_store, 8, &data, &len) == 1) {
                            char *c = BytesToString(data, len);
                            if (c != NULL) {
                                SCLogNotice("NFSv3 LOOKUP %s", c);
                                SCFree(c);
                            }
                        }
                    } else if (procedure == 8) {
                        uint8_t *data;
                        uint32_t len;
                        if (r_getdata(nested_store, 9, &data, &len) == 1) {
                            char *c = BytesToString(data, len);
                            if (c != NULL) {
                                SCLogNotice("NFSv3 CREATE %s", c);
                                SCFree(c);
                            }
                        }
                    }
                }

                r_dropstore(data_store, xid);
            }
        }
    }

    return r;
}

static uint64_t Nfs3TcpGetTxCnt(void *state)
{
#if 0
    Nfs3TcpState *echo = state;
    SCLogNotice("Current tx count is %"PRIu64".", echo->transaction_max);
    return echo->transaction_max;
#endif
    return 0;
}

static void *Nfs3TcpGetTx(void *state, uint64_t tx_id)
{
#if 0
    Nfs3TcpState *echo = state;
    Nfs3TcpTransaction *tx;

    SCLogNotice("Requested tx ID %"PRIu64".", tx_id);

    TAILQ_FOREACH(tx, &echo->tx_list, next) {
        if (tx->tx_id == tx_id) {
            SCLogNotice("Transaction %"PRIu64" found, returning tx object %p.",
                tx_id, tx);
            return tx;
        }
    }

    SCLogNotice("Transaction ID %"PRIu64" not found.", tx_id);
#endif
    return NULL;
}

static void Nfs3TcpSetTxLogged(void *state, void *vtx, uint32_t logger)
{
#if 0
    Nfs3TcpTransaction *tx = (Nfs3TcpTransaction *)vtx;
    tx->logged |= logger;
#endif
}

static int Nfs3TcpGetTxLogged(void *state, void *vtx, uint32_t logger)
{
#if 0
    Nfs3TcpTransaction *tx = (Nfs3TcpTransaction *)vtx;
    if (tx->logged & logger)
        return 1;
#endif
    return 0;
}

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int Nfs3TcpGetAlstateProgressCompletionStatus(uint8_t direction) {
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
static int Nfs3TcpGetStateProgress(void *tx, uint8_t direction)
{
#if 0
    Nfs3TcpTransaction *echotx = tx;

    SCLogNotice("Transaction progress requested for tx ID %"PRIu64
        ", direction=0x%02x", echotx->tx_id, direction);

    if (direction & STREAM_TOCLIENT && echotx->response_done) {
        return 1;
    }
    else if (direction & STREAM_TOSERVER) {
        /* For echo, just the existence of the transaction means the
         * request is done. */
        return 1;
    }
#endif
    return 0;
}

/**
 * \brief ???
 */
static DetectEngineState *Nfs3TcpGetTxDetectState(void *vtx)
{
#if 0
    Nfs3TcpTransaction *tx = vtx;
    return tx->de_state;
#endif
    return NULL;
}

/**
 * \brief ???
 */
static int Nfs3TcpSetTxDetectState(void *state, void *vtx,
    DetectEngineState *s)
{
#if 0
    Nfs3TcpTransaction *tx = vtx;
    tx->de_state = s;
#endif
    return 0;
}

static FileContainer *Nfs3TcpGetFiles(void *state, uint8_t direction)
{
    return r_nfstcp_getfiles(direction, state);
}

void RegisterNfs3TcpParsers(void)
{
    char *proto_name = "nfs3tcp";

    int r = r_nfstcp_init(&nfs_rust_config);
    BUG_ON(r);

    /* Check if Nfs3Tcp TCP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {

        SCLogNotice("Nfs3Tcp TCP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_NFS3TCP, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogNotice("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, NFS3TCP_DEFAULT_PORT,
                ALPROTO_NFS3TCP, 0, NFS3TCP_MIN_FRAME_LEN, STREAM_TOSERVER,
                Nfs3TcpProbingParser, NULL);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_NFS3TCP, 0, NFS3TCP_MIN_FRAME_LEN,
                    Nfs3TcpProbingParser, NULL)) {
                SCLogNotice("No echo app-layer configuration, enabling echo"
                    " detection TCP detection on port %s.",
                    NFS3TCP_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                    NFS3TCP_DEFAULT_PORT, ALPROTO_NFS3TCP, 0,
                    NFS3TCP_MIN_FRAME_LEN, STREAM_TOSERVER,
                    Nfs3TcpProbingParser, NULL);
            }

        }

    }

    else {
        SCLogNotice("Protocol detecter and parser disabled for Nfs3Tcp.");
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name)) {

        SCLogNotice("Registering Nfs3Tcp protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new Nfs3Tcp flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_NFS3TCP,
            Nfs3TcpStateAlloc, Nfs3TcpStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_NFS3TCP,
            STREAM_TOSERVER, Nfs3TcpParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_NFS3TCP,
            STREAM_TOCLIENT, Nfs3TcpParseResponse);

        AppLayerParserRegisterGetFilesFunc(IPPROTO_TCP, ALPROTO_NFS3TCP, Nfs3TcpGetFiles);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_NFS3TCP,
            Nfs3TcpStateTxFree);

        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_NFS3TCP,
            Nfs3TcpGetTxLogged, Nfs3TcpSetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_NFS3TCP,
            Nfs3TcpGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_NFS3TCP,
            Nfs3TcpGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP,
            ALPROTO_NFS3TCP, Nfs3TcpGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_NFS3TCP,
            Nfs3TcpGetTx);

        /* Application layer event handling. */
        AppLayerParserRegisterHasEventsFunc(IPPROTO_TCP, ALPROTO_NFS3TCP,
            Nfs3TcpHasEvents);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_NFS3TCP,
            NULL, Nfs3TcpGetTxDetectState, Nfs3TcpSetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_NFS3TCP,
            Nfs3TcpStateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_NFS3TCP,
            Nfs3TcpGetEvents);
    }
    else {
        SCLogNotice("Nfs3Tcp protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_NFS3TCP,
        Nfs3TcpParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void Nfs3TcpParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
