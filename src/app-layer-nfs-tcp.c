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
 * NFS application layer detector and parser.
 *
 * This implements a application layer for the NFS protocol
 * running on port 2049.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-nfs-tcp.h"

#ifndef HAVE_RUST
void RegisterNFSTCPParsers(void)
{
}

#else

#include "rust.h"
#include "rust-nfs-nfs-gen.h"

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define NFSTCP_DEFAULT_PORT "2049"

/* The minimum size for a RFC message. For some protocols this might
 * be the size of a header. TODO actual min size is likely larger */
#define NFSTCP_MIN_FRAME_LEN 32

/* Enum of app-layer events for an echo protocol. Normally you might
 * have events for errors in parsing data, like unexpected data being
 * received. For echo we'll make something up, and log an app-layer
 * level alert if an empty message is received.
 *
 * Example rule:
 *
 * alert nfs any any -> any any (msg:"SURICATA NFS empty message"; \
 *    app-layer-event:nfs.empty_message; sid:X; rev:Y;)
 */
enum {
    NFSTCP_DECODER_EVENT_EMPTY_MESSAGE,
};

SCEnumCharMap nfs_decoder_event_table[] = {
    {"EMPTY_MESSAGE", NFSTCP_DECODER_EVENT_EMPTY_MESSAGE},
    { NULL, 0 }
};

static void *NFSTCPStateAlloc(void)
{
    return rs_nfs_state_new();
}

static void NFSTCPStateFree(void *state)
{
    rs_nfs_state_free(state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the NFSTCPState object.
 * \param tx_id the transaction ID to free.
 */
static void NFSTCPStateTxFree(void *state, uint64_t tx_id)
{
    rs_nfs_state_tx_free(state, tx_id);
}

static int NFSTCPStateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    return rs_nfs_state_get_event_info(event_name, event_id, event_type);
}

static int NFSTCPStateGetEventInfoById(int event_id, const char **event_name,
    AppLayerEventType *event_type)
{
    return rs_nfs_state_get_event_info_by_id(event_id, event_name, event_type);
}

static AppLayerDecoderEvents *NFSTCPGetEvents(void *tx)
{
    return rs_nfs_state_get_events(tx);
}

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_NFS if it looks like echo, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto NFSTCPProbingParserMidstream(Flow *f,
        uint8_t direction,
        uint8_t *input, uint32_t input_len,
        uint8_t *rdir)
{
    if (input_len < NFSTCP_MIN_FRAME_LEN) {
        return ALPROTO_UNKNOWN;
    }

    int8_t r = rs_nfs_probe_ms(direction, input, input_len, rdir);
    if (r == 1) {
        return ALPROTO_NFS;
    } else if (r == -1) {
        return ALPROTO_FAILED;
    }

    SCLogDebug("Protocol not detected as ALPROTO_NFS.");
    return ALPROTO_UNKNOWN;
}

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_NFS if it looks like echo, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto NFSTCPProbingParser(Flow *f,
        uint8_t direction,
        uint8_t *input, uint32_t input_len,
        uint8_t *rdir)
{
    if (input_len < NFSTCP_MIN_FRAME_LEN) {
        return ALPROTO_UNKNOWN;
    }

    int8_t r = rs_nfs_probe(direction, input, input_len);
    if (r == 1) {
        return ALPROTO_NFS;
    } else if (r == -1) {
        return ALPROTO_FAILED;
    }

    SCLogDebug("Protocol not detected as ALPROTO_NFS.");
    return ALPROTO_UNKNOWN;
}

static int NFSTCPParseRequest(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data, const uint8_t flags)
{
    uint16_t file_flags = FileFlowToFlags(f, STREAM_TOSERVER);
    rs_nfs_setfileflags(0, state, file_flags);

    int res;
    if (input == NULL && input_len > 0) {
        res = rs_nfs_parse_request_tcp_gap(state, input_len);
    } else {
        res = rs_nfs_parse_request(f, state, pstate, input, input_len, local_data);
    }
    return res;
}

static int NFSTCPParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data,
    const uint8_t flags)
{
    uint16_t file_flags = FileFlowToFlags(f, STREAM_TOCLIENT);
    rs_nfs_setfileflags(1, state, file_flags);

    int res;
    if (input == NULL && input_len > 0) {
        res = rs_nfs_parse_response_tcp_gap(state, input_len);
    } else {
        res = rs_nfs_parse_response(f, state, pstate, input, input_len, local_data);
    }
    return res;
}

static uint64_t NFSTCPGetTxCnt(void *state)
{
    return rs_nfs_state_get_tx_count(state);
}

static void *NFSTCPGetTx(void *state, uint64_t tx_id)
{
    return rs_nfs_state_get_tx(state, tx_id);
}

static AppLayerGetTxIterTuple RustNFSTCPGetTxIterator(
        const uint8_t ipproto, const AppProto alproto,
        void *alstate, uint64_t min_tx_id, uint64_t max_tx_id,
        AppLayerGetTxIterState *istate)
{
    return rs_nfs_state_get_tx_iterator(alstate, min_tx_id, (uint64_t *)istate);
}

static void NFSTCPSetTxLogged(void *state, void *vtx, LoggerId logged)
{
    rs_nfs_tx_set_logged(state, vtx, logged);
}

static LoggerId NFSTCPGetTxLogged(void *state, void *vtx)
{
    return rs_nfs_tx_get_logged(state, vtx);
}

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int NFSTCPGetAlstateProgressCompletionStatus(uint8_t direction) {
    return rs_nfs_state_progress_completion_status(direction);
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
static int NFSTCPGetStateProgress(void *tx, uint8_t direction)
{
    return rs_nfs_tx_get_alstate_progress(tx, direction);
}

/**
 * \brief get stored tx detect state
 */
static DetectEngineState *NFSTCPGetTxDetectState(void *vtx)
{
    return rs_nfs_state_get_tx_detect_state(vtx);
}

/**
 * \brief set store tx detect state
 */
static int NFSTCPSetTxDetectState(void *vtx, DetectEngineState *s)
{
    rs_nfs_state_set_tx_detect_state(vtx, s);
    return 0;
}

static FileContainer *NFSTCPGetFiles(void *state, uint8_t direction)
{
    return rs_nfs_getfiles(direction, state);
}

static void NFSTCPSetDetectFlags(void *tx, uint8_t dir, uint64_t flags)
{
    rs_nfs_tx_set_detect_flags(tx, dir, flags);
}

static uint64_t NFSTCPGetDetectFlags(void *tx, uint8_t dir)
{
    return rs_nfs_tx_get_detect_flags(tx, dir);
}

static StreamingBufferConfig sbcfg = STREAMING_BUFFER_CONFIG_INITIALIZER;
static SuricataFileContext sfc = { &sbcfg };

void RegisterNFSTCPParsers(void)
{
    const char *proto_name = "nfs";

    /* Check if NFSTCP TCP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {

        rs_nfs_init(&sfc);

        SCLogDebug("NFSTCP TCP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_NFS, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogDebug("Unittest mode, registering default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, NFSTCP_DEFAULT_PORT,
                ALPROTO_NFS, 0, NFSTCP_MIN_FRAME_LEN, STREAM_TOSERVER,
                NFSTCPProbingParser, NFSTCPProbingParser);

        }
        else {
            int midstream = 0;
            ConfGetBool("stream.midstream", &midstream);
            ProbingParserFPtr FuncPtr = NFSTCPProbingParser;
            if (midstream)
                FuncPtr = NFSTCPProbingParserMidstream;

            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_NFS, 0, NFSTCP_MIN_FRAME_LEN,
                    FuncPtr, FuncPtr)) {
                SCLogDebug("No NFSTCP app-layer configuration, enabling NFSTCP"
                    " detection TCP detection on port %s.",
                    NFSTCP_DEFAULT_PORT);
                /* register 'midstream' probing parsers if midstream is enabled. */
                AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                    NFSTCP_DEFAULT_PORT, ALPROTO_NFS, 0,
                    NFSTCP_MIN_FRAME_LEN, STREAM_TOSERVER,
                    FuncPtr, FuncPtr);
            }

        }

    }

    else {
        SCLogDebug("Protocol detecter and parser disabled for NFSTCP.");
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name))
    {
        SCLogDebug("Registering NFSTCP protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new NFSTCP flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_NFS,
            NFSTCPStateAlloc, NFSTCPStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_NFS,
            STREAM_TOSERVER, NFSTCPParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_NFS,
            STREAM_TOCLIENT, NFSTCPParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_NFS,
            NFSTCPStateTxFree);

        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_NFS,
            NFSTCPGetTxLogged, NFSTCPSetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_NFS,
            NFSTCPGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_NFS,
            NFSTCPGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP,
            ALPROTO_NFS, NFSTCPGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_NFS,
            NFSTCPGetTx);
        AppLayerParserRegisterGetTxIterator(IPPROTO_TCP, ALPROTO_NFS,
                RustNFSTCPGetTxIterator);

        AppLayerParserRegisterGetFilesFunc(IPPROTO_TCP, ALPROTO_NFS, NFSTCPGetFiles);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_NFS,
            NFSTCPGetTxDetectState, NFSTCPSetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_NFS,
                NFSTCPStateGetEventInfo);

        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_NFS,
                NFSTCPStateGetEventInfoById);

        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_NFS,
                NFSTCPGetEvents);

        AppLayerParserRegisterDetectFlagsFuncs(IPPROTO_TCP, ALPROTO_NFS,
                                               NFSTCPGetDetectFlags, NFSTCPSetDetectFlags);

        /* This parser accepts gaps. */
        AppLayerParserRegisterOptionFlags(IPPROTO_TCP, ALPROTO_NFS,
                APP_LAYER_PARSER_OPT_ACCEPT_GAPS);
    }
    else {
        SCLogDebug("NFSTCP protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_NFS,
        NFSTCPParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void NFSTCPParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}

#endif /* HAVE_RUST */
