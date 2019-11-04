/* Copyright (C) 2017 Open Information Security Foundation
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
 *
 */

/**
 * \file
 *
 * \author Clément Galland <clement.galland@epita.fr>
 *
 * Parser for NTP application layer running on UDP port 69.
 */


#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util/unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-tftp.h"
#include "rust.h"

/* The default port to probe if not provided in the configuration file. */
#define TFTP_DEFAULT_PORT "69"

/* The minimum size for an message. For some protocols this might
 * be the size of a header. */
#define TFTP_MIN_FRAME_LEN 4

static void *TFTPStateAlloc(void)
{
    return rs_tftp_state_alloc();
}

static void TFTPStateFree(void *state)
{
    rs_tftp_state_free(state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the TFTPState object.
 * \param tx_id the transaction ID to free.
 */
static void TFTPStateTxFree(void *state, uint64_t tx_id)
{
    rs_tftp_state_tx_free(state, tx_id);
}

static int TFTPStateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    return -1;
}

static AppLayerDecoderEvents *TFTPGetEvents(void *tx)
{
    return NULL;
}

/**
 * \brief Probe the input to see if it looks like echo.
 *
 * \retval ALPROTO_TFTP if it looks like echo, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto TFTPProbingParser(Flow *f, uint8_t direction,
        const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
    /* Very simple test - if there is input, this is tftp.
     * Also check if it's starting by a zero */
    if (input_len >= TFTP_MIN_FRAME_LEN && *input == 0) {
        SCLogDebug("Detected as ALPROTO_TFTP.");
        return ALPROTO_TFTP;
    }

    SCLogDebug("Protocol not detected as ALPROTO_TFTP.");
    return ALPROTO_UNKNOWN;
}

static int TFTPParseRequest(Flow *f, void *state,
    AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len,
    void *local_data, const uint8_t flags)
{
    SCLogDebug("Parsing echo request: len=%"PRIu32, input_len);

    /* Likely connection closed, we can just return here. */
    if ((input == NULL || input_len == 0) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        return 0;
    }

    /* Probably don't want to create a transaction in this case
     * either. */
    if (input == NULL || input_len == 0) {
        return 0;
    }

    return rs_tftp_request(state, input, input_len);
}

/**
 * \brief Response parsing is not implemented
 */
static int TFTPParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
    const uint8_t *input, uint32_t input_len, void *local_data,
    const uint8_t flags)
{
    return 0;
}

static uint64_t TFTPGetTxCnt(void *state)
{
    return rs_tftp_get_tx_cnt(state);
}

static void *TFTPGetTx(void *state, uint64_t tx_id)
{
    return rs_tftp_get_tx(state, tx_id);
}

static void TFTPSetTxLogged(void *state, void *vtx, uint32_t logger)
{
    rs_tftp_set_tx_logged(state, vtx, logger);
}

static LoggerId TFTPGetTxLogged(void *state, void *vtx)
{
    return rs_tftp_get_tx_logged(state, vtx);
}

/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int TFTPGetAlstateProgressCompletionStatus(uint8_t direction) {
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
static int TFTPGetStateProgress(void *tx, uint8_t direction)
{
    return 1;
}

static DetectEngineState *TFTPGetTxDetectState(void *vtx)
{
    return NULL;
}

static int TFTPSetTxDetectState(void *vtx,
    DetectEngineState *s)
{
    return 0;
}

void RegisterTFTPParsers(void)
{
    const char *proto_name = "tftp";

    /* Check if TFTP UDP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("udp", proto_name)) {

        SCLogDebug("TFTP UDP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_TFTP, proto_name);

        if (RunmodeIsUnittests()) {
            SCLogDebug("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_UDP, TFTP_DEFAULT_PORT,
                                          ALPROTO_TFTP, 0, TFTP_MIN_FRAME_LEN,
                                          STREAM_TOSERVER, TFTPProbingParser,
                                          TFTPProbingParser);
        } else {
            if (!AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP,
                                                     proto_name, ALPROTO_TFTP,
                                                     0, TFTP_MIN_FRAME_LEN,
                                                     TFTPProbingParser, TFTPProbingParser)) {
                SCLogDebug("No echo app-layer configuration, enabling echo"
                           " detection UDP detection on port %s.",
                           TFTP_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_UDP,
                                              TFTP_DEFAULT_PORT, ALPROTO_TFTP,
                                              0, TFTP_MIN_FRAME_LEN,
                                              STREAM_TOSERVER,TFTPProbingParser,
                                              TFTPProbingParser);
            }
        }
    } else {
        SCLogDebug("Protocol detecter and parser disabled for TFTP.");
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name)) {

        SCLogDebug("Registering TFTP protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new TFTP flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_TFTP,
                                         TFTPStateAlloc, TFTPStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_TFTP,
                                     STREAM_TOSERVER, TFTPParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_TFTP,
                                     STREAM_TOCLIENT, TFTPParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_TFTP,
                                         TFTPStateTxFree);

        AppLayerParserRegisterLoggerFuncs(IPPROTO_UDP, ALPROTO_TFTP,
                                          TFTPGetTxLogged, TFTPSetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_TFTP,
                                       TFTPGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_TFTP,
            TFTPGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP,
                                                   ALPROTO_TFTP,
                                                   TFTPGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_TFTP,
                                    TFTPGetTx);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_UDP, ALPROTO_TFTP,
                                               TFTPGetTxDetectState,
                                               TFTPSetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_UDP, ALPROTO_TFTP,
                                           TFTPStateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_UDP, ALPROTO_TFTP,
                                            TFTPGetEvents);
    }
    else {
        SCLogDebug("TFTP protocol parsing disabled.");
    }
}
