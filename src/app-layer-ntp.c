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
 */

/**
 * \file
 *
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 *
 * Parser for NTP application layer running on UDP port 123.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-ntp.h"

#if defined(HAVE_RUST) && defined(HAVE_RUST_EXTERNAL)

#include "rust-ntp-ntp-gen.h"

/* The default port to probe for NTP traffic if not provided in the
 * configuration file. */
#define NTP_DEFAULT_PORT "123"

/* The minimum size for an NTP message. */
#define NTP_MIN_FRAME_LEN 2


static void *NTPStateAlloc(void)
{
    return rs_ntp_state_new();
}

static void NTPStateFree(void *state)
{
    rs_ntp_state_free(state);
}

/**
 * \brief Callback from the application layer to have a transaction freed.
 *
 * \param state a void pointer to the NTPState object.
 * \param tx_id the transaction ID to free.
 */
static void NTPStateTxFree(void *state, uint64_t tx_id)
{
    rs_ntp_state_tx_free(state, tx_id);
}

static int NTPStateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    return rs_ntp_state_get_event_info(event_name, event_id, event_type);
}

static AppLayerDecoderEvents *NTPGetEvents(void *state, uint64_t tx_id)
{
    return rs_ntp_state_get_events(state, tx_id);
}

static int NTPHasEvents(void *state)
{
    return rs_ntp_state_has_events(state);
}

/**
 * \brief Probe the input to see if it looks like NTP.
 *
 * \retval ALPROTO_NTP if it looks like NTP, otherwise
 *     ALPROTO_UNKNOWN.
 */
static AppProto NTPProbingParser(uint8_t *input, uint32_t input_len,
    uint32_t *offset)
{
    if (input_len < NTP_MIN_FRAME_LEN) {
        return ALPROTO_UNKNOWN;
    }

    int8_t r = rs_ntp_probe(input, input_len);
    if (r == 1) {
        return ALPROTO_NTP;
    } else if (r == -1) {
        return ALPROTO_FAILED;
    }

    SCLogDebug("Protocol not detected as ALPROTO_NTP.");
    return ALPROTO_UNKNOWN;
}

static int RustNTPParseRequest(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    SCLogDebug("RustNTPParseRequest");
    return rs_ntp_parse_request(f, state, pstate, input, input_len,
            local_data);
}

static int RustNTPParseResponse(Flow *f, void *state,
    AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
    void *local_data)
{
    SCLogDebug("RustNTPParseResponse");
    return rs_ntp_parse_response(f, state, pstate, input, input_len,
            local_data);
}

static uint64_t NTPGetTxCnt(void *state)
{
    return rs_ntp_state_get_tx_count(state);
}

static void *NTPGetTx(void *state, uint64_t tx_id)
{
    return rs_ntp_state_get_tx(state, tx_id);
}

// static void NTPSetTxLogged(void *state, void *vtx, uint32_t logger)
// {
//     rs_ntp_tx_set_logged(state, vtx, logger);
// }
//
// static int NTPGetTxLogged(void *state, void *vtx, uint32_t logger)
// {
//     return rs_ntp_tx_get_logged(state, vtx, logger);
// }







/**
 * \brief Called by the application layer.
 *
 * In most cases 1 can be returned here.
 */
static int NTPGetAlstateProgressCompletionStatus(uint8_t direction) {
    return rs_ntp_state_progress_completion_status(direction);
}

/**
 * \brief Return the state of a transaction in a given direction.
 */
static int NTPGetStateProgress(void *tx, uint8_t direction)
{
    return rs_ntp_tx_get_alstate_progress(tx, direction);
}

/**
 * \brief Get stored Tx detect state
 */
static DetectEngineState *NTPGetTxDetectState(void *vtx)
{
    return rs_ntp_state_get_tx_detect_state(vtx);
}

/**
 * \brief Set stored Tx detect state
 */
static int NTPSetTxDetectState(void *state, void *vtx,
    DetectEngineState *s)
{
    rs_ntp_state_set_tx_detect_state(state, vtx, s);
    return 0;
}

void RegisterNTPParsers(void)
{
    const char *proto_name = "ntp";

    /* Check if NTP UDP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("udp", proto_name)) {

        SCLogDebug("NTP UDP protocol detection enabled.");

        AppLayerProtoDetectRegisterProtocol(ALPROTO_NTP, proto_name);

        if (RunmodeIsUnittests()) {

            SCLogDebug("Unittest mode, registeringd default configuration.");
            AppLayerProtoDetectPPRegister(IPPROTO_UDP, NTP_DEFAULT_PORT,
                ALPROTO_NTP, 0, NTP_MIN_FRAME_LEN, STREAM_TOSERVER,
                NTPProbingParser, NULL);

        }
        else {

            if (!AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP,
                    proto_name, ALPROTO_NTP, 0, NTP_MIN_FRAME_LEN,
                    NTPProbingParser, NULL)) {
                SCLogDebug("No NTP app-layer configuration, enabling NTP"
                    " detection UDP detection on port %s.",
                    NTP_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_UDP,
                    NTP_DEFAULT_PORT, ALPROTO_NTP, 0,
                    NTP_MIN_FRAME_LEN, STREAM_TOSERVER,
                    NTPProbingParser, NULL);
            }

        }

    }

    else {
        SCLogDebug("Protocol detecter and parser disabled for NTP.");
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name)) {

        SCLogDebug("Registering NTP protocol parser.");

        /* Register functions for state allocation and freeing. A
         * state is allocated for every new NTP flow. */
        AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_NTP,
            NTPStateAlloc, NTPStateFree);

        /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_NTP,
            STREAM_TOSERVER, RustNTPParseRequest);

        /* Register response parser for parsing frames from server to client. */
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_NTP,
            STREAM_TOCLIENT, RustNTPParseResponse);

        /* Register a function to be called by the application layer
         * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_NTP,
            NTPStateTxFree);

        // AppLayerParserRegisterLoggerFuncs(IPPROTO_UDP, ALPROTO_NTP,
        //     NTPGetTxLogged, NTPSetTxLogged);

        /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_NTP,
            NTPGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_NTP,
            NTPGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP,
            ALPROTO_NTP, NTPGetStateProgress);
        AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_NTP,
            NTPGetTx);

        /* Application layer event handling. */
        AppLayerParserRegisterHasEventsFunc(IPPROTO_UDP, ALPROTO_NTP,
            NTPHasEvents);

        /* What is this being registered for? */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_UDP, ALPROTO_NTP,
            NULL, NTPGetTxDetectState, NTPSetTxDetectState);

        AppLayerParserRegisterGetEventInfo(IPPROTO_UDP, ALPROTO_NTP,
            NTPStateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_UDP, ALPROTO_NTP,
            NTPGetEvents);
    }
    else {
        SCLogDebug("NTP protocol parsing disabled.");
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_UDP, ALPROTO_NTP,
        NTPParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void NTPParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}

#else /* HAVE_RUST */

void RegisterNTPParsers(void)
{
}

#endif /* HAVE_RUST */
