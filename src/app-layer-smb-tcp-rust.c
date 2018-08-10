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

#include "suricata-common.h"
#include "suricata.h"

#include "app-layer-protos.h"
#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "util-unittest.h"

#ifdef HAVE_RUST
#include "rust.h"
#include "app-layer-smb-tcp-rust.h"
#include "rust-smb-smb-gen.h"
#include "rust-smb-files-gen.h"
#include "util-misc.h"

#define MIN_REC_SIZE 32+4 // SMB hdr + nbss hdr

static int RustSMBTCPParseRequest(Flow *f, void *state,
        AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
        void *local_data, const uint8_t flags)
{
    SCLogDebug("RustSMBTCPParseRequest");
    uint16_t file_flags = FileFlowToFlags(f, STREAM_TOSERVER);
    rs_smb_setfileflags(0, state, file_flags|FILE_USE_DETECT);

    int res;
    if (input == NULL && input_len > 0) {
        res = rs_smb_parse_request_tcp_gap(state, input_len);
    } else {
        res = rs_smb_parse_request_tcp(f, state, pstate, input, input_len,
            local_data, flags);
    }
    if (res != 1) {
        SCLogNotice("SMB request%s of %u bytes, retval %d",
                (input == NULL && input_len > 0) ? " is GAP" : "", input_len, res);
    }
    return res;
}

static int RustSMBTCPParseResponse(Flow *f, void *state,
        AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
        void *local_data, const uint8_t flags)
{
    SCLogDebug("RustSMBTCPParseResponse");
    uint16_t file_flags = FileFlowToFlags(f, STREAM_TOCLIENT);
    rs_smb_setfileflags(1, state, file_flags|FILE_USE_DETECT);

    SCLogDebug("RustSMBTCPParseResponse %p/%u", input, input_len);
    int res;
    if (input == NULL && input_len > 0) {
        res = rs_smb_parse_response_tcp_gap(state, input_len);
    } else {
        res = rs_smb_parse_response_tcp(f, state, pstate, input, input_len,
            local_data, flags);
    }
    if (res != 1) {
        SCLogNotice("SMB response%s of %u bytes, retval %d",
                (input == NULL && input_len > 0) ? " is GAP" : "", input_len, res);
    }
    return res;
}

static uint16_t RustSMBTCPProbe(Flow *f,
        uint8_t *input, uint32_t len)
{
    SCLogDebug("RustSMBTCPProbe");

    if (len < MIN_REC_SIZE) {
        return ALPROTO_UNKNOWN;
    }

    const int r = rs_smb_probe_tcp(input, len);
    switch (r) {
        case 1:
            return ALPROTO_SMB;
        case 0:
            return ALPROTO_UNKNOWN;
        case -1:
        default:
            return ALPROTO_FAILED;
    }
}

static int RustSMBGetAlstateProgress(void *tx, uint8_t direction)
{
    return rs_smb_tx_get_alstate_progress(tx, direction);
}

static uint64_t RustSMBGetTxCnt(void *alstate)
{
    return rs_smb_state_get_tx_count(alstate);
}

static void *RustSMBGetTx(void *alstate, uint64_t tx_id)
{
    return rs_smb_state_get_tx(alstate, tx_id);
}

static AppLayerGetTxIterTuple RustSMBGetTxIterator(
        const uint8_t ipproto, const AppProto alproto,
        void *alstate, uint64_t min_tx_id, uint64_t max_tx_id,
        AppLayerGetTxIterState *istate)
{
    return rs_smb_state_get_tx_iterator(alstate, min_tx_id, (uint64_t *)istate);
}


static void RustSMBSetTxLogged(void *alstate, void *tx, uint32_t logger)
{
    rs_smb_tx_set_logged(alstate, tx, logger);
}

static LoggerId RustSMBGetTxLogged(void *alstate, void *tx)
{
    return rs_smb_tx_get_logged(alstate, tx);
}

static void RustSMBStateTransactionFree(void *state, uint64_t tx_id)
{
    rs_smb_state_tx_free(state, tx_id);
}

static DetectEngineState *RustSMBGetTxDetectState(void *tx)
{
    return rs_smb_state_get_tx_detect_state(tx);
}

static int RustSMBSetTxDetectState(void *tx, DetectEngineState *s)
{
    rs_smb_state_set_tx_detect_state(tx, s);
    return 0;
}

static FileContainer *RustSMBGetFiles(void *state, uint8_t direction)
{
    return rs_smb_getfiles(direction, state);
}

static AppLayerDecoderEvents *RustSMBGetEvents(void *state, uint64_t id)
{
    return rs_smb_state_get_events(state, id);
}

static int RustSMBGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type)
{
    return rs_smb_state_get_event_info(event_name, event_id, event_type);
}

static void RustSMBSetDetectFlags(void *tx, uint8_t dir, uint64_t flags)
{
    rs_smb_tx_set_detect_flags(tx, dir, flags);
}

static uint64_t RustSMBGetDetectFlags(void *tx, uint8_t dir)
{
    return rs_smb_tx_get_detect_flags(tx, dir);
}

static void RustSMBStateTruncate(void *state, uint8_t direction)
{
    return rs_smb_state_truncate(state, direction);
}

static int RustSMBRegisterPatternsForProtocolDetection(void)
{
    int r = 0;
    /* SMB1 */
    r |= AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB,
            "|ff|SMB", 8, 4, STREAM_TOSERVER);
    r |= AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB,
            "|ff|SMB", 8, 4, STREAM_TOCLIENT);

    /* SMB2/3 */
    r |= AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB,
            "|fe|SMB", 8, 4, STREAM_TOSERVER);
    r |= AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB,
            "|fe|SMB", 8, 4, STREAM_TOCLIENT);

    /* SMB3 encrypted records */
    r |= AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB,
            "|fd|SMB", 8, 4, STREAM_TOSERVER);
    r |= AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB,
            "|fd|SMB", 8, 4, STREAM_TOCLIENT);
    return r == 0 ? 0 : -1;
}

static StreamingBufferConfig sbcfg = STREAMING_BUFFER_CONFIG_INITIALIZER;
static SuricataFileContext sfc = { &sbcfg };

#define SMB_CONFIG_DEFAULT_STREAM_DEPTH 0

static uint32_t stream_depth = SMB_CONFIG_DEFAULT_STREAM_DEPTH;

void RegisterRustSMBTCPParsers(void)
{
    const char *proto_name = "smb";

    /** SMB */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_SMB, proto_name);
        if (RustSMBRegisterPatternsForProtocolDetection() < 0)
            return;

        rs_smb_init(&sfc);

        if (RunmodeIsUnittests()) {
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, "445", ALPROTO_SMB, 0,
                    MIN_REC_SIZE, STREAM_TOSERVER, RustSMBTCPProbe,
                    NULL);
        } else {
            int have_cfg = AppLayerProtoDetectPPParseConfPorts("tcp",
                    IPPROTO_TCP, proto_name, ALPROTO_SMB, 0,
                    MIN_REC_SIZE, RustSMBTCPProbe, RustSMBTCPProbe);
            /* if we have no config, we enable the default port 445 */
            if (!have_cfg) {
                SCLogWarning(SC_ERR_SMB_CONFIG, "no SMB TCP config found, "
                                                "enabling SMB detection on "
                                                "port 445.");
                AppLayerProtoDetectPPRegister(IPPROTO_TCP, "445", ALPROTO_SMB, 0,
                        MIN_REC_SIZE, STREAM_TOSERVER, RustSMBTCPProbe,
                        RustSMBTCPProbe);
            }
        }
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
                  proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_SMB, STREAM_TOSERVER,
                RustSMBTCPParseRequest);
        AppLayerParserRegisterParser(IPPROTO_TCP , ALPROTO_SMB, STREAM_TOCLIENT,
                RustSMBTCPParseResponse);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_SMB,
                rs_smb_state_new, rs_smb_state_free);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_SMB,
                RustSMBStateTransactionFree);

        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_SMB,
                RustSMBGetEvents);
        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_SMB,
                RustSMBGetEventInfo);

        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_SMB,
                RustSMBGetTxDetectState, RustSMBSetTxDetectState);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_SMB, RustSMBGetTx);
        AppLayerParserRegisterGetTxIterator(IPPROTO_TCP, ALPROTO_SMB, RustSMBGetTxIterator);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_SMB,
                RustSMBGetTxCnt);
        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_SMB,
                RustSMBGetTxLogged, RustSMBSetTxLogged);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_SMB,
                RustSMBGetAlstateProgress);
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_SMB,
                rs_smb_state_progress_completion_status);
        AppLayerParserRegisterDetectFlagsFuncs(IPPROTO_TCP, ALPROTO_SMB,
                                               RustSMBGetDetectFlags, RustSMBSetDetectFlags);
        AppLayerParserRegisterTruncateFunc(IPPROTO_TCP, ALPROTO_SMB,
                                          RustSMBStateTruncate);
        AppLayerParserRegisterGetFilesFunc(IPPROTO_TCP, ALPROTO_SMB, RustSMBGetFiles);

        /* This parser accepts gaps. */
        AppLayerParserRegisterOptionFlags(IPPROTO_TCP, ALPROTO_SMB,
                APP_LAYER_PARSER_OPT_ACCEPT_GAPS);

        ConfNode *p = ConfGetNode("app-layer.protocols.smb.stream-depth");
        if (p != NULL) {
            uint32_t value;
            if (ParseSizeStringU32(p->val, &value) < 0) {
                SCLogError(SC_ERR_SMB_CONFIG, "invalid value for stream-depth %s", p->val);
            } else {
                stream_depth = value;
            }
        }
        SCLogConfig("SMB stream depth: %u", stream_depth);

        AppLayerParserSetStreamDepth(IPPROTO_TCP, ALPROTO_SMB, stream_depth);
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }

    return;
}
#endif /* HAVE_RUST */
