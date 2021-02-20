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

#include "suricata-common.h"
#include "suricata.h"

#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"
#include "util-debug.h"

#include "flow-util.h"

#include "detect-engine-state.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer.h"

#include "util-spm.h"
#include "util-unittest.h"

#include "app-layer-dcerpc-common.h"
#include "app-layer-dcerpc.h"

static AppLayerResult DCERPCParseRequest(Flow *f, void *dcerpc_state,
                              AppLayerParserState *pstate,
                              const uint8_t *input, uint32_t input_len,
                              void *local_data, const uint8_t flags)
{
    if (input == NULL && input_len > 0) {
        AppLayerResult res = rs_parse_dcerpc_request_gap(dcerpc_state, input_len);
        SCLogDebug("DCERPC request GAP of %u bytes, retval %d", input_len, res.status);
        SCReturnStruct(res);
    } else {
        AppLayerResult res = rs_dcerpc_parse_request(
                f, dcerpc_state, pstate, input, input_len, local_data, flags);
        SCLogDebug("DCERPC request%s of %u bytes, retval %d",
                (input == NULL && input_len > 0) ? " is GAP" : "", input_len, res.status);
        SCReturnStruct(res);
    }
}

static AppLayerResult DCERPCParseResponse(Flow *f, void *dcerpc_state,
                               AppLayerParserState *pstate,
                               const uint8_t *input, uint32_t input_len,
                               void *local_data, const uint8_t flags)
{
    if (input == NULL && input_len > 0) {
        AppLayerResult res = rs_parse_dcerpc_response_gap(dcerpc_state, input_len);
        SCLogDebug("DCERPC response GAP of %u bytes, retval %d", input_len, res.status);
        SCReturnStruct(res);
    } else {
        AppLayerResult res = rs_dcerpc_parse_response(
                f, dcerpc_state, pstate, input, input_len, local_data, flags);
        SCLogDebug("DCERPC response%s of %u bytes, retval %d",
                (input == NULL && input_len > 0) ? " is GAP" : "", input_len, res.status);
        SCReturnStruct(res);
    }
}

static void *RustDCERPCStateNew(void *state_orig, AppProto proto_orig)
{
    return rs_dcerpc_state_new(state_orig, proto_orig);
}

static void DCERPCStateFree(void *s)
{
    return rs_dcerpc_state_free(s);
}

static int DCERPCSetTxDetectState(void *vtx, DetectEngineState *de_state)
{
    return rs_dcerpc_set_tx_detect_state(vtx, de_state);
}

static DetectEngineState *DCERPCGetTxDetectState(void *vtx)
{
    return rs_dcerpc_get_tx_detect_state(vtx);
}

static void DCERPCStateTransactionFree(void *state, uint64_t tx_id)
{
    return rs_dcerpc_state_transaction_free(state, tx_id);
}

static void *DCERPCGetTx(void *state, uint64_t tx_id)
{
    return rs_dcerpc_get_tx(state, tx_id);
}

static uint64_t DCERPCGetTxCnt(void *state)
{
    return rs_dcerpc_get_tx_cnt(state);
}

static int DCERPCGetAlstateProgressCompletionStatus(uint8_t direction)
{
    return rs_dcerpc_get_alstate_progress_completion_status(direction);
}

static int DCERPCGetAlstateProgress(void *tx, uint8_t direction)
{
    return rs_dcerpc_get_alstate_progress(tx, direction);
}

static uint16_t DCERPCTCPProbe(
        Flow *f, uint8_t direction, const uint8_t *input, uint32_t len, uint8_t *rdir)
{
    SCLogDebug("DCERPCTCPProbe");

    const int r = rs_dcerpc_probe_tcp(direction, input, len, rdir);
    switch (r) {
        case 1:
            return ALPROTO_DCERPC;
        case 0:
            return ALPROTO_UNKNOWN;
        case -1:
        default:
            return ALPROTO_FAILED;
    }
}

static int DCERPCRegisterPatternsForProtocolDetection(void)
{
    if (AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP, ALPROTO_DCERPC, "|05 00|", 2, 0,
                STREAM_TOSERVER, DCERPCTCPProbe, 0, 0) < 0) {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP, ALPROTO_DCERPC, "|05 00|", 2, 0,
                STREAM_TOCLIENT, DCERPCTCPProbe, 0, 0) < 0) {
        return -1;
    }

    return 0;
}

void RegisterDCERPCParsers(void)
{
    const char *proto_name = "dcerpc";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_DCERPC, proto_name);
        if (DCERPCRegisterPatternsForProtocolDetection() < 0)
            return;
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
                  proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_DCERPC, STREAM_TOSERVER,
                                     DCERPCParseRequest);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_DCERPC, STREAM_TOCLIENT,
                                     DCERPCParseResponse);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_DCERPC, RustDCERPCStateNew,
                                         DCERPCStateFree);
        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_DCERPC, STREAM_TOSERVER);


        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_DCERPC, DCERPCStateTransactionFree);

        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_DCERPC,
                                               DCERPCGetTxDetectState, DCERPCSetTxDetectState);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_DCERPC, DCERPCGetTx);
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_DCERPC, rs_dcerpc_get_tx_data);

        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_DCERPC, DCERPCGetTxCnt);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_DCERPC, DCERPCGetAlstateProgress);

        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_DCERPC,
                                                               DCERPCGetAlstateProgressCompletionStatus);
        /* This parser accepts gaps. */
        AppLayerParserRegisterOptionFlags(IPPROTO_TCP, ALPROTO_DCERPC, APP_LAYER_PARSER_OPT_ACCEPT_GAPS);

        AppLayerParserRegisterTruncateFunc(IPPROTO_TCP, ALPROTO_DCERPC, rs_dcerpc_state_trunc);
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }
    return;
}
