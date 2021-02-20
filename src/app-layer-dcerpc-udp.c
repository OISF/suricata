/*
 * Copyright (c) 2009, 2010 Open Information Security Foundation
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
 * \todo Updated by AS: Inspect the possibilities of sending junk start at the
 *       start of udp session to avoid alproto detection.
 */

#include "suricata-common.h"
#include "suricata.h"

#include "debug.h"
#include "decode.h"

#include "flow-util.h"

#include "threads.h"

#include "util-print.h"
#include "util-pool.h"
#include "util-debug.h"

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
#include "app-layer-dcerpc-udp.h"

static AppLayerResult RustDCERPCUDPParse(Flow *f, void *dcerpc_state,
    AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len,
    void *local_data, const uint8_t flags)
{
    return rs_dcerpc_udp_parse(f, dcerpc_state, pstate, input, input_len,
                               local_data, flags);
}

static void *RustDCERPCUDPStateNew(void *state_orig, AppProto proto_orig)
{
    return rs_dcerpc_udp_state_new(state_orig, proto_orig);
}

static void RustDCERPCUDPStateFree(void *s)
{
    return rs_dcerpc_udp_state_free(s);
}

static int RustDCERPCUDPSetTxDetectState(void *vtx, DetectEngineState *de_state)
{
    return rs_dcerpc_udp_set_tx_detect_state(vtx, de_state);
}

static DetectEngineState *RustDCERPCUDPGetTxDetectState(void *vtx)
{
    return rs_dcerpc_udp_get_tx_detect_state(vtx);
}

static void RustDCERPCUDPStateTransactionFree(void *state, uint64_t tx_id)
{
    return rs_dcerpc_udp_state_transaction_free(state, tx_id);
}

static void *RustDCERPCUDPGetTx(void *state, uint64_t tx_id)
{
    return rs_dcerpc_udp_get_tx(state, tx_id);
}

static uint64_t RustDCERPCUDPGetTxCnt(void *state)
{
    return rs_dcerpc_udp_get_tx_cnt(state);
}

static int RustDCERPCUDPGetAlstateProgressCompletionStatus(uint8_t direction)
{
    return rs_dcerpc_get_alstate_progress_completion_status(direction);
}

static int RustDCERPCUDPGetAlstateProgress(void *tx, uint8_t direction)
{
    return rs_dcerpc_get_alstate_progress(tx, direction);
}

static uint16_t DCERPCUDPProbe(
        Flow *f, uint8_t direction, const uint8_t *input, uint32_t len, uint8_t *rdir)
{
    SCLogDebug("DCERPCUDPProbe");

    const int r = rs_dcerpc_probe_udp(direction, input, len, rdir);
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

static int DCERPCUDPRegisterPatternsForProtocolDetection(void)
{
    if (AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_UDP, ALPROTO_DCERPC, "|04 00|", 2, 0,
                STREAM_TOSERVER, DCERPCUDPProbe, 0, 0) < 0) {
        return -1;
    }

    return 0;
}

void RegisterDCERPCUDPParsers(void)
{
    const char *proto_name = "dcerpc";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("udp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_DCERPC, proto_name);
        if (DCERPCUDPRegisterPatternsForProtocolDetection() < 0)
            return;
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
            "dcerpc");
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", "dcerpc")) {
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_DCERPC, STREAM_TOSERVER,
            RustDCERPCUDPParse);
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_DCERPC, STREAM_TOCLIENT,
            RustDCERPCUDPParse);
        AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_DCERPC, RustDCERPCUDPStateNew,
            RustDCERPCUDPStateFree);
        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_UDP, ALPROTO_DCERPC, STREAM_TOSERVER);

        AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_DCERPC, RustDCERPCUDPStateTransactionFree);

        AppLayerParserRegisterDetectStateFuncs(IPPROTO_UDP, ALPROTO_DCERPC,
                                               RustDCERPCUDPGetTxDetectState, RustDCERPCUDPSetTxDetectState);

        AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_DCERPC, RustDCERPCUDPGetTx);
        AppLayerParserRegisterTxDataFunc(IPPROTO_UDP, ALPROTO_DCERPC, rs_dcerpc_udp_get_tx_data);

        AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_DCERPC, RustDCERPCUDPGetTxCnt);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP, ALPROTO_DCERPC, RustDCERPCUDPGetAlstateProgress);

        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_DCERPC,
                                                               RustDCERPCUDPGetAlstateProgressCompletionStatus);
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
            "still on.", "dcerpc");
    }

    return;
}
