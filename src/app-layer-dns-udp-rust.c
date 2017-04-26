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
#include "app-layer-dns-common.h"

#ifdef HAVE_RUST

#include "app-layer-dns-udp-rust.h"
#include "rust-dns-dns-gen.h"

static int RustDNSUDPParseRequest(Flow *f, void *state,
        AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
        void *local_data)
{
    return rs_dns_parse_request(f, state, pstate, input, input_len,
            local_data);
}

static int RustDNSUDPParseResponse(Flow *f, void *state,
        AppLayerParserState *pstate, uint8_t *input, uint32_t input_len,
        void *local_data)
{
    return rs_dns_parse_response(f, state, pstate, input, input_len,
            local_data);
}

static uint16_t DNSUDPProbe(uint8_t *input, uint32_t len, uint32_t *offset)
{
    if (len == 0 || len < sizeof(DNSHeader)) {
        return ALPROTO_UNKNOWN;
    }

    // Validate and return ALPROTO_FAILED if needed.
    if (!rs_dns_probe(input, len)) {
        return ALPROTO_FAILED;
    }

    return ALPROTO_DNS;
}

static int RustDNSGetAlstateProgress(void *tx, uint8_t direction)
{
    return rs_dns_tx_get_alstate_progress(tx, direction);
}

static uint64_t RustDNSGetTxCnt(void *alstate)
{
    return rs_dns_state_get_tx_count(alstate);
}

static void *RustDNSGetTx(void *alstate, uint64_t tx_id)
{
    return rs_dns_state_get_tx(alstate, tx_id);
}

static void RustDNSSetTxLogged(void *alstate, void *tx, uint32_t logger)
{
    rs_dns_tx_set_logged(alstate, tx, logger);
}

static int RustDNSGetTxLogged(void *alstate, void *tx, uint32_t logger)
{
    return rs_dns_tx_get_logged(alstate, tx, logger);
}

static void RustDNSStateTransactionFree(void *state, uint64_t tx_id)
{
    rs_dns_state_tx_free(state, tx_id);
}

static int RustDNSStateHasTxDetectState(void *state)
{
    return rs_dns_state_has_detect_state(state);
}

static DetectEngineState *RustDNSGetTxDetectState(void *tx)
{
    return rs_dns_state_get_tx_detect_state(tx);
}

static int RustDNSSetTxDetectState(void *state, void *tx,
        DetectEngineState *s)
{
    rs_dns_state_set_tx_detect_state(state, tx, s);
    return 0;
}

static int RustDNSHasEvents(void *state)
{
    return rs_dns_state_has_events(state);
}

static AppLayerDecoderEvents *RustDNSGetEvents(void *state, uint64_t id)
{
    return rs_dns_state_get_events(state, id);
}

void RegisterRustDNSUDPParsers(void)
{
    const char *proto_name = "dns";

    /** DNS */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("udp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_DNS, proto_name);

        if (RunmodeIsUnittests()) {
            AppLayerProtoDetectPPRegister(IPPROTO_UDP, "53", ALPROTO_DNS, 0,
                    sizeof(DNSHeader), STREAM_TOSERVER, DNSUDPProbe,
                    NULL);
        } else {
            int have_cfg = AppLayerProtoDetectPPParseConfPorts("udp",
                    IPPROTO_UDP, proto_name, ALPROTO_DNS, 0, sizeof(DNSHeader),
                    DNSUDPProbe, NULL);

            /* If no config, enable on port 53. */
            if (!have_cfg) {
#ifndef AFLFUZZ_APPLAYER
                SCLogWarning(SC_ERR_DNS_CONFIG, "no DNS UDP config found, "
                        "enabling DNS detection on port 53.");
#endif
                AppLayerProtoDetectPPRegister(IPPROTO_UDP, "53", ALPROTO_DNS,
                        0, sizeof(DNSHeader), STREAM_TOSERVER,
                        DNSUDPProbe, NULL);
            }
        }
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
                  proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_DNS, STREAM_TOSERVER,
                RustDNSUDPParseRequest);
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_DNS, STREAM_TOCLIENT,
                RustDNSUDPParseResponse);
        AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_DNS,
                rs_dns_state_new, rs_dns_state_free);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_DNS,
                RustDNSStateTransactionFree);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_UDP, ALPROTO_DNS,
                RustDNSGetEvents);
        AppLayerParserRegisterHasEventsFunc(IPPROTO_UDP, ALPROTO_DNS,
                RustDNSHasEvents);
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_UDP, ALPROTO_DNS,
                RustDNSStateHasTxDetectState, RustDNSGetTxDetectState,
                RustDNSSetTxDetectState);

        AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_DNS, RustDNSGetTx);
        AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_DNS,
                RustDNSGetTxCnt);
        AppLayerParserRegisterLoggerFuncs(IPPROTO_UDP, ALPROTO_DNS,
                RustDNSGetTxLogged, RustDNSSetTxLogged);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP, ALPROTO_DNS,
                RustDNSGetAlstateProgress);

        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_DNS,
                rs_dns_state_progress_completion_status);

        DNSAppLayerRegisterGetEventInfo(IPPROTO_UDP, ALPROTO_DNS);

#if 0
        DNSUDPConfigure();
#endif
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                "still on.", proto_name);
    }
#if 0
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_UDP, ALPROTO_DNS,
            DNSUDPParserRegisterTests);
#endif
#endif
}

#endif /* HAVE_RUST */
