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

#include "util-unittest.h"

#ifdef HAVE_RUST

#include "app-layer-dns-udp-rust.h"
#include "rust-dns-dns-gen.h"

#ifdef UNITTESTS
static void RustDNSUDPParserRegisterTests(void);
#endif

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
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_UDP, ALPROTO_DNS,
            RustDNSUDPParserRegisterTests);
#endif
}

#ifdef UNITTESTS

#include "util-unittest-helper.h"

static int RustDNSUDPParserTest01 (void)
{
    /* query: abcdefghijk.com
     * TTL: 86400
     * serial 20130422 refresh 28800 retry 7200 exp 604800 min ttl 86400
     * ns, hostmaster */
    uint8_t buf[] = { 0x00, 0x3c, 0x85, 0x00, 0x00, 0x01, 0x00, 0x00,
                      0x00, 0x01, 0x00, 0x00, 0x0b, 0x61, 0x62, 0x63,
                      0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
                      0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x0f, 0x00,
                      0x01, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x01,
                      0x51, 0x80, 0x00, 0x25, 0x02, 0x6e, 0x73, 0x00,
                      0x0a, 0x68, 0x6f, 0x73, 0x74, 0x6d, 0x61, 0x73,
                      0x74, 0x65, 0x72, 0xc0, 0x2f, 0x01, 0x33, 0x2a,
                      0x76, 0x00, 0x00, 0x70, 0x80, 0x00, 0x00, 0x1c,
                      0x20, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x01, 0x51,
                      0x80};
    size_t buflen = sizeof(buf);
    Flow *f = NULL;

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 53);
    FAIL_IF_NULL(f);
    f->proto = IPPROTO_UDP;
    f->alproto = ALPROTO_DNS;
    f->alstate = rs_dns_state_new();
    FAIL_IF_NULL(f->alstate);

    FAIL_IF_NOT(RustDNSUDPParseResponse(f, f->alstate, NULL, buf, buflen,
                    NULL));

    UTHFreeFlow(f);
    PASS;
}

static int RustDNSUDPParserTest02 (void)
{
    uint8_t buf[] = {
        0x6D,0x08,0x84,0x80,0x00,0x01,0x00,0x08,0x00,0x00,0x00,0x01,0x03,0x57,0x57,0x57,
        0x04,0x54,0x54,0x54,0x54,0x03,0x56,0x56,0x56,0x03,0x63,0x6F,0x6D,0x02,0x79,0x79,
        0x00,0x00,0x01,0x00,0x01,0xC0,0x0C,0x00,0x05,0x00,0x01,0x00,0x00,0x0E,0x10,0x00,
        0x02,0xC0,0x0C,0xC0,0x31,0x00,0x05,0x00,0x01,0x00,0x00,0x0E,0x10,0x00,0x02,0xC0,
        0x31,0xC0,0x3F,0x00,0x05,0x00,0x01,0x00,0x00,0x0E,0x10,0x00,0x02,0xC0,0x3F,0xC0,
        0x4D,0x00,0x05,0x00,0x01,0x00,0x00,0x0E,0x10,0x00,0x02,0xC0,0x4D,0xC0,0x5B,0x00,
        0x05,0x00,0x01,0x00,0x00,0x0E,0x10,0x00,0x02,0xC0,0x5B,0xC0,0x69,0x00,0x05,0x00,
        0x01,0x00,0x00,0x0E,0x10,0x00,0x02,0xC0,0x69,0xC0,0x77,0x00,0x05,0x00,0x01,0x00,
        0x00,0x0E,0x10,0x00,0x02,0xC0,0x77,0xC0,0x85,0x00,0x05,0x00,0x01,0x00,0x00,0x0E,
        0x10,0x00,0x02,0xC0,0x85,0x00,0x00,0x29,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };
    size_t buflen = sizeof(buf);
    Flow *f = NULL;

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 53);
    FAIL_IF_NULL(f);
    f->proto = IPPROTO_UDP;
    f->alproto = ALPROTO_DNS;
    f->alstate = rs_dns_state_new();
    FAIL_IF_NULL(f->alstate);

    FAIL_IF_NOT(RustDNSUDPParseResponse(f, f->alstate, NULL, buf, buflen,
                    NULL));

    UTHFreeFlow(f);
    PASS;
}

static int RustDNSUDPParserTest03 (void)
{
    uint8_t buf[] = {
        0x6F,0xB4,0x84,0x80,0x00,0x01,0x00,0x02,0x00,0x02,0x00,0x03,0x03,0x57,0x57,0x77,
        0x0B,0x56,0x56,0x56,0x56,0x56,0x56,0x56,0x56,0x56,0x56,0x56,0x03,0x55,0x55,0x55,
        0x02,0x79,0x79,0x00,0x00,0x01,0x00,0x01,0xC0,0x0C,0x00,0x05,0x00,0x01,0x00,0x00,
        0x0E,0x10,0x00,0x02,0xC0,0x10,0xC0,0x34,0x00,0x01,0x00,0x01,0x00,0x00,0x0E,0x10,
        0x00,0x04,0xC3,0xEA,0x04,0x19,0xC0,0x34,0x00,0x02,0x00,0x01,0x00,0x00,0x0E,0x10,
        0x00,0x0A,0x03,0x6E,0x73,0x31,0x03,0x61,0x67,0x62,0xC0,0x20,0xC0,0x46,0x00,0x02,
        0x00,0x01,0x00,0x00,0x0E,0x10,0x00,0x06,0x03,0x6E,0x73,0x32,0xC0,0x56,0xC0,0x52,
        0x00,0x01,0x00,0x01,0x00,0x00,0x0E,0x10,0x00,0x04,0xC3,0xEA,0x04,0x0A,0xC0,0x68,
        0x00,0x01,0x00,0x01,0x00,0x00,0x0E,0x10,0x00,0x04,0xC3,0xEA,0x05,0x14,0x00,0x00,
        0x29,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    size_t buflen = sizeof(buf);
    Flow *f = NULL;

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 53);
    FAIL_IF_NULL(f);
    f->proto = IPPROTO_UDP;
    f->alproto = ALPROTO_DNS;
    f->alstate = rs_dns_state_new();
    FAIL_IF_NULL(f->alstate);

    FAIL_IF_NOT(RustDNSUDPParseResponse(f, f->alstate, NULL, buf, buflen,
                    NULL));

    UTHFreeFlow(f);
    PASS;
}

/** \test TXT records in answer */
static int RustDNSUDPParserTest04 (void)
{
    uint8_t buf[] = {
        0xc2,0x2f,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x01,0x0a,0x41,0x41,0x41,
        0x41,0x41,0x4f,0x31,0x6b,0x51,0x41,0x05,0x3d,0x61,0x75,0x74,0x68,0x03,0x73,0x72,
        0x76,0x06,0x74,0x75,0x6e,0x6e,0x65,0x6c,0x03,0x63,0x6f,0x6d,0x00,0x00,0x10,0x00,
        0x01,
        /* answer record start */
        0xc0,0x0c,0x00,0x10,0x00,0x01,0x00,0x00,0x00,0x03,0x00,0x22,
        /* txt record starts: */
        0x20, /* <txt len 32 */  0x41,0x68,0x76,0x4d,0x41,0x41,0x4f,0x31,0x6b,0x41,0x46,
        0x45,0x35,0x54,0x45,0x39,0x51,0x54,0x6a,0x46,0x46,0x4e,0x30,0x39,0x52,0x4e,0x31,
        0x6c,0x59,0x53,0x44,0x6b,0x00, /* <txt len 0 */   0xc0,0x1d,0x00,0x02,0x00,0x01,
        0x00,0x09,0x3a,0x80,0x00,0x09,0x06,0x69,0x6f,0x64,0x69,0x6e,0x65,0xc0,0x21,0xc0,
        0x6b,0x00,0x01,0x00,0x01,0x00,0x09,0x3a,0x80,0x00,0x04,0x0a,0x1e,0x1c,0x5f
    };
    size_t buflen = sizeof(buf);
    Flow *f = NULL;

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 53);
    FAIL_IF_NULL(f);
    f->proto = IPPROTO_UDP;
    f->alproto = ALPROTO_DNS;
    f->alstate = rs_dns_state_new();
    FAIL_IF_NULL(f->alstate);

    FAIL_IF_NOT(RustDNSUDPParseResponse(f, f->alstate, NULL, buf, buflen,
                    NULL));

    UTHFreeFlow(f);
    PASS;
}

/** \test TXT records in answer, bad txtlen */
static int RustDNSUDPParserTest05 (void)
{
    uint8_t buf[] = {
        0xc2,0x2f,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x01,0x0a,0x41,0x41,0x41,
        0x41,0x41,0x4f,0x31,0x6b,0x51,0x41,0x05,0x3d,0x61,0x75,0x74,0x68,0x03,0x73,0x72,
        0x76,0x06,0x74,0x75,0x6e,0x6e,0x65,0x6c,0x03,0x63,0x6f,0x6d,0x00,0x00,0x10,0x00,
        0x01,
        /* answer record start */
        0xc0,0x0c,0x00,0x10,0x00,0x01,0x00,0x00,0x00,0x03,0x00,0x22,
        /* txt record starts: */
        0x40, /* <txt len 64 */  0x41,0x68,0x76,0x4d,0x41,0x41,0x4f,0x31,0x6b,0x41,0x46,
        0x45,0x35,0x54,0x45,0x39,0x51,0x54,0x6a,0x46,0x46,0x4e,0x30,0x39,0x52,0x4e,0x31,
        0x6c,0x59,0x53,0x44,0x6b,0x00, /* <txt len 0 */   0xc0,0x1d,0x00,0x02,0x00,0x01,
        0x00,0x09,0x3a,0x80,0x00,0x09,0x06,0x69,0x6f,0x64,0x69,0x6e,0x65,0xc0,0x21,0xc0,
        0x6b,0x00,0x01,0x00,0x01,0x00,0x09,0x3a,0x80,0x00,0x04,0x0a,0x1e,0x1c,0x5f
    };
    size_t buflen = sizeof(buf);
    Flow *f = NULL;

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 53);
    FAIL_IF_NULL(f);
    f->proto = IPPROTO_UDP;
    f->alproto = ALPROTO_DNS;
    f->alstate = rs_dns_state_new();
    FAIL_IF_NULL(f->alstate);

    FAIL_IF(RustDNSUDPParseResponse(f, f->alstate, NULL, buf, buflen,
                    NULL) != -1);

    UTHFreeFlow(f);
    PASS;
}

static void RustDNSUDPParserRegisterTests(void)
{
    UtRegisterTest("RustDNSUDPParserTest01", RustDNSUDPParserTest01);
    UtRegisterTest("RustDNSUDPParserTest02", RustDNSUDPParserTest02);
    UtRegisterTest("RustDNSUDPParserTest03", RustDNSUDPParserTest03);
    UtRegisterTest("RustDNSUDPParserTest04", RustDNSUDPParserTest04);
    UtRegisterTest("RustDNSUDPParserTest05", RustDNSUDPParserTest05);
}

#endif

#endif /* HAVE_RUST */
