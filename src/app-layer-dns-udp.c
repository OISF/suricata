/* Copyright (C) 2013 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"
#include "suricata.h"

#include "conf.h"
#include "util-misc.h"

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

#include "util-spm.h"
#include "util-unittest.h"

#include "app-layer-dns-udp.h"

#ifdef HAVE_RUST
#include "app-layer-dns-udp-rust.h"
#endif

/** \internal
 *  \brief Parse DNS request packet
 */
static int DNSUDPRequestParse(Flow *f, void *dstate,
                              AppLayerParserState *pstate,
                              uint8_t *input, uint32_t input_len,
                              void *local_data)
{
    DNSState *dns_state = (DNSState *)dstate;

    SCLogDebug("starting %u", input_len);

    if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        SCReturnInt(1);
    }

    /** \todo remove this when PP is fixed to enforce ipproto */
    if (f != NULL && f->proto != IPPROTO_UDP)
        SCReturnInt(-1);

    if (input == NULL || input_len == 0 || input_len < sizeof(DNSHeader)) {
        SCLogDebug("ilen too small, hoped for at least %"PRIuMAX, (uintmax_t)sizeof(DNSHeader));
        goto insufficient_data;
    }

    DNSHeader *dns_header = (DNSHeader *)input;
    SCLogDebug("DNS %p", dns_header);

    if (DNSValidateRequestHeader(dns_state, dns_header) < 0)
        goto bad_data;

    if (dns_state != NULL) {
        if (timercmp(&dns_state->last_req, &dns_state->last_resp, >=)) {
            if (dns_state->window <= dns_state->unreplied_cnt) {
                dns_state->window++;
            }
        }
    }

    uint16_t q;
    const uint8_t *data = input + sizeof(DNSHeader);
    for (q = 0; q < ntohs(dns_header->questions); q++) {
        uint8_t fqdn[DNS_MAX_SIZE];
        uint16_t fqdn_offset = 0;

        if (input + input_len < data + 1) {
            SCLogDebug("input buffer too small for len");
            goto insufficient_data;
        }
        SCLogDebug("query length %u", *data);

        while (*data != 0) {
            if (*data > 63) {
                /** \todo set event?*/
                goto insufficient_data;
            }
            uint8_t length = *data;

            data++;

            if (length == 0) {
                break;
            }

            if (input + input_len < data + length) {
                SCLogDebug("input buffer too small for domain of len %u", length);
                goto insufficient_data;
            }
            //PrintRawDataFp(stdout, data, qry->length);

            if ((size_t)(fqdn_offset + length + 1) < sizeof(fqdn)) {
                memcpy(fqdn + fqdn_offset, data, length);
                fqdn_offset += length;
                fqdn[fqdn_offset++] = '.';
            } else {
                /** \todo set event? */
                goto insufficient_data;
            }

            data += length;

            if (input + input_len < data + 1) {
                SCLogDebug("input buffer too small for len(2)");
                goto insufficient_data;
            }

            SCLogDebug("qry length %u", *data);
        }
        if (fqdn_offset) {
            fqdn_offset--;
        }

        data++;
        if (input + input_len < data + sizeof(DNSQueryTrailer)) {
            SCLogDebug("input buffer too small for DNSQueryTrailer");
            goto insufficient_data;
        }
        DNSQueryTrailer *trailer = (DNSQueryTrailer *)data;
        SCLogDebug("trailer type %04x class %04x", ntohs(trailer->type), ntohs(trailer->class));
        data += sizeof(DNSQueryTrailer);

        /* store our data */
        if (dns_state != NULL) {
            DNSStoreQueryInState(dns_state, fqdn, fqdn_offset,
                    ntohs(trailer->type), ntohs(trailer->class),
                    ntohs(dns_header->tx_id));
        }
    }

    if (dns_state != NULL && f != NULL) {
        dns_state->last_req = f->lastts;
    }

    SCReturnInt(1);
bad_data:
insufficient_data:
    SCReturnInt(-1);
}

/** \internal
 *  \brief DNS UDP record parser, entry function
 *
 *  Parses a DNS UDP record and fills the DNS state
 *
 */
static int DNSUDPResponseParse(Flow *f, void *dstate,
                               AppLayerParserState *pstate,
                               uint8_t *input, uint32_t input_len,
                               void *local_data)
{
    DNSState *dns_state = (DNSState *)dstate;

    SCLogDebug("starting %u", input_len);

    if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        SCReturnInt(1);
    }

    /** \todo remove this when PP is fixed to enforce ipproto */
    if (f != NULL && f->proto != IPPROTO_UDP)
        SCReturnInt(-1);

    if (input == NULL || input_len == 0 || input_len < sizeof(DNSHeader)) {
        SCLogDebug("ilen too small, hoped for at least %"PRIuMAX, (uintmax_t)sizeof(DNSHeader));
        goto insufficient_data;
    }

    DNSHeader *dns_header = (DNSHeader *)input;
    SCLogDebug("DNS %p %04x %04x", dns_header, ntohs(dns_header->tx_id), dns_header->flags);

    DNSTransaction *tx = NULL;
    int found = 0;
    if ((tx = DNSTransactionFindByTxId(dns_state, ntohs(dns_header->tx_id))) != NULL)
        found = 1;

    if (!found) {
        SCLogDebug("DNS_DECODER_EVENT_UNSOLLICITED_RESPONSE");
        DNSSetEvent(dns_state, DNS_DECODER_EVENT_UNSOLLICITED_RESPONSE);
    } else if (dns_state->unreplied_cnt > 0) {
        dns_state->unreplied_cnt--;
    }

    if (DNSValidateResponseHeader(dns_state, dns_header) < 0)
        goto bad_data;

    SCLogDebug("queries %04x", ntohs(dns_header->questions));

    uint16_t q;
    const uint8_t *data = input + sizeof(DNSHeader);
    for (q = 0; q < ntohs(dns_header->questions); q++) {
        uint8_t fqdn[DNS_MAX_SIZE];
        uint16_t fqdn_offset = 0;

        if (input + input_len < data + 1) {
            SCLogDebug("input buffer too small for len");
            goto insufficient_data;
        }
        SCLogDebug("qry length %u", *data);

        while (*data != 0) {
            uint8_t length = *data;
            data++;

            if (length == 0)
                break;

            if (input + input_len < data + length) {
                SCLogDebug("input buffer too small for domain of len %u", length);
                goto insufficient_data;
            }
            //PrintRawDataFp(stdout, data, length);

            if ((size_t)(fqdn_offset + length + 1) < sizeof(fqdn)) {
                memcpy(fqdn + fqdn_offset, data, length);
                fqdn_offset += length;
                fqdn[fqdn_offset++] = '.';
            }

            data += length;

            if (input + input_len < data + 1) {
                SCLogDebug("input buffer too small for len");
                goto insufficient_data;
            }

            SCLogDebug("length %u", *data);
        }
        if (fqdn_offset) {
            fqdn_offset--;
        }

        data++;
        if (input + input_len < data + sizeof(DNSQueryTrailer)) {
            SCLogDebug("input buffer too small for DNSQueryTrailer");
            goto insufficient_data;
        }
#if DEBUG
        DNSQueryTrailer *trailer = (DNSQueryTrailer *)data;
        SCLogDebug("trailer type %04x class %04x", ntohs(trailer->type), ntohs(trailer->class));
#endif
        data += sizeof(DNSQueryTrailer);
    }

    SCLogDebug("answer_rr %04x", ntohs(dns_header->answer_rr));
    for (q = 0; q < ntohs(dns_header->answer_rr); q++) {
        data = DNSReponseParse(dns_state, dns_header, q, DNS_LIST_ANSWER,
                input, input_len, data);
        if (data == NULL) {
            goto insufficient_data;
        }
    }

    SCLogDebug("authority_rr %04x", ntohs(dns_header->authority_rr));
    for (q = 0; q < ntohs(dns_header->authority_rr); q++) {
        data = DNSReponseParse(dns_state, dns_header, q, DNS_LIST_AUTHORITY,
                input, input_len, data);
        if (data == NULL) {
            goto insufficient_data;
        }
    }

    /* if we previously didn't have a tx, it could have been created by the
     * above code, so lets check again */
    if (tx == NULL) {
        tx = DNSTransactionFindByTxId(dns_state, ntohs(dns_header->tx_id));
    }
    if (tx != NULL) {
        /* parse rcode, e.g. "noerror" or "nxdomain" */
        uint8_t rcode = ntohs(dns_header->flags) & 0x0F;
        if (rcode <= DNS_RCODE_NOTZONE) {
            SCLogDebug("rcode %u", rcode);
            tx->rcode = rcode;
        } else {
            /* this is not invalid, rcodes can be user defined */
            SCLogDebug("unexpected DNS rcode %u", rcode);
        }

        if (ntohs(dns_header->flags) & 0x0080) {
            SCLogDebug("recursion desired");
            tx->recursion_desired = 1;
        }

        tx->replied = 1;
    }
    if (f != NULL) {
        dns_state->last_resp = f->lastts;
    }
    SCReturnInt(1);

bad_data:
insufficient_data:
    DNSSetEvent(dns_state, DNS_DECODER_EVENT_MALFORMED_DATA);
    SCReturnInt(-1);
}

static uint16_t DNSUdpProbingParser(uint8_t *input, uint32_t ilen, uint32_t *offset)
{
    if (ilen == 0 || ilen < sizeof(DNSHeader)) {
        SCLogDebug("ilen too small, hoped for at least %"PRIuMAX, (uintmax_t)sizeof(DNSHeader));
        return ALPROTO_UNKNOWN;
    }

    if (DNSUDPRequestParse(NULL, NULL, NULL, input, ilen, NULL) == -1)
        return ALPROTO_FAILED;

    return ALPROTO_DNS;
}

static void DNSUDPConfigure(void)
{
    uint32_t request_flood = DNS_CONFIG_DEFAULT_REQUEST_FLOOD;
    uint32_t state_memcap = DNS_CONFIG_DEFAULT_STATE_MEMCAP;
    uint64_t global_memcap = DNS_CONFIG_DEFAULT_GLOBAL_MEMCAP;

    ConfNode *p = ConfGetNode("app-layer.protocols.dns.request-flood");
    if (p != NULL) {
        uint32_t value;
        if (ParseSizeStringU32(p->val, &value) < 0) {
            SCLogError(SC_ERR_DNS_CONFIG, "invalid value for request-flood %s", p->val);
        } else {
            request_flood = value;
        }
    }
    SCLogConfig("DNS request flood protection level: %u", request_flood);
    DNSConfigSetRequestFlood(request_flood);

    p = ConfGetNode("app-layer.protocols.dns.state-memcap");
    if (p != NULL) {
        uint32_t value;
        if (ParseSizeStringU32(p->val, &value) < 0) {
            SCLogError(SC_ERR_DNS_CONFIG, "invalid value for state-memcap %s", p->val);
        } else {
            state_memcap = value;
        }
    }
    SCLogConfig("DNS per flow memcap (state-memcap): %u", state_memcap);
    DNSConfigSetStateMemcap(state_memcap);

    p = ConfGetNode("app-layer.protocols.dns.global-memcap");
    if (p != NULL) {
        uint64_t value;
        if (ParseSizeStringU64(p->val, &value) < 0) {
            SCLogError(SC_ERR_DNS_CONFIG, "invalid value for global-memcap %s", p->val);
        } else {
            global_memcap = value;
        }
    }
    SCLogConfig("DNS global memcap: %"PRIu64, global_memcap);
    DNSConfigSetGlobalMemcap(global_memcap);
}

void RegisterDNSUDPParsers(void)
{
    const char *proto_name = "dns";

#ifdef HAVE_RUST
    return RegisterRustDNSUDPParsers();
#endif

    /** DNS */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("udp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_DNS, proto_name);

        if (RunmodeIsUnittests()) {
            AppLayerProtoDetectPPRegister(IPPROTO_UDP,
                                          "53",
                                          ALPROTO_DNS,
                                          0, sizeof(DNSHeader),
                                          STREAM_TOSERVER,
                                          DNSUdpProbingParser,
                                          NULL);
        } else {
            int have_cfg = AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP,
                                                proto_name, ALPROTO_DNS,
                                                0, sizeof(DNSHeader),
                                                DNSUdpProbingParser, NULL);
            /* if we have no config, we enable the default port 53 */
            if (!have_cfg) {
#ifndef AFLFUZZ_APPLAYER
                SCLogWarning(SC_ERR_DNS_CONFIG, "no DNS UDP config found, "
                                                "enabling DNS detection on "
                                                "port 53.");
#endif
                AppLayerProtoDetectPPRegister(IPPROTO_UDP, "53",
                                   ALPROTO_DNS, 0, sizeof(DNSHeader),
                                   STREAM_TOSERVER, DNSUdpProbingParser, NULL);
            }
        }
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
                  proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_DNS, STREAM_TOSERVER,
                                     DNSUDPRequestParse);
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_DNS, STREAM_TOCLIENT,
                                     DNSUDPResponseParse);
        AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_DNS, DNSStateAlloc,
                                         DNSStateFree);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_DNS,
                                         DNSStateTransactionFree);

        AppLayerParserRegisterGetEventsFunc(IPPROTO_UDP, ALPROTO_DNS, DNSGetEvents);
        AppLayerParserRegisterHasEventsFunc(IPPROTO_UDP, ALPROTO_DNS, DNSHasEvents);
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_UDP, ALPROTO_DNS,
                                               DNSStateHasTxDetectState,
                                               DNSGetTxDetectState, DNSSetTxDetectState);

        AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_DNS,
                                    DNSGetTx);
        AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_DNS,
                                       DNSGetTxCnt);
        AppLayerParserRegisterLoggerFuncs(IPPROTO_UDP, ALPROTO_DNS, DNSGetTxLogged,
                                          DNSSetTxLogged);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP, ALPROTO_DNS,
                                                   DNSGetAlstateProgress);
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_DNS,
                                                               DNSGetAlstateProgressCompletionStatus);

        DNSAppLayerRegisterGetEventInfo(IPPROTO_UDP, ALPROTO_DNS);

        DNSUDPConfigure();
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_UDP, ALPROTO_DNS, DNSUDPParserRegisterTests);
#endif
}

/* UNITTESTS */
#ifdef UNITTESTS
#include "util-unittest-helper.h"

static int DNSUDPParserTest01 (void)
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
    f->alstate = DNSStateAlloc();

    FAIL_IF_NOT(DNSUDPResponseParse(f, f->alstate, NULL, buf, buflen, NULL));

    UTHFreeFlow(f);
    PASS;
}

static int DNSUDPParserTest02 (void)
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
    f->alstate = DNSStateAlloc();

    FAIL_IF_NOT(DNSUDPResponseParse(f, f->alstate, NULL, buf, buflen, NULL));

    UTHFreeFlow(f);
    PASS;
}

static int DNSUDPParserTest03 (void)
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
    f->alstate = DNSStateAlloc();

    FAIL_IF_NOT(DNSUDPResponseParse(f, f->alstate, NULL, buf, buflen, NULL));

    UTHFreeFlow(f);
    PASS;
}

/** \test TXT records in answer */
static int DNSUDPParserTest04 (void)
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
    f->alstate = DNSStateAlloc();

    FAIL_IF_NOT(DNSUDPResponseParse(f, f->alstate, NULL, buf, buflen, NULL));

    UTHFreeFlow(f);
    PASS;
}

/** \test TXT records in answer, bad txtlen */
static int DNSUDPParserTest05 (void)
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
    f->alstate = DNSStateAlloc();

    FAIL_IF(DNSUDPResponseParse(f, f->alstate, NULL, buf, buflen, NULL) != -1);

    UTHFreeFlow(f);
    PASS;
}

/**
 * \test Test subsequent requests before response.
 *
 * This test sends 2 DNS requests on the same state then sends the response
 * to the first request checking that it is seen and associated with the
 * transaction.
 */
static int DNSUDPParserTestDelayedResponse(void)
{
    /* DNS request:
     * - Flags: 0x0100 Standard query
     * - A www.google.com
     */
    uint8_t req[] = {
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
    };
    size_t reqlen = sizeof(req);

    /* DNS response:
     * - Flags: 0x8180 Standard query response, no error
     * - www.google.com A 24.244.4.56
     * - www.google.com A 24.244.4.54
     * - www.google.com A 24.244.4.57
     * - www.google.com A 24.244.4.55
     * - www.google.com A 24.244.4.52
     * - www.google.com A 24.244.4.53
     * - www.google.com A 24.244.4.58
     * - www.google.com A 24.244.4.59
     */
    uint8_t res[] = {
        0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x38,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x39,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x34,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x35,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x36,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x3b,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x37,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x3a
    };
    size_t reslen = sizeof(res);

    DNSState *state = DNSStateAlloc();
    FAIL_IF_NULL(state);
    Flow *f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 53);
    FAIL_IF_NULL(f);
    f->proto = IPPROTO_UDP;
    f->alproto = ALPROTO_DNS;
    f->alstate = state;

    /* Send to requests with an incrementing tx id. */
    FAIL_IF_NOT(DNSUDPRequestParse(f, f->alstate, NULL, req, reqlen, NULL));
    req[1] = 0x02;
    FAIL_IF_NOT(DNSUDPRequestParse(f, f->alstate, NULL, req, reqlen, NULL));

    /* Send response to the first request. */
    FAIL_IF_NOT(DNSUDPResponseParse(f, f->alstate, NULL, res, reslen, NULL));
    DNSTransaction *tx = TAILQ_FIRST(&state->tx_list);
    FAIL_IF_NULL(tx);
    FAIL_IF_NOT(tx->replied);

    /* Also free's state. */
    UTHFreeFlow(f);

    PASS;
}

/**
 * \test Test entering the flood/givenup state.
 */
static int DNSUDPParserTestFlood(void)
{
    /* DNS request:
     * - Flags: 0x0100 Standard query
     * - A www.google.com
     */
    uint8_t req[] = {
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
    };
    size_t reqlen = sizeof(req);

    DNSState *state = DNSStateAlloc();
    FAIL_IF_NULL(state);
    Flow *f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 53);
    FAIL_IF_NULL(f);
    f->proto = IPPROTO_UDP;
    f->alproto = ALPROTO_DNS;
    f->alstate = state;

    uint16_t txid;
    for (txid = 1; txid <= DNS_CONFIG_DEFAULT_REQUEST_FLOOD + 1; txid++) {
        req[0] = (txid >> 8) & 0xff;
        req[1] = txid & 0xff;
        FAIL_IF_NOT(DNSUDPRequestParse(f, f->alstate, NULL, req, reqlen, NULL));
        FAIL_IF(state->givenup);
    }

    /* With one more request we should enter a flooded state. */
    txid++;
    req[0] = (txid >> 8) & 0xff;
    req[1] = txid & 0xff;
    FAIL_IF_NOT(DNSUDPRequestParse(f, f->alstate, NULL, req, reqlen, NULL));
    FAIL_IF(!state->givenup);

    /* Also free's state. */
    UTHFreeFlow(f);

    PASS;
}

static int DNSUDPParserTestLostResponse(void)
{
    /* DNS request:
     * - Flags: 0x0100 Standard query
     * - A www.google.com
     */
    uint8_t req[] = {
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
    };
    size_t reqlen = sizeof(req);

    uint8_t res[] = {
        0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x38,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x39,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x34,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x35,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x36,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x3b,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x37,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x18, 0xf4, 0x04, 0x3a
    };
    size_t reslen = sizeof(res);

    DNSTransaction *tx;
    DNSState *state = DNSStateAlloc();
    FAIL_IF_NULL(state);
    Flow *f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 53);
    FAIL_IF_NULL(f);
    f->proto = IPPROTO_UDP;
    f->alproto = ALPROTO_DNS;
    f->alstate = state;

    /* First request. */
    req[1] = 0x01;
    FAIL_IF_NOT(DNSUDPRequestParse(f, f->alstate, NULL, req, reqlen, NULL));
    FAIL_IF_NOT(state->transaction_max == 1);
    FAIL_IF_NOT(state->unreplied_cnt == 1);
    FAIL_IF_NOT(state->window == 1);

    /* Second request. */
    req[1] = 0x02;
    FAIL_IF_NOT(DNSUDPRequestParse(f, f->alstate, NULL, req, reqlen, NULL));
    FAIL_IF_NOT(state->transaction_max == 2);
    FAIL_IF_NOT(state->unreplied_cnt == 2);
    FAIL_IF_NOT(state->window == 2);

    /* Third request. */
    req[1] = 0x03;
    FAIL_IF_NOT(DNSUDPRequestParse(f, f->alstate, NULL, req, reqlen, NULL));
    FAIL_IF_NOT(state->transaction_max == 3);
    FAIL_IF_NOT(state->unreplied_cnt == 3);
    FAIL_IF_NOT(state->window == 3);

    /* Now respond to the second. */
    res[1] = 0x02;
    FAIL_IF_NOT(DNSUDPResponseParse(f, f->alstate, NULL, res, reslen, NULL));
    FAIL_IF_NOT(state->unreplied_cnt == 2);
    FAIL_IF_NOT(state->window == 3);
    tx = TAILQ_FIRST(&state->tx_list);
    FAIL_IF_NULL(tx);
    FAIL_IF(tx->replied);
    FAIL_IF(tx->reply_lost);

    /* Send a 4th request. */
    req[1] = 0x04;
    FAIL_IF_NOT(DNSUDPRequestParse(f, f->alstate, NULL, req, reqlen, NULL));
    FAIL_IF_NOT(state->unreplied_cnt == 3);
    FAIL_IF(state->window != 3);
    FAIL_IF_NOT(state->transaction_max == 4);

    /* Response to the third request. */
    res[1] = 0x03;
    FAIL_IF_NOT(DNSUDPResponseParse(f, f->alstate, NULL, res, reslen, NULL));
    FAIL_IF_NOT(state->unreplied_cnt == 2);
    FAIL_IF_NOT(state->window == 3);
    tx = TAILQ_FIRST(&state->tx_list);
    FAIL_IF_NULL(tx);
    FAIL_IF(tx->replied);
    FAIL_IF(!tx->reply_lost);

    /* Also free's state. */
    UTHFreeFlow(f);

    PASS;
}

void DNSUDPParserRegisterTests(void)
{
    UtRegisterTest("DNSUDPParserTest01", DNSUDPParserTest01);
    UtRegisterTest("DNSUDPParserTest02", DNSUDPParserTest02);
    UtRegisterTest("DNSUDPParserTest03", DNSUDPParserTest03);
    UtRegisterTest("DNSUDPParserTest04", DNSUDPParserTest04);
    UtRegisterTest("DNSUDPParserTest05", DNSUDPParserTest05);
    UtRegisterTest("DNSUDPParserTestFlood", DNSUDPParserTestFlood);
    UtRegisterTest("DNSUDPParserTestDelayedResponse",
        DNSUDPParserTestDelayedResponse);
    UtRegisterTest("DNSUDPParserTestLostResponse",
        DNSUDPParserTestLostResponse);
}
#endif
