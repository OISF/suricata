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

#include "app-layer-dns-tcp.h"

typedef struct DNSTcpHeader_ {
    uint16_t len;
    DNSHeader header;
} __attribute__((__packed__)) DNSTcpHeader;

static int ParserBufferAdd(ParserBuffer *buffer, const uint8_t *data,
    uint32_t len)
{
    if (buffer->size == 0) {
        buffer->buffer = SCCalloc(1, len);
        if (unlikely(buffer->buffer == NULL)) {
            return 0;
        }
        buffer->size = len;
    }
    else if (buffer->len + len > buffer->size) {
        uint8_t *tmp = SCRealloc(buffer->buffer, buffer->len + len);
        if (unlikely(tmp == NULL)) {
            return 0;
        }
        buffer->buffer = tmp;
        buffer->size = buffer->len + len;
    }
    memcpy(buffer->buffer + buffer->len, data, len);
    buffer->len += len;

    return 1;
}

static void ParserBufferReset(ParserBuffer *buffer)
{
    buffer->offset = 0;
    buffer->len = 0;
}

static int ParserBufferAdvance(ParserBuffer *buffer, uint32_t len)
{
    if (buffer->offset + len > buffer->len) {
        return 0;
    }
    buffer->offset += len;
    return 1;
}

/**
 * \brief Trim a ParserBuffer.
 *
 * Trimming a buffer moves the data in the buffer up to the front of
 * the buffer freeing up room at the end for more incoming data.
 *
 * \param buffer The buffer to trim.
 */
static void ParserBufferTrim(ParserBuffer *buffer)
{
    if (buffer->offset == buffer->len) {
        ParserBufferReset(buffer);
    }
    else if (buffer->offset > 0) {
        memmove(buffer->buffer, buffer->buffer + buffer->offset,
            buffer->len - buffer->offset);
        buffer->len = buffer->len - buffer->offset;
        buffer->offset = 0;
    }
}

static int DNSRequestParseData(Flow *f, DNSState *dns_state,
    const uint8_t *input, const uint32_t input_len)
{
    uint64_t tx_id = rs_dns_state_parse_request(dns_state->rs_state, input,
        input_len);

    if (tx_id > 0) {
        DNSTransaction *tx = DNSTransactionAlloc(dns_state, 0);
        BUG_ON(tx == NULL);
        dns_state->transaction_max = tx_id;
        dns_state->curr = tx;
        tx->tx_num = tx_id;
        tx->rs_tx = rs_dns_state_tx_get(dns_state->rs_state, tx_id - 1);
        BUG_ON(tx->rs_tx == NULL);
        TAILQ_INSERT_TAIL(&dns_state->tx_list, tx, next);
    }

    SCReturnInt((tx_id > 0 ? 1 : -1));
}

/** \internal
 *  \brief Parse DNS request packet
 */
static int DNSTCPRequestParse(Flow *f, void *dstate,
                              AppLayerParserState *pstate,
                              uint8_t *input, uint32_t input_len,
                              void *local_data)
{
    DNSState *dns_state = (DNSState *)dstate;
    ParserBuffer *buffer = &dns_state->buffer;
    SCLogDebug("starting %u", input_len);

    if (input == NULL && AppLayerParserStateIssetFlag(pstate,
            APP_LAYER_PARSER_EOF)) {
        SCReturnInt(1);
    }

    /** \todo remove this when PP is fixed to enforce ipproto */
    if (f != NULL && f->proto != IPPROTO_TCP) {
        SCReturnInt(-1);
    }

    /* probably a rst/fin sending an eof */
    if (input == NULL || input_len == 0) {
        goto insufficient_data;
    }

    if (buffer->len) {
        if (!ParserBufferAdd(buffer, input, input_len)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory to buffer "
                "DNS request data");
            return -1;
        }
        input = buffer->buffer;
        input_len = buffer->len;
    }

    while (input_len >= sizeof(DNSTcpHeader)) {

        DNSTcpHeader *header = (DNSTcpHeader *)input;

        uint16_t hlen = ntohs(header->len);

        if (hlen < sizeof(DNSHeader)) {
            /* Looks like a bogus header or not DNS traffic as the
             * length value isn't even large enought for a DNS
             * header. */
            goto bad_data;
        }

        if (hlen > input_len - 2) {
            /* Not enough data, thats why we have a buffer. */
            break;
        }

        if (DNSRequestParseData(f, dns_state, input + 2, hlen) < 0) {
            goto bad_data;
        }

        input_len -= (2 + hlen);
        input += (2 + hlen);
    }

    if (buffer->len) {
        /* Advance the buffer by the number of bytes that were taken. */
        ParserBufferAdvance(buffer, buffer->len - input_len);
        ParserBufferTrim(buffer);
    } else if (input_len) {
        /* We have remaining unbuffered data, start buffering. */
        ParserBufferAdd(buffer, input, input_len);
    }

    SCReturnInt(1);
insufficient_data:
bad_data:
    ParserBufferReset(buffer);
    SCReturnInt(-1);

}

static int DNSResponseParseData(Flow *f, DNSState *dns_state,
    const uint8_t *input, const uint32_t input_len)
{
    uint64_t tx_id = rs_dns_state_parse_response(dns_state->rs_state, input,
        input_len);
    BUG_ON(tx_id == 0);

    if (tx_id > dns_state->transaction_max) {
        DNSTransaction *tx = DNSTransactionAlloc(dns_state, 0);
        BUG_ON(tx == NULL);
        dns_state->transaction_max = tx_id;
        dns_state->curr = tx;
        tx->tx_num = tx_id;
        tx->rs_tx = rs_dns_state_tx_get(dns_state->rs_state, tx_id - 1);
        BUG_ON(tx->rs_tx == NULL);
        TAILQ_INSERT_TAIL(&dns_state->tx_list, tx, next);
    }

    SCReturnInt((tx_id > 0 ? 1 : -1));
}

/** \internal
 *  \brief DNS TCP record parser, entry function
 *
 *  Parses a DNS TCP record and fills the DNS state
 *
 *  As TCP records can be 64k we'll have to buffer the data. Streaming parsing
 *  would have been _very_ tricky due to the way names are compressed in DNS
 *
 */
static int DNSTCPResponseParse(Flow *f, void *dstate,
                               AppLayerParserState *pstate,
                               uint8_t *input, uint32_t input_len,
                               void *local_data)
{
    DNSState *dns_state = (DNSState *)dstate;
    ParserBuffer *buffer = &dns_state->buffer;

    if (input == NULL && AppLayerParserStateIssetFlag(pstate,
            APP_LAYER_PARSER_EOF)) {
        SCReturnInt(1);
    }

    /** \todo remove this when PP is fixed to enforce ipproto */
    if (f != NULL && f->proto != IPPROTO_TCP) {
        SCReturnInt(-1);
    }

    /* probably a rst/fin sending an eof */
    if (input == NULL || input_len == 0) {
        goto insufficient_data;
    }

    if (buffer->len) {
        if (!ParserBufferAdd(buffer, input, input_len)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory to buffer "
                "DNS request data");
            return -1;
        }
        input = buffer->buffer;
        input_len = buffer->len;
    }
        
    while (input_len >= sizeof(DNSTcpHeader)) {

        DNSTcpHeader *header = (DNSTcpHeader *)input;
        uint16_t hlen = ntohs(header->len);

        if (hlen < sizeof(DNSHeader)) {
            /* Looks like a bogus header or not DNS traffic as the
             * length value isn't even large enought for a DNS
             * header. */
            goto bad_data;
        }

        if (hlen > input_len - 2) {
            /* Not enough data, thats why we have a buffer. */
            break;
        }

        if (DNSResponseParseData(f, dns_state, input + 2, hlen) < 0) {
            goto bad_data;
        }

        input_len -= (2 + hlen);
        input += (2 + hlen);
    }

    if (buffer->len) {
        /* Advance the buffer by the number of bytes that were taken. */
        ParserBufferAdvance(buffer, buffer->len - input_len);
        ParserBufferTrim(buffer);
    } else if (input_len) {
        ParserBufferAdd(buffer, input, input_len);
    }

    SCReturnInt(1);
insufficient_data:
bad_data:
    ParserBufferReset(buffer);
    SCReturnInt(-1);
}

static uint16_t DNSTcpProbingParser(uint8_t *input, uint32_t ilen,
    uint32_t *offset)
{
    if (ilen == 0 || ilen < sizeof(DNSTcpHeader)) {
        return ALPROTO_UNKNOWN;
    }

    DNSTcpHeader *dns_header = (DNSTcpHeader *)input;
    if (ntohs(dns_header->len) < sizeof(DNSHeader)) {
        return ALPROTO_FAILED;
    }

    if (rs_dns_probe(input + 2, ntohs(dns_header->len))) {
        return ALPROTO_DNS;
    }

    return ALPROTO_FAILED;
}

void RegisterDNSTCPParsers(void)
{
    char *proto_name = "dns";

    /** DNS */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_DNS, proto_name);

        if (RunmodeIsUnittests()) {
            AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                          "53",
                                          ALPROTO_DNS,
                                          0, sizeof(DNSTcpHeader),
                                          STREAM_TOSERVER,
                                          DNSTcpProbingParser, NULL);
        } else {
            int have_cfg = AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                                                proto_name, ALPROTO_DNS,
                                                0, sizeof(DNSTcpHeader),
                                                DNSTcpProbingParser,
                                                DNSTcpProbingParser);
            /* if we have no config, we enable the default port 53 */
            if (!have_cfg) {
                SCLogWarning(SC_ERR_DNS_CONFIG, "no DNS TCP config found, "
                                                "enabling DNS detection on "
                                                "port 53.");
                AppLayerProtoDetectPPRegister(IPPROTO_TCP, "53",
                                   ALPROTO_DNS, 0, sizeof(DNSTcpHeader),
                                   STREAM_TOSERVER, DNSTcpProbingParser,
                                   DNSTcpProbingParser);
            }
        }
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
                  proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_DNS, STREAM_TOSERVER,
                                     DNSTCPRequestParse);
        AppLayerParserRegisterParser(IPPROTO_TCP , ALPROTO_DNS, STREAM_TOCLIENT,
                                     DNSTCPResponseParse);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_DNS, DNSStateAlloc,
                                         DNSStateFree);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_DNS,
                                         DNSStateTransactionFree);

        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_DNS, DNSGetEvents);
        AppLayerParserRegisterHasEventsFunc(IPPROTO_TCP, ALPROTO_DNS, DNSHasEvents);
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_DNS,
                                               DNSStateHasTxDetectState,
                                               DNSGetTxDetectState, DNSSetTxDetectState);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_DNS, DNSGetTx);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_DNS, DNSGetTxCnt);
        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_DNS, DNSGetTxLogged,
                                          DNSSetTxLogged);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_DNS,
                                                   DNSGetAlstateProgress);
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_DNS,
                                                               DNSGetAlstateProgressCompletionStatus);
        DNSAppLayerRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_DNS);
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_DNS,
        DNSTCPParserRegisterTests);
#endif

    return;
}

/* UNITTESTS */
#ifdef UNITTESTS

#include "util-unittest-helper.h"

static int DNSTCPParserTestMultiRecord(void)
{
    /* This is a buffer containing 20 DNS requests each prefixed by
     * the request length for transport over TCP.  It was generated with Scapy,
     * where each request is:
     *    DNS(id=i, rd=1, qd=DNSQR(qname="%d.google.com" % i, qtype="A"))
     * where i is 0 to 19.
     */
    uint8_t req[] = {
        0x00, 0x1e, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x30,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x31,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x02, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x32,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x03, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x33,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x34,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x35,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x06, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x36,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x07, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x37,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x08, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x38,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x09, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x39,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1f, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x31,
        0x30, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x1f, 0x00, 0x0b, 0x01, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x31, 0x31, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x1f, 0x00, 0x0c, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x31, 0x32, 0x06, 0x67, 0x6f, 0x6f, 0x67,
        0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x1f, 0x00, 0x0d, 0x01,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x31, 0x33, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x1f, 0x00, 0x0e,
        0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x31, 0x34, 0x06, 0x67, 0x6f,
        0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x1f, 0x00,
        0x0f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x31, 0x35, 0x06, 0x67,
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f,
        0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x1f,
        0x00, 0x10, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x31, 0x36, 0x06,
        0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x1f, 0x00, 0x11, 0x01, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x31, 0x37,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1f, 0x00, 0x12, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x31,
        0x38, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x1f, 0x00, 0x13, 0x01, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x31, 0x39, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
        0x00, 0x01
    };
    size_t reqlen = sizeof(req);

    DNSState *state = DNSStateAlloc();
    FAIL_IF_NULL(state);
    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 53);
    FAIL_IF_NULL(f);
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_DNS;
    f->alstate = state;

    FAIL_IF_NOT(DNSTCPRequestParse(f, f->alstate, NULL, req, reqlen, NULL));
    FAIL_IF(state->transaction_max != 20);

    UTHFreeFlow(f);
    PASS;
}

static int DNSTCPParserTestMultiRecordPartials(void)
{
    /* This is a buffer containing 20 DNS requests each prefixed by
     * the request length for transport over TCP.  It was generated with Scapy,
     * where each request is:
     *    DNS(id=i, rd=1, qd=DNSQR(qname="%d.google.com" % i, qtype="A"))
     * where i is 0 to 19.
     */
    uint8_t req[] = {
        0x00, 0x1e, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x30,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x31,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x02, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x32,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x03, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x33,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x34,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x35,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x06, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x36,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x07, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x37,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x08, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x38,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1e, 0x00, 0x09, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x39,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1f, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x31,
        0x30, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x1f, 0x00, 0x0b, 0x01, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x31, 0x31, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x1f, 0x00, 0x0c, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x31, 0x32, 0x06, 0x67, 0x6f, 0x6f, 0x67,
        0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x1f, 0x00, 0x0d, 0x01,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x31, 0x33, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x1f, 0x00, 0x0e,
        0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x31, 0x34, 0x06, 0x67, 0x6f,
        0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x1f, 0x00,
        0x0f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x31, 0x35, 0x06, 0x67,
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f,
        0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x1f,
        0x00, 0x10, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x31, 0x36, 0x06,
        0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x1f, 0x00, 0x11, 0x01, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x31, 0x37,
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x1f, 0x00, 0x12, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x31,
        0x38, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x1f, 0x00, 0x13, 0x01, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x31, 0x39, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
        0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
        0x00, 0x01
    };
    size_t reqlen = sizeof(req);

    DNSState *state = DNSStateAlloc();
    FAIL_IF_NULL(state);
    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 53);
    FAIL_IF_NULL(f);
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_DNS;
    f->alstate = state;

    /* Dribble the bytes in one by one. */
    for (size_t i = 0; i < reqlen; i++) {
        FAIL_IF_NOT(
            DNSTCPRequestParse(f, f->alstate, NULL, req + i, 1, NULL));
    }

    FAIL_IF(state->transaction_max != 20);

    UTHFreeFlow(f);
    PASS;
}

void DNSTCPParserRegisterTests(void)
{
    UtRegisterTest("DNSTCPParserTestMultiRecord", DNSTCPParserTestMultiRecord);
    UtRegisterTest("DNSTCPParserTestMultiRecordPartials",
        DNSTCPParserTestMultiRecordPartials);
}

#endif /* UNITTESTS */
