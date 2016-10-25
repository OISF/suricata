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

struct DNSTcpHeader_ {
    uint16_t len;
    uint16_t tx_id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answer_rr;
    uint16_t authority_rr;
    uint16_t additional_rr;
} __attribute__((__packed__));
typedef struct DNSTcpHeader_ DNSTcpHeader;

/** \internal
 *  \param input_len at least enough for the DNSTcpHeader
 */
static int DNSTCPRequestParseProbe(uint8_t *input, uint32_t input_len)
{
#ifdef DEBUG
    BUG_ON(input_len < sizeof(DNSTcpHeader));
#endif
    SCLogDebug("starting %u", input_len);

    DNSTcpHeader *dns_tcp_header = (DNSTcpHeader *)input;
    if (ntohs(dns_tcp_header->len) < sizeof(DNSHeader)) {
        goto bad_data;
    }
    if (ntohs(dns_tcp_header->len) >= input_len) {
        goto insufficient_data;
    }

    input += 2;
    input_len -= 2;
    DNSHeader *dns_header = (DNSHeader *)input;

    uint16_t q;
    const uint8_t *data = input + sizeof(DNSHeader);

    for (q = 0; q < ntohs(dns_header->questions); q++) {
        uint16_t fqdn_offset = 0;

        if (input + input_len < data + 1) {
            SCLogDebug("input buffer too small for len field");
            goto insufficient_data;
        }
        SCLogDebug("query length %u", *data);

        while (*data != 0) {
            if (*data > 63) {
                /** \todo set event?*/
                goto bad_data;
            }
            uint8_t length = *data;

            data++;

            if (length > 0) {
                if (input + input_len < data + length) {
                    SCLogDebug("input buffer too small for domain of len %u", length);
                    goto insufficient_data;
                }
                //PrintRawDataFp(stdout, data, qry->length);

                if ((fqdn_offset + length + 1) < DNS_MAX_SIZE) {
                    fqdn_offset += length;
                } else {
                    /** \todo set event? */
                    goto bad_data;
                }
            }

            data += length;

            if (input + input_len < data + 1) {
                SCLogDebug("input buffer too small for new len");
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
#ifdef DEBUG
        DNSQueryTrailer *trailer = (DNSQueryTrailer *)data;
        SCLogDebug("trailer type %04x class %04x", ntohs(trailer->type), ntohs(trailer->class));
#endif
        data += sizeof(DNSQueryTrailer);
    }

    SCReturnInt(1);
insufficient_data:
    SCReturnInt(0);
bad_data:
    SCReturnInt(-1);
}

static int BufferData(DNSState *dns_state, uint8_t *data, uint16_t len)
{
    if (dns_state->buffer == NULL) {
        if (DNSCheckMemcap(0xffff, dns_state) < 0)
            return -1;

        /** \todo be smarter about this, like use a pool or several pools for
         *        chunks of various sizes */
        dns_state->buffer = SCMalloc(0xffff);
        if (dns_state->buffer == NULL) {
            return -1;
        }
        DNSIncrMemcap(0xffff, dns_state);
    }

    if ((uint32_t)len + (uint32_t)dns_state->offset > (uint32_t)dns_state->record_len) {
        SCLogDebug("oh my, we have more data than the max record size. What do we do. WHAT DO WE DOOOOO!");
#ifdef DEBUG
        BUG_ON(1);
#endif
        len = dns_state->record_len - dns_state->offset;
    }

    memcpy(dns_state->buffer + dns_state->offset, data, len);
    dns_state->offset += len;
    return 0;
}

static void BufferReset(DNSState *dns_state)
{
    dns_state->record_len = 0;
    dns_state->offset = 0;
}

static int DNSRequestParseData(Flow *f, DNSState *dns_state, const uint8_t *input, const uint32_t input_len)
{
    DNSHeader *dns_header = (DNSHeader *)input;

    if (DNSValidateRequestHeader(dns_state, dns_header) < 0)
        goto bad_data;

    //SCLogInfo("ID %04x", ntohs(dns_header->tx_id));

    uint16_t q;
    const uint8_t *data = input + sizeof(DNSHeader);

    //PrintRawDataFp(stdout, (uint8_t*)data, input_len - (data - input));

    for (q = 0; q < ntohs(dns_header->questions); q++) {
        uint8_t fqdn[DNS_MAX_SIZE];
        uint16_t fqdn_offset = 0;

        if (input + input_len < data + 1) {
            SCLogDebug("input buffer too small for DNSTcpQuery");
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

            if (length > 0) {
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
            }

            data += length;

            if (input + input_len < data + 1) {
                SCLogDebug("input buffer too small for DNSTcpQuery(2)");
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

    SCReturnInt(1);
bad_data:
insufficient_data:
    SCReturnInt(-1);

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
    SCLogDebug("starting %u", input_len);

    if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        SCReturnInt(1);
    }

    /** \todo remove this when PP is fixed to enforce ipproto */
    if (f != NULL && f->proto != IPPROTO_TCP)
        SCReturnInt(-1);

    /* probably a rst/fin sending an eof */
    if (input == NULL || input_len == 0) {
        goto insufficient_data;
    }

next_record:
    /* if this is the beginning of a record, we need at least the header */
    if (dns_state->offset == 0 && input_len < sizeof(DNSTcpHeader)) {
        SCLogDebug("ilen too small, hoped for at least %"PRIuMAX, (uintmax_t)sizeof(DNSTcpHeader));
        goto insufficient_data;
    }
    SCLogDebug("input_len %u offset %u record %u",
            input_len, dns_state->offset, dns_state->record_len);

    /* this is the first data of this record */
    if (dns_state->offset == 0) {
        DNSTcpHeader *dns_tcp_header = (DNSTcpHeader *)input;
        SCLogDebug("DNS %p", dns_tcp_header);

        if (ntohs(dns_tcp_header->len) < sizeof(DNSHeader)) {
            /* bogus len, doesn't fit even basic dns header */
            goto bad_data;
        } else if (ntohs(dns_tcp_header->len) == (input_len-2)) {
            /* we have all data, so process w/o buffering */
            if (DNSRequestParseData(f, dns_state, input+2, input_len-2) < 0)
                goto bad_data;

        } else if ((input_len-2) > ntohs(dns_tcp_header->len)) {
            /* we have all data, so process w/o buffering */
            if (DNSRequestParseData(f, dns_state, input+2, ntohs(dns_tcp_header->len)) < 0)
                goto bad_data;

            /* treat the rest of the data as a (potential) new record */
            input += (2 + ntohs(dns_tcp_header->len));
            input_len -= (2 + ntohs(dns_tcp_header->len));
            goto next_record;
        } else {
            /* not enough data, store record length and buffer */
            dns_state->record_len = ntohs(dns_tcp_header->len);
            BufferData(dns_state, input+2, input_len-2);
        }
    } else if (input_len + dns_state->offset < dns_state->record_len) {
        /* we don't have the full record yet, buffer */
        BufferData(dns_state, input, input_len);
    } else if (input_len > (uint32_t)(dns_state->record_len - dns_state->offset)) {
        /* more data than expected, we may have another record coming up */
        uint16_t need = (dns_state->record_len - dns_state->offset);
        BufferData(dns_state, input, need);
        int r = DNSRequestParseData(f, dns_state, dns_state->buffer, dns_state->record_len);
        BufferReset(dns_state);
        if (r < 0)
            goto bad_data;

        /* treat the rest of the data as a (potential) new record */
        input += need;
        input_len -= need;
        goto next_record;
    } else {
        /* implied exactly the amount of data we want
         * add current to buffer, then inspect buffer */
        BufferData(dns_state, input, input_len);
        int r = DNSRequestParseData(f, dns_state, dns_state->buffer, dns_state->record_len);
        BufferReset(dns_state);
        if (r < 0)
            goto bad_data;
    }

    SCReturnInt(1);
insufficient_data:
    SCReturnInt(-1);
bad_data:
    SCReturnInt(-1);
}

static int DNSReponseParseData(Flow *f, DNSState *dns_state, const uint8_t *input, const uint32_t input_len)
{
    DNSHeader *dns_header = (DNSHeader *)input;

    if (DNSValidateResponseHeader(dns_state, dns_header) < 0)
        goto bad_data;

    DNSTransaction *tx = NULL;
    int found = 0;
    if ((tx = DNSTransactionFindByTxId(dns_state, ntohs(dns_header->tx_id))) != NULL)
        found = 1;

    if (!found) {
        SCLogDebug("DNS_DECODER_EVENT_UNSOLLICITED_RESPONSE");
        DNSSetEvent(dns_state, DNS_DECODER_EVENT_UNSOLLICITED_RESPONSE);
    }

    uint16_t q;
    const uint8_t *data = input + sizeof(DNSHeader);
    for (q = 0; q < ntohs(dns_header->questions); q++) {
        uint8_t fqdn[DNS_MAX_SIZE];
        uint16_t fqdn_offset = 0;

        if (input + input_len < data + 1) {
            SCLogDebug("input buffer too small for len field");
            goto insufficient_data;
        }
        SCLogDebug("qry length %u", *data);

        while (*data != 0) {
            uint8_t length = *data;
            data++;

            if (length > 0) {
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
            }

            data += length;

            if (input + input_len < data + 1) {
                SCLogDebug("input buffer too small for len field");
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

    for (q = 0; q < ntohs(dns_header->answer_rr); q++) {
        data = DNSReponseParse(dns_state, dns_header, q, DNS_LIST_ANSWER,
                input, input_len, data);
        if (data == NULL) {
            goto insufficient_data;
        }
    }

    //PrintRawDataFp(stdout, (uint8_t *)data, input_len - (data - input));
    for (q = 0; q < ntohs(dns_header->authority_rr); q++) {
        data = DNSReponseParse(dns_state, dns_header, q, DNS_LIST_AUTHORITY,
                input, input_len, data);
        if (data == NULL) {
            goto insufficient_data;
        }
    }

    /* parse rcode, e.g. "noerror" or "nxdomain" */
    uint8_t rcode = ntohs(dns_header->flags) & 0x0F;
    if (rcode <= DNS_RCODE_NOTZONE) {
        SCLogDebug("rcode %u", rcode);
        if (tx != NULL)
            tx->rcode = rcode;
    } else {
        /* this is not invalid, rcodes can be user defined */
        SCLogDebug("unexpected DNS rcode %u", rcode);
    }

    if (ntohs(dns_header->flags) & 0x0080) {
        SCLogDebug("recursion desired");
        if (tx != NULL)
            tx->recursion_desired = 1;
    }

    if (tx != NULL) {
        tx->replied = 1;
    }

    SCReturnInt(1);
bad_data:
insufficient_data:
    SCReturnInt(-1);
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

    if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        SCReturnInt(1);
    }

    /** \todo remove this when PP is fixed to enforce ipproto */
    if (f != NULL && f->proto != IPPROTO_TCP)
        SCReturnInt(-1);

    /* probably a rst/fin sending an eof */
    if (input == NULL || input_len == 0) {
        goto insufficient_data;
    }

next_record:
    /* if this is the beginning of a record, we need at least the header */
    if (dns_state->offset == 0 &&  input_len < sizeof(DNSTcpHeader)) {
        SCLogDebug("ilen too small, hoped for at least %"PRIuMAX, (uintmax_t)sizeof(DNSTcpHeader));
        goto insufficient_data;
    }
    SCLogDebug("input_len %u offset %u record %u",
            input_len, dns_state->offset, dns_state->record_len);

    /* this is the first data of this record */
    if (dns_state->offset == 0) {
        DNSTcpHeader *dns_tcp_header = (DNSTcpHeader *)input;
        SCLogDebug("DNS %p", dns_tcp_header);

        if (ntohs(dns_tcp_header->len) == 0) {
            goto bad_data;
        } else if (ntohs(dns_tcp_header->len) == (input_len-2)) {
            /* we have all data, so process w/o buffering */
            if (DNSReponseParseData(f, dns_state, input+2, input_len-2) < 0)
                goto bad_data;

        } else if ((input_len-2) > ntohs(dns_tcp_header->len)) {
            /* we have all data, so process w/o buffering */
            if (DNSReponseParseData(f, dns_state, input+2, ntohs(dns_tcp_header->len)) < 0)
                goto bad_data;

            /* treat the rest of the data as a (potential) new record */
            input += (2 + ntohs(dns_tcp_header->len));
            input_len -= (2 + ntohs(dns_tcp_header->len));
            goto next_record;
        } else {
            /* not enough data, store record length and buffer */
            dns_state->record_len = ntohs(dns_tcp_header->len);
            BufferData(dns_state, input+2, input_len-2);
        }
    } else if (input_len + dns_state->offset < dns_state->record_len) {
        /* we don't have the full record yet, buffer */
        BufferData(dns_state, input, input_len);
    } else if (input_len > (uint32_t)(dns_state->record_len - dns_state->offset)) {
        /* more data than expected, we may have another record coming up */
        uint16_t need = (dns_state->record_len - dns_state->offset);
        BufferData(dns_state, input, need);
        int r = DNSReponseParseData(f, dns_state, dns_state->buffer, dns_state->record_len);
        BufferReset(dns_state);
        if (r < 0)
            goto bad_data;

        /* treat the rest of the data as a (potential) new record */
        input += need;
        input_len -= need;
        goto next_record;
    } else {
        /* implied exactly the amount of data we want
         * add current to buffer, then inspect buffer */
        BufferData(dns_state, input, input_len);
        int r = DNSReponseParseData(f, dns_state, dns_state->buffer, dns_state->record_len);
        BufferReset(dns_state);
        if (r < 0)
            goto bad_data;
    }
    SCReturnInt(1);
insufficient_data:
    SCReturnInt(-1);
bad_data:
    SCReturnInt(-1);
}

static uint16_t DNSTcpProbingParser(uint8_t *input, uint32_t ilen, uint32_t *offset)
{
    if (ilen == 0 || ilen < sizeof(DNSTcpHeader)) {
        SCLogDebug("ilen too small, hoped for at least %"PRIuMAX, (uintmax_t)sizeof(DNSTcpHeader));
        return ALPROTO_UNKNOWN;
    }

    DNSTcpHeader *dns_header = (DNSTcpHeader *)input;
    if (ntohs(dns_header->len) < sizeof(DNSHeader)) {
        /* length field bogus, won't even fit a minimal DNS header. */
        return ALPROTO_FAILED;
    } else if (ntohs(dns_header->len) > ilen) {
        int r = DNSTCPRequestParseProbe(input, ilen);
        if (r == -1) {
            /* probing parser told us "bad data", so it's not
             * DNS */
            return ALPROTO_FAILED;
        } else if (ilen > 512) {
            SCLogDebug("all the parser told us was not enough data, which is expected. Lets assume it's DNS");
            return ALPROTO_DNS;
        }

        SCLogDebug("not yet enough info %u > %u", ntohs(dns_header->len), ilen);
        return ALPROTO_UNKNOWN;
    }

    int r = DNSTCPRequestParseProbe(input, ilen);
    if (r != 1)
        return ALPROTO_FAILED;

    SCLogDebug("ALPROTO_DNS");
    return ALPROTO_DNS;
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
                                          DNSTcpProbingParser);
        } else {
            int have_cfg = AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                                                proto_name, ALPROTO_DNS,
                                                0, sizeof(DNSTcpHeader),
                                                DNSTcpProbingParser);
            /* if we have no config, we enable the default port 53 */
            if (!have_cfg) {
                SCLogWarning(SC_ERR_DNS_CONFIG, "no DNS TCP config found, "
                                                "enabling DNS detection on "
                                                "port 53.");
                AppLayerProtoDetectPPRegister(IPPROTO_TCP, "53",
                                   ALPROTO_DNS, 0, sizeof(DNSTcpHeader),
                                   STREAM_TOSERVER, DNSTcpProbingParser);
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

    return;
}

/* UNITTESTS */
#ifdef UNITTESTS
void DNSTCPParserRegisterTests(void)
{
//    UtRegisterTest("DNSTCPParserTest01", DNSTCPParserTest01, 1);
}
#endif
