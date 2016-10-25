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
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __APP_LAYER_DNS_COMMON_H__
#define __APP_LAYER_DNS_COMMON_H__

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "flow.h"
#include "queue.h"
#include "util-byte.h"

#define DNS_MAX_SIZE 256


#define DNS_RECORD_TYPE_A           1
#define DNS_RECORD_TYPE_NS          2
#define DNS_RECORD_TYPE_MD          3   // Obsolete
#define DNS_RECORD_TYPE_MF          4   // Obsolete
#define DNS_RECORD_TYPE_CNAME       5
#define DNS_RECORD_TYPE_SOA         6
#define DNS_RECORD_TYPE_MB          7   // Experimental
#define DNS_RECORD_TYPE_MG          8   // Experimental
#define DNS_RECORD_TYPE_MR          9   // Experimental
#define DNS_RECORD_TYPE_NULL        10  // Experimental
#define DNS_RECORD_TYPE_WKS         11
#define DNS_RECORD_TYPE_PTR         12
#define DNS_RECORD_TYPE_HINFO       13
#define DNS_RECORD_TYPE_MINFO       14
#define DNS_RECORD_TYPE_MX          15
#define DNS_RECORD_TYPE_TXT         16
#define DNS_RECORD_TYPE_RP          17
#define DNS_RECORD_TYPE_AFSDB       18
#define DNS_RECORD_TYPE_X25         19
#define DNS_RECORD_TYPE_ISDN        20
#define DNS_RECORD_TYPE_RT          21
#define DNS_RECORD_TYPE_NSAP        22
#define DNS_RECORD_TYPE_NSAPPTR     23
#define DNS_RECORD_TYPE_SIG         24
#define DNS_RECORD_TYPE_KEY         25
#define DNS_RECORD_TYPE_PX          26
#define DNS_RECORD_TYPE_GPOS        27
#define DNS_RECORD_TYPE_AAAA        28
#define DNS_RECORD_TYPE_LOC         29
#define DNS_RECORD_TYPE_NXT         30  // Obosolete
#define DNS_RECORD_TYPE_SRV         33
#define DNS_RECORD_TYPE_ATMA        34
#define DNS_RECORD_TYPE_NAPTR       35
#define DNS_RECORD_TYPE_KX          36
#define DNS_RECORD_TYPE_CERT        37
#define DNS_RECORD_TYPE_A6          38  // Obsolete
#define DNS_RECORD_TYPE_DNAME       39
#define DNS_RECORD_TYPE_OPT         41
#define DNS_RECORD_TYPE_APL         42
#define DNS_RECORD_TYPE_DS          43
#define DNS_RECORD_TYPE_SSHFP       44
#define DNS_RECORD_TYPE_IPSECKEY    45
#define DNS_RECORD_TYPE_RRSIG       46
#define DNS_RECORD_TYPE_NSEC        47
#define DNS_RECORD_TYPE_DNSKEY      48
#define DNS_RECORD_TYPE_DHCID       49
#define DNS_RECORD_TYPE_NSEC3       50
#define DNS_RECORD_TYPE_NSEC3PARAM  51
#define DNS_RECORD_TYPE_TLSA        52
#define DNS_RECORD_TYPE_HIP         55
#define DNS_RECORD_TYPE_CDS         59
#define DNS_RECORD_TYPE_CDNSKEY     60
#define DNS_RECORD_TYPE_SPF         99  // Obsolete
#define DNS_RECORD_TYPE_TKEY        249
#define DNS_RECORD_TYPE_TSIG        250
#define DNS_RECORD_TYPE_MAILA       254 // Obsolete
#define DNS_RECORD_TYPE_ANY         255
#define DNS_RECORD_TYPE_URI         256

#define DNS_RCODE_NOERROR       0
#define DNS_RCODE_FORMERR       1
#define DNS_RCODE_SERVFAIL      2
#define DNS_RCODE_NXDOMAIN      3
#define DNS_RCODE_NOTIMP        4
#define DNS_RCODE_REFUSED       5
#define DNS_RCODE_YXDOMAIN      6
#define DNS_RCODE_YXRRSET       7
#define DNS_RCODE_NXRRSET       8
#define DNS_RCODE_NOTAUTH       9
#define DNS_RCODE_NOTZONE       10
// Support for OPT RR from RFC6891 will be needed to
// parse RCODE values over 15
#define DNS_RCODE_BADVERS       16
#define DNS_RCODE_BADSIG        16
#define DNS_RCODE_BADKEY        17
#define DNS_RCODE_BADTIME       18
#define DNS_RCODE_BADMODE       19
#define DNS_RCODE_BADNAME       20
#define DNS_RCODE_BADALG        21
#define DNS_RCODE_BADTRUNC      22

enum {
    DNS_DECODER_EVENT_UNSOLLICITED_RESPONSE,
    DNS_DECODER_EVENT_MALFORMED_DATA,
    DNS_DECODER_EVENT_NOT_A_REQUEST,
    DNS_DECODER_EVENT_NOT_A_RESPONSE,
    DNS_DECODER_EVENT_Z_FLAG_SET,
    DNS_DECODER_EVENT_FLOODED,
    DNS_DECODER_EVENT_STATE_MEMCAP_REACHED,
};

/** \brief DNS packet header */
typedef struct DNSHeader_ {
    uint16_t tx_id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answer_rr;
    uint16_t authority_rr;
    uint16_t additional_rr;
} __attribute__((__packed__)) DNSHeader;

typedef struct DNSQueryTrailer_ {
    uint16_t type;
    uint16_t class;
} __attribute__((__packed__)) DNSQueryTrailer;

/** \brief DNS answer header
 *  packed as we don't want alignment to mess up sizeof() */
struct DNSAnswerHeader_ {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t len;
} __attribute__((__packed__));
typedef struct DNSAnswerHeader_ DNSAnswerHeader;

/** \brief List types in the TX.
 *  Used when storing answers from "Answer" or "Authority" */
typedef enum {
    DNS_LIST_ANSWER = 0,
    DNS_LIST_AUTHORITY,
} DnsListEnum;

/** \brief DNS Query storage. Stored in TX list.
 *
 *  Layout is:
 *  [list ptr][2 byte type][2 byte class][2 byte len][...data...]
 */
typedef struct DNSQueryEntry_ {
    TAILQ_ENTRY(DNSQueryEntry_) next;
    uint16_t type;
    uint16_t class;
    uint16_t len;
} DNSQueryEntry;

/** \brief DNS Answer storage. Stored in TX list.
 *
 *  Layout is:
 *  [list ptr][2 byte type][2 byte class][2 byte ttl] \
 *      [2 byte fqdn len][2 byte data len][...fqdn...][...data...]
 */
typedef struct DNSAnswerEntry_ {
    TAILQ_ENTRY(DNSAnswerEntry_) next;

    uint16_t type;
    uint16_t class;

    uint32_t ttl;

    uint16_t fqdn_len;
    uint16_t data_len;
} DNSAnswerEntry;

/** \brief DNS Transaction, request/reply with same TX id. */
typedef struct DNSTransaction_ {
    uint16_t tx_num;                                /**< internal: id */
    uint16_t tx_id;                                 /**< transaction id */
    uint32_t logged;                                /**< flags for loggers done logging */
    uint8_t replied;                                /**< bool indicating request is
                                                         replied to. */
    uint8_t reply_lost;
    uint8_t rcode;                                  /**< response code (e.g. "no error" / "no such name") */
    uint8_t recursion_desired;                      /**< server said "recursion desired" */

    TAILQ_HEAD(, DNSQueryEntry_) query_list;        /**< list for query/queries */
    TAILQ_HEAD(, DNSAnswerEntry_) answer_list;      /**< list for answers */
    TAILQ_HEAD(, DNSAnswerEntry_) authority_list;   /**< list for authority records */

    AppLayerDecoderEvents *decoder_events;          /**< per tx events */

    TAILQ_ENTRY(DNSTransaction_) next;
    DetectEngineState *de_state;
} DNSTransaction;

/** \brief Per flow DNS state container */
typedef struct DNSState_ {
    TAILQ_HEAD(, DNSTransaction_) tx_list;  /**< transaction list */
    DNSTransaction *curr;                   /**< ptr to current tx */
    DNSTransaction *iter;
    uint64_t transaction_max;
    uint32_t unreplied_cnt;                 /**< number of unreplied requests in a row */
    uint32_t memuse;                        /**< state memuse, for comparing with
                                                 state-memcap settings */
    uint64_t tx_with_detect_state_cnt;

    struct timeval last_req;      /**< Timestamp of last request. */
    struct timeval last_resp;     /**< Timestamp of last response. */

    uint16_t window;              /**< Window of allowed unreplied
                                   * requests. Set by the maximum
                                   * number of subsequent requests
                                   * without a response. */
    uint16_t events;
    uint16_t givenup;

    /* used by TCP only */
    uint16_t offset;
    uint16_t record_len;
    uint8_t *buffer;
} DNSState;

#define DNS_CONFIG_DEFAULT_REQUEST_FLOOD 500
#define DNS_CONFIG_DEFAULT_STATE_MEMCAP 512*1024
#define DNS_CONFIG_DEFAULT_GLOBAL_MEMCAP 16*1024*1024

void DNSConfigInit(void);
void DNSConfigSetRequestFlood(uint32_t value);
void DNSConfigSetStateMemcap(uint32_t value);
void DNSConfigSetGlobalMemcap(uint64_t value);

void DNSIncrMemcap(uint32_t size, DNSState *state);
void DNSDecrMemcap(uint32_t size, DNSState *state);
int DNSCheckMemcap(uint32_t want, DNSState *state);
uint64_t DNSMemcapGetMemuseCounter(void);
uint64_t DNSMemcapGetMemcapStateCounter(void);
uint64_t DNSMemcapGetMemcapGlobalCounter(void);

void RegisterDNSParsers(void);
void DNSParserTests(void);
void DNSParserRegisterTests(void);
void DNSAppLayerDecoderEventsRegister(int alproto);
int DNSStateGetEventInfo(const char *event_name,
                         int *event_id, AppLayerEventType *event_type);
void DNSAppLayerRegisterGetEventInfo(uint8_t ipproto, AppProto alproto);

void *DNSGetTx(void *alstate, uint64_t tx_id);
uint64_t DNSGetTxCnt(void *alstate);
void DNSSetTxLogged(void *alstate, void *tx, uint32_t logger);
int DNSGetTxLogged(void *alstate, void *tx, uint32_t logger);
int DNSGetAlstateProgress(void *tx, uint8_t direction);
int DNSGetAlstateProgressCompletionStatus(uint8_t direction);

void DNSStateTransactionFree(void *state, uint64_t tx_id);
DNSTransaction *DNSTransactionFindByTxId(const DNSState *dns_state, const uint16_t tx_id);

int DNSStateHasTxDetectState(void *alstate);
DetectEngineState *DNSGetTxDetectState(void *vtx);
int DNSSetTxDetectState(void *alstate, void *vtx, DetectEngineState *s);

void DNSSetEvent(DNSState *s, uint8_t e);
void *DNSStateAlloc(void);
void DNSStateFree(void *s);
AppLayerDecoderEvents *DNSGetEvents(void *state, uint64_t id);
int DNSHasEvents(void *state);

int DNSValidateRequestHeader(DNSState *, const DNSHeader *dns_header);
int DNSValidateResponseHeader(DNSState *, const DNSHeader *dns_header);

void DNSStoreQueryInState(DNSState *dns_state, const uint8_t *fqdn, const uint16_t fqdn_len,
        const uint16_t type, const uint16_t class, const uint16_t tx_id);

void DNSStoreAnswerInState(DNSState *dns_state, const int rtype, const uint8_t *fqdn,
        const uint16_t fqdn_len, const uint16_t type, const uint16_t class, const uint16_t ttl,
        const uint8_t *data, const uint16_t data_len, const uint16_t tx_id);

const uint8_t *DNSReponseParse(DNSState *dns_state, const DNSHeader * const dns_header,
        const uint16_t num, const DnsListEnum list, const uint8_t * const input,
        const uint32_t input_len, const uint8_t *data);

uint16_t DNSUdpResponseGetNameByOffset(const uint8_t * const input, const uint32_t input_len,
        const uint16_t offset, uint8_t *fqdn, const size_t fqdn_size);

void DNSCreateTypeString(uint16_t type, char *str, size_t str_size);
void DNSCreateRcodeString(uint8_t rcode, char *str, size_t str_size);

#endif /* __APP_LAYER_DNS_COMMON_H__ */
