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

/** Opaque Rust types. */
typedef struct RSDNSState_ RSDNSState;
typedef struct RSDNSTransaction_ RSDNSTransaction;

/** \brief DNS packet header */
typedef struct DNSHeader_ {
    uint16_t tx_id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answer_rr;
    uint16_t authority_rr;
    uint16_t additional_rr;
} __attribute__((__packed__)) DNSHeader;

int DNSStateGetEventInfo(const char *event_name,
                         int *event_id, AppLayerEventType *event_type);
int DNSStateGetEventInfoById(int event_id, const char **event_name,
                             AppLayerEventType *event_type);
void DNSAppLayerRegisterGetEventInfo(uint8_t ipproto, AppProto alproto);
void DNSAppLayerRegisterGetEventInfoById(uint8_t ipproto, AppProto alproto);

void DNSCreateTypeString(uint16_t type, char *str, size_t str_size);
void DNSCreateRcodeString(uint8_t rcode, char *str, size_t str_size);

#endif /* __APP_LAYER_DNS_COMMON_H__ */
