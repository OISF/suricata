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

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DECODE_ICMPV6_H__
#define __DECODE_ICMPV6_H__

#include "decode-tcp.h"
#include "decode-sctp.h"
#include "decode-udp.h"
#include "decode-ipv6.h"

#define ICMPV6_HEADER_LEN       8
#define ICMPV6_HEADER_PKT_OFFSET 8

/** ICMPV6 Message Types: */
/** Error Messages: (type <128) */
#define ICMP6_DST_UNREACH             1
#define ICMP6_PACKET_TOO_BIG          2
#define ICMP6_TIME_EXCEEDED           3
#define ICMP6_PARAM_PROB              4

/** Informational Messages (type>=128) */
#define ICMP6_ECHO_REQUEST          128
#define ICMP6_ECHO_REPLY            129

#define MLD_LISTENER_QUERY          130
#define MLD_LISTENER_REPORT         131
#define MLD_LISTENER_REDUCTION      132

#define ND_ROUTER_SOLICIT           133
#define ND_ROUTER_ADVERT            134
#define ND_NEIGHBOR_SOLICIT         135
#define ND_NEIGHBOR_ADVERT          136
#define ND_REDIRECT                 137

#define ICMP6_RR                    138
#define ICMP6_NI_QUERY              139
#define ICMP6_NI_REPLY              140
#define ND_INVERSE_SOLICIT          141
#define ND_INVERSE_ADVERT           142
#define MLD_V2_LIST_REPORT          143
#define HOME_AGENT_AD_REQUEST       144
#define HOME_AGENT_AD_REPLY         145
#define MOBILE_PREFIX_SOLICIT       146
#define MOBILE_PREFIX_ADVERT        147
#define CERT_PATH_SOLICIT           148
#define CERT_PATH_ADVERT            149
#define ICMP6_MOBILE_EXPERIMENTAL   150
#define MC_ROUTER_ADVERT            151
#define MC_ROUTER_SOLICIT           152
#define MC_ROUTER_TERMINATE         153
#define FMIPV6_MSG                  154
#define RPL_CONTROL_MSG             155
#define LOCATOR_UDATE_MSG           156
#define DUPL_ADDR_REQUEST           157
#define DUPL_ADDR_CONFIRM           158
#define MPL_CONTROL_MSG             159

/** Destination Unreachable Message (type=1) Code: */

#define ICMP6_DST_UNREACH_NOROUTE       0 /* no route to destination */
#define ICMP6_DST_UNREACH_ADMIN         1 /* communication with destination */
                                          /* administratively prohibited */
#define ICMP6_DST_UNREACH_BEYONDSCOPE   2 /* beyond scope of source address */
#define ICMP6_DST_UNREACH_ADDR          3 /* address unreachable */
#define ICMP6_DST_UNREACH_NOPORT        4 /* bad port */
#define ICMP6_DST_UNREACH_FAILEDPOLICY  5 /* Source address failed ingress/egress policy */
#define ICMP6_DST_UNREACH_REJECTROUTE   6 /* Reject route to destination */


/** Time Exceeded Message (type=3) Code: */
#define ICMP6_TIME_EXCEED_TRANSIT     0 /* Hop Limit == 0 in transit */
#define ICMP6_TIME_EXCEED_REASSEMBLY  1 /* Reassembly time out */

/** Parameter Problem Message (type=4) Code: */
#define ICMP6_PARAMPROB_HEADER        0 /* erroneous header field */
#define ICMP6_PARAMPROB_NEXTHEADER    1 /* unrecognized Next Header */
#define ICMP6_PARAMPROB_OPTION        2 /* unrecognized IPv6 option */


/** macro for icmpv6 "type" access */
#define ICMPV6_GET_TYPE(p)      (p)->icmpv6h->type
/** macro for icmpv6 "code" access */
#define ICMPV6_GET_CODE(p)      (p)->icmpv6h->code
/** macro for icmpv6 "csum" access */
#define ICMPV6_GET_RAW_CSUM(p)      ntohs((p)->icmpv6h->csum)
#define ICMPV6_GET_CSUM(p)      (p)->icmpv6h->csum

/** If message is informational */
/** macro for icmpv6 "id" access */
#define ICMPV6_GET_ID(p)        (p)->icmpv6vars.id
/** macro for icmpv6 "seq" access */
#define ICMPV6_GET_SEQ(p)       (p)->icmpv6vars.seq

/** If message is Error */
/** macro for icmpv6 "unused" access */
#define ICMPV6_GET_UNUSED(p)       (p)->icmpv6h->icmpv6b.icmpv6e.unused
/** macro for icmpv6 "error_ptr" access */
#define ICMPV6_GET_ERROR_PTR(p)    (p)->icmpv6h->icmpv6b.icmpv6e.error_ptr
/** macro for icmpv6 "mtu" access */
#define ICMPV6_GET_MTU(p)          (p)->icmpv6h->icmpv6b.icmpv6e.mtu

/** macro for icmpv6 embedded "protocol" access */
#define ICMPV6_GET_EMB_PROTO(p)    (p)->icmpv6vars.emb_ip6_proto_next
/** macro for icmpv6 embedded "ipv6h" header access */
#define ICMPV6_GET_EMB_IPV6(p)     (p)->icmpv6vars.emb_ipv6h
/** macro for icmpv6 embedded "tcph" header access */
#define ICMPV6_GET_EMB_TCP(p)      (p)->icmpv6vars.emb_tcph
/** macro for icmpv6 embedded "udph" header access */
#define ICMPV6_GET_EMB_UDP(p)      (p)->icmpv6vars.emb_udph
/** macro for icmpv6 embedded "icmpv6h" header access */
#define ICMPV6_GET_EMB_icmpv6h(p)  (p)->icmpv6vars.emb_icmpv6h

typedef struct ICMPV6Info_
{
    uint16_t  id;
    uint16_t  seq;
} ICMPV6Info;

/** ICMPv6 header structure */
typedef struct ICMPV6Hdr_
{
    uint8_t  type;
    uint8_t  code;
    uint16_t csum;

    union {
        ICMPV6Info icmpv6i; /** Informational message */
        union
        {
            uint32_t  unused; /** for types 1 and 3, should be zero */
            uint32_t  error_ptr; /** for type 4, pointer to the octet that originate the error */
            uint32_t  mtu; /** for type 2, the Maximum Transmission Unit of the next-hop link */
        } icmpv6e;   /** Error Message */
    } icmpv6b;
} ICMPV6Hdr;

/** Data available from the decoded packet */
typedef struct ICMPV6Vars_ {
    /* checksum of the icmpv6 packet */
    uint16_t  id;
    uint16_t  seq;
    uint32_t  mtu;
    uint32_t  error_ptr;

    /** Pointers to the embedded packet headers */
    IPV6Hdr *emb_ipv6h;
    TCPHdr *emb_tcph;
    UDPHdr *emb_udph;
    ICMPV6Hdr *emb_icmpv6h;

    /** IPv6 src and dst address */
    uint32_t emb_ip6_src[4];
    uint32_t emb_ip6_dst[4];
    uint8_t emb_ip6_proto_next;

    /** TCP/UDP ports */
    uint16_t emb_sport;
    uint16_t emb_dport;

} ICMPV6Vars;


#define CLEAR_ICMPV6_PACKET(p) do { \
    (p)->level4_comp_csum = -1;     \
    PACKET_CLEAR_L4VARS((p));       \
    (p)->icmpv6h = NULL;            \
} while(0)

void DecodeICMPV6RegisterTests(void);

/** -------- Inline functions --------- */
static inline uint16_t ICMPV6CalculateChecksum(uint16_t *, uint16_t *, uint16_t);

/**
 * \brief Calculates the checksum for the ICMPV6 packet
 *
 * \param shdr Pointer to source address field from the IPV6 packet.  Used as a
 *             part of the psuedoheader for computing the checksum
 * \param pkt  Pointer to the start of the ICMPV6 packet
 * \param tlen Total length of the ICMPV6 packet(header + payload)
 *
 * \retval csum Checksum for the ICMPV6 packet
 */
static inline uint16_t ICMPV6CalculateChecksum(uint16_t *shdr, uint16_t *pkt,
                                        uint16_t tlen)
{
    uint16_t pad = 0;
    uint32_t csum = shdr[0];

    csum += shdr[1] + shdr[2] + shdr[3] + shdr[4] + shdr[5] + shdr[6] +
        shdr[7] + shdr[8] + shdr[9] + shdr[10] + shdr[11] + shdr[12] +
        shdr[13] + shdr[14] + shdr[15] + htons(58 + tlen);

    csum += pkt[0];

    tlen -= 4;
    pkt += 2;

    while (tlen >= 64) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15] + pkt[16] + pkt[17] + pkt[18] + pkt[19] +
            pkt[20] + pkt[21] + pkt[22] + pkt[23] + pkt[24] + pkt[25] +
            pkt[26] + pkt[27] + pkt[28] + pkt[29] + pkt[30] + pkt[31];
        tlen -= 64;
        pkt += 32;
    }

    while (tlen >= 32) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15];
        tlen -= 32;
        pkt += 16;
    }

    while(tlen >= 8) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3];
        tlen -= 8;
        pkt += 4;
    }

    while(tlen >= 4) {
        csum += pkt[0] + pkt[1];
        tlen -= 4;
        pkt += 2;
    }

    while (tlen > 1) {
        csum += pkt[0];
        tlen -= 2;
        pkt += 1;
    }

    if (tlen == 1) {
        *(uint8_t *)(&pad) = (*(uint8_t *)pkt);
        csum += pad;
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);
    csum += (csum >> 16);

    return (uint16_t) ~csum;
}


#endif /* __DECODE_ICMPV6_H__ */

