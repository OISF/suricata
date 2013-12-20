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

#ifndef __DECODE_ICMPV4_H__
#define __DECODE_ICMPV4_H__

#include "decode.h"
#include "decode-tcp.h"
#include "decode-sctp.h"
#include "decode-udp.h"

#define ICMPV4_HEADER_LEN       8

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY          0       /* Echo Reply                   */
#endif
#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH       3       /* Destination Unreachable      */
#endif
#ifndef ICMP_SOURCE_QUENCH
#define ICMP_SOURCE_QUENCH      4       /* Source Quench                */
#endif
#ifndef ICMP_REDIRECT
#define ICMP_REDIRECT           5       /* Redirect (change route)      */
#endif
#ifndef ICMP_ECHO
#define ICMP_ECHO               8       /* Echo Request                 */
#endif
#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded                */
#endif
#ifndef ICMP_PARAMETERPROB
#define ICMP_PARAMETERPROB      12      /* Parameter Problem            */
#endif
#ifndef ICMP_TIMESTAMP
#define ICMP_TIMESTAMP          13      /* Timestamp Request            */
#endif
#ifndef ICMP_TIMESTAMPREPLY
#define ICMP_TIMESTAMPREPLY     14      /* Timestamp Reply              */
#endif
#ifndef ICMP_INFO_REQUEST
#define ICMP_INFO_REQUEST       15      /* Information Request          */
#endif
#ifndef ICMP_INFO_REPLY
#define ICMP_INFO_REPLY         16      /* Information Reply            */
#endif
#ifndef ICMP_ADDRESS
#define ICMP_ADDRESS            17      /* Address Mask Request         */
#endif
#ifndef ICMP_ADDRESSREPLY
#define ICMP_ADDRESSREPLY       18      /* Address Mask Reply           */
#endif
#ifndef NR_ICMP_TYPES
#define NR_ICMP_TYPES           18
#endif


/* Codes for UNREACH. */
#ifndef ICMP_NET_UNREACH
#define ICMP_NET_UNREACH        0       /* Network Unreachable          */
#endif
#ifndef ICMP_HOST_UNREACH
#define ICMP_HOST_UNREACH       1       /* Host Unreachable             */
#endif
#ifndef ICMP_PROT_UNREACH
#define ICMP_PROT_UNREACH       2       /* Protocol Unreachable         */
#endif
#ifndef ICMP_PORT_UNREACH
#define ICMP_PORT_UNREACH       3       /* Port Unreachable             */
#endif
#ifndef ICMP_FRAG_NEEDED
#define ICMP_FRAG_NEEDED        4       /* Fragmentation Needed/DF set  */
#endif
#ifndef ICMP_SR_FAILED
#define ICMP_SR_FAILED          5       /* Source Route failed          */
#endif
#ifndef ICMP_NET_UNKNOWN
#define ICMP_NET_UNKNOWN        6
#endif
#ifndef ICMP_HOST_UNKNOWN
#define ICMP_HOST_UNKNOWN       7
#endif
#ifndef ICMP_HOST_ISOLATED
#define ICMP_HOST_ISOLATED      8
#endif
#ifndef ICMP_NET_ANO
#define ICMP_NET_ANO            9
#endif
#ifndef ICMP_HOST_ANO
#define ICMP_HOST_ANO           10
#endif
#ifndef ICMP_NET_UNR_TOS
#define ICMP_NET_UNR_TOS        11
#endif
#ifndef ICMP_HOST_UNR_TOS
#define ICMP_HOST_UNR_TOS       12
#endif
#ifndef ICMP_PKT_FILTERED
#define ICMP_PKT_FILTERED       13      /* Packet filtered */
#endif
#ifndef ICMP_PREC_VIOLATION
#define ICMP_PREC_VIOLATION     14      /* Precedence violation */

#endif
#ifndef ICMP_PREC_CUTOFF
#define ICMP_PREC_CUTOFF        15      /* Precedence cut off */
#endif
#ifndef NR_ICMP_UNREACH
#define NR_ICMP_UNREACH         15      /* instead of hardcoding immediate value */
#endif

/* Codes for REDIRECT. */
#ifndef ICMP_REDIR_NET
#define ICMP_REDIR_NET          0       /* Redirect Net                 */
#endif
#ifndef ICMP_REDIR_HOST
#define ICMP_REDIR_HOST         1       /* Redirect Host                */
#endif
#ifndef ICMP_REDIR_NETTOS
#define ICMP_REDIR_NETTOS       2       /* Redirect Net for TOS         */
#endif
#ifndef ICMP_REDIR_HOSTTOS
#define ICMP_REDIR_HOSTTOS      3       /* Redirect Host for TOS        */
#endif

/* Codes for TIME_EXCEEDED. */
#ifndef ICMP_EXC_TTL
#define ICMP_EXC_TTL            0       /* TTL count exceeded           */
#endif
#ifndef ICMP_EXC_FRAGTIME
#define ICMP_EXC_FRAGTIME       1       /* Fragment Reass time exceeded */
#endif

/** marco for icmpv4 type access */
#define ICMPV4_GET_TYPE(p)      (p)->icmpv4h->type
/** marco for icmpv4 code access */
#define ICMPV4_GET_CODE(p)      (p)->icmpv4h->code

/* ICMPv4 header structure */
typedef struct ICMPV4Hdr_
{
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
} __attribute__((__packed__)) ICMPV4Hdr;

/* ICMPv4 header structure */
typedef struct ICMPV4ExtHdr_
{
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} ICMPV4ExtHdr;

/* ICMPv4 vars */
typedef struct ICMPV4Vars_
{
    uint16_t  id;
    uint16_t  seq;
    uint32_t  mtu;
    uint32_t  error_ptr;

    /** Pointers to the embedded packet headers */
    IPV4Hdr *emb_ipv4h;
    TCPHdr *emb_tcph;
    UDPHdr *emb_udph;
    ICMPV4Hdr *emb_icmpv4h;

    /** IPv4 src and dst address */
    struct in_addr emb_ip4_src;
    struct in_addr emb_ip4_dst;
    uint8_t emb_ip4_hlen;
    uint8_t emb_ip4_proto;

    /** TCP/UDP ports */
    uint16_t emb_sport;
    uint16_t emb_dport;
} ICMPV4Vars;

#define CLEAR_ICMPV4_PACKET(p) do { \
    (p)->level4_comp_csum = -1; \
    (p)->icmpv4vars.id = 0; \
    (p)->icmpv4vars.seq = 0; \
    (p)->icmpv4vars.mtu = 0; \
    (p)->icmpv4vars.error_ptr = 0; \
    (p)->icmpv4vars.emb_ipv4h = NULL; \
    (p)->icmpv4vars.emb_tcph = NULL; \
    (p)->icmpv4vars.emb_udph = NULL; \
    (p)->icmpv4vars.emb_icmpv4h = NULL; \
    (p)->icmpv4vars.emb_ip4_src.s_addr = 0; \
    (p)->icmpv4vars.emb_ip4_dst.s_addr = 0; \
    (p)->icmpv4vars.emb_sport = 0; \
    (p)->icmpv4vars.emb_ip4_proto = 0; \
    (p)->icmpv4vars.emb_sport = 0; \
    (p)->icmpv4vars.emb_dport = 0; \
    (p)->icmpv4h = NULL; \
} while(0)

#define ICMPV4_HEADER_PKT_OFFSET 8

/** macro for icmpv4 "type" access */
#define ICMPV4_GET_TYPE(p)      (p)->icmpv4h->type
/** macro for icmpv4 "code" access */
#define ICMPV4_GET_CODE(p)      (p)->icmpv4h->code
/** macro for icmpv4 "csum" access */
#define ICMPV4_GET_CSUM(p)      (p)->icmpv4h->csum

/* If message is informational */

/** macro for icmpv4 "id" access */
#define ICMPV4_GET_ID(p)        ((p)->icmpv4vars.id)
/** macro for icmpv4 "seq" access */
#define ICMPV4_GET_SEQ(p)       ((p)->icmpv4vars.seq)

/* If message is Error */

/** macro for icmpv4 "unused" access */
#define ICMPV4_GET_UNUSED(p)       (p)->icmpv4h->icmpv4b.icmpv4e.unused
/** macro for icmpv4 "error_ptr" access */
#define ICMPV4_GET_ERROR_PTR(p)    (p)->icmpv4h->icmpv4b.icmpv4e.error_ptr
/** macro for icmpv4 "mtu" access */
#define ICMPV4_GET_MTU(p)          (p)->icmpv4h->icmpv4b.icmpv4e.mtu

/** macro for icmpv4 embedded "protocol" access */
#define ICMPV4_GET_EMB_PROTO(p)    (p)->icmpv4vars.emb_ip4_proto
/** macro for icmpv4 embedded "ipv4h" header access */
#define ICMPV4_GET_EMB_IPV4(p)     (p)->icmpv4vars.emb_ipv4h
/** macro for icmpv4 embedded "tcph" header access */
#define ICMPV4_GET_EMB_TCP(p)      (p)->icmpv4vars.emb_tcph
/** macro for icmpv4 embedded "udph" header access */
#define ICMPV4_GET_EMB_UDP(p)      (p)->icmpv4vars.emb_udph
/** macro for icmpv4 embedded "icmpv4h" header access */
#define ICMPV4_GET_EMB_ICMPV4H(p)  (p)->icmpv4vars.emb_icmpv4h

/** macro for checking if a ICMP DEST UNREACH packet is valid for use
 *  in other parts of the engine, such as the flow engine. 
 *
 *  \warning use only _after_ the decoder has processed the packet
 */
#define ICMPV4_DEST_UNREACH_IS_VALID(p) (((p)->icmpv4h != NULL) && \
    (ICMPV4_GET_TYPE((p)) == ICMP_DEST_UNREACH) && \
    (ICMPV4_GET_EMB_IPV4((p)) != NULL) && \
    ((ICMPV4_GET_EMB_TCP((p)) != NULL) || \
     (ICMPV4_GET_EMB_UDP((p)) != NULL)))

/**
 *  marco for checking if a ICMP packet is an error message or an
 *  query message.
 *
 *  \todo This check is used in the flow engine and needs to be as
 *        cheap as possible. Consider setting a bitflag at the decoder
 *        stage so we can to a bit check instead of the more expensive
 *        check below.
 */
#define ICMPV4_IS_ERROR_MSG(p) (ICMPV4_GET_TYPE((p)) == ICMP_DEST_UNREACH || \
        ICMPV4_GET_TYPE((p)) == ICMP_SOURCE_QUENCH || \
        ICMPV4_GET_TYPE((p)) == ICMP_REDIRECT || \
        ICMPV4_GET_TYPE((p)) == ICMP_TIME_EXCEEDED || \
        ICMPV4_GET_TYPE((p)) == ICMP_PARAMETERPROB)

typedef struct ICMPV4Cache_ {
} ICMPV4Cache;

void DecodeICMPV4RegisterTests(void);

/** ------ Inline functions ------ */
static inline uint16_t ICMPV4CalculateChecksum(uint16_t *, uint16_t);

/**
 * \brief Calculates the checksum for the ICMP packet
 *
 * \param pkt  Pointer to the start of the ICMP packet
 * \param hlen Total length of the ICMP packet(header + payload)
 *
 * \retval csum Checksum for the ICMP packet
 */
static inline uint16_t ICMPV4CalculateChecksum(uint16_t *pkt, uint16_t tlen)
{
    uint16_t pad = 0;
    uint32_t csum = pkt[0];

    tlen -= 4;
    pkt += 2;

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

#endif /* __DECODE_ICMPV4_H__ */

