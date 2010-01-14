/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __DECODE_ICMPV6_H__
#define __DECODE_ICMPV6_H__

#include "decode-tcp.h"
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
#define ICMPV6_GET_CSUM(p)      (p)->icmpv6h->csum

/** If message is informational */
/** macro for icmpv6 "id" access */
/* #define ICMPV6_GET_ID(p)        (p)->icmpv6h->icmpv6b.icmpv6i.id */
#define ICMPV6_GET_ID(p)        (p)->icmpv6vars.id
/** macro for icmpv6 "seq" access */
/* #define ICMPV6_GET_SEQ(p)       (p)->icmpv6h->icmpv6b.icmpv6i.seq */
#define ICMPV6_GET_SEQ(p)       (ntohs((p)->icmpv6vars.seq))

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

typedef struct ICMPV6Cache_ {
    /* checksum computed over the icmpv6 packet */
    int32_t comp_csum;
} ICMPV6Cache;

/** ICMPv6 header structure */
typedef struct ICMPV6Hdr_
{
    uint8_t  type;
    uint8_t  code;
    uint16_t csum;
    union{
        ICMPV6Info icmpv6i; /** Informational message */
        union
        {
            uint32_t  unused; /** for types 1 and 3, should be zero */
            uint32_t  error_ptr; /** for type 4, pointer to the octet that originate the error */
            uint32_t  mtu; /** for type 2, the Maximum Transmission Unit of the next-hop link */
        }icmpv6e;   /** Error Message */
    }icmpv6b;
} ICMPV6Hdr;

/** Data available from the decoded packet */
typedef struct ICMPV6Vars_ {
    uint8_t  type;
    uint8_t  code;

    /* checksum of the icmpv6 packet */
    uint16_t csum;
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

inline uint16_t ICMPV6CalculateChecksum(uint16_t *, uint16_t *, uint16_t);
void DecodeICMPV6RegisterTests(void);

#endif /* __DECODE_ICMPV6_H__ */

