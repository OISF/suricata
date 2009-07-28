/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __DECODE_ICMPV6_H__
#define __DECODE_ICMPV6_H__

#define ICMPV6_HEADER_LEN       8
#ifndef ICMP6_DST_UNREACH
#define ICMP6_DST_UNREACH             1
#endif
#ifndef ICMP6_PACKET_TOO_BIG
#define ICMP6_PACKET_TOO_BIG          2
#endif
#ifndef ICMP6_TIME_EXCEEDED
#define ICMP6_TIME_EXCEEDED           3
#endif
#ifndef ICMP6_PARAM_PROB
#define ICMP6_PARAM_PROB              4
#endif
#ifndef ICMP6_ECHO_REQUEST
#define ICMP6_ECHO_REQUEST          128
#endif
#ifndef ICMP6_ECHO_REPLY
#define ICMP6_ECHO_REPLY            129
#endif
#ifndef MLD_LISTENER_QUERY
#define MLD_LISTENER_QUERY          130
#endif
#ifndef MLD_LISTENER_REPORT
#define MLD_LISTENER_REPORT         131
#endif
#ifndef MLD_LISTENER_REDUCTION
#define MLD_LISTENER_REDUCTION      132
#endif

#ifndef ICMP6_DST_UNREACH_NOROUTE
#define ICMP6_DST_UNREACH_NOROUTE     0 /* no route to destination */
#endif
#ifndef ICMP6_DST_UNREACH_ADMIN
#define ICMP6_DST_UNREACH_ADMIN       1 /* communication with destination */
#endif                                  /* administratively prohibited */
#ifndef ICMP6_DST_UNREACH_BEYONDSCOPE
#define ICMP6_DST_UNREACH_BEYONDSCOPE 2 /* beyond scope of source address */
#endif
#ifndef ICMP6_DST_UNREACH_ADDR
#define ICMP6_DST_UNREACH_ADDR        3 /* address unreachable */
#endif
#ifndef ICMP6_DST_UNREACH_NOPORT
#define ICMP6_DST_UNREACH_NOPORT      4 /* bad port */
#endif
#ifndef ICMP6_TIME_EXCEED_TRANSIT
#define ICMP6_TIME_EXCEED_TRANSIT     0 /* Hop Limit == 0 in transit */
#endif
#ifndef ICMP6_TIME_EXCEED_REASSEMBLY
#define ICMP6_TIME_EXCEED_REASSEMBLY  1 /* Reassembly time out */
#endif
#ifndef ICMP6_PARAMPROB_HEADER
#define ICMP6_PARAMPROB_HEADER        0 /* erroneous header field */
#endif
#ifndef ICMP6_PARAMPROB_NEXTHEADER
#define ICMP6_PARAMPROB_NEXTHEADER    1 /* unrecognized Next Header */
#endif
#ifndef ICMP6_PARAMPROB_OPTION
#define ICMP6_PARAMPROB_OPTION        2 /* unrecognized IPv6 option */
#endif


typedef struct ICMPV6Hdr_
{
    u_int8_t  type;
    u_int8_t  code;
    u_int16_t csum;

    /* XXX incomplete */
} ICMPV6Hdr;

#endif /* __DECODE_ICMPV6_H__ */

