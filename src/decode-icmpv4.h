/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __DECODE_ICMPV4_H__
#define __DECODE_ICMPV4_H__

#define ICMPV4_HEADER_LEN         4
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

/* ICMPv4 header structure */
typedef struct ICMPV4Hdr_
{
    uint8_t  type;
    uint8_t  code;
    uint16_t csum;

    /* XXX incomplete */
} ICMPV4Hdr;

#endif /* __DECODE_ICMPV4_H__ */

