/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __DECODE_EVENTS_H__
#define __DECODE_EVENTS_H__

enum {
    /* IPV4 EVENTS */
    IPV4_PKT_TOO_SMALL = 1,       /* pkt smaller than minimum header size */
    IPV4_HLEN_TOO_SMALL,
    IPV4_IPLEN_SMALLER_THAN_HLEN,

    /* IPV6 EVENTS */
    IPV6_PKT_TOO_SMALL,
    IPV6_TRUNC_EXTHDR,
    IPV6_EXTHDR_DUPL_FH,
    IPV6_EXTHDR_DUPL_RH,
    IPV6_EXTHDR_DUPL_HH,
    IPV6_EXTHDR_DUPL_DH,
    IPV6_EXTHDR_DUPL_AH,
    IPV6_EXTHDR_DUPL_EH,

    IPV6_EXTHDR_INVALID_OPTLEN, /* the optlen in an hop or dst hdr is invalid. */

    /* TCP EVENTS */
    TCP_PKT_TOO_SMALL,
    TCP_HLEN_TOO_SMALL,
    TCP_INVALID_OPTLEN,

    /* TCP OPTIONS */
    TCP_OPT_INVALID_LEN,
    TCP_OPT_DUPLICATE, /* option length isn't right */

};

#endif /* __DECODE_EVENTS_H__ */
