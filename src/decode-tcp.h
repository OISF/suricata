/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/** \file
 *  \todo RAW* macro's should be returning the raw value, not the host order */

#ifndef __DECODE_TCP_H__
#define __DECODE_TCP_H__

#define TCP_HEADER_LEN                       20
#define TCP_OPTLENMAX                        40
#define TCP_OPTMAX                           20 /* every opt is at least 2 bytes
                                                 * (type + len), except EOL and NOP */

/* TCP flags */
#define TH_FIN                               0x01
#define TH_SYN                               0x02
#define TH_RST                               0x04
#define TH_PUSH                              0x08
#define TH_ACK                               0x10
#define TH_URG                               0x20
#define TH_RES2                              0x40
#define TH_RES1                              0x80

/* tcp option codes */
#define TCP_OPT_EOL                          0x00
#define TCP_OPT_NOP                          0x01
#define TCP_OPT_MSS                          0x02
#define TCP_OPT_WS                           0x03
#define TCP_OPT_SACKOK                       0x04
#define TCP_OPT_SACK                         0x05
#define TCP_OPT_TS                           0x08

#define TCP_OPT_SACKOK_LEN                   2
#define TCP_OPT_WS_LEN                       3
#define TCP_OPT_TS_LEN                       10
#define TCP_OPT_MSS_LEN                      4

/** Max valid wscale value. */
#define TCP_WSCALE_MAX                       14

#define TCP_OPTS                             tcpvars.tcp_opts
#define TCP_OPTS_CNT                         tcpvars.tcp_opt_cnt

#define TCP_GET_RAW_OFFSET(tcph)             (((tcph)->th_offx2 & 0xf0) >> 4)
#define TCP_GET_RAW_X2(tcph)                 ((tcph)->th_offx2 & 0x0f)
#define TCP_GET_RAW_SRC_PORT(tcph)           ntohs((tcph)->th_sport)
#define TCP_GET_RAW_DST_PORT(tcph)           ntohs((tcph)->th_dport)

#define TCP_SET_RAW_TCP_OFFSET(tcph, value)  ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0x0f) | (value << 4)))
#define TCP_SET_RAW_TCP_X2(tcph, value)      ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0xf0) | (value & 0x0f)))

#define TCP_GET_RAW_SEQ(tcph)                ntohl((tcph)->th_seq)
#define TCP_GET_RAW_ACK(tcph)                ntohl((tcph)->th_ack)

#define TCP_GET_RAW_WINDOW(tcph)             ntohs((tcph)->th_win)

/** macro for getting the first timestamp from the packet. Timestamp is in host
 *  order and either returned from the cache or from the packet directly. */
#define TCP_GET_TSVAL(p)                       ((p)->tcpc.ts1 != 0 ? \
                                             (p)->tcpc.ts1 : (p)->tcpvars.ts ? ((p)->tcpc.ts1 = (uint32_t)ntohl((*(uint32_t *)(p)->tcpvars.ts->data))) : 0)
/** macro for getting the second timestamp from the packet. Timestamp is in
 *  host order and either returned from the cache or from the packet directly. */
#define TCP_GET_TSECR(p)                       ((p)->tcpc.ts2 != 0 ? \
                                             (p)->tcpc.ts2 : (p)->tcpvars.ts ? ((p)->tcpc.ts2 = (uint32_t)ntohl((*(uint32_t *)((p)->tcpvars.ts->data+4)))) : 0)

/** macro for getting the wscale from the packet. */
#define TCP_GET_WSCALE(p)                    ((p)->tcpvars.ws ? (((*(uint8_t *)(p)->tcpvars.ws->data) <= TCP_WSCALE_MAX) ? (*(uint8_t *)((p)->tcpvars.ws->data)) : 0) : 0)

#define TCP_GET_OFFSET(p)                    TCP_GET_RAW_OFFSET(p->tcph)
#define TCP_GET_HLEN(p)                      TCP_GET_OFFSET(p) << 2
#define TCP_GET_SRC_PORT(p)                  TCP_GET_RAW_SRC_PORT(p->tcph)
#define TCP_GET_DST_PORT(p)                  TCP_GET_RAW_DST_PORT(p->tcph)
#define TCP_GET_SEQ(p)                       TCP_GET_RAW_SEQ(p->tcph)
#define TCP_GET_ACK(p)                       TCP_GET_RAW_ACK(p->tcph)
#define TCP_GET_WINDOW(p)                    TCP_GET_RAW_WINDOW(p->tcph)

#define TCP_ISSET_FLAG_FIN(p)                ((p)->tcph->th_flags & TH_FIN)
#define TCP_ISSET_FLAG_SYN(p)                ((p)->tcph->th_flags & TH_SYN)
#define TCP_ISSET_FLAG_RST(p)                ((p)->tcph->th_flags & TH_RST)
#define TCP_ISSET_FLAG_PUSH(p)               ((p)->tcph->th_flags & TH_PUSH)
#define TCP_ISSET_FLAG_ACK(p)                ((p)->tcph->th_flags & TH_ACK)
#define TCP_ISSET_FLAG_URG(p)                ((p)->tcph->th_flags & TH_URG)
#define TCP_ISSET_FLAG_RES2(p)               ((p)->tcph->th_flags & TH_RES2)
#define TCP_ISSET_FLAG_RES1(p)               ((p)->tcph->th_flags & TH_RES1)

typedef struct TCPOpt_ {
    uint8_t type;
    uint8_t len;
    uint8_t *data;
} TCPOpt;

typedef struct TCPHdr_
{
    uint16_t th_sport;     /* source port */
    uint16_t th_dport;     /* destination port */
    uint32_t th_seq;       /* sequence number */
    uint32_t th_ack;       /* acknowledgement number */
    uint8_t th_offx2;      /* offset and reserved */
    uint8_t th_flags;      /* pkt flags */
    uint16_t th_win;       /* pkt window */
    uint16_t th_sum;       /* checksum */
    uint16_t th_urp;       /* urgent pointer */
} TCPHdr;

typedef struct TCPVars_
{
    uint8_t hlen;

    uint8_t tcp_opt_len;
    TCPOpt tcp_opts[TCP_OPTMAX];
    uint8_t tcp_opt_cnt;

    /* ptrs to commonly used and needed opts */
    TCPOpt *sackok;
    TCPOpt *ws;
    TCPOpt *ts;
    TCPOpt *mss;
} TCPVars;

/** cache to store parsed/calculated results of the decoder */
typedef struct TCPCache_ {
    /* checksum computed over the tcp(for both ipv4 and ipv6) packet */
    int32_t comp_csum;

    uint32_t ts1; /**< host order version of the first ts */
    uint32_t ts2; /**< host order version of the second ts */
} TCPCache;

#define CLEAR_TCP_PACKET(p) { \
    (p)->tcph = NULL; \
    (p)->tcpvars.tcp_opt_cnt = 0; \
    (p)->tcpvars.sackok = NULL; \
    (p)->tcpvars.ts = NULL; \
    (p)->tcpvars.ws = NULL; \
    (p)->tcpvars.mss = NULL; \
    (p)->tcpc.ts1 = 0; \
    (p)->tcpc.ts2 = 0; \
}

inline uint16_t TCPCalculateChecksum(uint16_t *, uint16_t *, uint16_t);
inline uint16_t TCPV6CalculateChecksum(uint16_t *, uint16_t *, uint16_t);
void DecodeTCPRegisterTests(void);

#endif /* __DECODE_TCP_H__ */

