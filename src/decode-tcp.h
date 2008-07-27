/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __DECODE_TCP_H__
#define __DECODE_TCP_H__

#include <sys/types.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#define TCP_HEADER_LEN                       20
#define TCP_OPTLENMAX                        40
#define TCP_OPTMAX                           20 /* every opt is at least 2 bytes
                                                 * (type + len), except EOL and NOP */

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

#define TCP_OPTS                             tcpvars.tcp_opts
#define TCP_OPTS_CNT                         tcpvars.tcp_opt_cnt

#define TCP_GET_RAW_OFFSET(tcph)             (((tcph)->th_offx2 & 0xf0) >> 4)
#define TCP_GET_RAW_X2(tcph)                 ((tcph)->th_offx2 & 0x0f)
#define TCP_GET_RAW_SRC_PORT(tcph)           ntohs((tcph)->th_sport)
#define TCP_GET_RAW_DST_PORT(tcph)           ntohs((tcph)->th_dport)

#define TCP_SET_RAW_TCP_OFFSET(tcph, value)  ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0x0f) | (value << 4)))
#define TCP_SET_RAW_TCP_X2(tcph, value)      ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0xf0) | (value & 0x0f)))

#define TCP_GET_OFFSET(p)                    TCP_GET_RAW_OFFSET(p->tcph)
#define TCP_GET_HLEN(p)                      TCP_GET_OFFSET(p) << 2
#define TCP_GET_SRC_PORT(p)                  TCP_GET_RAW_SRC_PORT(p->tcph)
#define TCP_GET_DST_PORT(p)                  TCP_GET_RAW_DST_PORT(p->tcph)

typedef struct _TCPOpt {
    u_int8_t type;
    u_int8_t len;
    u_int8_t *data;
} TCPOpt;

typedef struct _TCPHdr
{
    u_int16_t th_sport;     /* source port */
    u_int16_t th_dport;     /* destination port */
    u_int32_t th_seq;       /* sequence number */
    u_int32_t th_ack;       /* acknowledgement number */
    u_int8_t th_offx2;      /* offset and reserved */
    u_int8_t th_flags;      /* pkt flags */
    u_int16_t th_win;       /* pkt window */
    u_int16_t th_sum;       /* checksum */
    u_int16_t th_urp;       /* urgent pointer */
} TCPHdr;

typedef struct _TCPVars
{
    u_int8_t hlen;

    u_int8_t tcp_opt_len;
    TCPOpt tcp_opts[TCP_OPTMAX];
    u_int8_t tcp_opt_cnt;

    /* ptrs to commonly used and needed opts */
    TCPOpt *sackok;
    TCPOpt *ws;
    TCPOpt *ts;
    TCPOpt *mss;
} TCPVars;

#define CLEAR_TCP_PACKET(p) { \
    (p)->tcph = NULL; \
    (p)->tcpvars.tcp_opt_cnt = 0; \
    (p)->tcpvars.sackok = NULL; \
    (p)->tcpvars.ts = NULL; \
    (p)->tcpvars.ws = NULL; \
    (p)->tcpvars.mss = NULL; \
}

#endif /* __DECODE_TCP_H__ */

