/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __DECODE_UDP_H__
#define __DECODE_UDP_H__

#define UDP_HEADER_LEN         8

/* XXX RAW* needs to be really 'raw', so no ntohs there */
#define UDP_GET_RAW_LEN(udph)                ntohs((udph)->uh_len)
#define UDP_GET_RAW_SRC_PORT(udph)           ntohs((udph)->uh_sport)
#define UDP_GET_RAW_DST_PORT(udph)           ntohs((udph)->uh_dport)

#define UDP_GET_LEN(p)                       UDP_GET_RAW_LEN(p->udph)
#define UDP_GET_SRC_PORT(p)                  UDP_GET_RAW_SRC_PORT(p->udph)
#define UDP_GET_DST_PORT(p)                  UDP_GET_RAW_DST_PORT(p->udph)

/* UDP header structure */
typedef struct UDPHdr_
{
	u_int16_t uh_sport;  /* source port */
	u_int16_t uh_dport;  /* destination port */
	u_int16_t uh_len;    /* length */
	u_int16_t uh_sum;    /* checksum */
} UDPHdr;

typedef struct UDPVars_
{
    u_int8_t hlen;
} UDPVars;

#endif /* __DECODE_UDP_H__ */
