/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */
#ifndef __DECODE_SLL_H__
#define __DECODE_SLL_H__

#define SLL_HEADER_LEN                16

typedef struct SllHdr_ {
    uint16_t sll_pkttype;      /* packet type */
    uint16_t sll_hatype;       /* link-layer address type */
    uint16_t sll_halen;        /* link-layer address length */
    uint8_t sll_addr[8];       /* link-layer address */
    uint16_t sll_protocol;     /* protocol */
} SllHdr;

#endif /* __DECODE_SLL_H__ */

