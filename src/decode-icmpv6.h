/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __DECODE_ICMPV6_H__
#define __DECODE_ICMPV6_H__

#define ICMPV6_HEADER_LEN       8

typedef struct _ICMPV6Hdr
{
    u_int8_t  type;
    u_int8_t  code;
    u_int16_t csum;

    /* XXX incomplete */
} ICMPV6Hdr;

#endif /* __DECODE_ICMPV6_H__ */

