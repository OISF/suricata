/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __DECODE_ICMPV4_H__
#define __DECODE_ICMPV4_H__

#define ICMPV4_HEADER_LEN         4

/* ICMPv4 header structure */
typedef struct _ICMPV4Hdr
{
    u_int8_t  type;
    u_int8_t  code;
    u_int16_t csum;

    /* XXX incomplete */
} ICMPV4Hdr;

#endif /* __DECODE_ICMPV4_H__ */

