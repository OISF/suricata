/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 *  \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *  \author William Metcalf <william.metcalf@gmail.com>
 *
 *  RespondRejectLibnet11 used to send out libnet based
 *  TCP resets and ICMP unreachables.
 *
 *  \todo calculate TTL base on average from stream tracking
 *  \todo come up with a way for users to specify icmp unreachable type
 *  \todo Possibly default to port unreachable for UDP traffic this seems
 *        to be the default in flexresp and iptables
 *  \todo implement ipv6 resets
 *  \todo implement pre-alloc resets for speed
 */

#include "suricata-common.h"

#include "decode.h"
#include "decode-ipv4.h"
#include "decode-tcp.h"
#include "decode-sctp.h"
#include "decode-udp.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "action-globals.h"
#include "respond-reject.h"
#include "respond-reject-libnet11.h"

#ifdef HAVE_LIBNET11

/** set to true in main if we're setting caps. We need it here if we're using
  * reject rules as libnet 1.1 is not compatible with caps. */
extern int sc_set_caps;

#include <libnet.h>


typedef struct Libnet11Packet_
{
    uint32_t ack, seq;
    uint16_t window, dsize;
    uint8_t ttl;
    uint16_t id;
    uint32_t flow;
    uint8_t class;
    struct in6_addr src6, dst6;
    uint32_t src4, dst4;
    uint16_t sp, dp;
    size_t len;
} Libnet11Packet;

int RejectSendLibnet11L3IPv4TCP(ThreadVars *tv, Packet *p, void *data, int dir) {

    Libnet11Packet lpacket;
    libnet_t *c; /* libnet context */
    char ebuf[LIBNET_ERRBUF_SIZE];
    int result;

    /* fill in struct defaults */
    lpacket.ttl = 0;
    lpacket.id = 0;
    lpacket.flow = 0;
    lpacket.class = 0;

    if ((c = libnet_init (LIBNET_RAW4, NULL, ebuf)) == NULL)
    {
        SCLogError(SC_ERR_LIBNET_INIT,"libnet_inint failed: %s", ebuf);
        return 1;
    }

    if (p->tcph == NULL)
       return 1;

    /* save payload len */
    lpacket.dsize = p->payload_len;

    if (dir == REJECT_DIR_SRC) {
        SCLogDebug("sending a tcp reset to src");
        lpacket.seq = TCP_GET_ACK(p);
        lpacket.ack = TCP_GET_SEQ(p) + lpacket.dsize;

        lpacket.sp = TCP_GET_DST_PORT(p);
        lpacket.dp = TCP_GET_SRC_PORT(p);

        lpacket.src4 = GET_IPV4_DST_ADDR_U32(p);
        lpacket.dst4 = GET_IPV4_SRC_ADDR_U32(p);
    }
    else if (dir == REJECT_DIR_DST) {
        SCLogDebug("sending a tcp reset to dst");
        lpacket.seq = TCP_GET_SEQ(p);
        lpacket.ack = TCP_GET_ACK(p);

        lpacket.sp = TCP_GET_SRC_PORT(p);
        lpacket.dp = TCP_GET_DST_PORT(p);

        lpacket.src4 = GET_IPV4_SRC_ADDR_U32(p);
        lpacket.dst4 = GET_IPV4_DST_ADDR_U32(p);

    } else {
        SCLogError(SC_ERR_LIBNET_INVALID_DIR,"reset not src or dst returning");
        return 1;
    }

    lpacket.window = TCP_GET_WINDOW(p);
    //lpacket.seq += lpacket.dsize;

    /* TODO come up with ttl calc function */
    lpacket.ttl = 64;

    /* build the package */
    if ((libnet_build_tcp (
                    lpacket.sp,            /* source port */
                    lpacket.dp,            /* dst port */
                    lpacket.seq,           /* seq number */
                    lpacket.ack+1,           /* ack number */
                    TH_RST|TH_ACK,         /* flags */
                    lpacket.window,        /* window size */
                    0,                     /* checksum */
                    0,                     /* urgent flag */
                    LIBNET_TCP_H,          /* header length */
                    NULL,                  /* payload */
                    0,                     /* payload length */
                    c,                     /* libnet context */
                    0)) < 0)               /* libnet ptag */
    {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_tcp %s", libnet_geterror(c));
        goto cleanup;
    }

    if((libnet_build_ipv4(
                    LIBNET_TCP_H + LIBNET_IPV4_H, /* entire packet length */
                    0,                            /* tos */
                    lpacket.id,                   /* ID */
                    0,                            /* fragmentation flags and offset */
                    lpacket.ttl,                  /* TTL */
                    IPPROTO_TCP,                  /* protocol */
                    0,                            /* checksum */
                    lpacket.src4,                 /* source address */
                    lpacket.dst4,                 /* destination address */
                    NULL,                         /* pointer to packet data (or NULL) */
                    0,                            /* payload length */
                    c,                            /* libnet context pointer */
                    0)) < 0)                      /* packet id */
    {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_ipv4 %s", libnet_geterror(c));
        goto cleanup;
    }

    result = libnet_write(c);
    if (result == -1) {
        SCLogError(SC_ERR_LIBNET_WRITE_FAILED,"libnet_write failed: %s", libnet_geterror(c));
        goto cleanup;
    }

cleanup:
    libnet_destroy (c);
    return 0;
}

int RejectSendLibnet11L3IPv4ICMP(ThreadVars *tv, Packet *p, void *data, int dir) {
    //printf("going to send a ICMP host unreachable\n");
    Libnet11Packet lpacket;
    libnet_t *c; /* libnet context */
    char ebuf[LIBNET_ERRBUF_SIZE];
    int result;

    /* fill in struct defaults */
    lpacket.ttl = 0;
    lpacket.id = 0;
    lpacket.flow = 0;
    lpacket.class = 0;

    lpacket.len = (IPV4_GET_HLEN(p) + p->payload_len);
    if ((c = libnet_init (LIBNET_RAW4, NULL, ebuf)) == NULL){
        SCLogError(SC_ERR_LIBNET_INIT,"libnet_inint failed: %s", ebuf);
        return 1;
    }

    if (dir == REJECT_DIR_SRC) {
        lpacket.src4 = GET_IPV4_DST_ADDR_U32(p);
        lpacket.dst4 = GET_IPV4_SRC_ADDR_U32(p);
    }
    else if (dir == REJECT_DIR_DST) {
        lpacket.src4 = GET_IPV4_SRC_ADDR_U32(p);
        lpacket.dst4 = GET_IPV4_DST_ADDR_U32(p);

    } else {
        SCLogError(SC_ERR_LIBNET_INVALID_DIR,"reset not src or dst returning");
        return 1;
    }

    /* TODO come up with ttl calc function */
    lpacket.ttl = 64;

    /* build the package */
    if ((libnet_build_icmpv4_unreach (
                    ICMP_DEST_UNREACH,        /* type */
                    ICMP_HOST_ANO,            /* code */
                    0,                        /* checksum */
                    (uint8_t *)p->ip4h,       /* payload */
                    lpacket.len,              /* payload length */
                    c,                        /* libnet context */
                    0)) < 0)                  /* libnet ptag */
    {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_icmpv4_unreach %s", libnet_geterror(c));
        goto cleanup;
    }

    if((libnet_build_ipv4(
                    LIBNET_ICMPV4_H + LIBNET_IPV4_H +
                    lpacket.len,                    /* entire packet length */
                    0,                              /* tos */
                    lpacket.id,                     /* ID */
                    0,                              /* fragmentation flags and offset */
                    lpacket.ttl,                    /* TTL */
                    IPPROTO_ICMP,                   /* protocol */
                    0,                              /* checksum */
                    lpacket.src4,                   /* source address */
                    lpacket.dst4,                   /* destination address */
                    NULL,                           /* pointer to packet data (or NULL) */
                    0,                              /* payload length */
                    c,                              /* libnet context pointer */
                    0)) < 0)                        /* packet id */
    {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_ipv4 %s", libnet_geterror(c));
        goto cleanup;
    }

    result = libnet_write(c);
    if (result == -1) {
        SCLogError(SC_ERR_LIBNET_WRITE_FAILED,"libnet_write_raw_ipv4 failed: %s", libnet_geterror(c));
        goto cleanup;
    }

cleanup:
    libnet_destroy (c);
    return 0;
}

#else

int RejectSendLibnet11L3IPv4TCP(ThreadVars *tv, Packet *p, void *data, int dir) {
	SCLogError(SC_ERR_LIBNET_NOT_ENABLED,"Libnet based rejects are disabled. Usually this means that you don't have libnet installed, or configure couldn't find it.");
	return 0;
}

int RejectSendLibnet11L3IPv4ICMP(ThreadVars *tv, Packet *p, void *data, int dir) {
    SCLogError(SC_ERR_LIBNET_NOT_ENABLED,"Libnet based rejects are disabled. Usually this means that you don't have libnet installed, or configure couldn't find it.");
	return 0;
}

#endif /* HAVE_LIBNET11 */
