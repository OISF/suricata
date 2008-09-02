/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/*  RespondRejectLibnet11 used to send out libnet based
 *  TCP resets and ICMP unreachables.
 */

/*TODO calculate TTL base on average from stream tracking*/

#include <pthread.h>
#include <sys/signal.h>
#include <libnet.h>

#include "vips.h"
#include "decode.h"
#include "decode-ipv4.h"
#include "decode-tcp.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "action-globals.h"
#include "respond-reject.h"
#include "respond-reject-libnet11.h"

typedef struct _Libnet11Packet
{
    u_int32_t ack, seq;
    u_int16_t window, dsize;
    u_int8_t ttl;
    u_int16_t id;
    u_int32_t flow;
    u_int8_t class;
    struct in6_addr src6, dst6;
    u_int32_t src4, dst4;
    u_int16_t sp, dp;
} Libnet11Packet;

int RejectSendLibnet11L3IPv4TCP(ThreadVars *tv, Packet *p, void *data, int dir){

    Libnet11Packet lpacket;

    libnet_t *c; /* libnet context */
    char ebuf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t t;
    int result;
    
    /* fill in struct defaults */
    lpacket.ttl = 0;
    lpacket.id = 0;
    lpacket.flow = 0;
    lpacket.class = 0;

    if ((c = libnet_init (LIBNET_RAW4, NULL, ebuf)) == NULL)
    {
        printf("RejectSendLibnet11IPv4TCP libnet_init %s\n", ebuf);
        return 1;
    }

    /* shut up a compiler warning
    lpacket.src4.s_addr = 0;
    lpacket.dst4.s_addr = 0;
    */
    if (p->tcph == NULL)
       return 1;

    /* save payload len */
    lpacket.dsize = p->tcp_payload_len;

    if(dir == REJECT_DIR_SRC){
        printf ("sending a tcp reset to src\n");
        lpacket.seq = TCP_GET_ACK(p);
        lpacket.ack = TCP_GET_SEQ(p) + lpacket.dsize;

        lpacket.sp = TCP_GET_DST_PORT(p);
        lpacket.dp = TCP_GET_SRC_PORT(p);
      
        lpacket.src4 = GET_IPV4_DST_ADDR_U32(p);
        lpacket.dst4 = GET_IPV4_SRC_ADDR_U32(p);
    }
    else if(dir == REJECT_DIR_DST){
        printf ("sending a tcp reset to dst\n");
        lpacket.seq = TCP_GET_SEQ(p);
        lpacket.ack = TCP_GET_ACK(p);

        lpacket.sp = TCP_GET_SRC_PORT(p);
        lpacket.dp = TCP_GET_DST_PORT(p);

        lpacket.src4 = GET_IPV4_SRC_ADDR_U32(p);
        lpacket.dst4 = GET_IPV4_DST_ADDR_U32(p);

    } else {
      printf ("reset not src or dst returning\n");
      return 1;
    }

    lpacket.window = TCP_GET_WINDOW(p);
    //lpacket.seq += lpacket.dsize;

    /* TODO come up with ttl calc function */
    lpacket.ttl = 64;

    /* build the package */
    if ((t = libnet_build_tcp (lpacket.sp,                      /* source port */
                               lpacket.dp,                      /* dst port */
                               lpacket.seq,                     /* seq number */
                               lpacket.ack,                     /* ack number */
                               TH_RST|TH_ACK,                    /* flags */
                               lpacket.window,                  /* window size */
                               0,                                /* checksum */
                               0,                                /* urgent flag */
                               LIBNET_TCP_H,                     /* header length */
                               NULL,                             /* payload */
                               0,                                /* payload length */
                               c,                                /* libnet context */
                               0)) < 0)                          /* libnet ptag */
    {
        printf("RejectSendLibnet11IPv4TCP libnet_build_tcp %s\n", libnet_geterror(c));
        goto cleanup;
    }

    if((t = libnet_build_ipv4(
                        LIBNET_TCP_H + LIBNET_IPV4_H,   /* entire packet length */
                        0,                              /* tos */
                        lpacket.id,                    /* ID */
                        0,                              /* fragmentation flags and offset */
                        lpacket.ttl,                   /* TTL */
                        IPPROTO_TCP,                    /* protocol */
                        0,                              /* checksum */
                        lpacket.src4,                 /* source address */
                        lpacket.dst4,                 /* destination address */
                        NULL,                           /* pointer to packet data (or NULL) */
                        0,                              /* payload length */
                        c,                              /* libnet context pointer */
                        0)) < 0)                        /* packet id */
    {
        printf("RejectSendLibnet11IPv4TCP libnet_build_ipv4 %s\n", libnet_geterror(c));
        goto cleanup;
    }

    result = libnet_write(c);
    if (result == -1) {
        printf("RejectSendLibnet11IPv4TCP libnet_write failed: %s\n", libnet_geterror(c));
        goto cleanup;
    }

    cleanup:
       libnet_destroy (c);
       return 0;
}
