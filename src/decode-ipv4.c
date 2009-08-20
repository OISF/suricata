/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "eidps-common.h"
#include "packet-queue.h"
#include "decode.h"
#include "decode-ipv4.h"
#include "decode-events.h"

/* XXX */
static int DecodeIPV4Options(ThreadVars *tv, Packet *p, uint8_t *pkt, uint16_t len)
{
    printf("*pkt %" PRIu32 "\n", *pkt);

    return 0;
}

static int DecodeIPV4Packet(ThreadVars *tv, Packet *p, uint8_t *pkt, uint16_t len)
{
#ifdef DEBUG
    printf("DecodeIPV4Packet\n");
#endif
    if (len < IPV4_HEADER_LEN) {
        DECODER_SET_EVENT(p,IPV4_PKT_TOO_SMALL);
        return -1;
    }

    p->ip4h = (IPV4Hdr *)pkt;

    if (IPV4_GET_HLEN(p) < IPV4_HEADER_LEN) {
        DECODER_SET_EVENT(p,IPV4_HLEN_TOO_SMALL);
        return -1;
    }

    if (IPV4_GET_IPLEN(p) < IPV4_GET_HLEN(p)) {
        DECODER_SET_EVENT(p,IPV4_IPLEN_SMALLER_THAN_HLEN);
        return -1;
    }

    if (len < IPV4_GET_IPLEN(p)) {
        DECODER_SET_EVENT(p,IPV4_TRUNC_PKT);
        return -1;
    }

    /* save the options len */
    p->ip4vars.ip_opts_len = IPV4_GET_HLEN(p) - IPV4_HEADER_LEN;
    if (p->ip4vars.ip_opts_len > 0) {
        DecodeIPV4Options(tv, p, pkt + IPV4_GET_HLEN(p), p->ip4vars.ip_opts_len);
    }

    /* set the address struct */
    SET_IPV4_SRC_ADDR(p,&p->src);
    SET_IPV4_DST_ADDR(p,&p->dst);
    return 0;
}

void DecodeIPV4(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    int ret;

    PerfCounterIncr(dtv->counter_ipv4, tv->pca);

    /* reset the decoder cache flags */
    IPV4_CACHE_INIT(p);

#ifdef DEBUG
    printf("DecodeIPV4\n");
#endif

    /* do the actual decoding */
    ret = DecodeIPV4Packet (tv, p, pkt, len);
    if (ret < 0) {
#ifdef DEBUG
        printf("DecodeIPV4 failed!\n");
#endif
        p->ip4h = NULL;
        return;
    }

    /* do hdr test, process hdr rules */

#ifdef DEBUG
    /* debug print */
    char s[16], d[16];
    inet_ntop(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), s, sizeof(s));
    inet_ntop(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), d, sizeof(d));
    printf("IPV4 %s->%s PROTO: %" PRIu32 " OFFSET: %" PRIu32 " RF: %" PRIu32 " DF: %" PRIu32 " MF: %" PRIu32 " ID: %" PRIu32 "\n", s,d,
            IPV4_GET_IPPROTO(p), IPV4_GET_IPOFFSET(p), IPV4_GET_RF(p),
            IPV4_GET_DF(p), IPV4_GET_MF(p), IPV4_GET_IPID(p));
#endif /* DEBUG */

    /* check what next decoder to invoke */
    switch (IPV4_GET_IPPROTO(p)) {
        case IPPROTO_IP:
            /* check PPP VJ uncompressed packets and decode tcp dummy */
            if(p->ppph != NULL && ntohs(p->ppph->protocol) == PPP_VJ_UCOMP)    {
                return(DecodeTCP(tv, dtv, p, pkt + IPV4_GET_HLEN(p),
                                 IPV4_GET_IPLEN(p) -  IPV4_GET_HLEN(p), pq));
            }
            break;
        case IPPROTO_TCP:
            return(DecodeTCP(tv, dtv, p, pkt + IPV4_GET_HLEN(p),
                             IPV4_GET_IPLEN(p) - IPV4_GET_HLEN(p), pq));
            break;
        case IPPROTO_UDP:
            //printf("DecodeIPV4: next layer is UDP\n");
            return(DecodeUDP(tv, dtv, p, pkt + IPV4_GET_HLEN(p),
                             IPV4_GET_IPLEN(p) - IPV4_GET_HLEN(p), pq));
            break;
        case IPPROTO_ICMP:
            //printf("DecodeIPV4: next layer is ICMP\n");
            return(DecodeICMPV4(tv, dtv, p, pkt + IPV4_GET_HLEN(p),
                                IPV4_GET_IPLEN(p) - IPV4_GET_HLEN(p), pq));
            break;
        case IPPROTO_IPV6:
            {
                if (pq != NULL) {
                    //printf("DecodeIPV4: next layer is IPV6\n");
                    //printf("DecodeIPV4: we are p %p\n", p);

                    /* spawn off tunnel packet */
                    Packet *tp = TunnelPktSetup(tv, dtv, p, pkt + IPV4_GET_HLEN(p), IPV4_GET_IPLEN(p) - IPV4_GET_HLEN(p), IPV4_GET_IPPROTO(p));
                    //printf("DecodeIPV4: tunnel is tp %p\n", tp);

                    /* send that to the Tunnel decoder */
                    DecodeTunnel(tv, dtv, tp, tp->pkt, tp->pktlen, pq);
                    /* add the tp to the packet queue. */
                    PacketEnqueue(pq,tp);

                    /* the current packet is now a tunnel packet */
                    SET_TUNNEL_PKT(p);
                }
                break;
            }
    }

    return;
}

