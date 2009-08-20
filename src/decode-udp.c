/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "eidps-common.h"
#include "decode.h"
#include "decode-udp.h"
#include "decode-events.h"

#include "flow.h"

static int DecodeUDPPacket(ThreadVars *t, Packet *p, uint8_t *pkt, uint16_t len)
{
    if (len < UDP_HEADER_LEN) {
        DECODER_SET_EVENT(p, UDP_HLEN_TOO_SMALL);
        return -1;
    }

    p->udph = (UDPHdr *)pkt;

    if (len < UDP_GET_LEN(p)) {
        DECODER_SET_EVENT(p, UDP_PKT_TOO_SMALL);
        return -1;
    }

    if (len != UDP_GET_LEN(p)) {
        DECODER_SET_EVENT(p, UDP_HLEN_INVALID);
        return -1;
    }

    SET_UDP_SRC_PORT(p,&p->sp);
    SET_UDP_DST_PORT(p,&p->dp);

    p->payload = pkt + UDP_HEADER_LEN;
    p->payload_len = len - UDP_HEADER_LEN;

    p->proto = IPPROTO_UDP;

    return 0;
}

void DecodeUDP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    PerfCounterIncr(dtv->counter_udp, tv->pca);

    if (DecodeUDPPacket(tv, p,pkt,len) < 0) {
        p->udph = NULL;
        return;
    }

#ifdef DEBUG
    printf("UDP sp: %" PRIu32 " -> dp: %" PRIu32 " - HLEN: %" PRIu32 " LEN: %" PRIu32 "\n",
        UDP_GET_SRC_PORT(p), UDP_GET_DST_PORT(p), UDP_HEADER_LEN, p->payload_len);
#endif

    /* Flow is an integral part of us */
    FlowHandlePacket(tv, p);

    return;
}
