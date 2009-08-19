/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "eidps-common.h"
#include "decode.h"
#include "decode-udp.h"
#include "decode-events.h"

#include "flow.h"

static int DecodeUDPPacket(ThreadVars *t, Packet *p, uint8_t *pkt, uint16_t len)
{
    p->udph = (UDPHdr *)pkt;

    if (len < UDP_GET_LEN(p)) {
        DECODER_SET_EVENT(p, UDP_PKT_TOO_SMALL);
        return -1;
    }

    if (len < UDP_HEADER_LEN) {
        DECODER_SET_EVENT(p, UDP_HLEN_TOO_SMALL);
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

void DecodeUDP(ThreadVars *t, Packet *p, u_int8_t *pkt, u_int16_t len,
               void *data)
{
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    PerfCounterIncr(dtv->counter_udp, t->pca);

    if (DecodeUDPPacket(t, p,pkt,len) < 0)
        return;

#ifdef DEBUG
    /** \todo XXX This has only 4 args for 5 formatters??? */
#if 0
    printf("UDP sp: %" PRIu32 " -> dp: %" PRIu32 " - HLEN: %" PRIu32 " LEN: %" PRIu32 " TEST: %" PRIu32 "\n",
        UDP_GET_SRC_PORT(p), UDP_GET_DST_PORT(p), UDP_HEADER_LEN, p->payload_len);
#endif
#endif

    /* Flow is an integral part of us */
    FlowHandlePacket(t, p);

    return;
}
