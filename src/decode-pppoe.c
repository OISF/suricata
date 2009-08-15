/**
 * \file Copyright (c) 2009 Open Information Security Foundation
 * \author James Riden <jamesr@europe.com>
 *
 * \brief PPPoE Decoder
 */

#include "eidps-common.h"

#include "packet-queue.h"

#include "decode.h"
#include "decode-ppp.h"
#include "decode-pppoe.h"
#include "decode-events.h"

#include "util-unittest.h"

/**
 * \brief Main decoding function for PPPoE packets
 */
void DecodePPPoE(ThreadVars *t, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
#ifdef DEBUG
    printf("DecodePPPoEPacket\n");
#endif

    if (len < PPPOE_HEADER_LEN) {
        DECODER_SET_EVENT(p, PPPOE_PKT_TOO_SMALL);
        return;
    }

    p->pppoeh = (PPPoEHdr *)pkt;

    if (p->pppoeh == NULL)
        return;

    if (p->pppoeh->pppoe_length>0) {
        /* decode contained PPP packet */
        PerfCounterIncr(COUNTER_DECODER_PPP, t->pca);
        DecodePPP(t, p, pkt + PPPOE_HEADER_LEN, len - PPPOE_HEADER_LEN, pq);
    }

}

/** DecodePPPoEtest01
 *  /brief Decode malformed PPPoE packet (too short)
 *  /retval Expected test value: 1
 */
static int DecodePPPoEtest01 (void)   {

    /* 0000  ff ff ff ff ff ff 00 0a e4 13 31 a3 81 00 03 98   ..........1.....
       0010  81 00 00 80 88 63 11 09 00 00 00 08 01 01 00 00   .....c..........
       0020  01 00 00 00 */

    uint8_t raw_pppoe[] = { 0x11, 0x00, 0x00, 0x00, 0x00 };
    Packet p;
    ThreadVars tv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&p, 0, sizeof(Packet));

    DecodePPPoE(&tv, &p, raw_pppoe, sizeof(raw_pppoe), NULL);

    if(DECODER_ISSET_EVENT(&p,PPPOE_PKT_TOO_SMALL))  {
        return 1;
    }

    return 0;
}

/** DecodePPPoEtest02
 *  /brief Valid PPPoE packet
 *  /retval Expected test value: 0
 */
static int DecodePPPoEtest02 (void)   {

    u_int8_t raw_pppoe[] = { 0x11, 0x00, 0x00, 0x01, 0x00, 0x68, 0x00, 0x21, 0x45, 0xc0, 0x00, 0x66, 0x02, 0xa3, 0x00, 0x00
                             , 0xff, 0xfd, 0x91, 0x7b, 0x64, 0x00, 0x00, 0x64, 0xc0, 0x55, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00
                             , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                             , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                             , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                             , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x27, 0x56, 0x8b, 0xa4, 0x7c, 0xfa
                             , 0x38, 0x78, 0xb3, 0x70, 0x3f, 0xda, 0x79, 0x50, 0x2e, 0xd7, 0x7f, 0x4d, 0x7c, 0xd2, 0xdc, 0x80
                             , 0xfa, 0x66};

    Packet p;
    ThreadVars tv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&p, 0, sizeof(Packet));

    DecodePPPoE(&tv, &p, raw_pppoe, sizeof(raw_pppoe), NULL);

    if(DECODER_ISSET_EVENT(&p,PPPOE_PKT_TOO_SMALL))  {
        return 1;
    }

    return 0;
}

/**
 * \brief Registers PPPoE unit tests
 * \todo More PPPoE tests
 */
void DecodePPPoERegisterTests(void) {
    UtRegisterTest("DecodePPPoEtest01", DecodePPPoEtest01, 1);
    UtRegisterTest("DecodePPPoEtest02", DecodePPPoEtest02, 0);
}
