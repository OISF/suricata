/**
 * \file Copyright (c) 2009 Open Information Security Foundation
 * \author James Riden <jamesr@europe.com>
 *
 * \brief PPPOE Decoder
 */

#include "eidps-common.h"

#include "packet-queue.h"

#include "decode.h"
#include "decode-ppp.h"
#include "decode-pppoe.h"
#include "decode-events.h"

#include "util-unittest.h"

/**
 * \brief Main decoding function for PPPOE Discovery packets
 */
void DecodePPPOEDiscovery(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    // TODO
}

/**
 * \brief Main decoding function for PPPOE Session packets
 */
void DecodePPPOESession(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    PerfCounterIncr(dtv->counter_pppoe, tv->pca);

    if (len < PPPOE_SESSION_HEADER_LEN) {
        DECODER_SET_EVENT(p, PPPOE_PKT_TOO_SMALL);
        return;
    }

    p->pppoesh = (PPPOESessionHdr *)pkt;
    if (p->pppoesh == NULL)
        return;

#ifdef DEBUG
    printf("PPPOE VERSION %" PRIu32 " TYPE %" PRIu32 " CODE %" PRIu32 " SESSIONID %" PRIu32 " LENGTH %" PRIu32 "\n",
           p->pppoesh->pppoe_version,  p->pppoesh->pppoe_type,  p->pppoesh->pppoe_code,  ntohs(p->pppoesh->session_id),  ntohs(p->pppoesh->pppoe_length));
#endif

    if (ntohs(p->pppoesh->pppoe_length) > 0) {
        /* decode contained PPP packet */

        switch (ntohs(p->pppoesh->protocol))
        {
            case PPP_VJ_COMP:
            case PPP_IPX:
            case PPP_OSI:
            case PPP_NS:
            case PPP_DECNET:
            case PPP_APPLE:
            case PPP_BRPDU:
            case PPP_STII:
            case PPP_VINES:
            case PPP_HELLO:
            case PPP_LUXCOM:
            case PPP_SNS:
            case PPP_MPLS_UCAST:
            case PPP_MPLS_MCAST:
            case PPP_IPCP:
            case PPP_OSICP:
            case PPP_NSCP:
            case PPP_DECNETCP:
            case PPP_APPLECP:
            case PPP_IPXCP:
            case PPP_STIICP:
            case PPP_VINESCP:
            case PPP_IPV6CP:
            case PPP_MPLSCP:
            case PPP_LCP:
            case PPP_PAP:
            case PPP_LQM:
            case PPP_CHAP:
                DECODER_SET_EVENT(p,PPP_UNSUP_PROTO);
                break;

            case PPP_VJ_UCOMP:

                if(len < (PPPOE_SESSION_HEADER_LEN + IPV4_HEADER_LEN))    {
                    DECODER_SET_EVENT(p,PPPVJU_PKT_TOO_SMALL);
                    return;
                }

                if(IPV4_GET_RAW_VER((IPV4Hdr *)(pkt + PPPOE_SESSION_HEADER_LEN)) == 4) {
                    DecodeIPV4(tv, dtv, p, pkt + PPPOE_SESSION_HEADER_LEN, len - PPPOE_SESSION_HEADER_LEN, pq );
                }
                break;

            case PPP_IP:
                if(len < (PPPOE_SESSION_HEADER_LEN + IPV4_HEADER_LEN))    {
                    DECODER_SET_EVENT(p,PPPIPV4_PKT_TOO_SMALL);
                    return;
                }

                DecodeIPV4(tv, dtv, p, pkt + PPPOE_SESSION_HEADER_LEN, len - PPPOE_SESSION_HEADER_LEN, pq );
            break;

            /* PPP IPv6 was not tested */
            case PPP_IPV6:
                if(len < (PPPOE_SESSION_HEADER_LEN + IPV6_HEADER_LEN))    {
                    DECODER_SET_EVENT(p,PPPIPV6_PKT_TOO_SMALL);
                    return;
                }

                DecodeIPV6(tv, dtv, p, pkt + PPPOE_SESSION_HEADER_LEN, len - PPPOE_SESSION_HEADER_LEN, pq );
                break;

            default:
#ifdef	DEBUG
                printf("Unknown PPP protocol: %" PRIx32 "\n",ntohs(p->ppph->protocol));
#endif
                DECODER_SET_EVENT(p,PPP_WRONG_TYPE);
                return;
        }
    }
}

/** DecodePPPOEtest01
 *  \brief Decode malformed PPPOE packet (too short)
 *  \retval 1 Expected test value
 */
static int DecodePPPOEtest01 (void)   {

    uint8_t raw_pppoe[] = { 0x11, 0x00, 0x00, 0x00, 0x00 };
    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodePPPOESession(&tv, &dtv, &p, raw_pppoe, sizeof(raw_pppoe), NULL);

    if (DECODER_ISSET_EVENT(&p,PPPOE_PKT_TOO_SMALL))  {
        return 1;
    }

    return 0;
}

/** DecodePPPOEtest02
 *  \brief Valid PPPOE packet
 *  \retval 0 Expected test value
 */
static int DecodePPPOEtest02 (void)   {

    uint8_t raw_pppoe[] = {
        0x11, 0x00, 0x00, 0x01, 0x00, 0x68, 0x00, 0x21,
        0x45, 0xc0, 0x00, 0x64, 0x00, 0x1e, 0x00, 0x00,
        0xff, 0x01, 0xa7, 0x78, 0x0a, 0x00, 0x00, 0x02,
        0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x4a, 0x61,
        0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x0f, 0x3b, 0xd4, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd };

    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodePPPOESession(&tv, &dtv, &p, raw_pppoe, sizeof(raw_pppoe), NULL);

    if(DECODER_ISSET_EVENT(&p,PPPOE_PKT_TOO_SMALL))  {
        return 1;
    }

    return 0;
}


/** DecodePPPOEtest03
 *  \brief Valid example PADO packet PPPOE packet taken from RFC2516
 *  \retval 0 Expected test value
 */
static int DecodePPPOEtest03 (void)   {

    /* example PADO packet taken from RFC2516 */
    uint8_t raw_pppoe[] = {
        0x11, 0x07, 0x00, 0x00, 0x00, 0x20, 0x01, 0x01,
        0x00, 0x00, 0x01, 0x02, 0x00, 0x18, 0x47, 0x6f,
        0x20, 0x52, 0x65, 0x64, 0x42, 0x61, 0x63, 0x6b,
        0x20, 0x2d, 0x20, 0x65, 0x73, 0x68, 0x73, 0x68,
        0x65, 0x73, 0x68, 0x6f, 0x6f, 0x74
    };

    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    DecodePPPOEDiscovery(&tv, &dtv, &p, raw_pppoe, sizeof(raw_pppoe), NULL);

    return 0; // TODO
}

/** DecodePPPOEtest04
 *  \brief Valid exaple PADI PPPOE packet taken from RFC2516
 *  \retval 0 Expected test value
 */
static int DecodePPPOEtest04 (void)   {

    /* example PADI packet taken from RFC2516 */
    uint8_t raw_pppoe[] = {
        0x11, 0x09, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01,
        0x00, 0x00
    };

    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    DecodePPPOEDiscovery(&tv, &dtv, &p, raw_pppoe, sizeof(raw_pppoe), NULL);

    return 0; // TODO
}

/**
 * \brief Registers PPPOE unit tests
 * \todo More PPPOE tests
 */
void DecodePPPOERegisterTests(void) {
    UtRegisterTest("DecodePPPOEtest01", DecodePPPOEtest01, 1);
    UtRegisterTest("DecodePPPOEtest02", DecodePPPOEtest02, 0);
    UtRegisterTest("DecodePPPOEtest03", DecodePPPOEtest03, 0);
    UtRegisterTest("DecodePPPOEtest04", DecodePPPOEtest04, 0);
}

