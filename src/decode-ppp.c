/** Copyright (c) 2009 Open Information Security Foundation
 *  \author Breno Silva Pinto <breno.silva@gmail.com> */

#include "eidps-common.h"

#include "decode.h"
#include "decode-ppp.h"
#include "decode-events.h"

#include "flow.h"

#include "util-unittest.h"

void DecodePPP(ThreadVars *t, Packet *p, u_int8_t *pkt, u_int16_t len,
               PacketQueue *pq, void *data)
{
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    PerfCounterIncr(dtv->counter_ppp, t->pca);

    if(len < PPP_HEADER_LEN)    {
        DECODER_SET_EVENT(p,PPP_PKT_TOO_SMALL);
        return;
    }

    p->ppph = (PPPHdr *)pkt;
    if(p->ppph == NULL)
        return;

#ifdef DEBUG
    printf("DecodePPP: p %p pkt %p PPP protocol %04x Len: %" PRId32 "\n", p, pkt, ntohs(p->ppph->protocol), len);
#endif

    switch (ntohs(p->ppph->protocol))
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

            if(len < (PPP_HEADER_LEN + IPV4_HEADER_LEN))    {
                DECODER_SET_EVENT(p,PPPVJU_PKT_TOO_SMALL);
                return;
            }

            if(IPV4_GET_RAW_VER((IPV4Hdr *)(pkt + PPP_HEADER_LEN)) == 4) {
                DecodeIPV4(t, p, pkt + PPP_HEADER_LEN, len - PPP_HEADER_LEN, pq,
                           data);
            }
            break;

        case PPP_IP:
            if(len < (PPP_HEADER_LEN + IPV4_HEADER_LEN))    {
                DECODER_SET_EVENT(p,PPPIPV4_PKT_TOO_SMALL);
                return;
            }

            DecodeIPV4(t, p, pkt + PPP_HEADER_LEN, len - PPP_HEADER_LEN, pq,
                       data);
            break;

            /* PPP IPv6 was not tested */
        case PPP_IPV6:
            if(len < (PPP_HEADER_LEN + IPV6_HEADER_LEN))    {
                DECODER_SET_EVENT(p,PPPIPV6_PKT_TOO_SMALL);
                return;
            }

            DecodeIPV6(t, p, pkt + PPP_HEADER_LEN, len - PPP_HEADER_LEN, data);
            break;

        default:
#ifdef	DEBUG
            printf("Unknown PPP protocol: %" PRIx32 "\n",ntohs(p->ppph->protocol));
#endif
            DECODER_SET_EVENT(p,PPP_WRONG_TYPE);
            return;
    }

    return;
}

/* TESTS BELOW */

/*  DecodePPPtest01
 *  Decode malformed ip layer PPP packet
 *  Expected test value: 1
 */
static int DecodePPPtest01 (void)   {
    uint8_t raw_ppp[] = { 0xff, 0x03, 0x00, 0x21, 0x45, 0xc0, 0x00 };
    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodePPP(&tv, &p, raw_ppp, sizeof(raw_ppp), NULL, &dtv);

    /* Function my returns here with expected value */

    if(DECODER_ISSET_EVENT(&p,PPPIPV4_PKT_TOO_SMALL))  {
        return 1;
    }

    return 0;
}

/*  DecodePPPtest02
 *  Decode malformed ppp layer packet
 *  Expected test value: 1
 */
static int DecodePPPtest02 (void)   {
    uint8_t raw_ppp[] = { 0xff, 0x03, 0x00, 0xff, 0x45, 0xc0, 0x00, 0x2c, 0x4d,
                           0xed, 0x00, 0x00, 0xff, 0x06, 0xd5, 0x17, 0xbf, 0x01,
                           0x0d, 0x01, 0xbf, 0x01, 0x0d, 0x03, 0xea, 0x37, 0x00,
                           0x17, 0x6d, 0x0b, 0xba, 0xc3, 0x00, 0x00, 0x00, 0x00,
                           0x60, 0x02, 0x10, 0x20, 0xdd, 0xe1, 0x00, 0x00 };
    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodePPP(&tv, &p, raw_ppp, sizeof(raw_ppp), NULL, &dtv);

    /* Function must returns here */

    if(DECODER_ISSET_EVENT(&p,PPP_WRONG_TYPE))  {
        return 1;
    }

    return 0;
}

/** DecodePPPtest03
 *  \brief Decode good PPP packet, additionally the IPv4 packet inside is
 *         4 bytes short.
 *  \retval 0 Test failed
 *  \retval 1 Test succeeded
 */
static int DecodePPPtest03 (void)   {
    uint8_t raw_ppp[] = { 0xff, 0x03, 0x00, 0x21, 0x45, 0xc0, 0x00, 0x2c, 0x4d,
                           0xed, 0x00, 0x00, 0xff, 0x06, 0xd5, 0x17, 0xbf, 0x01,
                           0x0d, 0x01, 0xbf, 0x01, 0x0d, 0x03, 0xea, 0x37, 0x00,
                           0x17, 0x6d, 0x0b, 0xba, 0xc3, 0x00, 0x00, 0x00, 0x00,
                           0x60, 0x02, 0x10, 0x20, 0xdd, 0xe1, 0x00, 0x00 };
    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    DecodePPP(&tv, &p, raw_ppp, sizeof(raw_ppp), NULL, &dtv);

    FlowShutdown();

    if(p.ppph == NULL) {
        return 0;
    }

    if(DECODER_ISSET_EVENT(&p,PPP_PKT_TOO_SMALL))  {
        return 0;
    }

    if(DECODER_ISSET_EVENT(&p,PPPIPV4_PKT_TOO_SMALL))  {
        return 0;
    }

    if(DECODER_ISSET_EVENT(&p,PPP_WRONG_TYPE))  {
        return 0;
    }

    if (!(DECODER_ISSET_EVENT(&p,IPV4_TRUNC_PKT))) {
        return 0;
    }
    /* Function must return here */

    return 1;
}


/*  DecodePPPtest04
 *  Check if ppp header is null
 *  Expected test value: 1
 */

static int DecodePPPtest04 (void)   {
    uint8_t raw_ppp[] = { 0xff, 0x03, 0x00, 0x21, 0x45, 0xc0, 0x00, 0x2c, 0x4d,
                           0xed, 0x00, 0x00, 0xff, 0x06, 0xd5, 0x17, 0xbf, 0x01,
                           0x0d, 0x01, 0xbf, 0x01, 0x0d, 0x03, 0xea, 0x37, 0x00,
                           0x17, 0x6d, 0x0b, 0xba, 0xc3, 0x00, 0x00, 0x00, 0x00,
                           0x60, 0x02, 0x10, 0x20, 0xdd, 0xe1, 0x00, 0x00 };
    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    DecodePPP(&tv, &p, raw_ppp, sizeof(raw_ppp), NULL, &dtv);

    FlowShutdown();

    if(p.ppph == NULL) {
        return 0;
    }

    if (!(DECODER_ISSET_EVENT(&p,IPV4_TRUNC_PKT))) {
        return 0;
    }

    /* Function must returns here */

    return 1;
}

void DecodePPPRegisterTests(void) {
    UtRegisterTest("DecodePPPtest01", DecodePPPtest01, 1);
    UtRegisterTest("DecodePPPtest02", DecodePPPtest02, 1);
    UtRegisterTest("DecodePPPtest03", DecodePPPtest03, 1);
    UtRegisterTest("DecodePPPtest04", DecodePPPtest04, 1);
}

