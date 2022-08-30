/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \ingroup decode
 *
 * @{
 */


/**
 * \file
 *
 * \author Breno Silva Pinto <breno.silva@gmail.com>
 *
 * Decode PPP
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-ppp.h"
#include "decode-events.h"

#include "flow.h"

#include "util-validate.h"
#include "util-unittest.h"
#include "util-debug.h"

int DecodePPP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    StatsIncr(tv, dtv->counter_ppp);

    if (unlikely(len < PPP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, PPP_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }
    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    p->ppph = (PPPHdr *)pkt;

    SCLogDebug("p %p pkt %p PPP protocol %04x Len: %" PRIu32 "",
        p, pkt, SCNtohs(p->ppph->protocol), len);

    switch (SCNtohs(p->ppph->protocol))
    {
        case PPP_VJ_UCOMP:
            if (unlikely(len < (PPP_HEADER_LEN + IPV4_HEADER_LEN))) {
                ENGINE_SET_INVALID_EVENT(p,PPPVJU_PKT_TOO_SMALL);
                p->ppph = NULL;
                return TM_ECODE_FAILED;
            }

            if (unlikely(len > PPP_HEADER_LEN + USHRT_MAX)) {
                return TM_ECODE_FAILED;
            }

            if (likely(IPV4_GET_RAW_VER((IPV4Hdr *)(pkt + PPP_HEADER_LEN)) == 4)) {
                return DecodeIPV4(
                        tv, dtv, p, pkt + PPP_HEADER_LEN, (uint16_t)(len - PPP_HEADER_LEN));
            } else
                return TM_ECODE_FAILED;
            break;

        case PPP_IP:
            if (unlikely(len < (PPP_HEADER_LEN + IPV4_HEADER_LEN))) {
                ENGINE_SET_INVALID_EVENT(p,PPPIPV4_PKT_TOO_SMALL);
                p->ppph = NULL;
                return TM_ECODE_FAILED;
            }
            if (unlikely(len > PPP_HEADER_LEN + USHRT_MAX)) {
                return TM_ECODE_FAILED;
            }

            return DecodeIPV4(tv, dtv, p, pkt + PPP_HEADER_LEN, (uint16_t)(len - PPP_HEADER_LEN));

            /* PPP IPv6 was not tested */
        case PPP_IPV6:
            if (unlikely(len < (PPP_HEADER_LEN + IPV6_HEADER_LEN))) {
                ENGINE_SET_INVALID_EVENT(p,PPPIPV6_PKT_TOO_SMALL);
                p->ppph = NULL;
                return TM_ECODE_FAILED;
            }
            if (unlikely(len > PPP_HEADER_LEN + USHRT_MAX)) {
                return TM_ECODE_FAILED;
            }

            return DecodeIPV6(tv, dtv, p, pkt + PPP_HEADER_LEN, (uint16_t)(len - PPP_HEADER_LEN));

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
            ENGINE_SET_EVENT(p,PPP_UNSUP_PROTO);
            return TM_ECODE_OK;

        default:
            SCLogDebug("unknown PPP protocol: %" PRIx32 "",SCNtohs(p->ppph->protocol));
            ENGINE_SET_INVALID_EVENT(p, PPP_WRONG_TYPE);
            return TM_ECODE_OK;
    }

}

/* TESTS BELOW */
#ifdef UNITTESTS

/*  DecodePPPtest01
 *  Decode malformed ip layer PPP packet
 *  Expected test value: 1
 */
static int DecodePPPtest01 (void)
{
    uint8_t raw_ppp[] = { 0xff, 0x03, 0x00, 0x21, 0x45, 0xc0, 0x00 };
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodePPP(&tv, &dtv, p, raw_ppp, sizeof(raw_ppp));

    /* Function my returns here with expected value */

    if(ENGINE_ISSET_EVENT(p,PPPIPV4_PKT_TOO_SMALL))  {
        SCFree(p);
        return 1;
    }

    SCFree(p);
    return 0;
}

/*  DecodePPPtest02
 *  Decode malformed ppp layer packet
 *  Expected test value: 1
 */
static int DecodePPPtest02 (void)
{
    uint8_t raw_ppp[] = { 0xff, 0x03, 0x00, 0xff, 0x45, 0xc0, 0x00, 0x2c, 0x4d,
                           0xed, 0x00, 0x00, 0xff, 0x06, 0xd5, 0x17, 0xbf, 0x01,
                           0x0d, 0x01, 0xbf, 0x01, 0x0d, 0x03, 0xea, 0x37, 0x00,
                           0x17, 0x6d, 0x0b, 0xba, 0xc3, 0x00, 0x00, 0x00, 0x00,
                           0x60, 0x02, 0x10, 0x20, 0xdd, 0xe1, 0x00, 0x00 };
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodePPP(&tv, &dtv, p, raw_ppp, sizeof(raw_ppp));

    /* Function must returns here */

    if(ENGINE_ISSET_EVENT(p,PPP_WRONG_TYPE))  {
        SCFree(p);
        return 1;
    }

    SCFree(p);
    return 0;
}

/** DecodePPPtest03
 *  \brief Decode good PPP packet, additionally the IPv4 packet inside is
 *         4 bytes short.
 *  \retval 0 Test failed
 *  \retval 1 Test succeeded
 */
static int DecodePPPtest03 (void)
{
    uint8_t raw_ppp[] = { 0xff, 0x03, 0x00, 0x21, 0x45, 0xc0, 0x00, 0x2c, 0x4d,
                           0xed, 0x00, 0x00, 0xff, 0x06, 0xd5, 0x17, 0xbf, 0x01,
                           0x0d, 0x01, 0xbf, 0x01, 0x0d, 0x03, 0xea, 0x37, 0x00,
                           0x17, 0x6d, 0x0b, 0xba, 0xc3, 0x00, 0x00, 0x00, 0x00,
                           0x60, 0x02, 0x10, 0x20, 0xdd, 0xe1, 0x00, 0x00 };
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    DecodePPP(&tv, &dtv, p, raw_ppp, sizeof(raw_ppp));

    FlowShutdown();

    if(p->ppph == NULL) {
        SCFree(p);
        return 0;
    }

    if(ENGINE_ISSET_EVENT(p,PPP_PKT_TOO_SMALL))  {
        SCFree(p);
        return 0;
    }

    if(ENGINE_ISSET_EVENT(p,PPPIPV4_PKT_TOO_SMALL))  {
        SCFree(p);
        return 0;
    }

    if(ENGINE_ISSET_EVENT(p,PPP_WRONG_TYPE))  {
        SCFree(p);
        return 0;
    }

    if (!(ENGINE_ISSET_EVENT(p,IPV4_TRUNC_PKT))) {
        SCFree(p);
        return 0;
    }
    /* Function must return here */

    SCFree(p);
    return 1;
}


/*  DecodePPPtest04
 *  Check if ppp header is null
 *  Expected test value: 1
 */

static int DecodePPPtest04 (void)
{
    uint8_t raw_ppp[] = { 0xff, 0x03, 0x00, 0x21, 0x45, 0xc0, 0x00, 0x2c, 0x4d,
                           0xed, 0x00, 0x00, 0xff, 0x06, 0xd5, 0x17, 0xbf, 0x01,
                           0x0d, 0x01, 0xbf, 0x01, 0x0d, 0x03, 0xea, 0x37, 0x00,
                           0x17, 0x6d, 0x0b, 0xba, 0xc3, 0x00, 0x00, 0x00, 0x00,
                           0x60, 0x02, 0x10, 0x20, 0xdd, 0xe1, 0x00, 0x00 };
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    DecodePPP(&tv, &dtv, p, raw_ppp, sizeof(raw_ppp));

    FlowShutdown();

    if(p->ppph == NULL) {
        SCFree(p);
        return 0;
    }

    if (!(ENGINE_ISSET_EVENT(p,IPV4_TRUNC_PKT))) {
        SCFree(p);
        return 0;
    }

    /* Function must returns here */

    SCFree(p);
    return 1;
}
#endif /* UNITTESTS */

void DecodePPPRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodePPPtest01", DecodePPPtest01);
    UtRegisterTest("DecodePPPtest02", DecodePPPtest02);
    UtRegisterTest("DecodePPPtest03", DecodePPPtest03);
    UtRegisterTest("DecodePPPtest04", DecodePPPtest04);
#endif /* UNITTESTS */
}

/**
 * @}
 */
