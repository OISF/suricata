/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * \author James Riden <jamesr@europe.com>
 *
 * PPPOE Decoder
 */

#include "suricata-common.h"

#include "decode-pppoe.h"
#include "flow.h"

#include "util-validate.h"

/**
 * \brief Main decoding function for PPPOE Discovery packets
 */
int DecodePPPOEDiscovery(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    StatsIncr(tv, dtv->counter_pppoe);

    if (len < PPPOE_DISCOVERY_HEADER_MIN_LEN) {
        ENGINE_SET_INVALID_EVENT(p, PPPOE_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    p->pppoedh = (PPPOEDiscoveryHdr *)pkt;

    /* parse the PPPOE code */
    switch (p->pppoedh->pppoe_code)
    {
        case  PPPOE_CODE_PADI:
            break;
        case  PPPOE_CODE_PADO:
            break;
        case  PPPOE_CODE_PADR:
            break;
        case PPPOE_CODE_PADS:
            break;
        case PPPOE_CODE_PADT:
            break;
        default:
            SCLogDebug("unknown PPPOE code: 0x%0"PRIX8"", p->pppoedh->pppoe_code);
            ENGINE_SET_INVALID_EVENT(p, PPPOE_WRONG_CODE);
            return TM_ECODE_OK;
    }

    /* parse any tags we have in the packet */

    uint32_t tag_length = 0;
    PPPOEDiscoveryTag* pppoedt = (PPPOEDiscoveryTag*) (p->pppoedh +  PPPOE_DISCOVERY_HEADER_MIN_LEN);

    uint32_t pppoe_length = SCNtohs(p->pppoedh->pppoe_length);
    uint32_t packet_length = len - PPPOE_DISCOVERY_HEADER_MIN_LEN ;

    SCLogDebug("pppoe_length %"PRIu32", packet_length %"PRIu32"",
        pppoe_length, packet_length);

    if (pppoe_length > packet_length) {
        SCLogDebug("malformed PPPOE tags");
        ENGINE_SET_INVALID_EVENT(p, PPPOE_MALFORMED_TAGS);
        return TM_ECODE_OK;
    }

    while (pppoedt < (PPPOEDiscoveryTag*) (pkt + (len - sizeof(PPPOEDiscoveryTag))) && pppoe_length >=4 && packet_length >=4)
    {
#ifdef DEBUG
        uint16_t tag_type = SCNtohs(pppoedt->pppoe_tag_type);
#endif
        tag_length = SCNtohs(pppoedt->pppoe_tag_length);

        SCLogDebug ("PPPoE Tag type %x, length %"PRIu32, tag_type, tag_length);

        if (pppoe_length >= (4 + tag_length)) {
            pppoe_length -= (4 + tag_length);
        } else {
            pppoe_length = 0; // don't want an underflow
        }

        if (packet_length >= 4 + tag_length) {
            packet_length -= (4 + tag_length);
        } else {
            packet_length = 0; // don't want an underflow
        }

        pppoedt = pppoedt + (4 + tag_length);
    }

    return TM_ECODE_OK;
}

/**
 * \brief Main decoding function for PPPOE Session packets
 */
int DecodePPPOESession(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    StatsIncr(tv, dtv->counter_pppoe);

    if (len < PPPOE_SESSION_HEADER_MIN_LEN) {
        ENGINE_SET_INVALID_EVENT(p, PPPOE_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    p->pppoesh = (PPPOESessionHdr *)pkt;

    SCLogDebug("PPPOE VERSION %" PRIu32 " TYPE %" PRIu32 " CODE %" PRIu32 " SESSIONID %" PRIu32 " LENGTH %" PRIu32 "",
           PPPOE_SESSION_GET_VERSION(p->pppoesh),  PPPOE_SESSION_GET_TYPE(p->pppoesh),  p->pppoesh->pppoe_code,  SCNtohs(p->pppoesh->session_id),  SCNtohs(p->pppoesh->pppoe_length));

    /* can't use DecodePPP() here because we only get a single 2-byte word to indicate protocol instead of the full PPP header */
    if (SCNtohs(p->pppoesh->pppoe_length) > 0) {
        /* decode contained PPP packet */

        uint8_t pppoesh_len;
        uint16_t ppp_protocol = SCNtohs(p->pppoesh->protocol);

        /* According to RFC1661-2, if the least significant bit of the most significant octet is
         * set, we're dealing with a single-octet protocol field */
        if (ppp_protocol & 0x0100) {
            /* Single-octet variant */
            ppp_protocol >>= 8;
            pppoesh_len = PPPOE_SESSION_HEADER_MIN_LEN;
        } else {
            /* Double-octet variant; increase the length of the session header accordingly */
            pppoesh_len = PPPOE_SESSION_HEADER_MIN_LEN + 1;

            if (len < pppoesh_len) {
                ENGINE_SET_INVALID_EVENT(p, PPPOE_PKT_TOO_SMALL);
                return TM_ECODE_FAILED;
            }
        }

        SCLogDebug("Protocol %" PRIu16 " len %" PRIu8 "", ppp_protocol, pppoesh_len);

        switch (ppp_protocol) {
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
                break;

            case PPP_VJ_UCOMP:

                if (len - pppoesh_len < IPV4_HEADER_LEN) {
                    ENGINE_SET_INVALID_EVENT(p, PPPVJU_PKT_TOO_SMALL);
                    return TM_ECODE_OK;
                }
                if (unlikely(len - pppoesh_len > USHRT_MAX)) {
                    return TM_ECODE_FAILED;
                }

                if (IPV4_GET_RAW_VER((IPV4Hdr *)(pkt + pppoesh_len)) == 4) {
                    DecodeIPV4(tv, dtv, p, pkt + pppoesh_len, (uint16_t)(len - pppoesh_len));
                }
                break;

            case PPP_IP:
                if (len - pppoesh_len < IPV4_HEADER_LEN) {
                    ENGINE_SET_INVALID_EVENT(p, PPPIPV4_PKT_TOO_SMALL);
                    return TM_ECODE_OK;
                }
                if (unlikely(len - pppoesh_len > USHRT_MAX)) {
                    return TM_ECODE_FAILED;
                }
                DecodeIPV4(tv, dtv, p, pkt + pppoesh_len, (uint16_t)(len - pppoesh_len));
                break;

            /* PPP IPv6 was not tested */
            case PPP_IPV6:
                if (len - pppoesh_len < IPV6_HEADER_LEN) {
                    ENGINE_SET_INVALID_EVENT(p, PPPIPV6_PKT_TOO_SMALL);
                    return TM_ECODE_OK;
                }
                if (unlikely(len - pppoesh_len > USHRT_MAX)) {
                    return TM_ECODE_FAILED;
                }

                DecodeIPV6(tv, dtv, p, pkt + pppoesh_len, (uint16_t)(len - pppoesh_len));
                break;

            default:
                SCLogDebug("unknown PPP protocol: %" PRIx32 "", ppp_protocol);
                ENGINE_SET_INVALID_EVENT(p, PPP_WRONG_TYPE);
                return TM_ECODE_OK;
        }
    }
    return TM_ECODE_OK;
}

#ifdef UNITTESTS
/** DecodePPPOEtest01
 *  \brief Decode malformed PPPOE packet (too short)
 *  \retval 1 Expected test value
 */
static int DecodePPPOEtest01 (void)
{

    uint8_t raw_pppoe[] = { 0x11, 0x00, 0x00, 0x00, 0x00 };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodePPPOESession(&tv, &dtv, p, raw_pppoe, sizeof(raw_pppoe));

    FAIL_IF(!ENGINE_ISSET_EVENT(p, PPPOE_PKT_TOO_SMALL));

    SCFree(p);
    PASS;
}

/** DecodePPPOEtest02
 *  \brief Valid PPPOE packet - check the invalid ICMP type encapsulated is flagged
 *  \retval 0 Expected test value
 */
static int DecodePPPOEtest02 (void)
{

    uint8_t raw_pppoe[] = {
        0x11, 0x00, 0x00, 0x01, 0x00, 0x40, 0x00, 0x21,
        0x45, 0x00, 0x00, 0x3c, 0x05, 0x5c, 0x00, 0x00,
        0x20, 0x01, 0xff, 0x30, 0xc0, 0xa8, 0x0a, 0x7f,
        0xc0, 0xa8, 0x0a, 0x65, 0xab, 0xcd, 0x16, 0x5e,
        0x02, 0x00, 0x37, 0x00, 0x41, 0x42, 0x43, 0x44,
        0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
        0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
        0x55, 0x56, 0x57, 0x41, 0x42, 0x43, 0x44, 0x45,
        0x46, 0x47, 0x48, 0x49 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    DecodePPPOESession(&tv, &dtv, p, raw_pppoe, sizeof(raw_pppoe));

    FAIL_IF(ENGINE_ISSET_EVENT(p, PPPOE_PKT_TOO_SMALL));

    // and we insist that the invalid ICMP encapsulated (type 0xab, code 0xcd) is flagged
    FAIL_IF(!ENGINE_ISSET_EVENT(p, ICMPV4_UNKNOWN_TYPE));

    FlowShutdown();
    SCFree(p);
    PASS;
}


/** DecodePPPOEtest03
 *  \brief Valid example PADO packet PPPOE packet taken from RFC2516
 *  \retval 0 Expected test value
 */
static int DecodePPPOEtest03 (void)
{

    /* example PADO packet taken from RFC2516 */
    uint8_t raw_pppoe[] = {
        0x11, 0x07, 0x00, 0x00, 0x00, 0x20, 0x01, 0x01,
        0x00, 0x00, 0x01, 0x02, 0x00, 0x18, 0x47, 0x6f,
        0x20, 0x52, 0x65, 0x64, 0x42, 0x61, 0x63, 0x6b,
        0x20, 0x2d, 0x20, 0x65, 0x73, 0x68, 0x73, 0x68,
        0x65, 0x73, 0x68, 0x6f, 0x6f, 0x74
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodePPPOEDiscovery(&tv, &dtv, p, raw_pppoe, sizeof(raw_pppoe));
    FAIL_IF_NULL(p->pppoedh);

    SCFree(p);
    PASS;
}

/** DecodePPPOEtest04
 *  \brief Valid example PPPOE packet taken from RFC2516 - but with wrong PPPOE code
 *  \retval 1 Expected test value
 */
static int DecodePPPOEtest04 (void)
{

    /* example PADI packet taken from RFC2516, but with wrong code */
    uint8_t raw_pppoe[] = {
        0x11, 0xbb, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01,
        0x00, 0x00
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodePPPOEDiscovery(&tv, &dtv, p, raw_pppoe, sizeof(raw_pppoe));

    FAIL_IF(!ENGINE_ISSET_EVENT(p, PPPOE_WRONG_CODE));

    SCFree(p);
    PASS;
}

/** DecodePPPOEtest05
 *  \brief Valid exaple PADO PPPOE packet taken from RFC2516, but too short for given length
 *  \retval 0 Expected test value
 */
static int DecodePPPOEtest05 (void)
{

    /* example PADI packet taken from RFC2516 */
    uint8_t raw_pppoe[] = {
        0x11, 0x07, 0x00, 0x00, 0x00, 0x20, 0x01, 0x01,
        0x00, 0x00, 0x01, 0x02, 0x00, 0x18, 0x47, 0x6f,
        0x20, 0x52, 0x65, 0x64, 0x42, 0x61, 0x63, 0x6b,
        0x20, 0x2d, 0x20, 0x65, 0x73, 0x68, 0x73, 0x68
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodePPPOEDiscovery(&tv, &dtv, p, raw_pppoe, sizeof(raw_pppoe));

    FAIL_IF(!ENGINE_ISSET_EVENT(p, PPPOE_MALFORMED_TAGS));

    SCFree(p);
    PASS;
}

/** DecodePPPOEtest06
 *  \brief Check that the macros work as expected. Type and version are
 * fields of 4 bits length. So they are sharing the same var and the macros
 * should extract the first 4 bits for version and the second 4 bits for type
 *  \retval 1 Expected test value
 */
static int DecodePPPOEtest06 (void)
{

    PPPOESessionHdr pppoesh;
    PPPOEDiscoveryHdr pppoedh;
    pppoesh.pppoe_version_type = 0xAB;
    pppoedh.pppoe_version_type = 0xCD;

    FAIL_IF(PPPOE_SESSION_GET_VERSION(&pppoesh) != 0x0A);
    FAIL_IF(PPPOE_SESSION_GET_TYPE(&pppoesh) != 0x0B);
    FAIL_IF(PPPOE_DISCOVERY_GET_VERSION(&pppoedh) != 0x0C);
    FAIL_IF(PPPOE_DISCOVERY_GET_TYPE(&pppoedh) != 0x0D);
    PASS;
}

/** DecodePPPOEtest07
 *  \brief Valid PPPOE packet with 8 bit protocol field - check the valid  ICMP type is accepted
 *  \retval 1 Expected test value
 */
static int DecodePPPOEtest07(void)
{

    uint8_t raw_pppoe[] = { 0x11, 0x00, 0x00, 0x2d, 0x00, 0x1c, 0x21, 0x45, 0x00, 0x00, 0x1d, 0x97,
        0xc3, 0x00, 0x00, 0x40, 0x01, 0x47, 0x0f, 0x0a, 0x64, 0x00, 0x00, 0xc0, 0xa8, 0xd1, 0x01,
        0x08, 0x00, 0xd4, 0x4c, 0x1f, 0x32, 0x04, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodePPPOESession(&tv, &dtv, p, raw_pppoe, sizeof(raw_pppoe));

    FAIL_IF(ENGINE_ISSET_EVENT(p, PPP_WRONG_TYPE));
    SCFree(p);
    PASS;
}

/** DecodePPPOEtest08
 *  \brief Valid PPPOE packet with 8 bit protocol field - check the valid HTTP type is accepted
 *  \retval 1 Expected test value
 */
static int DecodePPPOEtest08(void)
{

    uint8_t raw_pppoe[] = { 0x11, 0x00, 0x00, 0x2d, 0x00, 0x3d, 0x21, 0x45, 0x00, 0x00, 0x3c, 0x00,
        0x00, 0x40, 0x00, 0x40, 0x06, 0xed, 0xda, 0x0a, 0x64, 0x00, 0x00, 0x8e, 0xfa, 0xb3, 0x83,
        0xde, 0xb5, 0x00, 0x50, 0xd4, 0xbd, 0x76, 0x54, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xfe,
        0xcc, 0x74, 0x2f, 0x00, 0x00, 0x02, 0x04, 0x05, 0xac, 0x01, 0x03, 0x03, 0x07, 0x04, 0x02,
        0x08, 0x0a, 0xcb, 0xae, 0x92, 0x63, 0x00, 0x00, 0x00, 0x00 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodePPPOESession(&tv, &dtv, p, raw_pppoe, sizeof(raw_pppoe));

    FAIL_IF(ENGINE_ISSET_EVENT(p, PPP_WRONG_TYPE));
    SCFree(p);
    PASS;
}

/** DecodePPPOEtest09
 *  \brief Valid PPPOE packet with 16 bit protocol field - check the valid  ICMP type is accepted
 *  \retval 1 Expected test value
 */
static int DecodePPPOEtest09(void)
{

    uint8_t raw_pppoe[] = { 0x11, 0x00, 0x00, 0x2d, 0x00, 0x1c, 0x00, 0x21, 0x45, 0x00, 0x00, 0x1d,
        0x97, 0xc3, 0x00, 0x00, 0x40, 0x01, 0x47, 0x0f, 0x0a, 0x64, 0x00, 0x00, 0xc0, 0xa8, 0xd1,
        0x01, 0x08, 0x00, 0xd4, 0x4c, 0x1f, 0x32, 0x04, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodePPPOESession(&tv, &dtv, p, raw_pppoe, sizeof(raw_pppoe));

    FAIL_IF(ENGINE_ISSET_EVENT(p, PPP_WRONG_TYPE));
    SCFree(p);
    PASS;
}

/** DecodePPPOEtest10
 *  \brief Valid PPPOE packet with 16 bit protocol field - check the valid HTTP type is accepted
 *  \retval 1 Expected test value
 */
static int DecodePPPOEtest10(void)
{

    uint8_t raw_pppoe[] = { 0x11, 0x00, 0x00, 0x2d, 0x00, 0x3d, 0x00, 0x21, 0x45, 0x00, 0x00, 0x3c,
        0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0xed, 0xda, 0x0a, 0x64, 0x00, 0x00, 0x8e, 0xfa, 0xb3,
        0x83, 0xde, 0xb5, 0x00, 0x50, 0xd4, 0xbd, 0x76, 0x54, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
        0xfe, 0xcc, 0x74, 0x2f, 0x00, 0x00, 0x02, 0x04, 0x05, 0xac, 0x01, 0x03, 0x03, 0x07, 0x04,
        0x02, 0x08, 0x0a, 0xcb, 0xae, 0x92, 0x63, 0x00, 0x00, 0x00, 0x00 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodePPPOESession(&tv, &dtv, p, raw_pppoe, sizeof(raw_pppoe));

    FAIL_IF(ENGINE_ISSET_EVENT(p, PPP_WRONG_TYPE));
    SCFree(p);
    PASS;
}
#endif /* UNITTESTS */

/**
 * \brief Registers PPPOE unit tests
 * \todo More PPPOE tests
 */
void DecodePPPOERegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodePPPOEtest01", DecodePPPOEtest01);
    UtRegisterTest("DecodePPPOEtest02", DecodePPPOEtest02);
    UtRegisterTest("DecodePPPOEtest03", DecodePPPOEtest03);
    UtRegisterTest("DecodePPPOEtest04", DecodePPPOEtest04);
    UtRegisterTest("DecodePPPOEtest05", DecodePPPOEtest05);
    UtRegisterTest("DecodePPPOEtest06", DecodePPPOEtest06);
    UtRegisterTest("DecodePPPOEtest07", DecodePPPOEtest07);
    UtRegisterTest("DecodePPPOEtest08", DecodePPPOEtest08);
    UtRegisterTest("DecodePPPOEtest09", DecodePPPOEtest09);
    UtRegisterTest("DecodePPPOEtest10", DecodePPPOEtest10);
#endif /* UNITTESTS */
}

/**
 * @}
 */
