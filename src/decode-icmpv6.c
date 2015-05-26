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
 * \ingroup decode
 *
 * @{
 */


/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Decode ICMPv6
 */

#include "suricata-common.h"
#include "decode-icmpv6.h"
#include "decode.h"
#include "decode-tcp.h"
#include "decode-sctp.h"
#include "decode-udp.h"
#include "decode-events.h"
#include "util-unittest.h"
#include "flow.h"
#include "util-debug.h"
#include "util-print.h"

#include "pkt-var.h"
#include "util-profiling.h"
#include "host.h"


/**
 * \brief Get variables and do some checks of the embedded IPV6 packet
 *
 * \param p Pointer to the packet we are filling
 * \param partial_packet  Pointer to the raw packet buffer
 * \param len the len of the rest of the packet not processed yet
 *
 * \retval void No return value
 */
void DecodePartialIPV6(Packet *p, uint8_t *partial_packet, uint16_t len )
{
    /** Check the sizes, the header must fit at least */
    if (len < IPV6_HEADER_LEN) {
        SCLogDebug("ICMPV6_IPV6_TRUNC_PKT");
        ENGINE_SET_INVALID_EVENT(p, ICMPV6_IPV6_TRUNC_PKT);
        return;
    }

    IPV6Hdr *icmp6_ip6h = (IPV6Hdr*)partial_packet;

    /** Check the embedded version */
    if(((icmp6_ip6h->s_ip6_vfc & 0xf0) >> 4) != 6)
    {
        SCLogDebug("ICMPv6 contains Unknown IPV6 version "
                "ICMPV6_IPV6_UNKNOWN_VER");
        ENGINE_SET_INVALID_EVENT(p, ICMPV6_IPV6_UNKNOWN_VER);
        return;
    }

    /** We need to fill icmpv6vars */
    p->icmpv6vars.emb_ipv6h = icmp6_ip6h;

    /** Get the IP6 address */
    p->icmpv6vars.emb_ip6_src[0] = icmp6_ip6h->s_ip6_src[0];
    p->icmpv6vars.emb_ip6_src[1] = icmp6_ip6h->s_ip6_src[1];
    p->icmpv6vars.emb_ip6_src[2] = icmp6_ip6h->s_ip6_src[2];
    p->icmpv6vars.emb_ip6_src[3] = icmp6_ip6h->s_ip6_src[3];

    p->icmpv6vars.emb_ip6_dst[0] = icmp6_ip6h->s_ip6_dst[0];
    p->icmpv6vars.emb_ip6_dst[1] = icmp6_ip6h->s_ip6_dst[1];
    p->icmpv6vars.emb_ip6_dst[2] = icmp6_ip6h->s_ip6_dst[2];
    p->icmpv6vars.emb_ip6_dst[3] = icmp6_ip6h->s_ip6_dst[3];

    /** Get protocol and ports inside the embedded ipv6 packet and set the pointers */
    p->icmpv6vars.emb_ip6_proto_next = icmp6_ip6h->s_ip6_nxt;

    switch (icmp6_ip6h->s_ip6_nxt) {
        case IPPROTO_TCP:
            if (len >= IPV6_HEADER_LEN + TCP_HEADER_LEN ) {
                p->icmpv6vars.emb_tcph = (TCPHdr*)(partial_packet + IPV6_HEADER_LEN);
                p->icmpv6vars.emb_sport = p->icmpv6vars.emb_tcph->th_sport;
                p->icmpv6vars.emb_dport = p->icmpv6vars.emb_tcph->th_dport;

                SCLogDebug("ICMPV6->IPV6->TCP header sport: "
                           "%"PRIu8" dport %"PRIu8"", p->icmpv6vars.emb_sport,
                            p->icmpv6vars.emb_dport);
            } else {
                SCLogDebug("Warning, ICMPV6->IPV6->TCP "
                           "header Didn't fit in the packet!");
                p->icmpv6vars.emb_sport = 0;
                p->icmpv6vars.emb_dport = 0;
            }

            break;
        case IPPROTO_UDP:
            if (len >= IPV6_HEADER_LEN + UDP_HEADER_LEN ) {
                p->icmpv6vars.emb_udph = (UDPHdr*)(partial_packet + IPV6_HEADER_LEN);
                p->icmpv6vars.emb_sport = p->icmpv6vars.emb_udph->uh_sport;
                p->icmpv6vars.emb_dport = p->icmpv6vars.emb_udph->uh_dport;

                SCLogDebug("ICMPV6->IPV6->UDP header sport: "
                           "%"PRIu8" dport %"PRIu8"", p->icmpv6vars.emb_sport,
                            p->icmpv6vars.emb_dport);
            } else {
                SCLogDebug("Warning, ICMPV6->IPV6->UDP "
                           "header Didn't fit in the packet!");
                p->icmpv6vars.emb_sport = 0;
                p->icmpv6vars.emb_dport = 0;
            }

            break;
        case IPPROTO_ICMPV6:
            p->icmpv6vars.emb_icmpv6h = (ICMPV6Hdr*)(partial_packet + IPV6_HEADER_LEN);
            p->icmpv6vars.emb_sport = 0;
            p->icmpv6vars.emb_dport = 0;

            SCLogDebug("ICMPV6->IPV6->ICMP header");

            break;
    }

    /* debug print */
#ifdef DEBUG
    char s[46], d[46];
    PrintInet(AF_INET6, (const void *)p->icmpv6vars.emb_ip6_src, s, sizeof(s));
    PrintInet(AF_INET6, (const void *)p->icmpv6vars.emb_ip6_dst, d, sizeof(d));
    SCLogDebug("ICMPv6 embedding IPV6 %s->%s - CLASS: %" PRIu32 " FLOW: "
               "%" PRIu32 " NH: %" PRIu32 " PLEN: %" PRIu32 " HLIM: %" PRIu32,
               s, d, IPV6_GET_RAW_CLASS(icmp6_ip6h), IPV6_GET_RAW_FLOW(icmp6_ip6h),
               IPV6_GET_RAW_NH(icmp6_ip6h), IPV6_GET_RAW_PLEN(icmp6_ip6h), IPV6_GET_RAW_HLIM(icmp6_ip6h));
#endif

    return;
}

/**
 * \brief Decode ICMPV6 packets and fill the Packet with the decoded info
 *
 * \param tv Pointer to the thread variables
 * \param dtv Pointer to the decode thread variables
 * \param p Pointer to the packet we are filling
 * \param pkt Pointer to the raw packet buffer
 * \param len the len of the rest of the packet not processed yet
 * \param pq the packet queue were this packet go
 *
 * \retval void No return value
 */
int DecodeICMPV6(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                  uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    int full_hdr = 0;
    StatsIncr(tv, dtv->counter_icmpv6);

    if (len < ICMPV6_HEADER_LEN) {
        SCLogDebug("ICMPV6_PKT_TOO_SMALL");
        ENGINE_SET_INVALID_EVENT(p, ICMPV6_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    p->icmpv6h = (ICMPV6Hdr *)pkt;
    p->proto = IPPROTO_ICMPV6;
    p->type = p->icmpv6h->type;
    p->code = p->icmpv6h->code;
    p->payload_len = len - ICMPV6_HEADER_LEN;
    p->payload = pkt + ICMPV6_HEADER_LEN;

    SCLogDebug("ICMPV6 TYPE %" PRIu32 " CODE %" PRIu32 "", p->icmpv6h->type,
               p->icmpv6h->code);

    switch (ICMPV6_GET_TYPE(p)) {
        case ICMP6_DST_UNREACH:
            SCLogDebug("ICMP6_DST_UNREACH");

            if (ICMPV6_GET_CODE(p) > ICMP6_DST_UNREACH_REJECTROUTE) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            } else {
                DecodePartialIPV6(p, (uint8_t*) (pkt + ICMPV6_HEADER_LEN),
                                  len - ICMPV6_HEADER_LEN );
                full_hdr = 1;
            }

            break;
        case ICMP6_PACKET_TOO_BIG:
            SCLogDebug("ICMP6_PACKET_TOO_BIG");

            if (ICMPV6_GET_CODE(p) != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            } else {
                p->icmpv6vars.mtu = ICMPV6_GET_MTU(p);
                DecodePartialIPV6(p, (uint8_t*) (pkt + ICMPV6_HEADER_LEN),
                                  len - ICMPV6_HEADER_LEN );
                full_hdr = 1;
            }

            break;
        case ICMP6_TIME_EXCEEDED:
            SCLogDebug("ICMP6_TIME_EXCEEDED");

            if (ICMPV6_GET_CODE(p) > ICMP6_TIME_EXCEED_REASSEMBLY) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            } else {
                DecodePartialIPV6(p, (uint8_t*) (pkt + ICMPV6_HEADER_LEN),
                                  len - ICMPV6_HEADER_LEN );
                full_hdr = 1;
            }

            break;
        case ICMP6_PARAM_PROB:
            SCLogDebug("ICMP6_PARAM_PROB");

            if (ICMPV6_GET_CODE(p) > ICMP6_PARAMPROB_OPTION) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            } else {
                p->icmpv6vars.error_ptr= ICMPV6_GET_ERROR_PTR(p);
                DecodePartialIPV6(p, (uint8_t*) (pkt + ICMPV6_HEADER_LEN),
                                  len - ICMPV6_HEADER_LEN );
                full_hdr = 1;
            }

            break;
        case ICMP6_ECHO_REQUEST:
            SCLogDebug("ICMP6_ECHO_REQUEST id: %u seq: %u",
                       p->icmpv6h->icmpv6b.icmpv6i.id, p->icmpv6h->icmpv6b.icmpv6i.seq);

            if (ICMPV6_GET_CODE(p) != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            } else {
                p->icmpv6vars.id = p->icmpv6h->icmpv6b.icmpv6i.id;
                p->icmpv6vars.seq = p->icmpv6h->icmpv6b.icmpv6i.seq;
                full_hdr = 1;
            }

            break;
        case ICMP6_ECHO_REPLY:
            SCLogDebug("ICMP6_ECHO_REPLY id: %u seq: %u",
                       p->icmpv6h->icmpv6b.icmpv6i.id, p->icmpv6h->icmpv6b.icmpv6i.seq);

            if (p->icmpv6h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            } else {
                p->icmpv6vars.id = p->icmpv6h->icmpv6b.icmpv6i.id;
                p->icmpv6vars.seq = p->icmpv6h->icmpv6b.icmpv6i.seq;
                full_hdr = 1;
            }

            break;
        case ND_ROUTER_SOLICIT:
            SCLogDebug("ND_ROUTER_SOLICIT");
            if (p->icmpv6h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case ND_ROUTER_ADVERT:
            SCLogDebug("ND_ROUTER_ADVERT");
            if (p->icmpv6h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case ND_NEIGHBOR_SOLICIT:
            SCLogDebug("ND_NEIGHBOR_SOLICIT");
            if (p->icmpv6h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case ND_NEIGHBOR_ADVERT:
            SCLogDebug("ND_NEIGHBOR_ADVERT");
            if (p->icmpv6h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case ND_REDIRECT:
            SCLogDebug("ND_REDIRECT");
            if (p->icmpv6h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case MLD_LISTENER_QUERY:
            SCLogDebug("MLD_LISTENER_QUERY");
            if (p->icmpv6h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            if (IPV6_GET_HLIM(p) != 1) {
                ENGINE_SET_EVENT(p, ICMPV6_MLD_MESSAGE_WITH_INVALID_HL);
            }
            break;
        case MLD_LISTENER_REPORT:
            SCLogDebug("MLD_LISTENER_REPORT");
            if (p->icmpv6h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            if (IPV6_GET_HLIM(p) != 1) {
                ENGINE_SET_EVENT(p, ICMPV6_MLD_MESSAGE_WITH_INVALID_HL);
            }
            break;
        case MLD_LISTENER_REDUCTION:
            SCLogDebug("MLD_LISTENER_REDUCTION");
            if (p->icmpv6h->code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            if (IPV6_GET_HLIM(p) != 1) {
                ENGINE_SET_EVENT(p, ICMPV6_MLD_MESSAGE_WITH_INVALID_HL);
            }
            break;
        default:
            SCLogDebug("ICMPV6 Message type %" PRIu8 " not "
                       "implemented yet", ICMPV6_GET_TYPE(p));
            ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_TYPE);
    }

    /* for a info message the header is just 4 bytes */
    if (!full_hdr) {
        if (p->payload_len >= 4) {
            p->payload_len -= 4;
            p->payload = pkt + 4;
        } else {
            p->payload_len = 0;
            p->payload = NULL;
        }
    }

#ifdef DEBUG
    if (ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE))
        SCLogDebug("Unknown Code, ICMPV6_UNKNOWN_CODE");

    if (ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_TYPE))
        SCLogDebug("Unknown Type, ICMPV6_UNKNOWN_TYPE");
#endif

    /* Flow is an integral part of us */
    FlowHandlePacket(tv, dtv, p);

    return TM_ECODE_OK;
}

#ifdef UNITTESTS

static int ICMPV6CalculateValidChecksumtest01(void)
{
    uint16_t csum = 0;

    uint8_t raw_ipv6[] = {
        0x00, 0x00, 0x86, 0x05, 0x80, 0xda, 0x00, 0x60,
        0x97, 0x07, 0x69, 0xea, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x44, 0x3a, 0x40, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x60,
        0x97, 0xff, 0xfe, 0x07, 0x69, 0xea, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x03, 0x00,
        0xf7, 0x52, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x01, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0x9b, 0x00, 0x14, 0x82, 0x8b, 0x01, 0x01,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0xf5, 0xed,
        0x08, 0x00};

    csum = *( ((uint16_t *)(raw_ipv6 + 56)));

    return (csum == ICMPV6CalculateChecksum((uint16_t *)(raw_ipv6 + 14 + 8),
                                            (uint16_t *)(raw_ipv6 + 54), 68));
}

static int ICMPV6CalculateInvalidChecksumtest02(void)
{
    uint16_t csum = 0;

    uint8_t raw_ipv6[] = {
        0x00, 0x00, 0x86, 0x05, 0x80, 0xda, 0x00, 0x60,
        0x97, 0x07, 0x69, 0xea, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x44, 0x3a, 0x40, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x60,
        0x97, 0xff, 0xfe, 0x07, 0x69, 0xea, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x03, 0x00,
        0xf7, 0x52, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x01, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0x9b, 0x00, 0x14, 0x82, 0x8b, 0x01, 0x01,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0xf5, 0xed,
        0x08, 0x01};

    csum = *( ((uint16_t *)(raw_ipv6 + 56)));

    return (csum == ICMPV6CalculateChecksum((uint16_t *)(raw_ipv6 + 14 + 8),
                                            (uint16_t *)(raw_ipv6 + 54), 68));
}


/** \test icmpv6 message type: parameter problem, valid packet
 *
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6ParamProbTest01(void)
{
    int retval = 0;
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x38, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x00, 0xcc, 0x2a, 0x6d, 0x93, 0x0b, 0xdf,
        0x69, 0x70, 0x12, 0xb7, 0x00, 0x08, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x80, 0x00, 0x08, 0xb5, 0x99, 0xc3, 0xde, 0x40 };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;
    uint32_t *ipv6src;
    uint32_t *ipv6dst;
    ipv6src = (uint32_t*) &raw_ipv6[8];
    ipv6dst = (uint32_t*) &raw_ipv6[24];

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (p->icmpv6h == NULL) {
        SCLogDebug("ICMPv6 Unable to detect icmpv6 layer from ipv6");
        retval = 0;
        goto end;
    }

    if (ICMPV6_GET_TYPE(p) != 4 || ICMPV6_GET_CODE(p) != 0 ||
        ICMPV6_GET_EMB_PROTO(p) != IPPROTO_ICMPV6) {
        SCLogDebug("ICMPv6 not processed at all");
        retval = 0;
        goto end;
    }

    /* Let's check if we retrieved the embedded ipv6 addresses correctly */
    uint32_t i=0;
    for (i = 0; i < 4; i++) {
        if (p->icmpv6vars.emb_ip6_src[i] != ipv6src[i] ||
            p->icmpv6vars.emb_ip6_dst[i] != ipv6dst[i]) {
            SCLogDebug("ICMPv6 DecodePartialICMPV6 (Embedded ip6h) didn't set "
                       "the src and dest ip addresses correctly");
            retval = 0;
            goto end;
        }
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

/** \test icmpv6 message type: packet too big, valid packet
 *
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6PktTooBigTest01(void)
{
    int retval = 0;
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x30, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x00, 0x5c, 0x7a, 0x00, 0x00, 0x05, 0x00,
        0x64, 0x14, 0xfd, 0xff, 0x00, 0x00, 0x3b, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;
    uint32_t *ipv6src;
    uint32_t *ipv6dst;
    ipv6src = (uint32_t*) &raw_ipv6[8];
    ipv6dst = (uint32_t*) &raw_ipv6[24];

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (p->icmpv6h == NULL) {
        SCLogDebug("ICMPv6 Unable to detect icmpv6 layer from ipv6");
        retval = 0;
        goto end;
    }

    /* Note: it has an embedded ipv6 packet but no protocol after ipv6 (IPPROTO_NONE) */
    if (ICMPV6_GET_TYPE(p) != 2 || ICMPV6_GET_CODE(p) != 0 ) {
        SCLogDebug("ICMPv6 Not processed at all");
        retval = 0;
        goto end;
    }

    /* Let's check if we retrieved the embedded ipv6 addresses correctly */
    uint32_t i=0;
    for (i = 0; i < 4; i++) {
        if (p->icmpv6vars.emb_ip6_src[i] != ipv6src[i] ||
            p->icmpv6vars.emb_ip6_dst[i] != ipv6dst[i]) {
            SCLogDebug("ICMPv6 DecodePartialICMPV6 (Embedded ip6h) didn't set "
                       "the src and dest ip addresses correctly");
            retval = 0;
            goto end;
        }
    }

    SCLogDebug("ICMPV6 IPV6 src and dst properly set");

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

/** \test icmpv6 message type: time exceed, valid packet
 *
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6TimeExceedTest01(void)
{
    int retval = 0;
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x30, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x03, 0x00, 0x56, 0x2d, 0x00, 0x00, 0x00, 0x00,
        0x6d, 0x23, 0xff, 0x3d, 0x00, 0x00, 0x3b, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;
    uint32_t *ipv6src;
    uint32_t *ipv6dst;
    ipv6src = (uint32_t*) &raw_ipv6[8];
    ipv6dst = (uint32_t*) &raw_ipv6[24];


    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (p->icmpv6h == NULL) {
        SCLogDebug("ICMPv6 Unable to detect icmpv6 layer from ipv6");
        retval = 0;
        goto end;
    }

    /* Note: it has an embedded ipv6 packet but no protocol after ipv6 (IPPROTO_NONE) */
    if (ICMPV6_GET_TYPE(p) != 3 || ICMPV6_GET_CODE(p) != 0 ||
        ICMPV6_GET_EMB_IPV6(p)==NULL || ICMPV6_GET_EMB_PROTO(p) != IPPROTO_NONE ) {
        SCLogDebug("ICMPv6 Not processed at all");
        retval = 0;
        goto end;
    }

    /* Let's check if we retrieved the embedded ipv6 addresses correctly */
    uint32_t i=0;
    for (i = 0; i < 4; i++) {
        if (p->icmpv6vars.emb_ip6_src[i] != ipv6src[i] ||
            p->icmpv6vars.emb_ip6_dst[i] != ipv6dst[i]) {
            SCLogDebug("ICMPv6 DecodePartialICMPV6 (Embedded ip6h) didn't set "
                       "the src and dest ip addresses correctly");
            retval = 0;
            goto end;
        }
    }

    SCLogDebug("ICMPV6 IPV6 src and dst properly set");

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

/** \test icmpv6 message type: destination unreach, valid packet
 *
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6DestUnreachTest01(void)
{
    int retval = 0;
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x30, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x01, 0x00, 0x7b, 0x85, 0x00, 0x00, 0x00, 0x00,
        0x60, 0x4b, 0xe8, 0xbd, 0x00, 0x00, 0x3b, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;
    uint32_t *ipv6src;
    uint32_t *ipv6dst;
    ipv6src = (uint32_t*) &raw_ipv6[8];
    ipv6dst = (uint32_t*) &raw_ipv6[24];


    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (p->icmpv6h == NULL) {
        SCLogDebug("ICMPv6 Unable to detect icmpv6 layer from ipv6");
        retval = 0;
        goto end;
    }

    /* Note: it has an embedded ipv6 packet but no protocol after ipv6 (IPPROTO_NONE) */
    if (ICMPV6_GET_TYPE(p) != 1 || ICMPV6_GET_CODE(p) != 0 ||
        ICMPV6_GET_EMB_IPV6(p) == NULL || ICMPV6_GET_EMB_PROTO(p) != IPPROTO_NONE ) {
        SCLogDebug("ICMPv6 Not processed at all");
        retval = 0;
        goto end;
    }

    /* Let's check if we retrieved the embedded ipv6 addresses correctly */
    uint32_t i=0;
    for (i = 0; i < 4; i++) {
        if (p->icmpv6vars.emb_ip6_src[i] != ipv6src[i] ||
            p->icmpv6vars.emb_ip6_dst[i] != ipv6dst[i]) {
            SCLogDebug("ICMPv6 DecodePartialICMPV6 (Embedded ip6h) didn't set "
                       "the src and dest ip addresses correctly");
            retval = 0;
            goto end;
        }
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

/**\test icmpv6 message type: echo request, valid packet
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6EchoReqTest01(void)
{
    int retval = 0;
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x80, 0x00, 0xe5, 0xa5, 0x25, 0xf0, 0x75, 0x23 };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (p->icmpv6h == NULL) {
        SCLogDebug("ICMPv6 Unable to detect icmpv6 layer from ipv6");
        goto end;
    }

    SCLogDebug("ID: %u seq: %u", ICMPV6_GET_ID(p), ICMPV6_GET_SEQ(p));

    if (ICMPV6_GET_TYPE(p) != 128 || ICMPV6_GET_CODE(p) != 0 ||
        ntohs(ICMPV6_GET_ID(p)) != 9712 || ntohs(ICMPV6_GET_SEQ(p)) != 29987) {
        printf("ICMPv6 Echo reply decode failed TYPE %u CODE %u ID %04x(%u) SEQ %04x(%u): ",
                ICMPV6_GET_TYPE(p), ICMPV6_GET_CODE(p), ICMPV6_GET_ID(p), ntohs(ICMPV6_GET_ID(p)),
                ICMPV6_GET_SEQ(p), ntohs(ICMPV6_GET_SEQ(p)));
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

/**\test icmpv6 message type: echo reply, valid packet
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6EchoRepTest01(void)
{
    int retval = 0;
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a,
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x81, 0x00,
        0xe5, 0xa5, 0x25, 0xf0, 0x75, 0x23 };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (p->icmpv6h == NULL) {
        SCLogDebug("ICMPv6 Unable to detect icmpv6 layer from ipv6");
        goto end;
    }

    SCLogDebug("type: %u code %u ID: %u seq: %u", ICMPV6_GET_TYPE(p),
               ICMPV6_GET_CODE(p),ICMPV6_GET_ID(p), ICMPV6_GET_SEQ(p));

    if (ICMPV6_GET_TYPE(p) != 129 || ICMPV6_GET_CODE(p) != 0 ||
        ntohs(ICMPV6_GET_ID(p)) != 9712 || ntohs(ICMPV6_GET_SEQ(p)) != 29987) {
        printf("ICMPv6 Echo reply decode failed TYPE %u CODE %u ID %04x(%u) SEQ %04x(%u): ",
                ICMPV6_GET_TYPE(p), ICMPV6_GET_CODE(p), ICMPV6_GET_ID(p), ntohs(ICMPV6_GET_ID(p)),
                ICMPV6_GET_SEQ(p), ntohs(ICMPV6_GET_SEQ(p)));
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

/** \test icmpv6 message type: parameter problem, invalid packet
 * \brief set the event ICMPV6_IPV6_UNKNOWN_VER properly when the embedded packet has an unknown version
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6ParamProbTest02(void)
{
    int retval = 0;
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x38, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x00, 0xcc, 0x2a, 0x6d, 0x93, 0x0b, 0xdf,
        0x38, 0x70, 0x12, 0xb7, 0x00, 0x08, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x80, 0x00, 0x08, 0xb5, 0x99, 0xc3, 0xde, 0x40 };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (p->icmpv6h == NULL) {
        SCLogDebug("ICMPv6 Unable to detect icmpv6 layer from ipv6");
        retval = 0;
        goto end;
    }

    if (ICMPV6_GET_TYPE(p) != 4 || ICMPV6_GET_CODE(p) != 0) {
        SCLogDebug("ICMPv6 Not processed at all");
        retval = 0;
        goto end;
    }

    if (!ENGINE_ISSET_EVENT(p, ICMPV6_IPV6_UNKNOWN_VER)) {
        SCLogDebug("ICMPv6 Error: Unknown embedded ipv6 version event not set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

/** \test icmpv6 message type: packet too big, invalid packet
 *  \brief Set the event ICMPV6_UNKNOWN_CODE if code is invalid for this type
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6PktTooBigTest02(void)
{
    int retval = 0;
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x30, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x10, 0x5c, 0x7a, 0x00, 0x00, 0x05, 0x00,
        0x64, 0x14, 0xfd, 0xff, 0x00, 0x00, 0x3b, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (p->icmpv6h == NULL) {
        SCLogDebug("ICMPv6 Unable to detect icmpv6 layer from ipv6");
        retval = 0;
        goto end;
    }

    if (!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE)) {
        SCLogDebug("ICMPv6 Error: Unknown code event not set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

/** \test icmpv6 message type: time exceed, invalid packet
 * \brief set the event ICMPV6_PKT_TOO_SMALL properly
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6TimeExceedTest02(void)
{
    int retval = 0;
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x03, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x10, 0x5c };

    /* The icmpv6 header is broken in the checksum (so we dont have a complete header) */

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (!ENGINE_ISSET_EVENT(p, ICMPV6_PKT_TOO_SMALL)) {
        SCLogDebug("ICMPv6 Error: event packet too small not set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

/**\test icmpv6 message type: destination unreach, invalid packet
 * \brief The embedded packet header (ipv6) is truncated
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6DestUnreachTest02(void)
{
    int retval = 0;
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x01, 0x00, 0x7b, 0x85, 0x00, 0x00, 0x00, 0x00,
        0x60, 0x4b, 0xe8, 0xbd, 0x00, 0x00, 0x3b, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00 };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (!ENGINE_ISSET_EVENT(p, ICMPV6_IPV6_TRUNC_PKT)) {
        SCLogDebug("ICMPv6 Error: embedded ipv6 truncated packet event not set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

/**\test icmpv6 message type: echo request, invalid packet
 * \brief unknown code
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6EchoReqTest02(void)
{
    int retval = 0;
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a,
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x01,
        0xe5, 0xa5, 0x25, 0xf0, 0x75, 0x23 };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE)) {
        SCLogDebug("ICMPv6 Error: Unknown code event not set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

/**\test icmpv6 message type: echo reply, invalid packet
 * \brief unknown code
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6EchoRepTest02(void)
{
    int retval = 0;
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a,
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x81, 0x01,
        0xe5, 0xa5, 0x25, 0xf0, 0x75, 0x23 };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE)) {
        SCLogDebug("ICMPv6 Error: Unknown code event not set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

/**\test icmpv6 packet decoding and setting up of payload_len and payload buufer
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6PayloadTest01(void)
{
    int retval = 0;
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x01, 0x00, 0x7b, 0x85, 0x00, 0x00, 0x00, 0x00,
        0x60, 0x4b, 0xe8, 0xbd, 0x00, 0x00, 0x3b, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00 };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (p->payload == NULL) {
        printf("payload == NULL, expected non-NULL: ");
        goto end;
    }

    if (p->payload_len != 37) {
        printf("payload_len %"PRIu16", expected 37: ", p->payload_len);
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

static int ICMPV6RouterSolicitTestKnownCode(void)
{
    int retval = 0;

    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x85, 0x00, 0xbe, 0xb0, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE)) {
        SCLogDebug("ICMPv6 Error: Unknown code event is set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

static int ICMPV6RouterSolicitTestUnknownCode(void)
{
    int retval = 0;

    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x85, 0x01, 0xbe, 0xaf, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE)) {
        SCLogDebug("ICMPv6 Error: Unknown code event is not set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

static int ICMPV6RouterAdvertTestKnownCode(void)
{
    int retval = 0;

    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x86, 0x00, 0xbd, 0xb0, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE)) {
        SCLogDebug("ICMPv6 Error: Unknown code event is set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

static int ICMPV6RouterAdvertTestUnknownCode(void)
{
    int retval = 0;

    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x86, 0x01, 0xbd, 0xaf, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE)) {
        SCLogDebug("ICMPv6 Error: Unknown code event is not set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

static int ICMPV6NeighbourSolicitTestKnownCode(void)
{
    int retval = 0;

    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x87, 0x00, 0xbc, 0xb0, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE)) {
        SCLogDebug("ICMPv6 Error: Unknown code event is set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

static int ICMPV6NeighbourSolicitTestUnknownCode(void)
{
    int retval = 0;

    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x87, 0x01, 0xbc, 0xaf, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE)) {
        SCLogDebug("ICMPv6 Error: Unknown code event is not set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

static int ICMPV6NeighbourAdvertTestKnownCode(void)
{
    int retval = 0;

    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x88, 0x00, 0xbb, 0xb0, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE)) {
        SCLogDebug("ICMPv6 Error: Unknown code event is set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

static int ICMPV6NeighbourAdvertTestUnknownCode(void)
{
    int retval = 0;

    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x88, 0x01, 0xbb, 0xaf, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE)) {
        SCLogDebug("ICMPv6 Error: Unknown code event is not set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

static int ICMPV6RedirectTestKnownCode(void)
{
    int retval = 0;

    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x89, 0x00, 0xba, 0xb0, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE)) {
        SCLogDebug("ICMPv6 Error: Unknown code event is set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

static int ICMPV6RedirectTestUnknownCode(void)
{
    int retval = 0;

    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x89, 0x01, 0xba, 0xaf, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6), NULL);

    if (!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE)) {
        SCLogDebug("ICMPv6 Error: Unknown code event is not set");
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return retval;
}

#endif /* UNITTESTS */
/**
 * \brief Registers ICMPV6 unit tests
 * \todo More ICMPv6 tests
 */
void DecodeICMPV6RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ICMPV6CalculateValidChecksumtest01", ICMPV6CalculateValidChecksumtest01, 1);
    UtRegisterTest("ICMPV6CalculateInValidChecksumtest02", ICMPV6CalculateInvalidChecksumtest02, 0);

    UtRegisterTest("ICMPV6ParamProbTest01 (Valid)", ICMPV6ParamProbTest01, 1);
    UtRegisterTest("ICMPV6DestUnreachTest01 (Valid)", ICMPV6DestUnreachTest01, 1);
    UtRegisterTest("ICMPV6PktTooBigTest01 (Valid)", ICMPV6PktTooBigTest01, 1);
    UtRegisterTest("ICMPV6TimeExceedTest01 (Valid)", ICMPV6TimeExceedTest01, 1);
    UtRegisterTest("ICMPV6EchoReqTest01 (Valid)", ICMPV6EchoReqTest01, 1);
    UtRegisterTest("ICMPV6EchoRepTest01 (Valid)", ICMPV6EchoRepTest01, 1);

    UtRegisterTest("ICMPV6ParamProbTest02 (Invalid)", ICMPV6ParamProbTest02, 1);
    UtRegisterTest("ICMPV6DestUnreachTest02 (Invalid)", ICMPV6DestUnreachTest02, 1);
    UtRegisterTest("ICMPV6PktTooBigTest02 (Invalid)", ICMPV6PktTooBigTest02, 1);
    UtRegisterTest("ICMPV6TimeExceedTest02 (Invalid)", ICMPV6TimeExceedTest02, 1);
    UtRegisterTest("ICMPV6EchoReqTest02 (Invalid)", ICMPV6EchoReqTest02, 1);
    UtRegisterTest("ICMPV6EchoRepTest02 (Invalid)", ICMPV6EchoRepTest02, 1);

    UtRegisterTest("ICMPV6PayloadTest01", ICMPV6PayloadTest01, 1);

    UtRegisterTest("ICMPV6RouterSolicitTestKnownCode",
        ICMPV6RouterSolicitTestKnownCode, 1);
    UtRegisterTest("ICMPV6RouterSolicitTestUnknownCode",
        ICMPV6RouterSolicitTestUnknownCode, 1);
    UtRegisterTest("ICMPV6RouterAdvertTestKnownCode",
        ICMPV6RouterAdvertTestKnownCode, 1);
    UtRegisterTest("ICMPV6RouterAdvertTestUnknownCode",
        ICMPV6RouterAdvertTestUnknownCode, 1);

    UtRegisterTest("ICMPV6NeighbourSolicitTestKnownCode",
        ICMPV6NeighbourSolicitTestKnownCode, 1);
    UtRegisterTest("ICMPV6NeighbourSolicitTestUnknownCode",
        ICMPV6NeighbourSolicitTestUnknownCode, 1);
    UtRegisterTest("ICMPV6NeighbourAdvertTestKnownCode",
        ICMPV6NeighbourAdvertTestKnownCode, 1);
    UtRegisterTest("ICMPV6NeighbourAdvertTestUnknownCode",
        ICMPV6NeighbourAdvertTestUnknownCode, 1);

    UtRegisterTest("ICMPV6RedirectTestKnownCode", ICMPV6RedirectTestKnownCode, 1);
    UtRegisterTest("ICMPV6RedirectTestUnknownCode",
        ICMPV6RedirectTestUnknownCode, 1);
#endif /* UNITTESTS */
}
/**
 * @}
 */
