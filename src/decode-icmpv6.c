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
#include "flow.h"
#include "util-print.h"
#include "util-validate.h"

#if defined(DEBUG) || defined(UNITTESTS)
static inline const IPV6Hdr *PacketGetICMPv6EmbIPv6(const Packet *p)
{
    BUG_ON(p->l4.type != PACKET_L4_ICMPV6);
    const uint8_t *start = (const uint8_t *)PacketGetICMPv6(p);
    const uint8_t *ip = start + p->l4.vars.icmpv6.emb_ip6h_offset;
    return (const IPV6Hdr *)ip;
}
#endif

/**
 * \brief Get variables and do some checks of the embedded IPV6 packet
 *
 * \param p Pointer to the packet we are filling
 * \param partial_packet  Pointer to the raw packet buffer
 * \param len the len of the rest of the packet not processed yet
 *
 * \retval void No return value
 */
static void DecodePartialIPV6(Packet *p, uint8_t *partial_packet, uint16_t len )
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

    /** We need to fill l4.vars.icmpv6 */
    const uint8_t *icmpv6_ptr = (const uint8_t *)p->l4.hdrs.icmpv6h;
    DEBUG_VALIDATE_BUG_ON((ptrdiff_t)(partial_packet - icmpv6_ptr) > (ptrdiff_t)UINT16_MAX);
    p->l4.vars.icmpv6.emb_ip6h_offset = (uint16_t)(partial_packet - icmpv6_ptr);
    /** Get protocol and ports inside the embedded ipv6 packet and set the pointers */
    p->l4.vars.icmpv6.emb_ip6_proto_next = icmp6_ip6h->s_ip6_nxt;

    switch (icmp6_ip6h->s_ip6_nxt) {
        case IPPROTO_TCP:
            if (len >= IPV6_HEADER_LEN + TCP_HEADER_LEN ) {
                TCPHdr *emb_tcph = (TCPHdr *)(partial_packet + IPV6_HEADER_LEN);
                p->l4.vars.icmpv6.emb_sport = emb_tcph->th_sport;
                p->l4.vars.icmpv6.emb_dport = emb_tcph->th_dport;
                p->l4.vars.icmpv6.emb_ports_set = true;

                SCLogDebug("ICMPV6->IPV6->TCP header sport: "
                           "%" PRIu16 " dport %" PRIu16 "",
                        p->l4.vars.icmpv6.emb_sport, p->l4.vars.icmpv6.emb_dport);
            } else {
                SCLogDebug("Warning, ICMPV6->IPV6->TCP "
                           "header Didn't fit in the packet!");
                p->l4.vars.icmpv6.emb_sport = 0;
                p->l4.vars.icmpv6.emb_dport = 0;
            }

            break;
        case IPPROTO_UDP:
            if (len >= IPV6_HEADER_LEN + UDP_HEADER_LEN ) {
                UDPHdr *emb_udph = (UDPHdr *)(partial_packet + IPV6_HEADER_LEN);
                p->l4.vars.icmpv6.emb_sport = emb_udph->uh_sport;
                p->l4.vars.icmpv6.emb_dport = emb_udph->uh_dport;
                p->l4.vars.icmpv6.emb_ports_set = true;

                SCLogDebug("ICMPV6->IPV6->UDP header sport: "
                           "%" PRIu16 " dport %" PRIu16 "",
                        p->l4.vars.icmpv6.emb_sport, p->l4.vars.icmpv6.emb_dport);
            } else {
                SCLogDebug("Warning, ICMPV6->IPV6->UDP "
                           "header Didn't fit in the packet!");
                p->l4.vars.icmpv6.emb_sport = 0;
                p->l4.vars.icmpv6.emb_dport = 0;
            }

            break;
        case IPPROTO_ICMPV6:
            p->l4.vars.icmpv6.emb_sport = 0;
            p->l4.vars.icmpv6.emb_dport = 0;

            SCLogDebug("ICMPV6->IPV6->ICMP header");

            break;
    }

    /* debug print */
#ifdef DEBUG
    char s[46], d[46];
    PrintInet(AF_INET6, (const void *)PacketGetICMPv6EmbIPv6(p)->s_ip6_src, s, sizeof(s));
    PrintInet(AF_INET6, (const void *)PacketGetICMPv6EmbIPv6(p)->s_ip6_dst, d, sizeof(d));
    SCLogDebug("ICMPv6 embedding IPV6 %s->%s - CLASS: %" PRIu32 " FLOW: "
               "%" PRIu32 " NH: %" PRIu32 " PLEN: %" PRIu32 " HLIM: %" PRIu32,
               s, d, IPV6_GET_RAW_CLASS(icmp6_ip6h), IPV6_GET_RAW_FLOW(icmp6_ip6h),
               IPV6_GET_RAW_NH(icmp6_ip6h), IPV6_GET_RAW_PLEN(icmp6_ip6h), IPV6_GET_RAW_HLIM(icmp6_ip6h));
#endif
}

/** \retval type counterpart type or -1 */
int ICMPv6GetCounterpart(uint8_t type)
{
#define CASE_CODE(t,r) case (t): return r; case (r): return t;
    switch (type) {
        CASE_CODE(ICMP6_ECHO_REQUEST,   ICMP6_ECHO_REPLY);
        CASE_CODE(ND_NEIGHBOR_SOLICIT,  ND_NEIGHBOR_ADVERT);
        CASE_CODE(ND_ROUTER_SOLICIT,    ND_ROUTER_ADVERT);
        CASE_CODE(MLD_LISTENER_QUERY,   MLD_LISTENER_REPORT);
        CASE_CODE(ICMP6_NI_QUERY,       ICMP6_NI_REPLY);
        CASE_CODE(HOME_AGENT_AD_REQUEST,HOME_AGENT_AD_REPLY);

        CASE_CODE(MOBILE_PREFIX_SOLICIT,MOBILE_PREFIX_ADVERT);
        CASE_CODE(CERT_PATH_SOLICIT,    CERT_PATH_ADVERT);
        CASE_CODE(MC_ROUTER_ADVERT,     MC_ROUTER_SOLICIT);
        CASE_CODE(DUPL_ADDR_REQUEST,    DUPL_ADDR_CONFIRM);
        default:
            return -1;
    }
#undef CASE_CODE
}

/**
 * \brief Decode ICMPV6 packets and fill the Packet with the decoded info
 *
 * \param tv Pointer to the thread variables
 * \param dtv Pointer to the decode thread variables
 * \param p Pointer to the packet we are filling
 * \param pkt Pointer to the raw packet buffer
 * \param len the len of the rest of the packet not processed yet
 *
 * \retval void No return value
 */
int DecodeICMPV6(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                 const uint8_t *pkt, uint32_t len)
{
    const IPV6Hdr *ip6h = PacketGetIPv6(p);
    int full_hdr = 0;
    StatsIncr(tv, dtv->counter_icmpv6);

    if (len < ICMPV6_HEADER_LEN) {
        SCLogDebug("ICMPV6_PKT_TOO_SMALL");
        ENGINE_SET_INVALID_EVENT(p, ICMPV6_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    ICMPV6Hdr *icmpv6h = PacketSetICMPv6(p, pkt);
    p->proto = IPPROTO_ICMPV6;
    const uint8_t type = p->icmp_s.type = icmpv6h->type;
    const uint8_t code = p->icmp_s.code = icmpv6h->code;
    DEBUG_VALIDATE_BUG_ON(len - ICMPV6_HEADER_LEN > UINT16_MAX);
    p->payload_len = (uint16_t)(len - ICMPV6_HEADER_LEN);
    p->payload = (uint8_t *)pkt + ICMPV6_HEADER_LEN;

    int ctype = ICMPv6GetCounterpart(p->icmp_s.type);
    if (ctype != -1) {
        p->icmp_d.type = (uint8_t)ctype;
    }

    SCLogDebug("ICMPV6 TYPE %u CODE %u", type, code);

    switch (type) {
        case ICMP6_DST_UNREACH:
            SCLogDebug("ICMP6_DST_UNREACH");

            if (code > ICMP6_DST_UNREACH_REJECTROUTE) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            } else {
                if (unlikely(len > ICMPV6_HEADER_LEN + USHRT_MAX)) {
                    return TM_ECODE_FAILED;
                }
                DecodePartialIPV6(p, (uint8_t *)(pkt + ICMPV6_HEADER_LEN),
                        (uint16_t)(len - ICMPV6_HEADER_LEN));
                full_hdr = 1;
            }

            break;
        case ICMP6_PACKET_TOO_BIG:
            SCLogDebug("ICMP6_PACKET_TOO_BIG");

            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            } else {
                if (unlikely(len > ICMPV6_HEADER_LEN + USHRT_MAX)) {
                    return TM_ECODE_FAILED;
                }
                p->l4.vars.icmpv6.mtu = ICMPV6_GET_MTU(icmpv6h);
                DecodePartialIPV6(p, (uint8_t *)(pkt + ICMPV6_HEADER_LEN),
                        (uint16_t)(len - ICMPV6_HEADER_LEN));
                full_hdr = 1;
            }

            break;
        case ICMP6_TIME_EXCEEDED:
            SCLogDebug("ICMP6_TIME_EXCEEDED");

            if (code > ICMP6_TIME_EXCEED_REASSEMBLY) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            } else {
                if (unlikely(len > ICMPV6_HEADER_LEN + USHRT_MAX)) {
                    return TM_ECODE_FAILED;
                }
                DecodePartialIPV6(p, (uint8_t *)(pkt + ICMPV6_HEADER_LEN),
                        (uint16_t)(len - ICMPV6_HEADER_LEN));
                full_hdr = 1;
            }

            break;
        case ICMP6_PARAM_PROB:
            SCLogDebug("ICMP6_PARAM_PROB");

            if (code > ICMP6_PARAMPROB_OPTION) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            } else {
                if (unlikely(len > ICMPV6_HEADER_LEN + USHRT_MAX)) {
                    return TM_ECODE_FAILED;
                }
                DecodePartialIPV6(p, (uint8_t *)(pkt + ICMPV6_HEADER_LEN),
                        (uint16_t)(len - ICMPV6_HEADER_LEN));
                full_hdr = 1;
            }

            break;
        case ICMP6_ECHO_REQUEST:
            SCLogDebug("ICMP6_ECHO_REQUEST id: %u seq: %u", icmpv6h->icmpv6b.icmpv6i.id,
                    icmpv6h->icmpv6b.icmpv6i.seq);

            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            } else {
                p->l4.vars.icmpv6.id = icmpv6h->icmpv6b.icmpv6i.id;
                p->l4.vars.icmpv6.seq = icmpv6h->icmpv6b.icmpv6i.seq;
                full_hdr = 1;
            }

            break;
        case ICMP6_ECHO_REPLY:
            SCLogDebug("ICMP6_ECHO_REPLY id: %u seq: %u", icmpv6h->icmpv6b.icmpv6i.id,
                    icmpv6h->icmpv6b.icmpv6i.seq);

            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            } else {
                p->l4.vars.icmpv6.id = icmpv6h->icmpv6b.icmpv6i.id;
                p->l4.vars.icmpv6.seq = icmpv6h->icmpv6b.icmpv6i.seq;
                full_hdr = 1;
            }

            break;
        case ND_ROUTER_SOLICIT:
            SCLogDebug("ND_ROUTER_SOLICIT");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case ND_ROUTER_ADVERT:
            SCLogDebug("ND_ROUTER_ADVERT");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case ND_NEIGHBOR_SOLICIT:
            SCLogDebug("ND_NEIGHBOR_SOLICIT");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case ND_NEIGHBOR_ADVERT:
            SCLogDebug("ND_NEIGHBOR_ADVERT");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case ND_REDIRECT:
            SCLogDebug("ND_REDIRECT");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case MLD_LISTENER_QUERY:
            SCLogDebug("MLD_LISTENER_QUERY");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            if (IPV6_GET_RAW_HLIM(ip6h) != 1) {
                ENGINE_SET_EVENT(p, ICMPV6_MLD_MESSAGE_WITH_INVALID_HL);
            }
            break;
        case MLD_LISTENER_REPORT:
            SCLogDebug("MLD_LISTENER_REPORT");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            if (IPV6_GET_RAW_HLIM(ip6h) != 1) {
                ENGINE_SET_EVENT(p, ICMPV6_MLD_MESSAGE_WITH_INVALID_HL);
            }
            break;
        case MLD_LISTENER_REDUCTION:
            SCLogDebug("MLD_LISTENER_REDUCTION");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            if (IPV6_GET_RAW_HLIM(ip6h) != 1) {
                ENGINE_SET_EVENT(p, ICMPV6_MLD_MESSAGE_WITH_INVALID_HL);
            }
            break;
        case ICMP6_RR:
            SCLogDebug("ICMP6_RR");
            if (code > 2 && code != 255) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case ICMP6_NI_QUERY:
            SCLogDebug("ICMP6_NI_QUERY");
            if (code > 2) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case ICMP6_NI_REPLY:
            SCLogDebug("ICMP6_NI_REPLY");
            if (code > 2) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case ND_INVERSE_SOLICIT:
            SCLogDebug("ND_INVERSE_SOLICIT");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case ND_INVERSE_ADVERT:
            SCLogDebug("ND_INVERSE_ADVERT");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case MLD_V2_LIST_REPORT:
            SCLogDebug("MLD_V2_LIST_REPORT");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case HOME_AGENT_AD_REQUEST:
            SCLogDebug("HOME_AGENT_AD_REQUEST");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case HOME_AGENT_AD_REPLY:
            SCLogDebug("HOME_AGENT_AD_REPLY");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case MOBILE_PREFIX_SOLICIT:
            SCLogDebug("MOBILE_PREFIX_SOLICIT");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case MOBILE_PREFIX_ADVERT:
            SCLogDebug("MOBILE_PREFIX_ADVERT");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case CERT_PATH_SOLICIT:
            SCLogDebug("CERT_PATH_SOLICIT");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case CERT_PATH_ADVERT:
            SCLogDebug("CERT_PATH_ADVERT");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case ICMP6_MOBILE_EXPERIMENTAL:
            SCLogDebug("ICMP6_MOBILE_EXPERIMENTAL");
            break;
        case MC_ROUTER_ADVERT:
            SCLogDebug("MC_ROUTER_ADVERT");
            break;
        case MC_ROUTER_SOLICIT:
            SCLogDebug("MC_ROUTER_SOLICIT");
            break;
        case MC_ROUTER_TERMINATE:
            SCLogDebug("MC_ROUTER_TERMINATE");
            break;
        case FMIPV6_MSG:
            SCLogDebug("FMIPV6_MSG");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case RPL_CONTROL_MSG:
            SCLogDebug("RPL_CONTROL_MSG");
            if (code > 3 && code < 128) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            if (code > 132) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case LOCATOR_UDATE_MSG:
            SCLogDebug("LOCATOR_UDATE_MSG");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case DUPL_ADDR_REQUEST:
            SCLogDebug("DUPL_ADDR_REQUEST");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case DUPL_ADDR_CONFIRM:
            SCLogDebug("DUPL_ADDR_CONFIRM");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        case MPL_CONTROL_MSG:
            SCLogDebug("MPL_CONTROL_MSG");
            if (code != 0) {
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_CODE);
            }
            break;
        default:
            /* Various range taken from:
             *   http://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-2
             */
            if (type > 4 && type < 100) {
                ENGINE_SET_EVENT(p, ICMPV6_UNASSIGNED_TYPE);
            } else if (type >= 100 && type < 102) {
                ENGINE_SET_EVENT(p, ICMPV6_EXPERIMENTATION_TYPE);
            } else if (type >= 102 && type < 127) {
                ENGINE_SET_EVENT(p, ICMPV6_UNASSIGNED_TYPE);
            } else if (type >= 160 && type < 200) {
                ENGINE_SET_EVENT(p, ICMPV6_UNASSIGNED_TYPE);
            } else if (type >= 200 && type < 202) {
                ENGINE_SET_EVENT(p, ICMPV6_EXPERIMENTATION_TYPE);
            } else if (type >= 202) {
                ENGINE_SET_EVENT(p, ICMPV6_UNASSIGNED_TYPE);
            } else {
                SCLogDebug("ICMPV6 Message type %u not "
                           "implemented yet",
                        type);
                ENGINE_SET_EVENT(p, ICMPV6_UNKNOWN_TYPE);
            }
    }

    /* for a info message the header is just 4 bytes */
    if (!full_hdr) {
        if (p->payload_len >= 4) {
            p->payload_len -= 4;
            p->payload = (uint8_t *)pkt + 4;
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

    FlowSetupPacket(p);

    return TM_ECODE_OK;
}

#ifdef UNITTESTS
#include "packet.h"
#include "util-unittest-helper.h"

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

    FAIL_IF(csum != ICMPV6CalculateChecksum((uint16_t *)(raw_ipv6 + 14 + 8),
                                            (uint16_t *)(raw_ipv6 + 54), 68));
    PASS;
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

    FAIL_IF(csum == ICMPV6CalculateChecksum((uint16_t *)(raw_ipv6 + 14 + 8),
                                            (uint16_t *)(raw_ipv6 + 54), 68));
    PASS;
}

/** \test icmpv6 message type: parameter problem, valid packet
 *
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6ParamProbTest01(void)
{
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

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;
    uint32_t *ipv6src;
    uint32_t *ipv6dst;
    ipv6src = (uint32_t*) &raw_ipv6[8];
    ipv6dst = (uint32_t*) &raw_ipv6[24];

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));
    FAIL_IF(!PacketIsICMPv6(p));

    /* ICMPv6 not processed at all? */
    FAIL_IF(ICMPV6_GET_TYPE(PacketGetICMPv6(p)) != 4);
    FAIL_IF(ICMPV6_GET_CODE(PacketGetICMPv6(p)) != 0);
    FAIL_IF(ICMPV6_GET_EMB_PROTO(p) != IPPROTO_ICMPV6);

    /* Let's check if we retrieved the embedded ipv6 addresses correctly */
    for (int i = 0; i < 4; i++) {
        FAIL_IF(PacketGetICMPv6EmbIPv6(p)->s_ip6_src[i] != ipv6src[i] ||
                PacketGetICMPv6EmbIPv6(p)->s_ip6_dst[i] != ipv6dst[i]);
    }

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/** \test icmpv6 message type: packet too big, valid packet
 *
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6PktTooBigTest01(void)
{
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

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;
    uint32_t *ipv6src;
    uint32_t *ipv6dst;
    ipv6src = (uint32_t*) &raw_ipv6[8];
    ipv6dst = (uint32_t*) &raw_ipv6[24];

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));
    FAIL_IF(!PacketIsICMPv6(p));

    /* Note: it has an embedded ipv6 packet but no protocol after ipv6
     * (IPPROTO_NONE) */
    /* Check if ICMPv6 header was processed at all. */
    FAIL_IF(ICMPV6_GET_TYPE(PacketGetICMPv6(p)) != 2);
    FAIL_IF(ICMPV6_GET_CODE(PacketGetICMPv6(p)) != 0);

    /* Let's check if we retrieved the embedded ipv6 addresses correctly */
    for (int i = 0; i < 4; i++) {
        FAIL_IF(PacketGetICMPv6EmbIPv6(p)->s_ip6_src[i] != ipv6src[i] ||
                PacketGetICMPv6EmbIPv6(p)->s_ip6_dst[i] != ipv6dst[i]);
    }

    SCLogDebug("ICMPV6 IPV6 src and dst properly set");

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/** \test icmpv6 message type: time exceed, valid packet
 *
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6TimeExceedTest01(void)
{
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

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;
    uint32_t *ipv6src;
    uint32_t *ipv6dst;
    ipv6src = (uint32_t*) &raw_ipv6[8];
    ipv6dst = (uint32_t*) &raw_ipv6[24];

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));
    FAIL_IF(!PacketIsICMPv6(p));

    /* Note: it has an embedded ipv6 packet but no protocol after ipv6 (IPPROTO_NONE) */
    FAIL_IF(ICMPV6_GET_TYPE(PacketGetICMPv6(p)) != 3);
    FAIL_IF(ICMPV6_GET_CODE(PacketGetICMPv6(p)) != 0);
    FAIL_IF_NULL(PacketGetICMPv6EmbIPv6(p));
    FAIL_IF(ICMPV6_GET_EMB_PROTO(p) != IPPROTO_NONE);

    /* Let's check if we retrieved the embedded ipv6 addresses correctly */
    for (int i = 0; i < 4; i++) {
        FAIL_IF(PacketGetICMPv6EmbIPv6(p)->s_ip6_src[i] != ipv6src[i] ||
                PacketGetICMPv6EmbIPv6(p)->s_ip6_dst[i] != ipv6dst[i]);
    }

    SCLogDebug("ICMPV6 IPV6 src and dst properly set");

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/** \test icmpv6 message type: destination unreach, valid packet
 *
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6DestUnreachTest01(void)
{
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

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;
    uint32_t *ipv6src;
    uint32_t *ipv6dst;
    ipv6src = (uint32_t*) &raw_ipv6[8];
    ipv6dst = (uint32_t*) &raw_ipv6[24];

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));
    FAIL_IF(!PacketIsICMPv6(p));

    /* Note: it has an embedded ipv6 packet but no protocol after ipv6 (IPPROTO_NONE) */
    FAIL_IF(ICMPV6_GET_TYPE(PacketGetICMPv6(p)) != 1);
    FAIL_IF(ICMPV6_GET_CODE(PacketGetICMPv6(p)) != 0);
    FAIL_IF_NULL(PacketGetICMPv6EmbIPv6(p));
    FAIL_IF(ICMPV6_GET_EMB_PROTO(p) != IPPROTO_NONE);

    /* Let's check if we retrieved the embedded ipv6 addresses correctly */
    for (int i = 0; i < 4; i++) {
        FAIL_IF(PacketGetICMPv6EmbIPv6(p)->s_ip6_src[i] != ipv6src[i] ||
                PacketGetICMPv6EmbIPv6(p)->s_ip6_dst[i] != ipv6dst[i]);
    }

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/**\test icmpv6 message type: echo request, valid packet
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6EchoReqTest01(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x80, 0x00, 0xe5, 0xa5, 0x25, 0xf0, 0x75, 0x23 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));
    FAIL_IF(!PacketIsICMPv6(p));

    SCLogDebug("ID: %u seq: %u", ICMPV6_GET_ID(p), ICMPV6_GET_SEQ(p));

    FAIL_IF(ICMPV6_GET_TYPE(PacketGetICMPv6(p)) != 128);
    FAIL_IF(ICMPV6_GET_CODE(PacketGetICMPv6(p)) != 0);
    FAIL_IF(SCNtohs(ICMPV6_GET_ID(p)) != 9712);
    FAIL_IF(SCNtohs(ICMPV6_GET_SEQ(p)) != 29987);

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/**\test icmpv6 message type: echo reply, valid packet
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6EchoRepTest01(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a,
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x81, 0x00,
        0xe5, 0xa5, 0x25, 0xf0, 0x75, 0x23 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));
    FAIL_IF(!PacketIsICMPv6(p));

    FAIL_IF(ICMPV6_GET_TYPE(PacketGetICMPv6(p)) != 129);
    FAIL_IF(ICMPV6_GET_CODE(PacketGetICMPv6(p)) != 0);
    FAIL_IF(SCNtohs(ICMPV6_GET_ID(p)) != 9712);
    FAIL_IF(SCNtohs(ICMPV6_GET_SEQ(p)) != 29987);

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/** \test icmpv6 message type: parameter problem, invalid packet
 * \brief set the event ICMPV6_IPV6_UNKNOWN_VER properly when the embedded packet has an unknown version
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6ParamProbTest02(void)
{
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

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));
    FAIL_IF(!PacketIsICMPv6(p));
    FAIL_IF(ICMPV6_GET_TYPE(PacketGetICMPv6(p)) != 4);
    FAIL_IF(ICMPV6_GET_CODE(PacketGetICMPv6(p)) != 0);
    FAIL_IF(!ENGINE_ISSET_EVENT(p, ICMPV6_IPV6_UNKNOWN_VER));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/** \test icmpv6 message type: packet too big, invalid packet
 *  \brief Set the event ICMPV6_UNKNOWN_CODE if code is invalid for this type
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6PktTooBigTest02(void)
{
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

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));
    FAIL_IF(!PacketIsICMPv6(p));
    FAIL_IF(!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/** \test icmpv6 message type: time exceed, invalid packet
 * \brief set the event ICMPV6_PKT_TOO_SMALL properly
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6TimeExceedTest02(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x03, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x10, 0x5c };

    /* The icmpv6 header is broken in the checksum (so we dont have a complete header) */

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF(!ENGINE_ISSET_EVENT(p, ICMPV6_PKT_TOO_SMALL));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/**\test icmpv6 message type: destination unreach, invalid packet
 * \brief The embedded packet header (ipv6) is truncated
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6DestUnreachTest02(void)
{
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

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF(!ENGINE_ISSET_EVENT(p, ICMPV6_IPV6_TRUNC_PKT));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/**\test icmpv6 message type: echo request, invalid packet
 * \brief unknown code
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6EchoReqTest02(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a,
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x01,
        0xe5, 0xa5, 0x25, 0xf0, 0x75, 0x23 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF(!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/**\test icmpv6 message type: echo reply, invalid packet
 * \brief unknown code
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6EchoRepTest02(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a,
        0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x81, 0x01,
        0xe5, 0xa5, 0x25, 0xf0, 0x75, 0x23 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF(!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/**\test icmpv6 packet decoding and setting up of payload_len and payload buffer
 * \retval retval 0 = Error ; 1 = ok
 */
static int ICMPV6PayloadTest01(void)
{
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

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF_NULL(p->payload);
    FAIL_IF(p->payload_len != 37);

    PacketFree(p);
    FlowShutdown();
    PASS;
}

static int ICMPV6RouterSolicitTestKnownCode(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x85, 0x00, 0xbe, 0xb0, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF(ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

static int ICMPV6RouterSolicitTestUnknownCode(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x85, 0x01, 0xbe, 0xaf, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF(!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

static int ICMPV6RouterAdvertTestKnownCode(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x86, 0x00, 0xbd, 0xb0, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF(ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

static int ICMPV6RouterAdvertTestUnknownCode(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x86, 0x01, 0xbd, 0xaf, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF(!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

static int ICMPV6NeighbourSolicitTestKnownCode(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x87, 0x00, 0xbc, 0xb0, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF(ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

static int ICMPV6NeighbourSolicitTestUnknownCode(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x87, 0x01, 0xbc, 0xaf, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF(!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

static int ICMPV6NeighbourAdvertTestKnownCode(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x88, 0x00, 0xbb, 0xb0, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF(ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

static int ICMPV6NeighbourAdvertTestUnknownCode(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x88, 0x01, 0xbb, 0xaf, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF(!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

static int ICMPV6RedirectTestKnownCode(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x89, 0x00, 0xba, 0xb0, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF(ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

static int ICMPV6RedirectTestUnknownCode(void)
{
    static uint8_t raw_ipv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x24, 0x8c, 0xff, 0xfe, 0x0e, 0x31, 0x54,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x89, 0x01, 0xba, 0xaf, 0x00, 0x00, 0x00, 0x00
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV6(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));

    FAIL_IF(!ENGINE_ISSET_EVENT(p, ICMPV6_UNKNOWN_CODE));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/**
 * \test Test for valid ICMPv6 checksum when the FCS is still attached.
 *
 * Tests that the packet is decoded with sufficient info to verify the
 * checksum even if the packet has some trailing data like an ethernet
 * FCS.
 */
static int ICMPV6CalculateValidChecksumWithFCS(void)
{
    /* IPV6/ICMPv6 packet with ethernet header.
     * - IPv6 payload length: 36
     */
    uint8_t raw_ipv6[] = {
        0x33, 0x33, 0x00, 0x00, 0x00, 0x16, 0x00, 0x50,
        0x56, 0xa6, 0x6a, 0x7d, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x24, 0x00, 0x01, 0xfe, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf5, 0x09,
        0xad, 0x44, 0x49, 0x38, 0x5f, 0xa9, 0xff, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x3a, 0x00,
        0x05, 0x02, 0x00, 0x00, 0x01, 0x00, 0x8f, 0x00,
        0x24, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, /* Checksum: 0x24e0. */
        0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xfb, 0x1f, 0x34, 0xf6, 0xa4
    };
    uint16_t csum = *(((uint16_t *)(raw_ipv6 + 64)));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&tv, &dtv, p, raw_ipv6, sizeof(raw_ipv6));
    FAIL_IF(!PacketIsICMPv6(p));

    const ICMPV6Hdr *icmpv6h = PacketGetICMPv6(p);
    const IPV6Hdr *ip6h = PacketGetIPv6(p);
    uint16_t icmpv6_len = IPV6_GET_RAW_PLEN(ip6h) -
                          ((const uint8_t *)icmpv6h - (const uint8_t *)ip6h - IPV6_HEADER_LEN);
    FAIL_IF(icmpv6_len != 28);
    FAIL_IF(ICMPV6CalculateChecksum(ip6h->s_ip6_addrs, (uint16_t *)icmpv6h, icmpv6_len) != csum);

    PacketFree(p);
    FlowShutdown();
    PASS;
}

#endif /* UNITTESTS */
/**
 * \brief Registers ICMPV6 unit tests
 * \todo More ICMPv6 tests
 */
void DecodeICMPV6RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ICMPV6CalculateValidChecksumtest01",
                   ICMPV6CalculateValidChecksumtest01);
    UtRegisterTest("ICMPV6CalculateInvalidChecksumtest02", ICMPV6CalculateInvalidChecksumtest02);

    UtRegisterTest("ICMPV6ParamProbTest01 (Valid)", ICMPV6ParamProbTest01);
    UtRegisterTest("ICMPV6DestUnreachTest01 (Valid)", ICMPV6DestUnreachTest01);
    UtRegisterTest("ICMPV6PktTooBigTest01 (Valid)", ICMPV6PktTooBigTest01);
    UtRegisterTest("ICMPV6TimeExceedTest01 (Valid)", ICMPV6TimeExceedTest01);
    UtRegisterTest("ICMPV6EchoReqTest01 (Valid)", ICMPV6EchoReqTest01);
    UtRegisterTest("ICMPV6EchoRepTest01 (Valid)", ICMPV6EchoRepTest01);

    UtRegisterTest("ICMPV6ParamProbTest02 (Invalid)", ICMPV6ParamProbTest02);
    UtRegisterTest("ICMPV6DestUnreachTest02 (Invalid)",
                   ICMPV6DestUnreachTest02);
    UtRegisterTest("ICMPV6PktTooBigTest02 (Invalid)", ICMPV6PktTooBigTest02);
    UtRegisterTest("ICMPV6TimeExceedTest02 (Invalid)", ICMPV6TimeExceedTest02);
    UtRegisterTest("ICMPV6EchoReqTest02 (Invalid)", ICMPV6EchoReqTest02);
    UtRegisterTest("ICMPV6EchoRepTest02 (Invalid)", ICMPV6EchoRepTest02);

    UtRegisterTest("ICMPV6PayloadTest01", ICMPV6PayloadTest01);

    UtRegisterTest("ICMPV6RouterSolicitTestKnownCode",
                   ICMPV6RouterSolicitTestKnownCode);
    UtRegisterTest("ICMPV6RouterSolicitTestUnknownCode",
                   ICMPV6RouterSolicitTestUnknownCode);
    UtRegisterTest("ICMPV6RouterAdvertTestKnownCode",
                   ICMPV6RouterAdvertTestKnownCode);
    UtRegisterTest("ICMPV6RouterAdvertTestUnknownCode",
                   ICMPV6RouterAdvertTestUnknownCode);

    UtRegisterTest("ICMPV6NeighbourSolicitTestKnownCode",
                   ICMPV6NeighbourSolicitTestKnownCode);
    UtRegisterTest("ICMPV6NeighbourSolicitTestUnknownCode",
                   ICMPV6NeighbourSolicitTestUnknownCode);
    UtRegisterTest("ICMPV6NeighbourAdvertTestKnownCode",
                   ICMPV6NeighbourAdvertTestKnownCode);
    UtRegisterTest("ICMPV6NeighbourAdvertTestUnknownCode",
                   ICMPV6NeighbourAdvertTestUnknownCode);

    UtRegisterTest("ICMPV6RedirectTestKnownCode", ICMPV6RedirectTestKnownCode);
    UtRegisterTest("ICMPV6RedirectTestUnknownCode",
                   ICMPV6RedirectTestUnknownCode);
    UtRegisterTest("ICMPV6CalculateValidChecksumWithFCS",
                   ICMPV6CalculateValidChecksumWithFCS);
#endif /* UNITTESTS */
}
/**
 * @}
 */
