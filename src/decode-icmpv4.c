/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * Decode ICMPv4
 */

#include "suricata-common.h"

#include "decode.h"
#include "decode-events.h"
#include "decode-ipv4.h"
#include "decode-icmpv4.h"

#include "flow.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"
#include "util-print.h"
#include "util-validate.h"

/**
 * Note, this is the IP header, plus a bit of the original packet, not the whole thing!
 */
static int DecodePartialIPV4(Packet* p, uint8_t* partial_packet, uint16_t len)
{
    /** Check the sizes, the header must fit at least */
    if (len < IPV4_HEADER_LEN) {
        SCLogDebug("DecodePartialIPV4: ICMPV4_IPV4_TRUNC_PKT");
        ENGINE_SET_INVALID_EVENT(p, ICMPV4_IPV4_TRUNC_PKT);
        return -1;
    }

    IPV4Hdr *icmp4_ip4h = (IPV4Hdr*)partial_packet;

    /** Check the embedded version */
    if (IPV4_GET_RAW_VER(icmp4_ip4h) != 4) {
        /** Check the embedded version */
        SCLogDebug("DecodePartialIPV4: ICMPv4 contains Unknown IPV4 version "
                   "ICMPV4_IPV4_UNKNOWN_VER");
        ENGINE_SET_INVALID_EVENT(p, ICMPV4_IPV4_UNKNOWN_VER);
        return -1;
    }

    /** We need to fill icmpv4vars */
    const uint8_t *icmpv4_ptr = (const uint8_t *)p->l4.hdrs.icmpv4h;
    DEBUG_VALIDATE_BUG_ON((ptrdiff_t)(partial_packet - icmpv4_ptr) > (ptrdiff_t)UINT16_MAX);
    p->l4.vars.icmpv4.emb_ip4h_offset = (uint16_t)(partial_packet - icmpv4_ptr);

    switch (IPV4_GET_RAW_IPPROTO(icmp4_ip4h)) {
        case IPPROTO_TCP:
            if (len >= IPV4_HEADER_LEN + TCP_HEADER_LEN ) {
                TCPHdr *emb_tcph = (TCPHdr *)(partial_packet + IPV4_HEADER_LEN);
                p->l4.vars.icmpv4.emb_sport = SCNtohs(emb_tcph->th_sport);
                p->l4.vars.icmpv4.emb_dport = SCNtohs(emb_tcph->th_dport);
                p->l4.vars.icmpv4.emb_ports_set = true;
                p->l4.vars.icmpv4.emb_ip4_proto = IPPROTO_TCP;

                SCLogDebug("DecodePartialIPV4: ICMPV4->IPV4->TCP header sport: "
                           "%" PRIu16 " dport %" PRIu16 "",
                        p->l4.vars.icmpv4.emb_sport, p->l4.vars.icmpv4.emb_dport);
            } else if (len >= IPV4_HEADER_LEN + 4) {
                /* only access th_sport and th_dport */
                TCPHdr *emb_tcph = (TCPHdr *)(partial_packet + IPV4_HEADER_LEN);
                p->l4.vars.icmpv4.emb_sport = SCNtohs(emb_tcph->th_sport);
                p->l4.vars.icmpv4.emb_dport = SCNtohs(emb_tcph->th_dport);
                p->l4.vars.icmpv4.emb_ports_set = true;
                p->l4.vars.icmpv4.emb_ip4_proto = IPPROTO_TCP;
                SCLogDebug("DecodePartialIPV4: ICMPV4->IPV4->TCP partial header sport: "
                           "%" PRIu16 " dport %" PRIu16 "",
                        p->l4.vars.icmpv4.emb_sport, p->l4.vars.icmpv4.emb_dport);
            } else {
                SCLogDebug("DecodePartialIPV4: Warning, ICMPV4->IPV4->TCP "
                           "header Didn't fit in the packet!");
                p->l4.vars.icmpv4.emb_sport = 0;
                p->l4.vars.icmpv4.emb_dport = 0;
            }

            break;
        case IPPROTO_UDP:
            if (len >= IPV4_HEADER_LEN + UDP_HEADER_LEN ) {
                UDPHdr *emb_udph = (UDPHdr *)(partial_packet + IPV4_HEADER_LEN);
                p->l4.vars.icmpv4.emb_sport = SCNtohs(emb_udph->uh_sport);
                p->l4.vars.icmpv4.emb_dport = SCNtohs(emb_udph->uh_dport);
                p->l4.vars.icmpv4.emb_ports_set = true;
                p->l4.vars.icmpv4.emb_ip4_proto = IPPROTO_UDP;

                SCLogDebug("DecodePartialIPV4: ICMPV4->IPV4->UDP header sport: "
                           "%" PRIu16 " dport %" PRIu16 "",
                        p->l4.vars.icmpv4.emb_sport, p->l4.vars.icmpv4.emb_dport);
            } else {
                SCLogDebug("DecodePartialIPV4: Warning, ICMPV4->IPV4->UDP "
                           "header Didn't fit in the packet!");
                p->l4.vars.icmpv4.emb_sport = 0;
                p->l4.vars.icmpv4.emb_dport = 0;
            }

            break;
        case IPPROTO_ICMP:
            if (len >= IPV4_HEADER_LEN + ICMPV4_HEADER_LEN) {
                p->l4.vars.icmpv4.emb_sport = 0;
                p->l4.vars.icmpv4.emb_dport = 0;
                p->l4.vars.icmpv4.emb_ip4_proto = IPPROTO_ICMP;

                SCLogDebug("DecodePartialIPV4: ICMPV4->IPV4->ICMP header");
            }

            break;
    }

    return 0;
}

/** DecodeICMPV4
 *  \brief Main ICMPv4 decoding function
 */
int DecodeICMPV4(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    StatsIncr(tv, dtv->counter_icmpv4);

    if (len < ICMPV4_HEADER_LEN) {
        ENGINE_SET_INVALID_EVENT(p, ICMPV4_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    ICMPV4Hdr *icmpv4h = PacketSetICMPv4(p, pkt);

    SCLogDebug("ICMPV4 TYPE %" PRIu32 " CODE %" PRIu32 "", icmpv4h->type, icmpv4h->code);

    p->proto = IPPROTO_ICMP;
    const uint8_t type = p->icmp_s.type = icmpv4h->type;
    const uint8_t code = p->icmp_s.code = icmpv4h->code;

    int ctype = ICMPv4GetCounterpart(type);
    if (ctype != -1) {
        p->icmp_d.type = (uint8_t)ctype;
    }

    ICMPV4ExtHdr *icmp4eh = (ICMPV4ExtHdr *)icmpv4h;
    p->l4.vars.icmpv4.hlen = ICMPV4_HEADER_LEN;

    switch (type) {
        case ICMP_ECHOREPLY:
            p->l4.vars.icmpv4.id = icmp4eh->id;
            p->l4.vars.icmpv4.seq = icmp4eh->seq;
            if (code != 0) {
                ENGINE_SET_EVENT(p,ICMPV4_UNKNOWN_CODE);
            }
            break;

        case ICMP_DEST_UNREACH:
            if (code > NR_ICMP_UNREACH) {
                ENGINE_SET_EVENT(p,ICMPV4_UNKNOWN_CODE);
            } else {
                /* parse IP header plus 64 bytes */
                if (len > ICMPV4_HEADER_PKT_OFFSET) {
                    if (unlikely(len > ICMPV4_HEADER_PKT_OFFSET + USHRT_MAX)) {
                        return TM_ECODE_FAILED;
                    }
                    (void)DecodePartialIPV4(p, (uint8_t *)(pkt + ICMPV4_HEADER_PKT_OFFSET),
                            (uint16_t)(len - ICMPV4_HEADER_PKT_OFFSET));
                }
            }
            break;

        case ICMP_SOURCE_QUENCH:
            if (code != 0) {
                ENGINE_SET_EVENT(p,ICMPV4_UNKNOWN_CODE);
            } else {
                // parse IP header plus 64 bytes
                if (len >= ICMPV4_HEADER_PKT_OFFSET) {
                    if (unlikely(len > ICMPV4_HEADER_PKT_OFFSET + USHRT_MAX)) {
                        return TM_ECODE_FAILED;
                    }
                    DecodePartialIPV4(p, (uint8_t *)(pkt + ICMPV4_HEADER_PKT_OFFSET),
                            (uint16_t)(len - ICMPV4_HEADER_PKT_OFFSET));
                }
            }
            break;

        case ICMP_REDIRECT:
            if (code > ICMP_REDIR_HOSTTOS) {
                ENGINE_SET_EVENT(p,ICMPV4_UNKNOWN_CODE);
            } else {
                // parse IP header plus 64 bytes
                if (len > ICMPV4_HEADER_PKT_OFFSET) {
                    if (unlikely(len > ICMPV4_HEADER_PKT_OFFSET + USHRT_MAX)) {
                        return TM_ECODE_FAILED;
                    }
                    DecodePartialIPV4(p, (uint8_t *)(pkt + ICMPV4_HEADER_PKT_OFFSET),
                            (uint16_t)(len - ICMPV4_HEADER_PKT_OFFSET));
                }
            }
            break;

        case ICMP_ECHO:
            p->l4.vars.icmpv4.id = icmp4eh->id;
            p->l4.vars.icmpv4.seq = icmp4eh->seq;
            if (code != 0) {
                ENGINE_SET_EVENT(p,ICMPV4_UNKNOWN_CODE);
            }
            break;

        case ICMP_TIME_EXCEEDED:
            if (code > ICMP_EXC_FRAGTIME) {
                ENGINE_SET_EVENT(p,ICMPV4_UNKNOWN_CODE);
            } else {
                // parse IP header plus 64 bytes
                if (len > ICMPV4_HEADER_PKT_OFFSET) {
                    if (unlikely(len > ICMPV4_HEADER_PKT_OFFSET + USHRT_MAX)) {
                        return TM_ECODE_FAILED;
                    }
                    DecodePartialIPV4(p, (uint8_t *)(pkt + ICMPV4_HEADER_PKT_OFFSET),
                            (uint16_t)(len - ICMPV4_HEADER_PKT_OFFSET));
                }
            }
            break;

        case ICMP_PARAMETERPROB:
            if (code != 0) {
                ENGINE_SET_EVENT(p,ICMPV4_UNKNOWN_CODE);
            } else {
                // parse IP header plus 64 bytes
                if (len > ICMPV4_HEADER_PKT_OFFSET) {
                    if (unlikely(len > ICMPV4_HEADER_PKT_OFFSET + USHRT_MAX)) {
                        return TM_ECODE_FAILED;
                    }
                    DecodePartialIPV4(p, (uint8_t *)(pkt + ICMPV4_HEADER_PKT_OFFSET),
                            (uint16_t)(len - ICMPV4_HEADER_PKT_OFFSET));
                }
            }
            break;

        case ICMP_TIMESTAMP:
            p->l4.vars.icmpv4.id = icmp4eh->id;
            p->l4.vars.icmpv4.seq = icmp4eh->seq;
            if (code != 0) {
                ENGINE_SET_EVENT(p,ICMPV4_UNKNOWN_CODE);
            }

            if (len < (sizeof(ICMPV4Timestamp) + ICMPV4_HEADER_LEN)) {
                ENGINE_SET_EVENT(p, ICMPV4_IPV4_TRUNC_PKT);
            } else {
                p->l4.vars.icmpv4.hlen += sizeof(ICMPV4Timestamp);
            }
            break;

        case ICMP_TIMESTAMPREPLY:
            p->l4.vars.icmpv4.id = icmp4eh->id;
            p->l4.vars.icmpv4.seq = icmp4eh->seq;
            if (code != 0) {
                ENGINE_SET_EVENT(p,ICMPV4_UNKNOWN_CODE);
            }

            if (len < (sizeof(ICMPV4Timestamp) + ICMPV4_HEADER_LEN)) {
                ENGINE_SET_EVENT(p, ICMPV4_IPV4_TRUNC_PKT);
            } else {
                p->l4.vars.icmpv4.hlen += sizeof(ICMPV4Timestamp);
            }
            break;

        case ICMP_INFO_REQUEST:
            p->l4.vars.icmpv4.id = icmp4eh->id;
            p->l4.vars.icmpv4.seq = icmp4eh->seq;
            if (code != 0) {
                ENGINE_SET_EVENT(p,ICMPV4_UNKNOWN_CODE);
            }
            break;

        case ICMP_INFO_REPLY:
            p->l4.vars.icmpv4.id = icmp4eh->id;
            p->l4.vars.icmpv4.seq = icmp4eh->seq;
            if (code != 0) {
                ENGINE_SET_EVENT(p,ICMPV4_UNKNOWN_CODE);
            }
            break;

        case ICMP_ROUTERADVERT: {
            /* pkt points to beginning of icmp message */
            ICMPV4RtrAdvert *icmpv4_router_advert = (ICMPV4RtrAdvert *)(pkt + sizeof(ICMPV4Hdr));
            uint32_t advert_len = icmpv4_router_advert->naddr *
                                  (icmpv4_router_advert->addr_sz * sizeof(uint32_t));
            if (len < (advert_len + ICMPV4_HEADER_LEN)) {
                ENGINE_SET_EVENT(p, ICMPV4_IPV4_TRUNC_PKT);
            } else {
                p->l4.vars.icmpv4.hlen += advert_len;
            }
        } break;

        case ICMP_ADDRESS:
            p->l4.vars.icmpv4.id = icmp4eh->id;
            p->l4.vars.icmpv4.seq = icmp4eh->seq;
            if (code != 0) {
                ENGINE_SET_EVENT(p,ICMPV4_UNKNOWN_CODE);
            }
            break;

        case ICMP_ADDRESSREPLY:
            p->l4.vars.icmpv4.id = icmp4eh->id;
            p->l4.vars.icmpv4.seq = icmp4eh->seq;
            if (code != 0) {
                ENGINE_SET_EVENT(p,ICMPV4_UNKNOWN_CODE);
            }
            break;

        default:
            ENGINE_SET_EVENT(p, ICMPV4_UNKNOWN_TYPE);
    }

    p->payload = (uint8_t *)pkt + p->l4.vars.icmpv4.hlen;
    DEBUG_VALIDATE_BUG_ON(len - p->l4.vars.icmpv4.hlen > UINT16_MAX);
    p->payload_len = (uint16_t)(len - p->l4.vars.icmpv4.hlen);

    FlowSetupPacket(p);
    return TM_ECODE_OK;
}

/** \retval type counterpart type or -1 */
int ICMPv4GetCounterpart(uint8_t type)
{
#define CASE_CODE(t,r) case (t): return r; case (r): return t;
    switch (type) {
        CASE_CODE(ICMP_ECHO,            ICMP_ECHOREPLY);
        CASE_CODE(ICMP_TIMESTAMP,       ICMP_TIMESTAMPREPLY);
        CASE_CODE(ICMP_INFO_REQUEST,    ICMP_INFO_REPLY);
        CASE_CODE(ICMP_ROUTERSOLICIT,   ICMP_ROUTERADVERT);
        CASE_CODE(ICMP_ADDRESS,         ICMP_ADDRESSREPLY);
        default:
            return -1;
    }
#undef CASE_CODE
}

#ifdef UNITTESTS

/** DecodeICMPV4test01
 *  \brief
 *  \retval 1 Expected test value
 */
static int DecodeICMPV4test01(void)
{
    uint8_t raw_icmpv4[] = {
        0x08, 0x00, 0x78, 0x47, 0xfc, 0x55, 0x00, 0x04,
        0x52, 0xab, 0x86, 0x4a, 0x84, 0x50, 0x0e, 0x00,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    IPV4Hdr ip4h;

    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->src.addr_data32[0] = UTHSetIPv4Address("4.3.2.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");

    ip4h.s_ip_src.s_addr = p->src.addr_data32[0];
    ip4h.s_ip_dst.s_addr = p->dst.addr_data32[0];
    UTHSetIPV4Hdr(p, &ip4h);

    DecodeICMPV4(&tv, &dtv, p, raw_icmpv4, sizeof(raw_icmpv4));
    FAIL_IF_NOT(PacketIsICMPv4(p));

    const ICMPV4Hdr *icmpv4h = PacketGetICMPv4(p);
    FAIL_IF_NULL(icmpv4h);

    FAIL_IF_NOT(icmpv4h->type == 8);
    FAIL_IF_NOT(icmpv4h->code == 0);

    FlowShutdown();
    PacketFree(p);
    PASS;
}

/** DecodeICMPV4test02
 *  \brief
 *  \retval 1 Expected test value
 */
static int DecodeICMPV4test02(void)
{
    uint8_t raw_icmpv4[] = {
        0x00, 0x00, 0x57, 0x64, 0xfb, 0x55, 0x00, 0x03,
        0x43, 0xab, 0x86, 0x4a, 0xf6, 0x49, 0x02, 0x00,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    IPV4Hdr ip4h;

    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->src.addr_data32[0] = UTHSetIPv4Address("4.3.2.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");

    ip4h.s_ip_src.s_addr = p->src.addr_data32[0];
    ip4h.s_ip_dst.s_addr = p->dst.addr_data32[0];
    UTHSetIPV4Hdr(p, &ip4h);

    DecodeICMPV4(&tv, &dtv, p, raw_icmpv4, sizeof(raw_icmpv4));
    FAIL_IF_NOT(PacketIsICMPv4(p));

    const ICMPV4Hdr *icmpv4h = PacketGetICMPv4(p);
    FAIL_IF_NULL(icmpv4h);

    FAIL_IF_NOT(icmpv4h->type == 0);
    FAIL_IF_NOT(icmpv4h->code == 0);

    FlowShutdown();
    PacketFree(p);
    PASS;
}

/** DecodeICMPV4test03
 *  \brief  TTL exceeded
 *  \retval Expected test value: 1
 */
static int DecodeICMPV4test03(void)
{
    uint8_t raw_icmpv4[] = {
        0x0b, 0x00, 0x6a, 0x3d, 0x00, 0x00, 0x00, 0x00,
        0x45, 0x00, 0x00, 0x3c, 0x64, 0x15, 0x00, 0x00,
        0x01, 0x11, 0xde, 0xfd, 0xc0, 0xa8, 0x01, 0x0d,
        0xd1, 0x55, 0xe3, 0x93, 0x8b, 0x12, 0x82, 0xaa,
        0x00, 0x28, 0x7c, 0xdd };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    IPV4Hdr ip4h;

    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->src.addr_data32[0] = UTHSetIPv4Address("4.3.2.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");

    ip4h.s_ip_src.s_addr = p->src.addr_data32[0];
    ip4h.s_ip_dst.s_addr = p->dst.addr_data32[0];
    UTHSetIPV4Hdr(p, &ip4h);

    DecodeICMPV4(&tv, &dtv, p, raw_icmpv4, sizeof(raw_icmpv4));
    FAIL_IF_NOT(PacketIsICMPv4(p));

    const ICMPV4Hdr *icmpv4h = PacketGetICMPv4(p);
    FAIL_IF_NULL(icmpv4h);

    /* check it's type 11 code 0 */
    FAIL_IF_NOT(icmpv4h->type == 11);
    FAIL_IF_NOT(icmpv4h->code == 0);

    /* check it's source port 35602 to port 33450 */
    FAIL_IF(p->l4.vars.icmpv4.emb_sport != 35602);
    FAIL_IF(p->l4.vars.icmpv4.emb_dport != 33450);

    /* check the src,dst IPs contained inside */
    uint32_t src_ip = IPV4_GET_RAW_IPSRC_U32(PacketGetICMPv4EmbIPv4(p));
    uint32_t dst_ip = IPV4_GET_RAW_IPDST_U32(PacketGetICMPv4EmbIPv4(p));
    char s[16], d[16];
    PrintInet(AF_INET, &src_ip, s, sizeof(s));
    PrintInet(AF_INET, &dst_ip, d, sizeof(d));

    /* ICMPv4 embedding IPV4 192.168.1.13->209.85.227.147 pass */
    FAIL_IF_NOT(strcmp(s, "192.168.1.13") == 0);
    FAIL_IF_NOT(strcmp(d, "209.85.227.147") == 0);

    FlowShutdown();
    PacketFree(p);
    PASS;
}

/** DecodeICMPV4test04
 *  \brief dest. unreachable, administratively prohibited
 *  \retval 1 Expected test value
 */
static int DecodeICMPV4test04(void)
{
    uint8_t raw_icmpv4[] = {
        0x03, 0x0a, 0x36, 0xc3, 0x00, 0x00, 0x00, 0x00,
        0x45, 0x00, 0x00, 0x3c, 0x62, 0xee, 0x40, 0x00,
        0x33, 0x06, 0xb4, 0x8f, 0xc0, 0xa8, 0x01, 0x0d,
        0x58, 0x60, 0x16, 0x29, 0xb1, 0x0a, 0x00, 0x32,
        0x3e, 0x36, 0x38, 0x7c, 0x00, 0x00, 0x00, 0x00,
        0xa0, 0x02, 0x16, 0xd0, 0x72, 0x04, 0x00, 0x00,
        0x02, 0x04, 0x05, 0x8a, 0x04, 0x02, 0x08, 0x0a };
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;
    int ret = 0;
    IPV4Hdr ip4h;

    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->src.addr_data32[0] = UTHSetIPv4Address("4.3.2.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");

    ip4h.s_ip_src.s_addr = p->src.addr_data32[0];
    ip4h.s_ip_dst.s_addr = p->dst.addr_data32[0];
    UTHSetIPV4Hdr(p, &ip4h);

    DecodeICMPV4(&tv, &dtv, p, raw_icmpv4, sizeof(raw_icmpv4));
    FAIL_IF_NOT(PacketIsICMPv4(p));

    const ICMPV4Hdr *icmpv4h = PacketGetICMPv4(p);
    FAIL_IF_NULL(icmpv4h);

    /* check the type,code pair is correct - type 3, code 10 */
    FAIL_IF_NOT(icmpv4h->type == 3);
    FAIL_IF_NOT(icmpv4h->code == 10);

    /* check it's src port 45322 to dst port 50 */
    if (p->l4.vars.icmpv4.emb_sport != 45322 || p->l4.vars.icmpv4.emb_dport != 50) {
        goto end;
    }

    // check the src,dst IPs contained inside
    uint32_t src_ip = IPV4_GET_RAW_IPSRC_U32(PacketGetICMPv4EmbIPv4(p));
    uint32_t dst_ip = IPV4_GET_RAW_IPDST_U32(PacketGetICMPv4EmbIPv4(p));
    char s[16], d[16];
    PrintInet(AF_INET, &src_ip, s, sizeof(s));
    PrintInet(AF_INET, &dst_ip, d, sizeof(d));

    // ICMPv4 embedding IPV4 192.168.1.13->88.96.22.41
    if (strcmp(s, "192.168.1.13") == 0 && strcmp(d, "88.96.22.41") == 0) {
        ret = 1;
    }

end:
    FlowShutdown();
    PacketFree(p);
    return ret;
}

/** DecodeICMPV4test05
 *  \brief dest. unreachable, administratively prohibited
 *  \retval 1 Expected test value
 */
static int DecodeICMPV4test05(void)
{
    uint8_t raw_icmpv4[] = {
	0x0b, 0x00, 0x5c, 0x46, 0x00, 0x00, 0x00, 0x00, 0x45,
	0x00, 0x00, 0x30, 0x02, 0x17, 0x40, 0x00, 0x01, 0x06,
	0xd6, 0xbd, 0xc0, 0xa8, 0x02, 0x05, 0x3d, 0x23, 0xa1,
	0x23, 0x04, 0x18, 0x00, 0x50, 0xd2, 0x08, 0xc2, 0x48,
         };
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;
    int ret = 0;
    IPV4Hdr ip4h;

    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->src.addr_data32[0] = UTHSetIPv4Address("4.3.2.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");

    ip4h.s_ip_src.s_addr = p->src.addr_data32[0];
    ip4h.s_ip_dst.s_addr = p->dst.addr_data32[0];
    UTHSetIPV4Hdr(p, &ip4h);

    DecodeICMPV4(&tv, &dtv, p, raw_icmpv4, sizeof(raw_icmpv4));
    FAIL_IF_NOT(PacketIsICMPv4(p));

    const ICMPV4Hdr *icmpv4h = PacketGetICMPv4(p);
    FAIL_IF_NULL(icmpv4h);

    /* check the type,code pair is correct - type 11, code 0 */
    FAIL_IF_NOT(icmpv4h->type == 11);
    FAIL_IF_NOT(icmpv4h->code == 0);

    /* check it's src port 1048 to dst port 80 */
    if (p->l4.vars.icmpv4.emb_sport != 1048 || p->l4.vars.icmpv4.emb_dport != 80) {
        goto end;
    }

    // check the src,dst IPs contained inside
    uint32_t src_ip = IPV4_GET_RAW_IPSRC_U32(PacketGetICMPv4EmbIPv4(p));
    uint32_t dst_ip = IPV4_GET_RAW_IPDST_U32(PacketGetICMPv4EmbIPv4(p));
    char s[16], d[16];
    PrintInet(AF_INET, &src_ip, s, sizeof(s));
    PrintInet(AF_INET, &dst_ip, d, sizeof(d));

    // ICMPv4 embedding IPV4 192.168.2.5->61.35.161.35
    if (strcmp(s, "192.168.2.5") == 0 && strcmp(d, "61.35.161.35") == 0) {
        ret = 1;
    }

end:
    FlowShutdown();
    PacketFree(p);
    return ret;
}

static int ICMPV4CalculateValidChecksumtest05(void)
{
    uint16_t csum = 0;

    uint8_t raw_icmpv4[] = {
        0x08, 0x00, 0xab, 0x9b, 0x7f, 0x2b, 0x05, 0x2c,
        0x3f, 0x72, 0x93, 0x4a, 0x00, 0x4d, 0x0a, 0x00,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};

    csum = *( ((uint16_t *)raw_icmpv4) + 1);
    return (csum == ICMPV4CalculateChecksum((uint16_t *)raw_icmpv4, sizeof(raw_icmpv4)));
}

static int ICMPV4CalculateInvalidChecksumtest06(void)
{
    uint16_t csum = 0;

    uint8_t raw_icmpv4[] = {
        0x08, 0x00, 0xab, 0x9b, 0x7f, 0x2b, 0x05, 0x2c,
        0x3f, 0x72, 0x93, 0x4a, 0x00, 0x4d, 0x0a, 0x00,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x38};

    csum = *( ((uint16_t *)raw_icmpv4) + 1);
    return (csum != ICMPV4CalculateChecksum((uint16_t *)raw_icmpv4, sizeof(raw_icmpv4)));
}

static int ICMPV4InvalidType07(void)
{

    uint8_t raw_icmpv4[] = {
        0xff, 0x00, 0xab, 0x9b, 0x7f, 0x2b, 0x05, 0x2c,
        0x3f, 0x72, 0x93, 0x4a, 0x00, 0x4d, 0x0a, 0x00,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x38};

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
    return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;
    int ret = 0;
    IPV4Hdr ip4h;

    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->src.addr_data32[0] = UTHSetIPv4Address("4.3.2.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");

    ip4h.s_ip_src.s_addr = p->src.addr_data32[0];
    ip4h.s_ip_dst.s_addr = p->dst.addr_data32[0];
    UTHSetIPV4Hdr(p, &ip4h);

    DecodeICMPV4(&tv, &dtv, p, raw_icmpv4, sizeof(raw_icmpv4));

    if(ENGINE_ISSET_EVENT(p,ICMPV4_UNKNOWN_TYPE)) {
        ret = 1;
    }

    FlowShutdown();
    PacketFree(p);
    return ret;
}

/** DecodeICMPV4test08
 *  \brief
 *  \retval 1 Expected test value - what we really want is not to segfault
 */
static int DecodeICMPV4test08(void)
{
    uint8_t raw_icmpv4[] = {
        0x08, 0x00, 0x78, 0x47, 0xfc, 0x55, 0x00, 0x00
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    IPV4Hdr ip4h;

    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->src.addr_data32[0] = UTHSetIPv4Address("4.3.2.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");

    ip4h.s_ip_src.s_addr = p->src.addr_data32[0];
    ip4h.s_ip_dst.s_addr = p->dst.addr_data32[0];
    UTHSetIPV4Hdr(p, &ip4h);

    DecodeICMPV4(&tv, &dtv, p, raw_icmpv4, sizeof(raw_icmpv4));
    FAIL_IF_NOT(PacketIsICMPv4(p));

    const ICMPV4Hdr *icmpv4h = PacketGetICMPv4(p);
    FAIL_IF_NULL(icmpv4h);

    FAIL_IF_NOT(icmpv4h->type == 8);
    FAIL_IF_NOT(icmpv4h->code == 0);

    FlowShutdown();
    PacketFree(p);
    PASS;
}
#endif /* UNITTESTS */

/**
 * \brief Registers ICMPV4 unit test
 */
void DecodeICMPV4RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeICMPV4test01", DecodeICMPV4test01);
    UtRegisterTest("DecodeICMPV4test02", DecodeICMPV4test02);
    UtRegisterTest("DecodeICMPV4test03", DecodeICMPV4test03);
    UtRegisterTest("DecodeICMPV4test04", DecodeICMPV4test04);
    UtRegisterTest("DecodeICMPV4test05", DecodeICMPV4test05);
    UtRegisterTest("ICMPV4CalculateValidChecksumtest05",
                   ICMPV4CalculateValidChecksumtest05);
    UtRegisterTest("ICMPV4CalculateInvalidChecksumtest06",
                   ICMPV4CalculateInvalidChecksumtest06);
    UtRegisterTest("DecodeICMPV4InvalidType", ICMPV4InvalidType07);
    UtRegisterTest("DecodeICMPV4test08", DecodeICMPV4test08);
#endif /* UNITTESTS */
}
/**
 * @}
 */
