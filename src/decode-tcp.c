/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * Decode TCP
 */

#include "suricata-common.h"
#include "decode-tcp.h"
#include "decode.h"
#include "decode-events.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-optimize.h"
#include "flow.h"

static void DecodeTCPOptions(Packet *p, const uint8_t *pkt, uint16_t pktlen)
{
    uint8_t tcp_opt_cnt = 0;
    TCPOpt tcp_opts[TCP_OPTMAX];

    const TCPHdr *tcph = PacketGetTCP(p);
    uint16_t plen = pktlen;
    while (plen)
    {
        const uint8_t type = *pkt;

        /* single byte options */
        if (type == TCP_OPT_EOL) {
            break;
        } else if (type == TCP_OPT_NOP) {
            pkt++;
            plen--;

        /* multibyte options */
        } else {
            if (plen < 2) {
                break;
            }

            const uint8_t olen = *(pkt+1);

            /* we already know that the total options len is valid,
             * so here the len of the specific option must be bad.
             * Also check for invalid lengths 0 and 1. */
            if (unlikely(olen > plen || olen < 2)) {
                ENGINE_SET_INVALID_EVENT(p, TCP_OPT_INVALID_LEN);
                return;
            }

            tcp_opts[tcp_opt_cnt].type = type;
            tcp_opts[tcp_opt_cnt].len  = olen;
            tcp_opts[tcp_opt_cnt].data = (olen > 2) ? (pkt+2) : NULL;

            /* we are parsing the most commonly used opts to prevent
             * us from having to walk the opts list for these all the
             * time. */
            switch (type) {
                case TCP_OPT_WS:
                    if (olen != TCP_OPT_WS_LEN) {
                        ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->l4.vars.tcp.wscale_set != 0) {
                            ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            p->l4.vars.tcp.wscale_set = 1;
                            const uint8_t wscale = *(tcp_opts[tcp_opt_cnt].data);
                            if (wscale <= TCP_WSCALE_MAX) {
                                p->l4.vars.tcp.wscale = wscale;
                            } else {
                                p->l4.vars.tcp.wscale = 0;
                            }
                        }
                    }
                    break;
                case TCP_OPT_MSS:
                    if (olen != TCP_OPT_MSS_LEN) {
                        ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->l4.vars.tcp.mss_set) {
                            ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            p->l4.vars.tcp.mss_set = true;
                            p->l4.vars.tcp.mss = SCNtohs(*(uint16_t *)(tcp_opts[tcp_opt_cnt].data));
                        }
                    }
                    break;
                case TCP_OPT_SACKOK:
                    if (olen != TCP_OPT_SACKOK_LEN) {
                        ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (TCP_GET_SACKOK(p)) {
                            ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            p->l4.vars.tcp.sack_ok = true;
                        }
                    }
                    break;
                case TCP_OPT_TS:
                    if (olen != TCP_OPT_TS_LEN) {
                        ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->l4.vars.tcp.ts_set) {
                            ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            uint32_t values[2];
                            memcpy(&values, tcp_opts[tcp_opt_cnt].data, sizeof(values));
                            p->l4.vars.tcp.ts_val = SCNtohl(values[0]);
                            p->l4.vars.tcp.ts_ecr = SCNtohl(values[1]);
                            p->l4.vars.tcp.ts_set = true;
                        }
                    }
                    break;
                case TCP_OPT_SACK:
                    SCLogDebug("SACK option, len %u", olen);
                    if (olen == 2) {
                        /* useless, but common empty SACK record */
                    } else if (olen < TCP_OPT_SACK_MIN_LEN || olen > TCP_OPT_SACK_MAX_LEN ||
                               !((olen - 2) % 8 == 0)) {
                        ENGINE_SET_EVENT(p, TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->l4.vars.tcp.sack_set) {
                            ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            ptrdiff_t diff = tcp_opts[tcp_opt_cnt].data - (uint8_t *)tcph;
                            DEBUG_VALIDATE_BUG_ON(diff > UINT16_MAX);
                            p->l4.vars.tcp.sack_set = true;
                            p->l4.vars.tcp.sack_cnt = (olen - 2) / 8;
                            p->l4.vars.tcp.sack_offset = (uint16_t)diff;
                        }
                    }
                    break;
                case TCP_OPT_TFO:
                    SCLogDebug("TFO option, len %u", olen);
                    if ((olen != 2) && (olen < TCP_OPT_TFO_MIN_LEN || olen > TCP_OPT_TFO_MAX_LEN ||
                                               !(((olen - 2) & 0x1) == 0))) {
                        ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->l4.vars.tcp.tfo_set) {
                            ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            p->l4.vars.tcp.tfo_set = true;
                        }
                    }
                    break;
                /* experimental options, could be TFO */
                case TCP_OPT_EXP1:
                case TCP_OPT_EXP2:
                    SCLogDebug("TCP EXP option, len %u", olen);
                    if (olen == 4 || olen == 12) {
                        uint16_t magic = SCNtohs(*(uint16_t *)tcp_opts[tcp_opt_cnt].data);
                        if (magic == 0xf989) {
                            if (p->l4.vars.tcp.tfo_set) {
                                ENGINE_SET_EVENT(p,TCP_OPT_DUPLICATE);
                            } else {
                                p->l4.vars.tcp.tfo_set = true;
                            }
                        }
                    } else {
                        ENGINE_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    }
                    break;
                /* RFC 2385 MD5 option */
                case TCP_OPT_MD5:
                    SCLogDebug("MD5 option, len %u", olen);
                    if (olen != 18) {
                        ENGINE_SET_INVALID_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        /* we can't validate the option as the key is out of band */
                        p->l4.vars.tcp.md5_option_present = true;
                    }
                    break;
                /* RFC 5925 AO option */
                case TCP_OPT_AO:
                    SCLogDebug("AU option, len %u", olen);
                    if (olen < 4) {
                        ENGINE_SET_INVALID_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        /* we can't validate the option as the key is out of band */
                        p->l4.vars.tcp.ao_option_present = true;
                    }
                    break;
            }

            pkt += olen;
            plen -= olen;
            tcp_opt_cnt++;
        }
    }
}

static int DecodeTCPPacket(
        ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint16_t len)
{
    if (unlikely(len < TCP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, TCP_PKT_TOO_SMALL);
        return -1;
    }

    TCPHdr *tcph = PacketSetTCP(p, pkt);

    uint8_t hlen = TCP_GET_RAW_HLEN(tcph);
    if (unlikely(len < hlen)) {
        ENGINE_SET_INVALID_EVENT(p, TCP_HLEN_TOO_SMALL);
        return -1;
    }

    uint8_t tcp_opt_len = hlen - TCP_HEADER_LEN;
    if (unlikely(tcp_opt_len > TCP_OPTLENMAX)) {
        ENGINE_SET_INVALID_EVENT(p, TCP_INVALID_OPTLEN);
        return -1;
    }

    if (likely(tcp_opt_len > 0)) {
        DecodeTCPOptions(p, pkt + TCP_HEADER_LEN, tcp_opt_len);
    }

    p->sp = TCP_GET_RAW_SRC_PORT(tcph);
    p->dp = TCP_GET_RAW_DST_PORT(tcph);

    p->proto = IPPROTO_TCP;

    p->payload = (uint8_t *)pkt + hlen;
    p->payload_len = len - hlen;

    /* update counters */
    if ((tcph->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
        StatsIncr(tv, dtv->counter_tcp_synack);
    } else if (tcph->th_flags & (TH_SYN)) {
        StatsIncr(tv, dtv->counter_tcp_syn);
    }
    if (tcph->th_flags & (TH_RST)) {
        StatsIncr(tv, dtv->counter_tcp_rst);
    }
    if (tcph->th_flags & (TH_URG)) {
        StatsIncr(tv, dtv->counter_tcp_urg);
    }

#ifdef DEBUG
    SCLogDebug("TCP sp: %u -> dp: %u - HLEN: %" PRIu32 " LEN: %" PRIu32 " %s%s%s%s%s%s", p->sp,
            p->dp, TCP_GET_RAW_HLEN(tcph), len, TCP_GET_SACKOK(p) ? "SACKOK " : "",
            TCP_HAS_SACK(p) ? "SACK " : "", TCP_HAS_WSCALE(p) ? "WS " : "",
            TCP_HAS_TS(p) ? "TS " : "", TCP_HAS_MSS(p) ? "MSS " : "", TCP_HAS_TFO(p) ? "TFO " : "");
#endif
    return 0;
}

int DecodeTCP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint16_t len)
{
    StatsIncr(tv, dtv->counter_tcp);

    if (unlikely(DecodeTCPPacket(tv, dtv, p, pkt, len) < 0)) {
        SCLogDebug("invalid TCP packet");
        PacketClearL4(p);
        return TM_ECODE_FAILED;
    }

    FlowSetupPacket(p);

    return TM_ECODE_OK;
}

#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "packet.h"

static int TCPCalculateValidChecksumtest01(void)
{
    uint16_t csum = 0;

    uint8_t raw_ipshdr[] = {
        0x40, 0x8e, 0x7e, 0xb2, 0xc0, 0xa8, 0x01, 0x03};

    uint8_t raw_tcp[] = {
        0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
        0xcf, 0x0d, 0x21, 0x80, 0xa0, 0x12, 0x16, 0xa0,
        0xfa, 0x03, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
        0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 02};

    csum = *( ((uint16_t *)raw_tcp) + 8);

    FAIL_IF(TCPChecksum((uint16_t *)raw_ipshdr,
            (uint16_t *)raw_tcp, sizeof(raw_tcp), csum) != 0);
    PASS;
}

static int TCPCalculateInvalidChecksumtest02(void)
{
    uint16_t csum = 0;

    uint8_t raw_ipshdr[] = {
        0x40, 0x8e, 0x7e, 0xb2, 0xc0, 0xa8, 0x01, 0x03};

    uint8_t raw_tcp[] = {
        0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
        0xcf, 0x0d, 0x21, 0x80, 0xa0, 0x12, 0x16, 0xa0,
        0xfa, 0x03, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
        0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 03};

    csum = *( ((uint16_t *)raw_tcp) + 8);

    FAIL_IF(TCPChecksum((uint16_t *) raw_ipshdr,
            (uint16_t *)raw_tcp, sizeof(raw_tcp), csum) == 0);
    PASS;
}

static int TCPV6CalculateValidChecksumtest03(void)
{
    uint16_t csum = 0;

    static uint8_t raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x20, 0x06, 0x40, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0x03, 0xfe,
        0x00, 0x16, 0xd6, 0x76, 0xf5, 0x2d, 0x0c, 0x7a,
        0x08, 0x77, 0x80, 0x10, 0x21, 0x5c, 0xc2, 0xf1,
        0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x00, 0x08,
        0xca, 0x5a, 0x00, 0x01, 0x69, 0x27};

    csum = *( ((uint16_t *)(raw_ipv6 + 70)));

    FAIL_IF(TCPV6Checksum((uint16_t *)(raw_ipv6 + 14 + 8),
            (uint16_t *)(raw_ipv6 + 54), 32, csum) != 0);
    PASS;
}

static int TCPV6CalculateInvalidChecksumtest04(void)
{
    uint16_t csum = 0;

    static uint8_t raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x20, 0x06, 0x40, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0x03, 0xfe,
        0x00, 0x16, 0xd6, 0x76, 0xf5, 0x2d, 0x0c, 0x7a,
        0x08, 0x77, 0x80, 0x10, 0x21, 0x5c, 0xc2, 0xf1,
        0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x00, 0x08,
        0xca, 0x5a, 0x00, 0x01, 0x69, 0x28};

    csum = *( ((uint16_t *)(raw_ipv6 + 70)));

    FAIL_IF(TCPV6Checksum((uint16_t *)(raw_ipv6 + 14 + 8),
            (uint16_t *)(raw_ipv6 + 54), 32, csum) == 0);
    PASS;
}

/** \test Get the wscale of 2 */
static int TCPGetWscaleTest01(void)
{
    static uint8_t raw_tcp[] = {0xda, 0xc1, 0x00, 0x50, 0xb6, 0x21, 0x7f, 0x58,
                                0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x16, 0xd0,
                                0x8a, 0xaf, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
                                0x04, 0x02, 0x08, 0x0a, 0x00, 0x62, 0x88, 0x28,
                                0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x02};
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV4Hdr ip4h;
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    UTHSetIPV4Hdr(p, &ip4h);

    FlowInitConfig(FLOW_QUIET);
    DecodeTCP(&tv, &dtv, p, raw_tcp, sizeof(raw_tcp));
    FAIL_IF_NOT(PacketIsTCP(p));

    uint8_t wscale = TCP_GET_WSCALE(p);
    FAIL_IF(wscale != 2);

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/** \test Get the wscale of 15, so see if return 0 properly */
static int TCPGetWscaleTest02(void)
{
    static uint8_t raw_tcp[] = {0xda, 0xc1, 0x00, 0x50, 0xb6, 0x21, 0x7f, 0x58,
                                0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x16, 0xd0,
                                0x8a, 0xaf, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
                                0x04, 0x02, 0x08, 0x0a, 0x00, 0x62, 0x88, 0x28,
                                0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x0f};
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV4Hdr ip4h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    UTHSetIPV4Hdr(p, &ip4h);

    FlowInitConfig(FLOW_QUIET);
    DecodeTCP(&tv, &dtv, p, raw_tcp, sizeof(raw_tcp));
    FAIL_IF_NOT(PacketIsTCP(p));

    uint8_t wscale = TCP_GET_WSCALE(p);
    FAIL_IF(wscale != 0);

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/** \test Get the wscale, but it's missing, so see if return 0 properly */
static int TCPGetWscaleTest03(void)
{
    static uint8_t raw_tcp[] = {0xda, 0xc1, 0x00, 0x50, 0xb6, 0x21, 0x7f, 0x59,
                                0xdd, 0xa3, 0x6f, 0xf8, 0x80, 0x10, 0x05, 0xb4,
                                0x7c, 0x70, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
                                0x00, 0x62, 0x88, 0x9e, 0x00, 0x00, 0x00, 0x00};
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    IPV4Hdr ip4h;
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    UTHSetIPV4Hdr(p, &ip4h);

    FlowInitConfig(FLOW_QUIET);
    DecodeTCP(&tv, &dtv, p, raw_tcp, sizeof(raw_tcp));
    FAIL_IF_NOT(PacketIsTCP(p));

    uint8_t wscale = TCP_GET_WSCALE(p);
    FAIL_IF(wscale != 0);

    PacketFree(p);
    FlowShutdown();
    PASS;
}

static int TCPGetSackTest01(void)
{
    static uint8_t raw_tcp[] = {
        0x00, 0x50, 0x06, 0xa6, 0xfa, 0x87, 0x0b, 0xf5,
        0xf1, 0x59, 0x02, 0xe0, 0xa0, 0x10, 0x3e, 0xbc,
        0x1d, 0xe7, 0x00, 0x00, 0x01, 0x01, 0x05, 0x12,
        0xf1, 0x59, 0x13, 0xfc, 0xf1, 0x59, 0x1f, 0x64,
        0xf1, 0x59, 0x08, 0x94, 0xf1, 0x59, 0x0e, 0x48 };
    static uint8_t raw_tcp_sack[] = {
        0xf1, 0x59, 0x13, 0xfc, 0xf1, 0x59, 0x1f, 0x64,
        0xf1, 0x59, 0x08, 0x94, 0xf1, 0x59, 0x0e, 0x48 };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    IPV4Hdr ip4h;
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    UTHSetIPV4Hdr(p, &ip4h);

    FlowInitConfig(FLOW_QUIET);
    DecodeTCP(&tv, &dtv, p, raw_tcp, sizeof(raw_tcp));

    FAIL_IF_NOT(PacketIsTCP(p));

    FAIL_IF(!TCP_HAS_SACK(p));

    int sack = TCP_GET_SACK_CNT(p);
    FAIL_IF(sack != 2);

    const TCPHdr *tcph = PacketGetTCP(p);
    const uint8_t *sackptr = TCP_GET_SACK_PTR(p, tcph);
    FAIL_IF_NULL(sackptr);

    FAIL_IF(memcmp(sackptr, raw_tcp_sack, 16) != 0);

    PacketFree(p);
    FlowShutdown();
    PASS;
}
#endif /* UNITTESTS */

void DecodeTCPRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("TCPCalculateValidChecksumtest01",
                   TCPCalculateValidChecksumtest01);
    UtRegisterTest("TCPCalculateInvalidChecksumtest02",
                   TCPCalculateInvalidChecksumtest02);
    UtRegisterTest("TCPV6CalculateValidChecksumtest03",
                   TCPV6CalculateValidChecksumtest03);
    UtRegisterTest("TCPV6CalculateInvalidChecksumtest04",
                   TCPV6CalculateInvalidChecksumtest04);
    UtRegisterTest("TCPGetWscaleTest01", TCPGetWscaleTest01);
    UtRegisterTest("TCPGetWscaleTest02", TCPGetWscaleTest02);
    UtRegisterTest("TCPGetWscaleTest03", TCPGetWscaleTest03);
    UtRegisterTest("TCPGetSackTest01", TCPGetSackTest01);
#endif /* UNITTESTS */
}
/**
 * @}
 */
