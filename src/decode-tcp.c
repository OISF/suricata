/* Copyright (C) 2007-2010 Victor Julien <victor@inliniac.net>
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
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Decode TCP
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-tcp.h"
#include "decode-events.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "flow.h"

static int DecodeTCPOptions(ThreadVars *tv, Packet *p, uint8_t *pkt, uint16_t len)
{
    uint16_t plen = len;
    while (plen)
    {
        /* single byte options */
        if (*pkt == TCP_OPT_EOL) {
            break;
        } else if (*pkt == TCP_OPT_NOP) {
            pkt++;
            plen--;

        /* multibyte options */
        } else {
            if (plen < 2) {
                break;
            }

            /* we already know that the total options len is valid,
             * so here the len of the specific option must be bad.
             * Also check for invalid lengths 0 and 1. */
            if (*(pkt+1) > plen || *(pkt+1) < 2) {
                DECODER_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                return -1;
            }

            p->TCP_OPTS[p->TCP_OPTS_CNT].type = *pkt;
            p->TCP_OPTS[p->TCP_OPTS_CNT].len  = *(pkt+1);
            if (plen > 2)
                p->TCP_OPTS[p->TCP_OPTS_CNT].data = (pkt+2);
            else
                p->TCP_OPTS[p->TCP_OPTS_CNT].data = NULL;

            /* we are parsing the most commonly used opts to prevent
             * us from having to walk the opts list for these all the
             * time. */
            switch (p->TCP_OPTS[p->TCP_OPTS_CNT].type) {
                case TCP_OPT_WS:
                    if (p->TCP_OPTS[p->TCP_OPTS_CNT].len != TCP_OPT_WS_LEN) {
                        DECODER_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.ws != NULL) {
                            DECODER_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            p->tcpvars.ws = &p->TCP_OPTS[p->TCP_OPTS_CNT];
                        }
                    }
                    break;
                case TCP_OPT_MSS:
                    if (p->TCP_OPTS[p->TCP_OPTS_CNT].len != TCP_OPT_MSS_LEN) {
                        DECODER_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.mss != NULL) {
                            DECODER_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            p->tcpvars.mss = &p->TCP_OPTS[p->TCP_OPTS_CNT];
                        }
                    }
                    break;
                case TCP_OPT_SACKOK:
                    if (p->TCP_OPTS[p->TCP_OPTS_CNT].len != TCP_OPT_SACKOK_LEN) {
                        DECODER_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.sackok != NULL) {
                            DECODER_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            p->tcpvars.sackok = &p->TCP_OPTS[p->TCP_OPTS_CNT];
                        }
                    }
                    break;
                case TCP_OPT_TS:
                    if (p->TCP_OPTS[p->TCP_OPTS_CNT].len != TCP_OPT_TS_LEN) {
                        DECODER_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.ts != NULL) {
                            DECODER_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            p->tcpvars.ts = &p->TCP_OPTS[p->TCP_OPTS_CNT];
                        }
                    }
                    break;
            }

            pkt += p->TCP_OPTS[p->TCP_OPTS_CNT].len;
            plen -= (p->TCP_OPTS[p->TCP_OPTS_CNT].len);
            p->TCP_OPTS_CNT++;
        }
    }
    return 0;
}

static int DecodeTCPPacket(ThreadVars *tv, Packet *p, uint8_t *pkt, uint16_t len)
{
    if (len < TCP_HEADER_LEN) {
        DECODER_SET_EVENT(p, TCP_PKT_TOO_SMALL);
        return -1;
    }

    p->tcph = (TCPHdr *)pkt;

    p->tcpvars.hlen = TCP_GET_HLEN(p);
    if (len < p->tcpvars.hlen) {
        DECODER_SET_EVENT(p, TCP_HLEN_TOO_SMALL);
        return -1;
    }

    SET_TCP_SRC_PORT(p,&p->sp);
    SET_TCP_DST_PORT(p,&p->dp);

    p->tcpvars.tcp_opt_len = p->tcpvars.hlen - TCP_HEADER_LEN;
    if (p->tcpvars.tcp_opt_len > TCP_OPTLENMAX) {
        DECODER_SET_EVENT(p, TCP_INVALID_OPTLEN);
        return -1;
    }

    if (p->tcpvars.tcp_opt_len > 0) {
        DecodeTCPOptions(tv, p, pkt + TCP_HEADER_LEN, p->tcpvars.tcp_opt_len);
    }

    p->payload = pkt + p->tcpvars.hlen;
    p->payload_len = len - p->tcpvars.hlen;

    p->proto = IPPROTO_TCP;

    return 0;
}

void DecodeTCP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    SCPerfCounterIncr(dtv->counter_tcp, tv->sc_perf_pca);

    if (DecodeTCPPacket(tv, p,pkt,len) < 0) {
        p->tcph = NULL;
        return;
    }

#ifdef DEBUG
    SCLogDebug("TCP sp: %" PRIu32 " -> dp: %" PRIu32 " - HLEN: %" PRIu32 " LEN: %" PRIu32 " %s%s%s%s",
        GET_TCP_SRC_PORT(p), GET_TCP_DST_PORT(p), p->tcpvars.hlen, len,
        p->tcpvars.sackok ? "SACKOK " : "",
        p->tcpvars.ws ? "WS " : "",
        p->tcpvars.ts ? "TS " : "",
        p->tcpvars.mss ? "MSS " : "");
#endif

    /* Flow is an integral part of us */
    FlowHandlePacket(tv, p);

    return;
}

#ifdef UNITTESTS
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

    return (csum == TCPCalculateChecksum((uint16_t *) raw_ipshdr,
                                         (uint16_t *)raw_tcp, sizeof(raw_tcp)));
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

    return (csum == TCPCalculateChecksum((uint16_t *) raw_ipshdr,
                                         (uint16_t *)raw_tcp, sizeof(raw_tcp)));
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

    return (csum == TCPV6CalculateChecksum((uint16_t *)(raw_ipv6 + 14 + 8),
                                           (uint16_t *)(raw_ipv6 + 54), 32));
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

    return (csum == TCPV6CalculateChecksum((uint16_t *)(raw_ipv6 + 14 + 8),
                                           (uint16_t *)(raw_ipv6 + 54), 32));
}

/** \test Get the wscale of 2 */
static int TCPGetWscaleTest01(void)
{
    int retval = 0;
    static uint8_t raw_tcp[] = {0xda, 0xc1, 0x00, 0x50, 0xb6, 0x21, 0x7f, 0x58,
                                0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x16, 0xd0,
                                0x8a, 0xaf, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
                                0x04, 0x02, 0x08, 0x0a, 0x00, 0x62, 0x88, 0x28,
                                0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x02};
    Packet p;
    IPV4Hdr ip4h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.ip4h = &ip4h;


    FlowInitConfig(FLOW_QUIET);
    DecodeTCP(&tv, &dtv, &p, raw_tcp, sizeof(raw_tcp), NULL);
    FlowShutdown();

    if (p.tcph == NULL) {
        printf("tcp packet decode failed: ");
        goto end;
    }

    uint8_t wscale = TCP_GET_WSCALE(&p);
    if (wscale != 2) {
        printf("wscale %"PRIu8", expected 2: ", wscale);
        goto end;
    }

    retval = 1;
end:
    return retval;
}

/** \test Get the wscale of 15, so see if return 0 properly */
static int TCPGetWscaleTest02(void)
{
    int retval = 0;
    static uint8_t raw_tcp[] = {0xda, 0xc1, 0x00, 0x50, 0xb6, 0x21, 0x7f, 0x58,
                                0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x16, 0xd0,
                                0x8a, 0xaf, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
                                0x04, 0x02, 0x08, 0x0a, 0x00, 0x62, 0x88, 0x28,
                                0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x0f};
    Packet p;
    IPV4Hdr ip4h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.ip4h = &ip4h;

    FlowInitConfig(FLOW_QUIET);
    DecodeTCP(&tv, &dtv, &p, raw_tcp, sizeof(raw_tcp), NULL);
    FlowShutdown();

    if (p.tcph == NULL) {
        printf("tcp packet decode failed: ");
        goto end;
    }

    uint8_t wscale = TCP_GET_WSCALE(&p);
    if (wscale != 0) {
        printf("wscale %"PRIu8", expected 0: ", wscale);
        goto end;
    }

    retval = 1;
end:
    return retval;
}

/** \test Get the wscale, but it's missing, so see if return 0 properly */
static int TCPGetWscaleTest03(void)
{
    int retval = 0;
    static uint8_t raw_tcp[] = {0xda, 0xc1, 0x00, 0x50, 0xb6, 0x21, 0x7f, 0x59,
                                0xdd, 0xa3, 0x6f, 0xf8, 0x80, 0x10, 0x05, 0xb4,
                                0x7c, 0x70, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
                                0x00, 0x62, 0x88, 0x9e, 0x00, 0x00, 0x00, 0x00};
    Packet p;
    IPV4Hdr ip4h;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.ip4h = &ip4h;

    FlowInitConfig(FLOW_QUIET);
    DecodeTCP(&tv, &dtv, &p, raw_tcp, sizeof(raw_tcp), NULL);
    FlowShutdown();

    if (p.tcph == NULL) {
        printf("tcp packet decode failed: ");
        goto end;
    }

    uint8_t wscale = TCP_GET_WSCALE(&p);
    if (wscale != 0) {
        printf("wscale %"PRIu8", expected 0: ", wscale);
        goto end;
    }

    retval = 1;
end:
    return retval;
}
#endif /* UNITTESTS */

void DecodeTCPRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("TCPCalculateValidChecksumtest01",
                   TCPCalculateValidChecksumtest01, 1);
    UtRegisterTest("TCPCalculateInvalidChecksumtest02",
                   TCPCalculateInvalidChecksumtest02, 0);
    UtRegisterTest("TCPV6CalculateValidChecksumtest03",
                   TCPV6CalculateValidChecksumtest03, 1);
    UtRegisterTest("TCPV6CalculateInvalidChecksumtest04",
                   TCPV6CalculateInvalidChecksumtest04, 0);
    UtRegisterTest("TCPGetWscaleTest01", TCPGetWscaleTest01, 1);
    UtRegisterTest("TCPGetWscaleTest02", TCPGetWscaleTest02, 1);
    UtRegisterTest("TCPGetWscaleTest03", TCPGetWscaleTest03, 1);
#endif /* UNITTESTS */
}
