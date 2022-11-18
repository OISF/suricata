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
 * Decode UDP
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-geneve.h"
#include "decode-udp.h"
#include "decode-teredo.h"
#include "decode-vxlan.h"
#include "decode-events.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "flow.h"
#include "app-layer.h"

static int DecodeUDPPacket(ThreadVars *t, Packet *p, const uint8_t *pkt, uint16_t len)
{
    if (unlikely(len < UDP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, UDP_HLEN_TOO_SMALL);
        return -1;
    }

    p->udph = (UDPHdr *)pkt;

    if (unlikely(len < UDP_GET_LEN(p))) {
        ENGINE_SET_INVALID_EVENT(p, UDP_PKT_TOO_SMALL);
        return -1;
    }

    if (unlikely(len != UDP_GET_LEN(p) &&
                 // avoid flagging IP padded packets to the minimal Ethernet unit as invalid HLEN
                 (p->ethh != NULL && p->pktlen > ETHERNET_PKT_MIN_LEN))) {
        ENGINE_SET_INVALID_EVENT(p, UDP_HLEN_INVALID);
        return -1;
    }

    SET_UDP_SRC_PORT(p,&p->sp);
    SET_UDP_DST_PORT(p,&p->dp);

    p->payload = (uint8_t *)pkt + UDP_HEADER_LEN;
    p->payload_len = len - UDP_HEADER_LEN;

    p->proto = IPPROTO_UDP;

    return 0;
}

int DecodeUDP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint16_t len)
{
    StatsIncr(tv, dtv->counter_udp);

    if (unlikely(DecodeUDPPacket(tv, p, pkt,len) < 0)) {
        CLEAR_UDP_PACKET(p);
        return TM_ECODE_FAILED;
    }

    SCLogDebug("UDP sp: %" PRIu32 " -> dp: %" PRIu32 " - HLEN: %" PRIu32 " LEN: %" PRIu32 "",
        UDP_GET_SRC_PORT(p), UDP_GET_DST_PORT(p), UDP_HEADER_LEN, p->payload_len);

    if (DecodeTeredoEnabledForPort(p->sp, p->dp) &&
            likely(DecodeTeredo(tv, dtv, p, p->payload, p->payload_len) == TM_ECODE_OK)) {
        /* Here we have a Teredo packet and don't need to handle app
         * layer */
        FlowSetupPacket(p);
        return TM_ECODE_OK;
    }

    /* Handle Geneve if configured */
    if (DecodeGeneveEnabledForPort(p->sp, p->dp) &&
            unlikely(DecodeGeneve(tv, dtv, p, p->payload, p->payload_len) == TM_ECODE_OK)) {
        /* Here we have a Geneve packet and don't need to handle app
         * layer */
        FlowSetupPacket(p);
        return TM_ECODE_OK;
    }

    /* Handle VXLAN if configured */
    if (DecodeVXLANEnabledForPort(p->sp, p->dp) &&
            unlikely(DecodeVXLAN(tv, dtv, p, p->payload, p->payload_len) == TM_ECODE_OK)) {
        /* Here we have a VXLAN packet and don't need to handle app
         * layer */
        FlowSetupPacket(p);
        return TM_ECODE_OK;
    }

    FlowSetupPacket(p);

    return TM_ECODE_OK;
}

#ifdef UNITTESTS
static int UDPV4CalculateValidChecksumtest01(void)
{
    uint16_t csum = 0;

    uint8_t raw_ipshdr[] = {
        0xd0, 0x43, 0xdc, 0xdc, 0xc0, 0xa8, 0x01, 0x3};

    uint8_t raw_udp[] = {
        0x00, 0x35, 0xcf, 0x34, 0x00, 0x55, 0x6c, 0xe0,
        0x83, 0xfc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x70, 0x61, 0x67,
        0x65, 0x61, 0x64, 0x32, 0x11, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x73, 0x79, 0x6e, 0x64, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x4b,
        0x50, 0x00, 0x12, 0x06, 0x70, 0x61, 0x67, 0x65,
        0x61, 0x64, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0xc0, 0x26};

    csum = *( ((uint16_t *)raw_udp) + 3);

    FAIL_IF(UDPV4Checksum((uint16_t *) raw_ipshdr,
            (uint16_t *)raw_udp, sizeof(raw_udp), csum) != 0);
    PASS;
}

static int UDPV4CalculateInvalidChecksumtest02(void)
{
    uint16_t csum = 0;

    uint8_t raw_ipshdr[] = {
        0xd0, 0x43, 0xdc, 0xdc, 0xc0, 0xa8, 0x01, 0x3};

    uint8_t raw_udp[] = {
        0x00, 0x35, 0xcf, 0x34, 0x00, 0x55, 0x6c, 0xe0,
        0x83, 0xfc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x70, 0x61, 0x67,
        0x65, 0x61, 0x64, 0x32, 0x11, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x73, 0x79, 0x6e, 0x64, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x4b,
        0x50, 0x00, 0x12, 0x06, 0x70, 0x61, 0x67, 0x65,
        0x61, 0x64, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0xc0, 0x27};

    csum = *( ((uint16_t *)raw_udp) + 3);

    FAIL_IF(UDPV4Checksum((uint16_t *) raw_ipshdr,
            (uint16_t *)raw_udp, sizeof(raw_udp), csum) == 0);
    PASS;
}

static int UDPV6CalculateValidChecksumtest03(void)
{
    uint16_t csum = 0;

    static uint8_t raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x02, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0xa0, 0x00, 0x14, 0x1a, 0xc3, 0x06, 0x02,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0x57, 0xb0,
        0x09, 0x00};

    csum = *( ((uint16_t *)(raw_ipv6 + 60)));

    FAIL_IF(UDPV6Checksum((uint16_t *)(raw_ipv6 + 14 + 8),
            (uint16_t *)(raw_ipv6 + 54), 20, csum) != 0);
    PASS;
}

static int UDPV6CalculateInvalidChecksumtest04(void)
{
    uint16_t csum = 0;

    static uint8_t raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x02, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0xa0, 0x00, 0x14, 0x1a, 0xc3, 0x06, 0x02,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0x57, 0xb0,
        0x09, 0x01};

    csum = *( ((uint16_t *)(raw_ipv6 + 60)));

    FAIL_IF(UDPV6Checksum((uint16_t *)(raw_ipv6 + 14 + 8),
            (uint16_t *)(raw_ipv6 + 54), 20, csum) == 0);
    PASS;
}
#endif /* UNITTESTS */

void DecodeUDPV4RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("UDPV4CalculateValidChecksumtest01",
                   UDPV4CalculateValidChecksumtest01);
    UtRegisterTest("UDPV4CalculateInvalidChecksumtest02",
                   UDPV4CalculateInvalidChecksumtest02);
    UtRegisterTest("UDPV6CalculateValidChecksumtest03",
                   UDPV6CalculateValidChecksumtest03);
    UtRegisterTest("UDPV6CalculateInvalidChecksumtest04",
                   UDPV6CalculateInvalidChecksumtest04);
#endif /* UNITTESTS */
}
/**
 * @}
 */
