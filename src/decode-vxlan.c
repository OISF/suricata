/* Copyright (C) 2014 Open Information Security Foundation
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
 * \author Henrik Kramshoej <hlk@kramse.org>
 *
 * VXLAN decoder.
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-vxlan.h"
#include "decode-events.h"
#include "decode-udp.h"
#include "flow.h"

#include "util-unittest.h"
#include "util-debug.h"

#include "pkt-var.h"
#include "util-profiling.h"
#include "host.h"



#define VXLAN_HEADER_LEN         4
#define VXLAN_PW_LEN             4
#define VXLAN_MAX_RESERVED_LABEL 15

#define VXLAN_LABEL_IPV4         0
#define VXLAN_LABEL_ROUTER_ALERT 1
#define VXLAN_LABEL_IPV6         2
#define VXLAN_LABEL_NULL         3

#define VXLAN_LABEL(shim)        SCNtohl(shim) >> 12
#define VXLAN_BOTTOM(shim)       ((SCNtohl(shim) >> 8) & 0x1)

/* Inner protocol guessing values. */
#define VXLAN_PROTO_ETHERNET_PW  0
#define VXLAN_PROTO_IPV4         4
#define VXLAN_PROTO_IPV6         6

static bool g_vxlan_enabled = true;

void DecodeVXLANConfig(void)
{
    int enabled = 0;
    if (ConfGetBool("decoder.vxlan.enabled", &enabled) == 1) {
        if (enabled) {
            g_vxlan_enabled = true;
        } else {
            g_vxlan_enabled = false;
        }
    }
}

static int DecodeVXLANPacket(ThreadVars *t, Packet *p, uint8_t *pkt, uint16_t len)
{
    if (unlikely(len < UDP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, UDP_HLEN_TOO_SMALL);
        return -1;
    }

    p->udph = (UDPHdr *)pkt;

    SCLogDebug("VXLAN testing length %" PRIu16 " length %" PRIu16, len, UDP_GET_LEN(p));

    SET_UDP_SRC_PORT(p,&p->sp);
    SET_UDP_DST_PORT(p,&p->dp);

    SCLogDebug("VXLAN testing src port %" PRIu16 " -> dst port: %" PRIu16 , p->sp, p->dp );

    p->payload = pkt + UDP_HEADER_LEN;
    p->payload_len = len - UDP_HEADER_LEN;

    p->proto = IPPROTO_UDP;

    return 0;
}

int DecodeVXLAN(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt,
    uint16_t len, PacketQueue *pq)
{
    if (!g_vxlan_enabled)
        return TM_ECODE_FAILED;

    uint8_t *start = pkt;

    /* Is this packet to short to contain an IPv4/IPv6 packet ? */
    if (len < IPV4_HEADER_LEN)
        return TM_ECODE_FAILED;


    int event = 0;

    StatsIncr(tv, dtv->counter_vxlan);


    SCLogDebug("letshitgo on the decode!");

    if (unlikely(DecodeVXLANPacket(tv, p,pkt,len) < 0)) {
        p->udph = NULL;
        return TM_ECODE_FAILED;
    }

        SCLogDebug("VXLAN UDP sp: %" PRIu32 " -> dp: %" PRIu32 " - HLEN: %" PRIu32 " LEN: %" PRIu32 "",
            UDP_GET_SRC_PORT(p), UDP_GET_DST_PORT(p), UDP_HEADER_LEN, p->payload_len);

    /* VXLAN encapsulate Layer 2 in UDP, most likely IPv4 and IPv6  */


    /* Best guess at inner packet. */
/*    switch (pkt[0] >> 4) {
    case VXLAN_PROTO_IPV4:
        DecodeIPV4(tv, dtv, p, pkt, len, pq);
        break;
    case VXLAN_PROTO_IPV6:
        DecodeIPV6(tv, dtv, p, pkt, len, pq);
        break;
    case VXLAN_PROTO_ETHERNET_PW:
        DecodeEthernet(tv, dtv, p, pkt + VXLAN_PW_LEN, len - VXLAN_PW_LEN,
            pq);
        break;
    default:
        ENGINE_SET_INVALID_EVENT(p, VXLAN_UNKNOWN_PAYLOAD_TYPE);
        return TM_ECODE_OK;
    }
*/

end:
    if (event) {
        ENGINE_SET_EVENT(p, event);
    }
    return TM_ECODE_OK;
}

#ifdef UNITTESTS

/**
 * \test DecodeVXLANTest01 test a good vxlan header.
 * Contains a DNS request packet
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int DecodeVXLANtest01 (void)
{
    uint8_t raw_vxlan[] = {
      /* Frame (92 bytes) including ethernet frame  */
/*      0xac, 0x4b, 0xc8, 0x84, 0x77, 0xc3, /* destination MAC */
/*      0xa4, 0x1f, 0x72, 0x08, 0x3b, 0x4f, /* source MAC */
/*      0x08, 0x00, /* IPv4 0x0800 */
/*      0x45, 0x00, 0x00, 0x4e, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,*/
/*      0xdf, 0x30, 0x6d, 0x69, 0x60, 0x4e, 0x6d, 0x69, 0x60, 0x4d, /* IPv4 hdr */
      0x12, 0xb5, 0x12, 0xb5, 0x00, 0x3a, 0x87, 0x51, /* UDP header */
      0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x00, /* VXLAN header */
      0x10, 0x00, 0x00, 0x0c, 0x01, 0x00, /* inner destination MAC */
      0x00, 0x51, 0x52, 0xb3, 0x54, 0xe5, /* inner source MAC */
      0x08, 0x00, /* wot another IPv4 0x0800 */
      0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
      0x44, 0x45, 0x0a, 0x60, 0x00, 0x0a, 0xb9, 0x1b, 0x73, 0x06,  /* IPv4 hdr */
      0x00, 0x35, 0x30, 0x39, 0x00, 0x08, 0x98, 0xe4 /* UDP probe src port 53 */
      };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    SCLogDebug("VXLAN testing packet length %" PRIu64, sizeof(raw_vxlan));
    FlowInitConfig(FLOW_QUIET);
    DecodeVXLAN(&tv, &dtv, p, raw_vxlan, sizeof(raw_vxlan), NULL);

    FAIL_IF(p->icmpv6h == NULL);

    /* ICMPv6 not processed at all? */
    FAIL_IF(ICMPV6_GET_TYPE(p) != 4 || ICMPV6_GET_CODE(p) != 0 ||
        ICMPV6_GET_EMB_PROTO(p) != IPPROTO_ICMPV6);

    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    PASS;
}
#endif /* UNITTESTS */

void DecodeVXLANRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeVXLANtest01",
                   DecodeVXLANtest01);
#endif /* UNITTESTS */
}
