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
 * \author Breno Silva <breno.silva@gmail.com>
 *
 * Decode 802.1q
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-vlan.h"
#include "decode-events.h"

#include "flow.h"

#include "util-unittest.h"
#include "util-debug.h"

/**
 * \internal
 * \brief this function is used to decode IEEE802.1q packets
 *
 * \param tv pointer to the thread vars
 * \param dtv pointer code thread vars
 * \param p pointer to the packet struct
 * \param pkt pointer to the raw packet
 * \param len packet len
 * \param pq pointer to the packet queue
 *
 */
void DecodeVLAN(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    SCPerfCounterIncr(dtv->counter_vlan, tv->sc_perf_pca);

    if(len < VLAN_HEADER_LEN)    {
        ENGINE_SET_EVENT(p,VLAN_HEADER_TOO_SMALL);
        return;
    }

    p->vlanh = (VLANHdr *)pkt;
    if(p->vlanh == NULL)
        return;

    SCLogDebug("p %p pkt %p VLAN protocol %04x VLAN PRI %d VLAN CFI %d VLAN ID %d Len: %" PRId32 "",
        p, pkt, GET_VLAN_PROTO(p->vlanh), GET_VLAN_PRIORITY(p->vlanh), GET_VLAN_CFI(p->vlanh), GET_VLAN_ID(p->vlanh), len);

    switch (GET_VLAN_PROTO(p->vlanh))   {
        case ETHERNET_TYPE_IP:
            DecodeIPV4(tv, dtv, p, pkt + VLAN_HEADER_LEN,
                       len - VLAN_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(tv, dtv, p, pkt + VLAN_HEADER_LEN,
                       len - VLAN_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_PPPOE_SESS:
            DecodePPPOESession(tv, dtv, p, pkt + VLAN_HEADER_LEN,
                               len - VLAN_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_PPPOE_DISC:
            DecodePPPOEDiscovery(tv, dtv, p, pkt + VLAN_HEADER_LEN,
                                 len - VLAN_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_VLAN:
            DecodeVLAN(tv, dtv, p, pkt + VLAN_HEADER_LEN,
                                 len - VLAN_HEADER_LEN, pq);
            break;
        default:
            SCLogDebug("unknown VLAN type: %" PRIx32 "",GET_VLAN_PROTO(p->vlanh));
            ENGINE_SET_EVENT(p,VLAN_UNKNOWN_TYPE);
            return;
    }

    return;
}

#ifdef UNITTESTS
/** \todo Must GRE+VLAN and Multi-Vlan packets to
 * create more tests
 */

/**
 * \test DecodeVLANTest01 test if vlan header is too small.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int DecodeVLANtest01 (void)   {
    uint8_t raw_vlan[] = { 0x00, 0x20, 0x08 };
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    p->pkt = (uint8_t *)(p + 1);
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeVLAN(&tv, &dtv, p, raw_vlan, sizeof(raw_vlan), NULL);

    if(ENGINE_ISSET_EVENT(p,VLAN_HEADER_TOO_SMALL))  {
        SCFree(p);
        return 1;
    }

    SCFree(p);
    return 0;
}

/**
 * \test DecodeVLANTest02 test if vlan header has unknown type.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int DecodeVLANtest02 (void)   {
    uint8_t raw_vlan[] = {
        0x00, 0x20, 0x01, 0x00, 0x45, 0x00, 0x00, 0x34,
        0x3b, 0x36, 0x40, 0x00, 0x40, 0x06, 0xb7, 0xc9,
        0x83, 0x97, 0x20, 0x81, 0x83, 0x97, 0x20, 0x15,
        0x04, 0x8a, 0x17, 0x70, 0x4e, 0x14, 0xdf, 0x55,
        0x4d, 0x3d, 0x5a, 0x61, 0x80, 0x10, 0x6b, 0x50,
        0x3c, 0x4c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
        0x00, 0x04, 0xf0, 0xc8, 0x01, 0x99, 0xa3, 0xf3};
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    p->pkt = (uint8_t *)(p + 1);
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeVLAN(&tv, &dtv, p, raw_vlan, sizeof(raw_vlan), NULL);


    if(ENGINE_ISSET_EVENT(p,VLAN_UNKNOWN_TYPE))  {
        SCFree(p);
        return 1;
    }

    SCFree(p);
    return 0;
}

/**
 * \test DecodeVLANTest02 test a good vlan header.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int DecodeVLANtest03 (void)   {
    uint8_t raw_vlan[] = {
        0x00, 0x20, 0x08, 0x00, 0x45, 0x00, 0x00, 0x34,
        0x3b, 0x36, 0x40, 0x00, 0x40, 0x06, 0xb7, 0xc9,
        0x83, 0x97, 0x20, 0x81, 0x83, 0x97, 0x20, 0x15,
        0x04, 0x8a, 0x17, 0x70, 0x4e, 0x14, 0xdf, 0x55,
        0x4d, 0x3d, 0x5a, 0x61, 0x80, 0x10, 0x6b, 0x50,
        0x3c, 0x4c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
        0x00, 0x04, 0xf0, 0xc8, 0x01, 0x99, 0xa3, 0xf3};
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    p->pkt = (uint8_t *)(p + 1);
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    DecodeVLAN(&tv, &dtv, p, raw_vlan, sizeof(raw_vlan), NULL);

    FlowShutdown();

    if(p->vlanh == NULL) {
        SCFree(p);
        return 0;
    }

    if(ENGINE_ISSET_EVENT(p,VLAN_HEADER_TOO_SMALL))  {
        SCFree(p);
        return 0;
    }

    if(ENGINE_ISSET_EVENT(p,VLAN_UNKNOWN_TYPE))  {
        SCFree(p);
        return 0;
    }

    SCFree(p);
    return 1;
}
#endif /* UNITTESTS */

void DecodeVLANRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DecodeVLANtest01", DecodeVLANtest01, 1);
    UtRegisterTest("DecodeVLANtest02", DecodeVLANtest02, 1);
    UtRegisterTest("DecodeVLANtest03", DecodeVLANtest03, 1);
#endif /* UNITTESTS */
}

/**
 * @}
 */
