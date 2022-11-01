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
 * \author Breno Silva <breno.silva@gmail.com>
 *
 * Decode 802.1q
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-vlan.h"
#include "decode-events.h"

#include "util-validate.h"
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
int DecodeVLAN(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    uint16_t proto;

    if (p->vlan_idx == 0)
        StatsIncr(tv, dtv->counter_vlan);
    else if (p->vlan_idx == 1)
        StatsIncr(tv, dtv->counter_vlan_qinq);

    if(len < VLAN_HEADER_LEN)    {
        ENGINE_SET_INVALID_EVENT(p, VLAN_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }
    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }
    if (p->vlan_idx >= 2) {
        ENGINE_SET_EVENT(p,VLAN_HEADER_TOO_MANY_LAYERS);
        return TM_ECODE_FAILED;
    }

    VLANHdr *vlan_hdr = (VLANHdr *)pkt;

    proto = GET_VLAN_PROTO(vlan_hdr);

    SCLogDebug("p %p pkt %p VLAN protocol %04x VLAN PRI %d VLAN CFI %d VLAN ID %d Len: %" PRIu32 "",
            p, pkt, proto, GET_VLAN_PRIORITY(vlan_hdr), GET_VLAN_CFI(vlan_hdr),
            GET_VLAN_ID(vlan_hdr), len);

    p->vlan_id[p->vlan_idx++] = (uint16_t)GET_VLAN_ID(vlan_hdr);

    if (DecodeNetworkLayer(tv, dtv, proto, p,
                pkt + VLAN_HEADER_LEN, len - VLAN_HEADER_LEN) == false) {
        ENGINE_SET_INVALID_EVENT(p, VLAN_UNKNOWN_TYPE);
        return TM_ECODE_FAILED;
    }
    return TM_ECODE_OK;
}

uint16_t DecodeVLANGetId(const Packet *p, uint8_t layer)
{
    if (unlikely(layer > 1))
        return 0;
    if (p->vlan_idx > layer) {
        return p->vlan_id[layer];
    }
    return 0;
}

typedef struct IEEE8021ahHdr_ {
    uint32_t flags;
    uint8_t c_destination[6];
    uint8_t c_source[6];
    uint16_t type;              /**< next protocol */
}  __attribute__((__packed__)) IEEE8021ahHdr;

#define IEEE8021AH_HEADER_LEN sizeof(IEEE8021ahHdr)

int DecodeIEEE8021ah(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    StatsIncr(tv, dtv->counter_ieee8021ah);

    if (len < IEEE8021AH_HEADER_LEN) {
        ENGINE_SET_INVALID_EVENT(p, IEEE8021AH_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    IEEE8021ahHdr *hdr = (IEEE8021ahHdr *)pkt;
    const uint16_t next_proto = SCNtohs(hdr->type);

    DecodeNetworkLayer(tv, dtv, next_proto, p,
            pkt + IEEE8021AH_HEADER_LEN, len - IEEE8021AH_HEADER_LEN);

    return TM_ECODE_OK;
}

#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "packet.h"

/** \todo Must GRE+VLAN and Multi-Vlan packets to
 * create more tests
 */

/**
 * \test DecodeVLANTest01 test if vlan header is too small.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int DecodeVLANtest01 (void)
{
    uint8_t raw_vlan[] = { 0x00, 0x20, 0x08 };
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeVLAN(&tv, &dtv, p, raw_vlan, sizeof(raw_vlan));

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
static int DecodeVLANtest02 (void)
{
    uint8_t raw_vlan[] = {
        0x00, 0x20, 0x01, 0x00, 0x45, 0x00, 0x00, 0x34,
        0x3b, 0x36, 0x40, 0x00, 0x40, 0x06, 0xb7, 0xc9,
        0x83, 0x97, 0x20, 0x81, 0x83, 0x97, 0x20, 0x15,
        0x04, 0x8a, 0x17, 0x70, 0x4e, 0x14, 0xdf, 0x55,
        0x4d, 0x3d, 0x5a, 0x61, 0x80, 0x10, 0x6b, 0x50,
        0x3c, 0x4c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
        0x00, 0x04, 0xf0, 0xc8, 0x01, 0x99, 0xa3, 0xf3};
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeVLAN(&tv, &dtv, p, raw_vlan, sizeof(raw_vlan));


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
static int DecodeVLANtest03 (void)
{
    uint8_t raw_vlan[] = {
        0x00, 0x20, 0x08, 0x00, 0x45, 0x00, 0x00, 0x34,
        0x3b, 0x36, 0x40, 0x00, 0x40, 0x06, 0xb7, 0xc9,
        0x83, 0x97, 0x20, 0x81, 0x83, 0x97, 0x20, 0x15,
        0x04, 0x8a, 0x17, 0x70, 0x4e, 0x14, 0xdf, 0x55,
        0x4d, 0x3d, 0x5a, 0x61, 0x80, 0x10, 0x6b, 0x50,
        0x3c, 0x4c, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,
        0x00, 0x04, 0xf0, 0xc8, 0x01, 0x99, 0xa3, 0xf3};
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);

    DecodeVLAN(&tv, &dtv, p, raw_vlan, sizeof(raw_vlan));


    if(p->vlan_id[0] == 0) {
        goto error;
    }

    if(ENGINE_ISSET_EVENT(p,VLAN_HEADER_TOO_SMALL))  {
        goto error;
    }

    if(ENGINE_ISSET_EVENT(p,VLAN_UNKNOWN_TYPE))  {
        goto error;
    }

    PacketRecycle(p);
    FlowShutdown();
    SCFree(p);
    return 1;

error:
    PacketRecycle(p);
    FlowShutdown();
    SCFree(p);
    return 0;
}
#endif /* UNITTESTS */

void DecodeVLANRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeVLANtest01", DecodeVLANtest01);
    UtRegisterTest("DecodeVLANtest02", DecodeVLANtest02);
    UtRegisterTest("DecodeVLANtest03", DecodeVLANtest03);
#endif /* UNITTESTS */
}

/**
 * @}
 */
