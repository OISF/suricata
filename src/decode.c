/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/* Decode the raw packet */

#include "eidps-common.h"
#include "decode.h"
#include "util-debug.h"

void DecodeTunnel(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    switch (p->tunnel_proto) {
        case PPP_OVER_GRE:
            return DecodePPP(tv, dtv, p, pkt, len, pq);
            break;
        case IPPROTO_IP:
            return DecodeIPV4(tv, dtv, p, pkt, len, pq);
        case IPPROTO_IPV6:
            return DecodeIPV6(tv, dtv, p, pkt, len, pq);
        default:
            SCLogInfo("FIXME: DecodeTunnel: protocol %" PRIu32 " not supported.", p->tunnel_proto);
            break;
    }
}

/** \brief Set the No payload inspection Flag for the packet.
 *
 * \param p Packet to set the flag in
 */
void DecodeSetNoPayloadInspectionFlag(Packet *p) {
    p->flags |= PKT_NOPAYLOAD_INSPECTION;
}

/** \brief Set the No packet inspection Flag for the packet.
 *
 * \param p Packet to set the flag in
 */
void DecodeSetNoPacketInspectionFlag(Packet *p) {
    p->flags |= PKT_NOPACKET_INSPECTION;
}

