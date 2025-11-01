/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#ifndef SURICATA_PACKET_H
#define SURICATA_PACKET_H

#include "decode.h"
#include "util-device.h"

void PacketDrop(Packet *p, const uint8_t action, enum PacketDropReason r);
bool PacketCheckAction(const Packet *p, const uint8_t a);
uint8_t PacketGetAction(const Packet *p);

#ifdef UNITTESTS
static inline uint8_t PacketTestAction(const Packet *p, const uint8_t a)
{
    return PacketCheckAction(p, a);
}
#endif

void PacketInit(Packet *p);
void PacketReleaseRefs(Packet *p);
void PacketReinit(Packet *p);
void PacketRecycle(Packet *p);
void PacketDestructor(Packet *p);

/** \brief Set a packet release function.
 *
 * Set a custom release function for packet. This is required if extra
 * non-standard packet was done that needs to be cleaned up when
 * Suricata is done with a packet.
 *
 * Its also where IPS actions may be done.
 */
void SCPacketSetReleasePacket(Packet *p, void (*ReleasePacket)(Packet *p));

/** \brief Set a packets live device. */
void SCPacketSetLiveDevice(Packet *p, LiveDevice *device);

/** \brief Set a packets data link type. */
void SCPacketSetDatalink(Packet *p, int datalink);

/** \brief Set the timestamp for a packet.
 *
 * \param ts A timestamp in SCTime_t format. See SCTIME_FROM_TIMEVAL
 *     for conversion from struct timeval.
 */
void SCPacketSetTime(Packet *p, SCTime_t ts);

/** \brief Set packet source.
 */
void SCPacketSetSource(Packet *p, enum PktSrcEnum source);

#endif
