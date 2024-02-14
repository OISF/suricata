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

#ifndef __PACKET_H__
#define __PACKET_H__

#include "decode.h"

void PacketDrop(Packet *p, const uint8_t action, enum PacketDropReason r);
bool PacketCheckAction(const Packet *p, const uint8_t a);

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

#endif
