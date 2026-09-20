/* Copyright (C) 2026 Open Information Security Foundation
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

#ifndef SURICATA_PACKET_BINDGEN_H
#define SURICATA_PACKET_BINDGEN_H

typedef struct Packet_ Packet;
typedef struct Flow_ Flow;

uint8_t SCPacketGetIPProto(const Packet *p);
const Flow *SCPacketGetFlow(const Packet *p);
void SCPacketGetTimeAsParts(const Packet *p, uint64_t *secs, uint64_t *usecs);

#endif /* !SURICATA_PACKET_BINDGEN_H */
