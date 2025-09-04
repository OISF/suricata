/* Copyright (C) 2025 Open Information Security Foundation
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

#ifndef SURICATA_FLOW_BINDGEN_H
#define SURICATA_FLOW_BINDGEN_H

/* forward declaration for macset include */
typedef struct Flow_ Flow;

void SCFlowGetLastTimeAsParts(const Flow *flow, uint64_t *secs, uint64_t *usecs);
uint32_t SCFlowGetFlags(const Flow *flow);
uint16_t SCFlowGetSourcePort(const Flow *flow);
uint16_t SCFlowGetDestinationPort(const Flow *flow);

#endif /* SURICATA_FLOW_BINDGEN_H */
