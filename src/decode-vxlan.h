/* Copyright (C) 2018 Open Information Security Foundation
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

#ifndef SURICATA_DECODE_VXLAN_H
#define SURICATA_DECODE_VXLAN_H

void DecodeVXLANRegisterTests(void);
void DecodeVXLANConfig(void);
bool DecodeVXLANEnabledForPort(const uint16_t sp, const uint16_t dp);

#endif /* !SURICATA_DECODE_VXLAN_H */
