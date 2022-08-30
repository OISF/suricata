/* Copyright (C) 2012-2022 Open Information Security Foundation
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

#ifndef __DECODE_TEREDO_H__
#define __DECODE_TEREDO_H__

int DecodeTeredo(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                 const uint8_t *pkt, uint16_t len);
void DecodeTeredoConfig(void);
bool DecodeTeredoEnabledForPort(const uint16_t sp, const uint16_t dp);

#endif
