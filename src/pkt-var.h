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

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __PKT_VAR_H__
#define __PKT_VAR_H__

int WARN_UNUSED PktVarAddKeyValue(Packet *, uint8_t *, uint16_t, uint8_t *, uint16_t);
int WARN_UNUSED PktVarAdd(Packet *, uint32_t id, uint8_t *, uint16_t);
PktVar *PktVarGet(Packet *, uint32_t id);
void PktVarFree(PktVar *);

#endif /* __PKT_VAR_H__ */

