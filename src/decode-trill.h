/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Lukas Erlich <erlich.lukas@gmail.com>
 */

#ifndef __DECODE_TRILL_H__
#define __DECODE_TRILL_H__

#define ETHERNET_TYPE_TRILL           0x22F3
#define TRILL_HEADER_LEN              6

typedef struct TRILLHdr_ {
	uint16_t trill_info;
	uint16_t egress_nick;
	uint16_t ingress_nick;
} __attribute__((__packed__)) TRILLHdr;

#endif /* __DECODE_TRILL_H__ */
