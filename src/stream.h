/* Copyright (C) 2007-2017 Open Information Security Foundation
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

#ifndef __STREAM_H__
#define __STREAM_H__

#include "stream-tcp-private.h"

#define STREAM_FLAGS_FOR_PACKET(p) PKT_IS_TOSERVER((p)) ? STREAM_TOSERVER : STREAM_TOCLIENT

#define STREAM_DUMP_TOCLIENT BIT_U8(1)
#define STREAM_DUMP_TOSERVER BIT_U8(2)
#define STREAM_DUMP_HEADERS  BIT_U8(3)

typedef int (*StreamSegmentCallback)(
        const Packet *, TcpSegment *, void *, const uint8_t *, uint32_t);
int StreamSegmentForEach(const Packet *p, uint8_t flag,
                         StreamSegmentCallback CallbackFunc,
                         void *data);
int StreamSegmentForSession(
        const Packet *p, uint8_t flag, StreamSegmentCallback CallbackFunc, void *data);

#endif /* __STREAM_H__ */

