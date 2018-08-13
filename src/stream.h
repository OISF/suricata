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

#include "flow.h"

#define STREAM_START        BIT_U8(0)
#define STREAM_EOF          BIT_U8(1)
#define STREAM_TOSERVER     BIT_U8(2)
#define STREAM_TOCLIENT     BIT_U8(3)
#define STREAM_GAP          BIT_U8(4)   /**< data gap encountered */
#define STREAM_DEPTH        BIT_U8(5)   /**< depth reached */
#define STREAM_MIDSTREAM    BIT_U8(6)
#define STREAM_FLUSH        BIT_U8(7)

typedef int (*StreamSegmentCallback)(const Packet *, void *, const uint8_t *, uint32_t);
int StreamSegmentForEach(const Packet *p, uint8_t flag,
                         StreamSegmentCallback CallbackFunc,
                         void *data);

#endif /* __STREAM_H__ */

