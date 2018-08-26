/* Copyright (C) 2007-2011 Open Information Security Foundation
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

#ifndef __STREAM_TCP_SACK_H__
#define __STREAM_TCP_SACK_H__

#include "suricata-common.h"
#include "util-optimize.h"

/**
 *  \brief Get the size of the SACKed ranges
 *
 *  \param stream Stream to get the size for.
 *
 *  \retval size the size
 *
 *  Optimized for case where SACK is not in use in the
 *  stream, as it *should* only be used in case of packet
 *  loss.
 */
static inline uint32_t StreamTcpSackedSize(TcpStream *stream)
{
    if (likely(RB_EMPTY(&stream->sack_tree))) {
        SCReturnUInt(0U);
    } else {
        uint32_t size = 0;

        StreamTcpSackRecord *rec = NULL;
        RB_FOREACH(rec, TCPSACK, &stream->sack_tree) {
            size += (rec->re - rec->le);
        }

        SCReturnUInt(size);
    }
}

int StreamTcpSackUpdatePacket(TcpStream *, Packet *);
void StreamTcpSackPruneList(TcpStream *);
void StreamTcpSackFreeList(TcpStream *);
void StreamTcpSackRegisterTests (void);

#endif /* __STREAM_TCP_SACK_H__*/
