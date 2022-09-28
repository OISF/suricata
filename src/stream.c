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

#include "suricata-common.h"
#include "stream.h"
#include "stream-tcp.h"

/** \brief Run callback for all segments in a single direction.
 *
 * Must be called under flow lock.
 * \var flag determines the direction to run callback on (either to server or to client).
 *
 * \return -1 in case of error, the number of segment in case of success
 */
int StreamSegmentForEach(const Packet *p, uint8_t flag, StreamSegmentCallback CallbackFunc, void *data)
{
    switch(p->proto) {
        case IPPROTO_TCP:
            return StreamTcpSegmentForEach(p, flag, CallbackFunc, data);
            break;
#ifdef DEBUG
        case IPPROTO_UDP:
            SCLogWarning(SC_ERR_UNKNOWN_PROTOCOL, "UDP is currently unsupported");
            break;
        default:
            SCLogWarning(SC_ERR_UNKNOWN_PROTOCOL, "This protocol is currently unsupported");
            break;
#endif
    }
    return 0;
}

/** \brief Run callback for all segments on both directions of the session
 *
 * Must be called under flow lock.
 *
 * \return -1 in case of error, the number of segments in case of success.
 */
int StreamSegmentForSession(
        const Packet *p, uint8_t flag, StreamSegmentCallback CallbackFunc, void *data)
{
    switch (p->proto) {
        case IPPROTO_TCP:
            return StreamTcpSegmentForSession(p, flag, CallbackFunc, data);
            break;
#ifdef DEBUG
        case IPPROTO_UDP:
            SCLogWarning(SC_ERR_UNKNOWN_PROTOCOL, "UDP is currently unsupported");
            break;
        default:
            SCLogWarning(SC_ERR_UNKNOWN_PROTOCOL, "This protocol is currently unsupported");
            break;
#endif
    }
    return 0;
}
