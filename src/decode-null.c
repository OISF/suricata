/* Copyright (C) 2015 Open Information Security Foundation
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
 * \ingroup decode
 *
 * @{
 */


/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Decode linkype null:
 * http://www.tcpdump.org/linktypes.html
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-raw.h"
#include "decode-events.h"

#include "util-unittest.h"
#include "util-debug.h"

#include "pkt-var.h"
#include "util-profiling.h"
#include "host.h"

#define HDR_SIZE 4

int DecodeNull(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint32_t len, PacketQueue *pq)
{
    StatsIncr(tv, dtv->counter_null);

    if (unlikely(len < HDR_SIZE)) {
        ENGINE_SET_INVALID_EVENT(p, LTNULL_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (unlikely(GET_PKT_LEN(p) > HDR_SIZE + USHRT_MAX)) {
        return TM_ECODE_FAILED;
    }

    uint32_t type = *((uint32_t *)pkt);
    switch(type) {
        case AF_INET:
            SCLogDebug("IPV4 Packet");
            DecodeIPV4(tv, dtv, p, GET_PKT_DATA(p)+HDR_SIZE, GET_PKT_LEN(p)-HDR_SIZE, pq);
            break;
        case AF_INET6:
            SCLogDebug("IPV6 Packet");
            DecodeIPV6(tv, dtv, p, GET_PKT_DATA(p)+HDR_SIZE, GET_PKT_LEN(p)-HDR_SIZE, pq);
            break;
        default:
            SCLogDebug("Unknown Null packet type version %" PRIu32 "", type);
            ENGINE_SET_EVENT(p, LTNULL_UNSUPPORTED_TYPE);
            break;
    }
    return TM_ECODE_OK;
}

#ifdef UNITTESTS

#endif /* UNITTESTS */

/**
 * \brief Registers Null unit tests
 */
void DecodeNullRegisterTests(void)
{
#ifdef UNITTESTS
#endif /* UNITTESTS */
}
/**
 * @}
 */
