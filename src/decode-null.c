/* Copyright (C) 2015-2021 Open Information Security Foundation
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

#include "util-validate.h"
#include "util-unittest.h"
#include "util-debug.h"

#define HDR_SIZE 4

#define AF_INET6_BSD     24
#define AF_INET6_FREEBSD 28
#define AF_INET6_DARWIN  30
#define AF_INET6_LINUX   10
#define AF_INET6_SOLARIS 26
#define AF_INET6_WINSOCK 23

int DecodeNull(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    StatsIncr(tv, dtv->counter_null);

    if (unlikely(len < HDR_SIZE)) {
        ENGINE_SET_INVALID_EVENT(p, LTNULL_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (unlikely(GET_PKT_LEN(p) > HDR_SIZE + USHRT_MAX)) {
        return TM_ECODE_FAILED;
    }
#if __BYTE_ORDER__ == __BIG_ENDIAN
    uint32_t type = pkt[0] | pkt[1] << 8 | pkt[2] << 16 | pkt[3] << 24;
#else
    uint32_t type = *((uint32_t *)pkt);
#endif
    switch(type) {
        case AF_INET:
            SCLogDebug("IPV4 Packet");
            if (GET_PKT_LEN(p) - HDR_SIZE > USHRT_MAX) {
                return TM_ECODE_FAILED;
            }
            DecodeIPV4(
                    tv, dtv, p, GET_PKT_DATA(p) + HDR_SIZE, (uint16_t)(GET_PKT_LEN(p) - HDR_SIZE));
            break;
        case AF_INET6_BSD:
        case AF_INET6_FREEBSD:
        case AF_INET6_DARWIN:
        case AF_INET6_LINUX:
        case AF_INET6_SOLARIS:
        case AF_INET6_WINSOCK:
            SCLogDebug("IPV6 Packet");
            if (GET_PKT_LEN(p) - HDR_SIZE > USHRT_MAX) {
                return TM_ECODE_FAILED;
            }
            DecodeIPV6(
                    tv, dtv, p, GET_PKT_DATA(p) + HDR_SIZE, (uint16_t)(GET_PKT_LEN(p) - HDR_SIZE));
            break;
        default:
            SCLogDebug("Unknown Null packet type version %" PRIu32 "", type);
            ENGINE_SET_EVENT(p, LTNULL_UNSUPPORTED_TYPE);
            break;
    }
    return TM_ECODE_OK;
}

/**
 * @}
 */
