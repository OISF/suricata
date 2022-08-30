/* Copyright (C) 2011-2022 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * Decode SCTP
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-sctp.h"
#include "decode-events.h"

#include "util-validate.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-optimize.h"
#include "flow.h"

static int DecodeSCTPPacket(ThreadVars *tv, Packet *p, const uint8_t *pkt, uint16_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    if (unlikely(len < SCTP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, SCTP_PKT_TOO_SMALL);
        return -1;
    }

    p->sctph = (SCTPHdr *)pkt;

    SET_SCTP_SRC_PORT(p,&p->sp);
    SET_SCTP_DST_PORT(p,&p->dp);

    p->payload = (uint8_t *)pkt + sizeof(SCTPHdr);
    p->payload_len = len - sizeof(SCTPHdr);

    p->proto = IPPROTO_SCTP;

    return 0;
}

int DecodeSCTP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint16_t len)
{
    StatsIncr(tv, dtv->counter_sctp);

    if (unlikely(DecodeSCTPPacket(tv, p,pkt,len) < 0)) {
        CLEAR_SCTP_PACKET(p);
        return TM_ECODE_FAILED;
    }

#ifdef DEBUG
    SCLogDebug("SCTP sp: %" PRIu32 " -> dp: %" PRIu32,
        SCTP_GET_SRC_PORT(p), SCTP_GET_DST_PORT(p));
#endif

    FlowSetupPacket(p);

    return TM_ECODE_OK;
}
/**
 * @}
 */
