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
 * \ingroup decode
 *
 * @{
 */

/**
 * \file
 *
 * \author Lukas Erlich <erlich.lukas@gmail.com>
 *
 * Decode TRILL
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-trill.h"

#include "decode-events.h"

/**
 * \internal
 * \brief This function is used to decode TRILL packets
 *
 * \param tv - pointer to the thread vars
 * \param dtv - pointer code thread vars
 * \param p - pointer to the packet struct
 * \param pkt - pointer to the raw packet
 * \param len - packet len
 * \param pq - pointer to the packet queue
 *
 */
int DecodeTRILL(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
	StatsIncr(tv, dtv->counter_trill);

	if (unlikely(len < TRILL_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, TRILL_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    p->trillh = (TRILLHdr *)pkt;
    if (unlikely(p->trillh == NULL))
        return TM_ECODE_FAILED;

    DecodeEthernet(tv, dtv, p, pkt + TRILL_HEADER_LEN,
                    len - TRILL_HEADER_LEN, pq);
    
    return TM_ECODE_OK;
}
