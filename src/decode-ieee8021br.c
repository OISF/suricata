/* Copyright (C) 2015-2018 Open Information Security Foundation
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
 * \author XXX Sumera Priyadarsini <sylphrenadin@gmail.com>
 *
 * Decodes IEEE802.1BR 
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-ieee8021br.h"

#define IEEE8021BR_HEADER_LEN sizeof(Ieee8021brHdr)
/**
 * \brief Function to decode IEEE8021BR packets
 * \param tv thread vars
 * \param dtv decoder thread vars
 * \param p packet
 * \param pkt raw packet data
 * \param len length in bytes of pkt array
 * \retval TM_ECODE_OK or TM_ECODE_FAILED on serious error
 */

int DecodeIEEE8021BR(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   const uint8_t *pkt, uint32_t len)
{
    StatsIncr(tv, dtv->counter_ieee8021br);

    if (len < IEEE8021BR_HEADER_LEN) {
        ENGINE_SET_INVALID_EVENT(p, IEEE8021BR_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    const Ieee8021brHdr *hdr = (const Ieee8021brHdr *)pkt;

    const uint16_t next_proto = SCNtohs(hdr->pad1);

    DecodeNetworkLayer(tv, dtv, next_proto, pkt + IEEE8021BR_HEADER_LEN,
            len - IEEE8021BR_HEADER_LEN);

    /* lets assume we have UDP encapsulated
    if (hdr->proto == 17) {
        /* we need to pass on the pkt and it's length minus the current
         * header */
        size_t hdr_len = sizeof(Ieee8021brHdr);
        /* in this example it's clear that hdr_len can't be bigger than
         * 'len', but in more complex cases checking that we can't underflow
         * len is very important
        if (hdr_len >= len) {
            ENGINE_SET_EVENT(p,IEEE8021BR_MALFORMED_HDRLEN);
            return TM_ECODE_FAILED;
        }
         */

        /* invoke the next decoder on the remainder of the data 
        return DecodeUDP(tv, dtv, p, (uint8_t *)pkt + hdr_len, len - hdr_len);
    } else {
        //ENGINE_SET_EVENT(p,IEEE8021BR_UNSUPPORTED_PROTOCOL);
        return TM_ECODE_FAILED;
    }*/

    return TM_ECODE_OK;
}

/**
 * @}
 */
