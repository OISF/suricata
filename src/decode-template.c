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
 * \author XXX Your Name <your@email.com>
 *
 * Decodes XXX describe the protocol
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-template.h"

/**
 * \brief Function to decode TEMPLATE packets
 * \param tv thread vars
 * \param dtv decoder thread vars
 * \param p packet
 * \param pkt raw packet data
 * \param len length in bytes of pkt array
 * \retval TM_ECODE_OK or TM_ECODE_FAILED on serious error
 */

int DecodeTEMPLATE(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   const uint8_t *pkt, uint32_t len, PacketQueue *pq)
{
    /* TODO add counter for your type of packet to DecodeThreadVars,
     * and register it in DecodeRegisterPerfCounters */
    //StatsIncr(tv, dtv->counter_template);

    /* Validation: make sure that the input data is big enough to hold
     *             the header */
    if (len < sizeof(TemplateHdr)) {
        /* in case of errors, we set events. Events are defined in
         * decode-events.h, and are then exposed to the detection
         * engine through detect-engine-events.h */
        //ENGINE_SET_EVENT(p,TEMPLATE_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    /* Now we can access the header */
    const TemplateHdr *hdr = (const TemplateHdr *)pkt;

    /* lets assume we have UDP encapsulated */
    if (hdr->proto == 17) {
        /* we need to pass on the pkt and it's length minus the current
         * header */
        size_t hdr_len = sizeof(TemplateHdr);

        /* in this example it's clear that hdr_len can't be bigger than
         * 'len', but in more complex cases checking that we can't underflow
         * len is very important
        if (hdr_len >= len) {
            ENGINE_SET_EVENT(p,TEMPLATE_MALFORMED_HDRLEN);
            return TM_ECODE_FAILED;
        }
         */

        /* invoke the next decoder on the remainder of the data */
        return DecodeUDP(tv, dtv, p, (uint8_t *)pkt + hdr_len, len - hdr_len, pq);
    } else {
        //ENGINE_SET_EVENT(p,TEMPLATE_UNSUPPORTED_PROTOCOL);
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}

/**
 * @}
 */
