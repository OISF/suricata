/* Copyright (C) 2012 Open Information Security Foundation
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
 * Decode Teredo Tunneling protocol.
 *
 * This implementation is based upon RFC 4380: http://www.ietf.org/rfc/rfc4380.txt
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-ipv6.h"
#include "decode-teredo.h"
#include "util-debug.h"
#include "conf.h"

#define TEREDO_ORIG_INDICATION_LENGTH    8

static bool g_teredo_enabled = true;

void DecodeTeredoConfig(void)
{
    int enabled = 0;
    if (ConfGetBool("decoder.teredo.enabled", &enabled) == 1) {
        if (enabled) {
            g_teredo_enabled = true;
        } else {
            g_teredo_enabled = false;
        }
    }
}

/**
 * \brief Function to decode Teredo packets
 *
 * \retval TM_ECODE_FAILED if packet is not a Teredo packet, TM_ECODE_OK if it is
 */
int DecodeTeredo(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    if (!g_teredo_enabled)
        return TM_ECODE_FAILED;

    uint8_t *start = pkt;

    /* Is this packet to short to contain an IPv6 packet ? */
    if (len < IPV6_HEADER_LEN)
        return TM_ECODE_FAILED;

    /* Teredo encapsulate IPv6 in UDP and can add some custom message
     * part before the IPv6 packet. In our case, we just want to get
     * over an ORIGIN indication. So we just make one offset if needed. */
    if (start[0] == 0x0) {
        switch (start[1]) {
            /* origin indication: compatible with tunnel */
            case 0x0:
                /* offset is coherent with len and presence of an IPv6 header */
                if (len >= TEREDO_ORIG_INDICATION_LENGTH + IPV6_HEADER_LEN)
                    start += TEREDO_ORIG_INDICATION_LENGTH;
                else
                    return TM_ECODE_FAILED;
                break;
            /* authentication: negotiation not real tunnel */
            case 0x1:
                return TM_ECODE_FAILED;
            /* this case is not possible in Teredo: not that protocol */
            default:
                return TM_ECODE_FAILED;
        }
    }

    /* There is no specific field that we can check to prove that the packet
     * is a Teredo packet. We've zapped here all the possible Teredo header
     * and we should have an IPv6 packet at the start pointer.
     * We then can only do a few checks before sending the encapsulated packets
     * to decoding:
     *  - The packet has a protocol version which is IPv6.
     *  - The IPv6 length of the packet matches what remains in buffer.
     *  - HLIM is 0. This would technically be valid, but still weird.
     *  - NH 0 (HOP) and not enough data.
     *
     *  If all these conditions are met, the tunnel decoder will be called.
     *  If the packet gets an invalid event set, it will still be rejected.
     */
    if (IP_GET_RAW_VER(start) == 6) {
        IPV6Hdr *thdr = (IPV6Hdr *)start;

        /* ignore hoplimit 0 packets, most likely an artifact of bad detection */
        if (IPV6_GET_RAW_HLIM(thdr) == 0)
            return TM_ECODE_FAILED;

        /* if nh is 0 (HOP) with little data we have a bogus packet */
        if (IPV6_GET_RAW_NH(thdr) == 0 && IPV6_GET_RAW_PLEN(thdr) < 8)
            return TM_ECODE_FAILED;

        if (len ==  IPV6_HEADER_LEN +
                IPV6_GET_RAW_PLEN(thdr) + (start - pkt)) {
            if (pq != NULL) {
                int blen = len - (start - pkt);
                /* spawn off tunnel packet */
                Packet *tp = PacketTunnelPktSetup(tv, dtv, p, start, blen,
                                                  DECODE_TUNNEL_IPV6_TEREDO, pq);
                if (tp != NULL) {
                    PKT_SET_SRC(tp, PKT_SRC_DECODER_TEREDO);
                    /* add the tp to the packet queue. */
                    PacketEnqueue(pq,tp);
                    StatsIncr(tv, dtv->counter_teredo);
                    return TM_ECODE_OK;
                }
            }
        }
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_FAILED;
}

/**
 * @}
 */
