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
 * \author Christian Tramnitz <christian@tramnitz.com>
 *
 * Decodes B.A.T.M.A.N advanced protocol
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-batman.h"

/**
 * \brief Function to decode B.A.T.M.A.N. advanced packets
 * \param tv thread vars
 * \param dtv decoder thread vars
 * \param p packet
 * \param pkt raw packet data
 * \param len length in bytes of pkt array
 * \retval TM_ECODE_OK or TM_ECODE_FAILED on serious error
 */

int DecodeBatman(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint32_t len, PacketQueue *pq)
{
    StatsIncr(tv, dtv->counter_batman);

    if (len < sizeof(BATADV_MIN_PACKET_SIZE)) {
        return TM_ECODE_FAILED;
    }

    const batadv_header *batadv_basic = (const batadv_header *)pkt;

    if (batadv_basic->version == BATADV_VERSION_14) {
        switch (batadv_basic->packet_type) {
            case BATADV_14_IV_OGM:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_14_IV_OGM_HLEN, len - BATADV_14_IV_OGM_HLEN, pq);
                }
            break;
            case BATADV_14_ICMP:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_14_ICMP_HLEN, len - BATADV_14_ICMP_HLEN, pq);
                }
            break;
            case BATADV_14_UNICAST:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_14_UNICAST_HLEN, len - BATADV_14_UNICAST_HLEN, pq);
                }
            break;
            case BATADV_14_BCAST:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_14_BCAST_HLEN, len - BATADV_14_BCAST_HLEN, pq);
                }
            break;
            case BATADV_14_VIS:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_14_VIS_HLEN, len - BATADV_14_VIS_HLEN, pq);
                }
            break;
            case BATADV_14_UNICAST_FRAG:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_14_UNICAST_FRAG_HLEN, len - BATADV_14_UNICAST_FRAG_HLEN, pq);
                }
            break;
            case BATADV_14_TT_QUERY:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_14_TTQUERY_HLEN, len - BATADV_14_TTQUERY_HLEN, pq);
                }
            break;
            case BATADV_14_ROAM_ADV:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_14_ROAM_HLEN, len - BATADV_14_ROAM_HLEN, pq);
                }
            break;
            case BATADV_14_UNICAST_4ADDR:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_14_UNICAST4_HLEN, len - BATADV_14_UNICAST4_HLEN, pq);
                }
            break;
            case BATADV_14_CODED:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_14_CODED_HLEN, len - BATADV_14_CODED_HLEN, pq);
                }
            break;
            default:
                SCLogWarning(SC_ERR_NOT_SUPPORTED, "unsupported BATMAN-ADV version 14 packet_type %x ", batadv_basic->version);
                return TM_ECODE_FAILED;
        }
    }
    else if (batadv_basic->version == BATADV_VERSION_15) {
        switch (batadv_basic->packet_type) {
            case BATADV_15_IV_OGM:
                {   
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_15_OGM_HLEN, len - BATADV_15_OGM_HLEN, pq);
                }
            break;
            case BATADV_15_ICMP:
                {   
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_15_ICMP_HLEN, len - BATADV_15_ICMP_HLEN, pq);
                }
            break;
            case BATADV_15_UNICAST:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_15_UNICAST_HLEN, len - BATADV_15_UNICAST_HLEN, pq);
                }
            break;
            case BATADV_15_BCAST: 
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_15_BCAST_HLEN, len - BATADV_15_BCAST_HLEN, pq);
                }
            break; 
            case BATADV_15_OGM2:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_15_OGM2_HLEN, len - BATADV_15_OGM2_HLEN, pq);
                }
            break;
            case BATADV_15_UNICAST_FRAG:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_15_UNICAST_FRAG_HLEN, len - BATADV_15_UNICAST_FRAG_HLEN, pq);
                }
            break;
            case BATADV_15_UNICAST_TVLV:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_15_TVLV_HLEN, len - BATADV_15_TVLV_HLEN, pq);
                }
            break;
            case BATADV_15_ELP:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_15_ELP_HLEN, len - BATADV_15_ELP_HLEN, pq);
                }
            break;
            case BATADV_15_UNICAST_4ADDR:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_15_UNICAST4_HLEN, len - BATADV_15_UNICAST4_HLEN, pq);
                }
            break;
            case BATADV_15_CODED:
                {
                    // TODO: decorate flow with meta data from header
                    DecodeEthernet(tv, dtv, p, pkt + BATADV_15_CODED_HLEN, len - BATADV_15_CODED_HLEN, pq);
                }
            break;
            default:
                SCLogWarning(SC_ERR_NOT_SUPPORTED, "unsupported BATMAN-ADV version 15 packet_type %x ", batadv_basic->version);
                return TM_ECODE_FAILED;
        }
    }
    else {
        SCLogWarning(SC_ERR_NOT_SUPPORTED, "unsupported BATMAN-ADV version %d ", batadv_basic->version);
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}

/**
 * @}
 */
