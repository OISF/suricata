/* Copyright (C) 2012-2022 Open Information Security Foundation
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

#include "util-validate.h"
#include "util-debug.h"
#include "conf.h"
#include "detect-engine-port.h"

#define TEREDO_ORIG_INDICATION_LENGTH   8
#define TEREDO_MAX_PORTS                4
#define TEREDO_UNSET_PORT               -1

static bool g_teredo_enabled = true;
static bool g_teredo_ports_any = true;
static int g_teredo_ports_cnt = 0;
static int g_teredo_ports[TEREDO_MAX_PORTS] = { TEREDO_UNSET_PORT, TEREDO_UNSET_PORT,
    TEREDO_UNSET_PORT, TEREDO_UNSET_PORT };

bool DecodeTeredoEnabledForPort(const uint16_t sp, const uint16_t dp)
{
    SCLogDebug("ports %u->%u ports %d %d %d %d", sp, dp, g_teredo_ports[0], g_teredo_ports[1],
            g_teredo_ports[2], g_teredo_ports[3]);

    if (g_teredo_enabled) {
        /* no port config means we are enabled for all ports */
        if (g_teredo_ports_any) {
            return true;
        }

        for (int i = 0; i < g_teredo_ports_cnt; i++) {
            if (g_teredo_ports[i] == TEREDO_UNSET_PORT)
                return false;
            const int port = g_teredo_ports[i];
            if (port == (const int)sp || port == (const int)dp)
                return true;
        }
    }
    return false;
}

static void DecodeTeredoConfigPorts(const char *pstr)
{
    SCLogDebug("parsing \'%s\'", pstr);

    if (strcmp(pstr, "any") == 0) {
        g_teredo_ports_any = true;
        return;
    }

    DetectPort *head = NULL;
    DetectPortParse(NULL, &head, pstr);

    g_teredo_ports_any = false;
    g_teredo_ports_cnt = 0;
    for (DetectPort *p = head; p != NULL; p = p->next) {
        if (g_teredo_ports_cnt >= TEREDO_MAX_PORTS) {
            SCLogWarning(SC_ERR_INVALID_YAML_CONF_ENTRY, "only %d Teredo ports can be defined",
                    TEREDO_MAX_PORTS);
            break;
        }
        g_teredo_ports[g_teredo_ports_cnt++] = (int)p->port;
    }

    DetectPortCleanupList(NULL, head);
}

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
    if (g_teredo_enabled) {
        ConfNode *node = ConfGetNode("decoder.teredo.ports");
        if (node && node->val) {
            DecodeTeredoConfigPorts(node->val);
        }
    }
}

/**
 * \brief Function to decode Teredo packets
 *
 * \retval TM_ECODE_FAILED if packet is not a Teredo packet, TM_ECODE_OK if it is
 */
int DecodeTeredo(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint16_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    if (!g_teredo_enabled)
        return TM_ECODE_FAILED;

    const uint8_t *start = pkt;

    /* Is this packet to short to contain an IPv6 packet ? */
    if (len < IPV6_HEADER_LEN)
        return TM_ECODE_FAILED;

    /* Teredo encapsulate IPv6 in UDP and can add some custom message
     * part before the IPv6 packet. In our case, we just want to get
     * over an ORIGIN indication. So we just make one offset if needed. */
    if (start[0] == 0x0) {
        /* origin indication: compatible with tunnel */
        if (start[1] == 0x0) {
            /* offset is not coherent with len and presence of an IPv6 header */
            if (len < TEREDO_ORIG_INDICATION_LENGTH + IPV6_HEADER_LEN)
                return TM_ECODE_FAILED;

            start += TEREDO_ORIG_INDICATION_LENGTH;

            /* either authentication negotiation not real tunnel or invalid second byte */
        } else {
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
            int blen = len - (start - pkt);
            /* spawn off tunnel packet */
            Packet *tp = PacketTunnelPktSetup(tv, dtv, p, start, blen,
                    DECODE_TUNNEL_IPV6_TEREDO);
            if (tp != NULL) {
                PKT_SET_SRC(tp, PKT_SRC_DECODER_TEREDO);
                /* add the tp to the packet queue. */
                PacketEnqueueNoLock(&tv->decode_pq,tp);
                StatsIncr(tv, dtv->counter_teredo);
                return TM_ECODE_OK;
            }
        }
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_FAILED;
}

/**
 * @}
 */
