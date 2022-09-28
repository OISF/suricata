/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * \author Breno Silva <breno.silva@gmail.com>
 *
 * Decodes GRE
 */

#include "suricata-common.h"
#include "decode-gre.h"

#include "util-validate.h"
#include "util-unittest.h"

/**
 * \brief Function to decode GRE packets
 */

int DecodeGRE(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    uint32_t header_len = GRE_HDR_LEN;
    GRESreHdr *gsre = NULL;
    GREPPtPHd *gre_pptp_h = NULL;

    StatsIncr(tv, dtv->counter_gre);

    if(len < GRE_HDR_LEN)    {
        ENGINE_SET_INVALID_EVENT(p, GRE_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }
    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    p->greh = (GREHdr *)pkt;

    SCLogDebug("p %p pkt %p GRE protocol %04x Len: %d GRE version %x",
        p, pkt, GRE_GET_PROTO(p->greh), len,GRE_GET_VERSION(p->greh));

    switch (GRE_GET_VERSION(p->greh))
    {
        case GRE_VERSION_0:

            /* GRE version 0 doesn't support the fields below RFC 1701 */

            /**
             * \todo We need to make sure this does not allow bypassing
             *       inspection.  A server may just ignore these and
             *       continue processing the packet, but we will not look
             *       further into it.
             */

            if (GRE_FLAG_ISSET_RECUR(p->greh)) {
                ENGINE_SET_INVALID_EVENT(p, GRE_VERSION0_RECUR);
                return TM_ECODE_OK;
            }

            if (GREV1_FLAG_ISSET_FLAGS(p->greh))   {
                ENGINE_SET_INVALID_EVENT(p, GRE_VERSION0_FLAGS);
                return TM_ECODE_OK;
            }

            /* Adjust header length based on content */

            if (GRE_FLAG_ISSET_KY(p->greh))
                header_len += GRE_KEY_LEN;

            if (GRE_FLAG_ISSET_SQ(p->greh))
                header_len += GRE_SEQ_LEN;

            if (GRE_FLAG_ISSET_CHKSUM(p->greh) || GRE_FLAG_ISSET_ROUTE(p->greh))
                header_len += GRE_CHKSUM_LEN + GRE_OFFSET_LEN;

            if (header_len > len)   {
                ENGINE_SET_INVALID_EVENT(p, GRE_VERSION0_HDR_TOO_BIG);
                return TM_ECODE_OK;
            }

            if (GRE_FLAG_ISSET_ROUTE(p->greh))
            {
                while (1)
                {
                    if ((header_len + GRE_SRE_HDR_LEN) > len) {
                        ENGINE_SET_INVALID_EVENT(p,
                                                 GRE_VERSION0_MALFORMED_SRE_HDR);
                        return TM_ECODE_OK;
                    }

                    gsre = (GRESreHdr *)(pkt + header_len);

                    header_len += GRE_SRE_HDR_LEN;

                    if ((SCNtohs(gsre->af) == 0) && (gsre->sre_length == 0))
                        break;

                    header_len += gsre->sre_length;
                    if (header_len > len) {
                        ENGINE_SET_INVALID_EVENT(p,
                                                 GRE_VERSION0_MALFORMED_SRE_HDR);
                        return TM_ECODE_OK;
                    }
                }
            }
            break;

        case GRE_VERSION_1:

            /* GRE version 1 doesn't support the fields below RFC 1701 */

            /**
             * \todo We need to make sure this does not allow bypassing
             *       inspection.  A server may just ignore these and
             *       continue processing the packet, but we will not look
             *       further into it.
             */

            if (GRE_FLAG_ISSET_CHKSUM(p->greh))    {
                ENGINE_SET_INVALID_EVENT(p,GRE_VERSION1_CHKSUM);
                return TM_ECODE_OK;
            }

            if (GRE_FLAG_ISSET_ROUTE(p->greh)) {
                ENGINE_SET_INVALID_EVENT(p,GRE_VERSION1_ROUTE);
                return TM_ECODE_OK;
            }

            if (GRE_FLAG_ISSET_SSR(p->greh))   {
                ENGINE_SET_INVALID_EVENT(p,GRE_VERSION1_SSR);
                return TM_ECODE_OK;
            }

            if (GRE_FLAG_ISSET_RECUR(p->greh)) {
                ENGINE_SET_INVALID_EVENT(p,GRE_VERSION1_RECUR);
                return TM_ECODE_OK;
            }

            if (GREV1_FLAG_ISSET_FLAGS(p->greh))   {
                ENGINE_SET_INVALID_EVENT(p,GRE_VERSION1_FLAGS);
                return TM_ECODE_OK;
            }

            if (GRE_GET_PROTO(p->greh) != GRE_PROTO_PPP)  {
                ENGINE_SET_INVALID_EVENT(p,GRE_VERSION1_WRONG_PROTOCOL);
                return TM_ECODE_OK;
            }

            if (!(GRE_FLAG_ISSET_KY(p->greh))) {
                ENGINE_SET_INVALID_EVENT(p,GRE_VERSION1_NO_KEY);
                return TM_ECODE_OK;
            }

            header_len += GRE_KEY_LEN;
            /* key is set and proto == PPP */
            gre_pptp_h = (GREPPtPHd *)pkt;

            /* Adjust header length based on content */

            if (GRE_FLAG_ISSET_SQ(p->greh))
                header_len += GRE_SEQ_LEN;

            if (GREV1_FLAG_ISSET_ACK(p->greh))
                header_len += GREV1_ACK_LEN;

            if (header_len > len)   {
                ENGINE_SET_INVALID_EVENT(p, GRE_VERSION1_HDR_TOO_BIG);
                return TM_ECODE_OK;
            }

            break;
        default:
            ENGINE_SET_INVALID_EVENT(p, GRE_WRONG_VERSION);
            return TM_ECODE_OK;
    }

    switch (GRE_GET_PROTO(p->greh))
    {
        case ETHERNET_TYPE_IP:
        {
            Packet *tp = PacketTunnelPktSetup(tv, dtv, p, pkt + header_len,
                    len - header_len, DECODE_TUNNEL_IPV4);
            if (tp != NULL) {
                PKT_SET_SRC(tp, PKT_SRC_DECODER_GRE);
                PacketEnqueueNoLock(&tv->decode_pq,tp);
            }
            break;
        }

        case GRE_PROTO_PPP:
        {
            if (gre_pptp_h && !gre_pptp_h->payload_length)
                return TM_ECODE_OK;

            Packet *tp = PacketTunnelPktSetup(tv, dtv, p, pkt + header_len,
                    len - header_len, DECODE_TUNNEL_PPP);
            if (tp != NULL) {
                PKT_SET_SRC(tp, PKT_SRC_DECODER_GRE);
                PacketEnqueueNoLock(&tv->decode_pq,tp);
            }
            break;
        }

        case ETHERNET_TYPE_IPV6:
        {
            Packet *tp = PacketTunnelPktSetup(tv, dtv, p, pkt + header_len,
                    len - header_len, DECODE_TUNNEL_IPV6);
            if (tp != NULL) {
                PKT_SET_SRC(tp, PKT_SRC_DECODER_GRE);
                PacketEnqueueNoLock(&tv->decode_pq,tp);
            }
            break;
        }

        case ETHERNET_TYPE_VLAN:
        {
            Packet *tp = PacketTunnelPktSetup(tv, dtv, p, pkt + header_len,
                    len - header_len, DECODE_TUNNEL_VLAN);
            if (tp != NULL) {
                PKT_SET_SRC(tp, PKT_SRC_DECODER_GRE);
                PacketEnqueueNoLock(&tv->decode_pq,tp);
            }
            break;
        }

        case ETHERNET_TYPE_ERSPAN:
        {
            // Determine if it's Type I or Type II based on the flags in the GRE header.
            // Type I:  0|0|0|0|0|00000|000000000|00000
            // Type II: 0|0|0|1|0|00000|000000000|00000
            //                Seq
            Packet *tp = PacketTunnelPktSetup(tv, dtv, p, pkt + header_len,
                    len - header_len,
                    GRE_FLAG_ISSET_SQ(p->greh) == 0 ?
                            DECODE_TUNNEL_ERSPANI :
                            DECODE_TUNNEL_ERSPANII);
            if (tp != NULL) {
                PKT_SET_SRC(tp, PKT_SRC_DECODER_GRE);
                PacketEnqueueNoLock(&tv->decode_pq,tp);
            }
            break;
        }

        case ETHERNET_TYPE_BRIDGE:
        {
            Packet *tp = PacketTunnelPktSetup(tv, dtv, p, pkt + header_len,
                    len - header_len, DECODE_TUNNEL_ETHERNET);
            if (tp != NULL) {
                PKT_SET_SRC(tp, PKT_SRC_DECODER_GRE);
                PacketEnqueueNoLock(&tv->decode_pq,tp);
            }
            break;
        }

        default:
            return TM_ECODE_OK;
    }
    return TM_ECODE_OK;
}


#ifdef UNITTESTS
/**
 * \test DecodeGRETest01 is a test for small gre packet
 */

static int DecodeGREtest01 (void)
{
    uint8_t raw_gre[] = { 0x00 ,0x6e ,0x62 };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeGRE(&tv, &dtv, p, raw_gre, sizeof(raw_gre));
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, GRE_PKT_TOO_SMALL));

    SCFree(p);
    PASS;
}

/**
 * \test DecodeGRETest02 is a test for wrong gre version
 */

static int DecodeGREtest02 (void)
{
    uint8_t raw_gre[] = {
        0x00, 0x6e, 0x62, 0xac, 0x40, 0x00, 0x40, 0x2f,
        0xc2, 0xc7, 0x0a, 0x00, 0x00, 0x64, 0x0a, 0x00,
        0x00, 0x8a, 0x30, 0x01, 0x0b, 0x00, 0x4e, 0x00,
        0x00, 0x00, 0x18, 0x4a, 0x50, 0xff, 0x03, 0x00,
        0x21, 0x45, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x40,
        0x00, 0x40, 0x11, 0x94, 0x22, 0x50, 0x7e, 0x2b,
        0x2d, 0xc2, 0x6d, 0x68, 0x68, 0x80, 0x0e, 0x00,
        0x35, 0x00, 0x36, 0x9f, 0x18, 0xdb, 0xc4, 0x01,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x03, 0x73, 0x31, 0x36, 0x09, 0x73, 0x69,
        0x74, 0x65, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00 };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeGRE(&tv, &dtv, p, raw_gre, sizeof(raw_gre));
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, GRE_WRONG_VERSION));

    SCFree(p);
    PASS;
}


/**
 * \test DecodeGRETest03 is a test for valid gre packet
 */

static int DecodeGREtest03 (void)
{
    uint8_t raw_gre[] = {
        0x00, 0x6e, 0x62, 0xac, 0x40, 0x00, 0x40, 0x2f,
        0xc2, 0xc7, 0x0a, 0x00, 0x00, 0x64, 0x0a, 0x00,
        0x00, 0x8a, 0x30, 0x01, 0x88, 0x0b, 0x00, 0x4e,
        0x00, 0x00, 0x00, 0x18, 0x4a, 0x50, 0xff, 0x03,
        0x00, 0x21, 0x45, 0x00, 0x00, 0x4a, 0x00, 0x00,
        0x40, 0x00, 0x40, 0x11, 0x94, 0x22, 0x50, 0x7e,
        0x2b, 0x2d, 0xc2, 0x6d, 0x68, 0x68, 0x80, 0x0e,
        0x00, 0x35, 0x00, 0x36, 0x9f, 0x18, 0xdb, 0xc4,
        0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x03, 0x73, 0x31, 0x36, 0x09, 0x73,
        0x69, 0x74, 0x65, 0x6d, 0x65, 0x74, 0x65, 0x72,
        0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00 };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeGRE(&tv, &dtv, p, raw_gre, sizeof(raw_gre));
    FAIL_IF_NULL(p->greh);

    SCFree(p);
    PASS;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for GRE decoder
 */

void DecodeGRERegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeGREtest01", DecodeGREtest01);
    UtRegisterTest("DecodeGREtest02", DecodeGREtest02);
    UtRegisterTest("DecodeGREtest03", DecodeGREtest03);
#endif /* UNITTESTS */
}
/**
 * @}
 */
