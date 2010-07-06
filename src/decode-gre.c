/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \file
 *
 * \author Breno Silva <breno.silva@gmail.com>
 *
 * Decodes GRE
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-gre.h"

#include "util-unittest.h"
#include "util-debug.h"

/**
 * \brief Function to decode GRE packets
 */

void DecodeGRE(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    uint16_t header_len = GRE_HDR_LEN;
    GRESreHdr *gsre = NULL;

    SCPerfCounterIncr(dtv->counter_gre, tv->sc_perf_pca);

    if(len < GRE_HDR_LEN)    {
        DECODER_SET_EVENT(p,GRE_PKT_TOO_SMALL);
        return;
    }

    p->greh = (GREHdr *)pkt;
    if(p->greh == NULL)
        return;

    SCLogDebug("p %p pkt %p GRE protocol %04x Len: %d GRE version %x",
        p, pkt, GRE_GET_PROTO(p->greh), len,GRE_GET_VERSION(p->greh));

    switch (GRE_GET_VERSION(p->greh))
    {
        case GRE_VERSION_0:

            /* GRE version 0 doenst support the fields below RFC 1701 */

            /**
             * \todo We need to make sure this does not allow bypassing
             *       inspection.  A server may just ignore these and
             *       continue processing the packet, but we will not look
             *       further into it.
             */

            if (GRE_FLAG_ISSET_RECUR(p->greh)) {
                DECODER_SET_EVENT(p,GRE_VERSION0_RECUR);
                return;
            }

            if (GREV1_FLAG_ISSET_FLAGS(p->greh))   {
                DECODER_SET_EVENT(p,GRE_VERSION0_FLAGS);
                return;
            }

            /* Adjust header length based on content */

            if (GRE_FLAG_ISSET_KY(p->greh))
                header_len += GRE_KEY_LEN;

            if (GRE_FLAG_ISSET_SQ(p->greh))
                header_len += GRE_SEQ_LEN;

            if (GRE_FLAG_ISSET_CHKSUM(p->greh) || GRE_FLAG_ISSET_ROUTE(p->greh))
                header_len += GRE_CHKSUM_LEN + GRE_OFFSET_LEN;

            if (header_len > len)   {
                DECODER_SET_EVENT(p,GRE_VERSION0_HDR_TOO_BIG);
                return;
            }

            if (GRE_FLAG_ISSET_ROUTE(p->greh))
            {

                gsre = (GRESreHdr *)(pkt + header_len);
                if (gsre == NULL)
                    return;

                while (1)
                {
                    if ((header_len+GRE_SRE_HDR_LEN) > len) {
                        DECODER_SET_EVENT(p,GRE_VERSION1_MALFORMED_SRE_HDR);
                        break;
                    }

                    header_len += GRE_SRE_HDR_LEN;

                    if (gsre != NULL && (ntohs(gsre->af) == 0) && (gsre->sre_length == 0))
                        break;

                    header_len += gsre->sre_length;
                    gsre = (GRESreHdr *)(pkt + header_len);
                    if (gsre == NULL)
                        return;
                }
            }
            break;

        case GRE_VERSION_1:

            /* GRE version 1 doenst support the fields below RFC 1701 */

            /**
             * \todo We need to make sure this does not allow bypassing
             *       inspection.  A server may just ignore these and
             *       continue processing the packet, but we will not look
             *       further into it.
             */

            if (GRE_FLAG_ISSET_CHKSUM(p->greh))    {
                DECODER_SET_EVENT(p,GRE_VERSION1_CHKSUM);
                return;
            }

            if (GRE_FLAG_ISSET_ROUTE(p->greh)) {
                DECODER_SET_EVENT(p,GRE_VERSION1_ROUTE);
                return;
            }

            if (GRE_FLAG_ISSET_SSR(p->greh))   {
                DECODER_SET_EVENT(p,GRE_VERSION1_SSR);
                return;
            }

            if (GRE_FLAG_ISSET_RECUR(p->greh)) {
                DECODER_SET_EVENT(p,GRE_VERSION1_RECUR);
                return;
            }

            if (GREV1_FLAG_ISSET_FLAGS(p->greh))   {
                DECODER_SET_EVENT(p,GRE_VERSION1_FLAGS);
                return;
            }

            if (GRE_GET_PROTO(p->greh) != GRE_PROTO_PPP)  {
                DECODER_SET_EVENT(p,GRE_VERSION1_WRONG_PROTOCOL);
                return;
            }

            if (!(GRE_FLAG_ISSET_KY(p->greh))) {
                DECODER_SET_EVENT(p,GRE_VERSION1_NO_KEY);
                return;
            }

            header_len += GRE_KEY_LEN;

            /* Adjust header length based on content */

            if (GRE_FLAG_ISSET_SQ(p->greh))
                header_len += GRE_SEQ_LEN;

            if (GREV1_FLAG_ISSET_ACK(p->greh))
                header_len += GREV1_ACK_LEN;

            if (header_len > len)   {
                DECODER_SET_EVENT(p,GRE_VERSION1_HDR_TOO_BIG);
                return;
            }

            break;
        default:
            DECODER_SET_EVENT(p,GRE_WRONG_VERSION);
            return;
    }

    switch (GRE_GET_PROTO(p->greh))
    {
        case ETHERNET_TYPE_IP:
            {
                if (pq != NULL) {
                    Packet *tp = PacketPseudoPktSetup(p, pkt + header_len,
                            len - header_len, IPPROTO_IP);
                    if (tp != NULL) {
                        DecodeTunnel(tv, dtv, tp, tp->pkt, tp->pktlen, pq);
                        PacketEnqueue(pq,tp);
                    }
                }
                break;
            }

        case GRE_PROTO_PPP:
            {
                if (pq != NULL) {
                    Packet *tp = PacketPseudoPktSetup(p, pkt + header_len,
                            len - header_len, PPP_OVER_GRE);
                    if (tp != NULL) {
                        DecodeTunnel(tv, dtv, tp, tp->pkt, tp->pktlen, pq);
                        PacketEnqueue(pq,tp);
                    }
                }
                break;
            }

        case ETHERNET_TYPE_IPV6:
            {
                if (pq != NULL) {
                    Packet *tp = PacketPseudoPktSetup(p, pkt + header_len,
                            len - header_len, IPPROTO_IPV6);
                    if (tp != NULL) {
                        DecodeTunnel(tv, dtv, tp, tp->pkt, tp->pktlen, pq);
                        PacketEnqueue(pq,tp);
                    }
                }
                break;
            }

        case ETHERNET_TYPE_VLAN:
            {
                if (pq != NULL) {
                    Packet *tp = PacketPseudoPktSetup(p, pkt + header_len,
                            len - header_len, VLAN_OVER_GRE);
                    if (tp != NULL) {
                        DecodeTunnel(tv, dtv, tp, tp->pkt, tp->pktlen, pq);
                        PacketEnqueue(pq,tp);
                    }
                }
                break;
            }

        default:
            return;
    }

}


#ifdef UNITTESTS
/**
 * \test DecodeGRETest01 is a test for small gre packet
 */

static int DecodeGREtest01 (void)   {

    uint8_t raw_gre[] = { 0x00 ,0x6e ,0x62 };
    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeGRE(&tv, &dtv, &p, raw_gre, sizeof(raw_gre), NULL);

    if(DECODER_ISSET_EVENT(&p,GRE_PKT_TOO_SMALL))  {
        return 1;
    }

    return 0;
}

/**
 * \test DecodeGRETest02 is a test for wrong gre version
 */

static int DecodeGREtest02 (void)   {
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
    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeGRE(&tv, &dtv, &p, raw_gre, sizeof(raw_gre), NULL);

    if(DECODER_ISSET_EVENT(&p,GRE_WRONG_VERSION))  {
        return 1;
    }

    return 0;
}


/**
 * \test DecodeGRETest03 is a test for valid gre packet
 */

static int DecodeGREtest03 (void)   {
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
    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeGRE(&tv, &dtv, &p, raw_gre, sizeof(raw_gre), NULL);

    if(p.greh == NULL) {
        return 0;
    }


    return 1;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for GRE decoder
 */

void DecodeGRERegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DecodeGREtest01", DecodeGREtest01, 1);
    UtRegisterTest("DecodeGREtest02", DecodeGREtest02, 1);
    UtRegisterTest("DecodeGREtest03", DecodeGREtest03, 1);
#endif /* UNITTESTS */
}
