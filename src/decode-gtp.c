/* Copyright (C) 2014 Open Information Security Foundation
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
 * \author Jason Ish <jason.ish@emulex.com>
 *
 * Decode GTP data packets.
 */

#include "suricata-common.h"
#include "decode.h"

#include "util-unittest.h"

#include "decode-gtp.h"

#define GTP_HDR_LEN 8
#define GTP_OPT_HDR_LEN 4

#define GTP_PROTO_IPV4 4
#define GTP_PROTO_IPV6 6

enum GtpMessageTypes {
    GTP_TYPE_PDU = 255
};

typedef struct GtpHdr_ {
    uint8_t version; /**< Version and flags. */
    uint8_t type;
    uint16_t length;
    uint32_t teid;

    uint16_t seq; /**< Optional sequence number. */
    uint8_t npdu; /**< Optional N-PDU number. */
    uint8_t nh; /**< Optional next extension header type. */
} GtpHdr;

#define GTP_VERSION(hdr) hdr->version >> 5
#define GTP_PT(hdr) (hdr->version >> 4) & 0x1
#define GTP_E(hdr) (hdr->version >> 2) & 0x1
#define GTP_S(hdr) (hdr->version >> 1) & 0x1
#define GTP_PN(hdr) hdr->version & 0x1

/**
 * \brief Decode a GTP data packet.
 *
 * \param pkt The packet, first byte being the start of the GTP header.
 * \param data_len Pointer where the length of the payload is stored.
 *
 * \retval A pointer to the start of the payload.
 */
static uint8_t *DecodeGTPDataPacket(uint8_t *pkt, int *data_len) {
    GtpHdr *hdr = (GtpHdr *)pkt;

    SCLogDebug("Version: %d; "
        "PT: %d; "
        "E: %d; "
        "S: %d; "
        "PN: %d; "
        "Type: %d; "
        "Length: %d; ",
        GTP_VERSION(hdr),
        GTP_PT(hdr),
        GTP_E(hdr),
        GTP_S(hdr),
        GTP_PN(hdr),
        hdr->type,
        ntohs(hdr->length));

    if (hdr->type != GTP_TYPE_PDU) {
        return NULL;
    }

    int hdr_len = GTP_HDR_LEN;
    *data_len = ntohs(hdr->length);
    int eflag, sflag, pnflag;
    eflag = GTP_E(hdr);
    sflag = GTP_S(hdr);
    pnflag = GTP_PN(hdr);
    if (eflag || sflag || pnflag) {
        hdr_len += GTP_OPT_HDR_LEN;
        *data_len -= GTP_OPT_HDR_LEN;
    }

    return pkt + hdr_len;
}

/**
 * Decode GTP data packet.
 *
 * \retval TM_ECODE_OK if packet was handled as a GTP data packet,
 *     otherwise TM_ECODE_FAILED.
 */
int DecodeGTP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt,
    uint16_t len, PacketQueue *pq) {

    int data_len = 0;
    uint8_t *data = DecodeGTPDataPacket(pkt, &data_len);
    if (data != NULL) {
        switch (data[0] >> 4) {
        case GTP_PROTO_IPV4: {
            Packet *tp = PacketTunnelPktSetup(tv, dtv, p, data,
                data_len, IPPROTO_IP, pq);
            if (tp != NULL) {
                PKT_SET_SRC(tp, PKT_SRC_DECODER_GTP);
                PacketEnqueue(pq, tp);
                SCPerfCounterIncr(dtv->counter_gtp_data, tv->sc_perf_pca);
                return TM_ECODE_OK;
            }
            break;
        }
        case GTP_PROTO_IPV6: {
            Packet *tp = PacketTunnelPktSetup(tv, dtv, p, data, data_len,
                IPPROTO_IPV6, pq);
            if (tp != NULL) {
                PKT_SET_SRC(tp, PKT_SRC_DECODER_GTP);
                PacketEnqueue(pq, tp);
                SCPerfCounterIncr(dtv->counter_gtp_data, tv->sc_perf_pca);
                return TM_ECODE_OK;
            }
            break;
        }
        default:
            break;
        }
    }

    return TM_ECODE_FAILED;
}

#ifdef UNITTESTS

static int DecodeGTPTestNoFlags(void) {
    /* Version: 1.
     * Protocol type: 1.
     * Reserved: 0.
     * Has next header: 0.
     * Has sequence number: 0.
     * Has N-PDU: 0.
     * Type: 0xff.
     * Length: 52.
     * TEID: 0xa291ee25.
     */
    uint8_t raw_gtp_data_packet[] = {
        0x30, 0xff, 0x00, 0x34, 0xa2, 0x91, 0xee, 0x25,
        0x45, 0x00, 0x00, 0x34, 0x56, 0x8f, 0x40, 0x00,
        0x80, 0x06, 0x00, 0x89, 0x0a, 0xe6, 0x5c, 0x7a,
        0x45, 0x30, 0xf7, 0x1b, 0xc9, 0x58, 0x00, 0x50,
        0x8e, 0x12, 0xe4, 0x98, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x02, 0x20, 0x00, 0x6f, 0x16, 0x00, 0x00,
        0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x02,
        0x01, 0x01, 0x04, 0x02, 0x53, 0x45, 0xb6, 0x9c
    };

    int data_len;
    uint8_t *data = DecodeGTPDataPacket(raw_gtp_data_packet, &data_len);
    if (data == NULL) {
        return 0;
    }
    if (data_len != 52) {
        return 0;
    }
    if ((data[0] >> 4) != GTP_PROTO_IPV4) {
        return 0;
    }

    return 1;
}

static int DecodeGTPTestWithFlag(void) {
    /* Version: 1.
     * Protocol type: 1.
     * Reserved: 0.
     * Has next header: 0.
     * Has sequence number: 0.
     * Has N-PDU: 1.
     * Type: 0xff.
     * Length: 56.
     * TEID: 0xa291ee25.
     */
    uint8_t raw_gtp_data_packet[] = {
        0x31, 0xff, 0x00, 0x38, 0xa2, 0x91, 0xee, 0x25,

        /* Added N-PDU number. */
        0x00, 0x00, 0x01, 0x00,

        0x45, 0x00, 0x00, 0x34, 0x56, 0x8f, 0x40, 0x00,
        0x80, 0x06, 0x00, 0x89, 0x0a, 0xe6, 0x5c, 0x7a,
        0x45, 0x30, 0xf7, 0x1b, 0xc9, 0x58, 0x00, 0x50,
        0x8e, 0x12, 0xe4, 0x98, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x02, 0x20, 0x00, 0x6f, 0x16, 0x00, 0x00,
        0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x02,
        0x01, 0x01, 0x04, 0x02, 0x53, 0x45, 0xb6, 0x9c
    };

    int data_len;
    uint8_t *data = DecodeGTPDataPacket(raw_gtp_data_packet, &data_len);
    if (data == NULL) {
        return 0;
    }
    if (data_len != 52) {
        return 0;
    }
    if ((data[0] >> 4) != GTP_PROTO_IPV4) {
        return 0;
    }

    return 1;
}


#endif /* UNITTESTS */

void DecodeGTPRegisterUnitTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DecodeGTPTestNoFlags", DecodeGTPTestNoFlags, 1);
    UtRegisterTest("DecodeGTPTestWithFlag", DecodeGTPTestWithFlag, 1);
#endif /* UNITTESTS */
}
