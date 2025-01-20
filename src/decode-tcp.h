/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 * \todo RAW* macro's should be returning the raw value, not the host order
 */

#ifndef SURICATA_DECODE_TCP_H
#define SURICATA_DECODE_TCP_H

#define TCP_HEADER_LEN                       20
#define TCP_OPTLENMAX                        40
#define TCP_OPTMAX                           20 /* every opt is at least 2 bytes
                                                 * (type + len), except EOL and NOP */

/* TCP flags */

#define TH_FIN                               0x01
#define TH_SYN                               0x02
#define TH_RST                               0x04
#define TH_PUSH                              0x08
#define TH_ACK                               0x10
#define TH_URG                               0x20
/** Establish a new connection reducing window */
#define TH_ECN                               0x40
/** Echo Congestion flag */
#define TH_CWR                               0x80

/* tcp option codes */
#define TCP_OPT_EOL                          0x00
#define TCP_OPT_NOP                          0x01
#define TCP_OPT_MSS                          0x02
#define TCP_OPT_WS                           0x03
#define TCP_OPT_SACKOK                       0x04
#define TCP_OPT_SACK                         0x05
#define TCP_OPT_TS                           0x08
#define TCP_OPT_TFO                          0x22   /* TCP Fast Open */
#define TCP_OPT_EXP1                         0xfd   /* Experimental, could be TFO */
#define TCP_OPT_EXP2                         0xfe   /* Experimental, could be TFO */
#define TCP_OPT_MD5                          0x13   /* 19: RFC 2385 TCP MD5 option */
#define TCP_OPT_AO                           0x1d   /* 29: RFC 5925 TCP AO option */

#define TCP_OPT_SACKOK_LEN                   2
#define TCP_OPT_WS_LEN                       3
#define TCP_OPT_TS_LEN                       10
#define TCP_OPT_MSS_LEN                      4
#define TCP_OPT_SACK_MIN_LEN                 10 /* hdr 2, 1 pair 8 = 10 */
#define TCP_OPT_SACK_MAX_LEN                 34 /* hdr 2, 4 pair 32= 34 */
#define TCP_OPT_TFO_MIN_LEN                  4  /* kind, len, 2 bytes cookie: 4 */
#define TCP_OPT_TFO_MAX_LEN                  18 /* kind, len, 18 */

/** Max valid wscale value. */
#define TCP_WSCALE_MAX                       14

#define TCP_GET_RAW_OFFSET(tcph)             (((tcph)->th_offx2 & 0xf0) >> 4)
#define TCP_GET_RAW_HLEN(tcph)               ((uint8_t)(TCP_GET_RAW_OFFSET((tcph)) << 2))
#define TCP_GET_RAW_X2(tcph)                 (unsigned char)((tcph)->th_offx2 & 0x0f)
#define TCP_GET_RAW_SRC_PORT(tcph)           SCNtohs((tcph)->th_sport)
#define TCP_GET_RAW_DST_PORT(tcph)           SCNtohs((tcph)->th_dport)

#define TCP_SET_RAW_TCP_OFFSET(tcph, value)  ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0x0f) | (value << 4)))
#define TCP_SET_RAW_TCP_X2(tcph, value)      ((tcph)->th_offx2 = (unsigned char)(((tcph)->th_offx2 & 0xf0) | (value & 0x0f)))

#define TCP_GET_RAW_SEQ(tcph)                SCNtohl((tcph)->th_seq)
#define TCP_GET_RAW_ACK(tcph)                SCNtohl((tcph)->th_ack)

#define TCP_GET_RAW_WINDOW(tcph)             SCNtohs((tcph)->th_win)
#define TCP_GET_RAW_URG_POINTER(tcph)        SCNtohs((tcph)->th_urp)
#define TCP_GET_RAW_SUM(tcph)                SCNtohs((tcph)->th_sum)

/** macro for getting the first timestamp from the packet in host order */
#define TCP_GET_TSVAL(p) ((p)->l4.vars.tcp.ts_val)

/** macro for getting the second timestamp from the packet in host order. */
#define TCP_GET_TSECR(p) ((p)->l4.vars.tcp.ts_ecr)

#define TCP_HAS_WSCALE(p) ((p)->l4.vars.tcp.wscale_set)
#define TCP_HAS_SACK(p)   (p)->l4.vars.tcp.sack_set
#define TCP_HAS_TS(p)     ((p)->l4.vars.tcp.ts_set)
#define TCP_HAS_MSS(p)    ((p)->l4.vars.tcp.mss_set)
#define TCP_HAS_TFO(p)    ((p)->l4.vars.tcp.tfo_set)

/** macro for getting the wscale from the packet. */
#define TCP_GET_WSCALE(p) (p)->l4.vars.tcp.wscale

#define TCP_GET_SACKOK(p)         (p)->l4.vars.tcp.sack_ok
#define TCP_GET_SACK_PTR(p, tcph) ((uint8_t *)(tcph)) + (p)->l4.vars.tcp.sack_offset
#define TCP_GET_SACK_CNT(p)       (p)->l4.vars.tcp.sack_cnt
#define TCP_GET_MSS(p)            (p)->l4.vars.tcp.mss

#define TCP_GET_OFFSET(p)                    TCP_GET_RAW_OFFSET((p)->l4.hdrs.tcph)
#define TCP_GET_X2(p)                        TCP_GET_RAW_X2((p)->l4.hdrs.tcph)
#define TCP_GET_HLEN(p)                      ((uint8_t)(TCP_GET_OFFSET((p)) << 2))
#define TCP_GET_SRC_PORT(p)                  TCP_GET_RAW_SRC_PORT((p)->l4.hdrs.tcph)
#define TCP_GET_DST_PORT(p)                  TCP_GET_RAW_DST_PORT((p)->l4.hdrs.tcph)
#define TCP_GET_SEQ(p)                       TCP_GET_RAW_SEQ((p)->l4.hdrs.tcph)
#define TCP_GET_ACK(p)                       TCP_GET_RAW_ACK((p)->l4.hdrs.tcph)
#define TCP_GET_WINDOW(p)                    TCP_GET_RAW_WINDOW((p)->l4.hdrs.tcph)
#define TCP_GET_URG_POINTER(p)               TCP_GET_RAW_URG_POINTER((p)->l4.hdrs.tcph)
#define TCP_GET_SUM(p)                       TCP_GET_RAW_SUM((p)->l4.hdrs.tcph)
#define TCP_GET_FLAGS(p)                     (p)->l4.hdrs.tcph->th_flags

#define TCP_ISSET_FLAG_RAW_FIN(tcph)  ((tcph)->th_flags & TH_FIN)
#define TCP_ISSET_FLAG_RAW_SYN(tcph)  ((tcph)->th_flags & TH_SYN)
#define TCP_ISSET_FLAG_RAW_RST(tcph)  ((tcph)->th_flags & TH_RST)
#define TCP_ISSET_FLAG_RAW_PUSH(tcph) ((tcph)->th_flags & TH_PUSH)
#define TCP_ISSET_FLAG_RAW_ACK(tcph)  ((tcph)->th_flags & TH_ACK)
#define TCP_ISSET_FLAG_RAW_URG(tcph)  ((tcph)->th_flags & TH_URG)
#define TCP_ISSET_FLAG_RAW_RES2(tcph) ((tcph)->th_flags & TH_RES2)
#define TCP_ISSET_FLAG_RAW_RES1(tcph) ((tcph)->th_flags & TH_RES1)

#define TCP_ISSET_FLAG_FIN(p)  ((p)->l4.hdrs.tcph->th_flags & TH_FIN)
#define TCP_ISSET_FLAG_SYN(p)  ((p)->l4.hdrs.tcph->th_flags & TH_SYN)
#define TCP_ISSET_FLAG_RST(p)  ((p)->l4.hdrs.tcph->th_flags & TH_RST)
#define TCP_ISSET_FLAG_PUSH(p) ((p)->l4.hdrs.tcph->th_flags & TH_PUSH)
#define TCP_ISSET_FLAG_ACK(p)  ((p)->l4.hdrs.tcph->th_flags & TH_ACK)
#define TCP_ISSET_FLAG_URG(p)  ((p)->l4.hdrs.tcph->th_flags & TH_URG)
#define TCP_ISSET_FLAG_RES2(p) ((p)->l4.hdrs.tcph->th_flags & TH_RES2)
#define TCP_ISSET_FLAG_RES1(p) ((p)->l4.hdrs.tcph->th_flags & TH_RES1)

typedef struct TCPOpt_ {
    uint8_t type;
    uint8_t len;
    const uint8_t *data;
} TCPOpt;

typedef struct TCPOptSackRecord_ {
    uint32_t le;        /**< left edge, network order */
    uint32_t re;        /**< right edge, network order */
} TCPOptSackRecord;

typedef struct TCPHdr_
{
    uint16_t th_sport;  /**< source port */
    uint16_t th_dport;  /**< destination port */
    uint32_t th_seq;    /**< sequence number */
    uint32_t th_ack;    /**< acknowledgement number */
    uint8_t th_offx2;   /**< offset and reserved */
    uint8_t th_flags;   /**< pkt flags */
    uint16_t th_win;    /**< pkt window */
    uint16_t th_sum;    /**< checksum */
    uint16_t th_urp;    /**< urgent pointer */
} TCPHdr;

typedef struct TCPVars_
{
    /* commonly used and needed opts */
    uint8_t md5_option_present : 1;
    uint8_t ao_option_present : 1;
    uint8_t ts_set : 1;
    uint8_t sack_ok : 1;
    uint8_t mss_set : 1;
    uint8_t tfo_set : 1;
    uint8_t wscale_set : 1;
    uint8_t sack_set : 1;
    uint8_t wscale;
    uint8_t sack_cnt; /**< number of sack records */
    uint16_t mss;     /**< MSS value in host byte order */
    uint16_t stream_pkt_flags;
    uint32_t ts_val;    /* host-order */
    uint32_t ts_ecr;    /* host-order */
    uint16_t sack_offset; /**< offset relative to tcp header start */
} TCPVars;

void DecodeTCPRegisterTests(void);

/** -------- Inline functions ------- */

/**
 * \brief Calculate or validate the checksum for the TCP packet
 *
 * \param shdr Pointer to source address field from the IP packet.  Used as a
 *             part of the pseudoheader for computing the checksum
 * \param pkt  Pointer to the start of the TCP packet
 * \param tlen Total length of the TCP packet(header + payload)
 * \param init The current checksum if validating, 0 if generating.
 *
 * \retval csum For validation 0 will be returned for success, for calculation
 *    this will be the checksum.
 */
static inline uint16_t TCPChecksum(
        const uint16_t *shdr, const uint16_t *pkt, uint16_t tlen, uint16_t init)
{
    uint16_t pad = 0;
    uint32_t csum = init;

    csum += shdr[0] + shdr[1] + shdr[2] + shdr[3] + htons(6) + htons(tlen);

    csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
        pkt[7] + pkt[9];

    tlen -= 20;
    pkt += 10;

    while (tlen >= 32) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] +
            pkt[8] +
            pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15];
        tlen -= 32;
        pkt += 16;
    }

    while(tlen >= 8) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3];
        tlen -= 8;
        pkt += 4;
    }

    while(tlen >= 4) {
        csum += pkt[0] + pkt[1];
        tlen -= 4;
        pkt += 2;
    }

    while (tlen > 1) {
        csum += pkt[0];
        pkt += 1;
        tlen -= 2;
    }

    if (tlen == 1) {
        *(uint8_t *)(&pad) = (*(uint8_t *)pkt);
        csum += pad;
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);
    csum += (csum >> 16);

    return (uint16_t)~csum;
}

/**
 * \brief Calculate or validate the checksum for the TCP packet
 *
 * \param shdr Pointer to source address field from the IPV6 packet.  Used as a
 *             part of the psuedoheader for computing the checksum
 * \param pkt  Pointer to the start of the TCP packet
 * \param tlen Total length of the TCP packet(header + payload)
 * \param init The current checksum if validating, 0 if generating.
 *
 * \retval csum For validation 0 will be returned for success, for calculation
 *    this will be the checksum.
 */
static inline uint16_t TCPV6Checksum(
        const uint16_t *shdr, const uint16_t *pkt, uint16_t tlen, uint16_t init)
{
    uint16_t pad = 0;
    uint32_t csum = init;

    csum += shdr[0] + shdr[1] + shdr[2] + shdr[3] + shdr[4] + shdr[5] +
        shdr[6] +  shdr[7] + shdr[8] + shdr[9] + shdr[10] + shdr[11] +
        shdr[12] + shdr[13] + shdr[14] + shdr[15] + htons(6) + htons(tlen);

    csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
        pkt[7] + pkt[9];

    tlen -= 20;
    pkt += 10;

    while (tlen >= 32) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15];
        tlen -= 32;
        pkt += 16;
    }

    while(tlen >= 8) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3];
        tlen -= 8;
        pkt += 4;
    }

    while(tlen >= 4) {
        csum += pkt[0] + pkt[1];
        tlen -= 4;
        pkt += 2;
    }

    while (tlen > 1) {
        csum += pkt[0];
        pkt += 1;
        tlen -= 2;
    }

    if (tlen == 1) {
        *(uint8_t *)(&pad) = (*(uint8_t *)pkt);
        csum += pad;
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);
    csum += (csum >> 16);

    return (uint16_t)~csum;
}

#endif /* SURICATA_DECODE_TCP_H */
