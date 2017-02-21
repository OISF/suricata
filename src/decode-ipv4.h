/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Brian Rectanus <brectanu@gmail.com>
 */

#ifndef __DECODE_IPV4_H__
#define __DECODE_IPV4_H__

#define IPV4_HEADER_LEN           20    /**< Header length */
#define IPV4_OPTMAX               40    /**< Max options length */
#define	IPV4_MAXPACKET_LEN        65535 /**< Maximum packet size */

/** IP Option Types */
#define IPV4_OPT_EOL              0x00  /**< Option: End of List */
#define IPV4_OPT_NOP              0x01  /**< Option: No op */
#define IPV4_OPT_RR               0x07  /**< Option: Record Route */
#define IPV4_OPT_QS               0x19  /**< Option: Quick Start */
#define IPV4_OPT_TS               0x44  /**< Option: Timestamp */
#define IPV4_OPT_SEC              0x82  /**< Option: Security */
#define IPV4_OPT_LSRR             0x83  /**< Option: Loose Source Route */
#define IPV4_OPT_CIPSO            0x86  /**< Option: Commercial IP Security */
#define IPV4_OPT_SID              0x88  /**< Option: Stream Identifier */
#define IPV4_OPT_SSRR             0x89  /**< Option: Strict Source Route */
#define IPV4_OPT_RTRALT           0x94  /**< Option: Router Alert */

/** IP Option Lengths (fixed) */
#define IPV4_OPT_SEC_LEN          11    /**< SEC Option Fixed Length */
#define IPV4_OPT_SID_LEN          4     /**< SID Option Fixed Length */
#define IPV4_OPT_RTRALT_LEN       4     /**< RTRALT Option Fixed Length */

/** IP Option Lengths (variable) */
#define IPV4_OPT_ROUTE_MIN        3     /**< RR, SRR, LTRR Option Min Length */
#define IPV4_OPT_QS_MIN           8     /**< QS Option Min Length */
#define IPV4_OPT_TS_MIN           5     /**< TS Option Min Length */
#define IPV4_OPT_CIPSO_MIN        10    /**< CIPSO Option Min Length */

/** IP Option fields */
#define IPV4_OPTS                 ip4vars.ip_opts
#define IPV4_OPTS_CNT             ip4vars.ip_opt_cnt

typedef struct IPV4Opt_ {
    /** \todo We may want to break type up into its 3 fields
     *        as the reassembler may want to know which options
     *        must be copied to each fragment.
     */
    uint8_t type;         /**< option type */
    uint8_t len;          /**< option length (type+len+data) */
    uint8_t *data;        /**< option data */
} IPV4Opt;

typedef struct IPV4Hdr_
{
    uint8_t ip_verhl;     /**< version & header length */
    uint8_t ip_tos;       /**< type of service */
    uint16_t ip_len;      /**< length */
    uint16_t ip_id;       /**< id */
    uint16_t ip_off;      /**< frag offset */
    uint8_t ip_ttl;       /**< time to live */
    uint8_t ip_proto;     /**< protocol (tcp, udp, etc) */
    uint16_t ip_csum;     /**< checksum */
    union {
        struct {
            struct in_addr ip_src;/**< source address */
            struct in_addr ip_dst;/**< destination address */
        } ip4_un1;
        uint16_t ip_addrs[4];
    } ip4_hdrun1;
} __attribute__((__packed__)) IPV4Hdr;


#define s_ip_src                          ip4_hdrun1.ip4_un1.ip_src
#define s_ip_dst                          ip4_hdrun1.ip4_un1.ip_dst
#define s_ip_addrs                        ip4_hdrun1.ip_addrs

#define IPV4_GET_RAW_VER(ip4h)            (((ip4h)->ip_verhl & 0xf0) >> 4)
#define IPV4_GET_RAW_HLEN(ip4h)           ((ip4h)->ip_verhl & 0x0f)
#define IPV4_GET_RAW_IPTOS(ip4h)          ((ip4h)->ip_tos)
#define IPV4_GET_RAW_IPLEN(ip4h)          ((ip4h)->ip_len)
#define IPV4_GET_RAW_IPID(ip4h)           ((ip4h)->ip_id)
#define IPV4_GET_RAW_IPOFFSET(ip4h)       ((ip4h)->ip_off)
#define IPV4_GET_RAW_IPTTL(ip4h)          ((ip4h)->ip_ttl)
#define IPV4_GET_RAW_IPPROTO(ip4h)        ((ip4h)->ip_proto)
#define IPV4_GET_RAW_IPSRC(ip4h)          ((ip4h)->s_ip_src)
#define IPV4_GET_RAW_IPDST(ip4h)          ((ip4h)->s_ip_dst)

/** return the raw (directly from the header) src ip as uint32_t */
#define IPV4_GET_RAW_IPSRC_U32(ip4h)      (uint32_t)((ip4h)->s_ip_src.s_addr)
/** return the raw (directly from the header) dst ip as uint32_t */
#define IPV4_GET_RAW_IPDST_U32(ip4h)      (uint32_t)((ip4h)->s_ip_dst.s_addr)

/* we need to change them as well as get them */
#define IPV4_SET_RAW_VER(ip4h, value)     ((ip4h)->ip_verhl = (((ip4h)->ip_verhl & 0x0f) | (value << 4)))
#define IPV4_SET_RAW_HLEN(ip4h, value)    ((ip4h)->ip_verhl = (((ip4h)->ip_verhl & 0xf0) | (value & 0x0f)))
#define IPV4_SET_RAW_IPTOS(ip4h, value)   ((ip4h)->ip_tos = value)
#define IPV4_SET_RAW_IPLEN(ip4h, value)   ((ip4h)->ip_len = value)
#define IPV4_SET_RAW_IPPROTO(ip4h, value) ((ip4h)->ip_proto = value)

/* ONLY call these functions after making sure that:
 * 1. p->ip4h is set
 * 2. p->ip4h is valid (len is correct)
 */
#define IPV4_GET_VER(p) \
    IPV4_GET_RAW_VER((p)->ip4h)
#define IPV4_GET_HLEN(p) \
    (IPV4_GET_RAW_HLEN((p)->ip4h) << 2)
#define IPV4_GET_IPTOS(p) \
    IPV4_GET_RAW_IPTOS((p)->ip4h)
#define IPV4_GET_IPLEN(p) \
    (ntohs(IPV4_GET_RAW_IPLEN((p)->ip4h)))
#define IPV4_GET_IPID(p) \
    (ntohs(IPV4_GET_RAW_IPID((p)->ip4h)))
/* _IPV4_GET_IPOFFSET: get the content of the offset header field in host order */
#define _IPV4_GET_IPOFFSET(p) \
    (ntohs(IPV4_GET_RAW_IPOFFSET((p)->ip4h)))
/* IPV4_GET_IPOFFSET: get the final offset */
#define IPV4_GET_IPOFFSET(p) \
    (_IPV4_GET_IPOFFSET(p) & 0x1fff)
/* IPV4_GET_RF: get the RF flag. Use _IPV4_GET_IPOFFSET to save a ntohs call. */
#define IPV4_GET_RF(p) \
    (uint8_t)((_IPV4_GET_IPOFFSET((p)) & 0x8000) >> 15)
/* IPV4_GET_DF: get the DF flag. Use _IPV4_GET_IPOFFSET to save a ntohs call. */
#define IPV4_GET_DF(p) \
    (uint8_t)((_IPV4_GET_IPOFFSET((p)) & 0x4000) >> 14)
/* IPV4_GET_MF: get the MF flag. Use _IPV4_GET_IPOFFSET to save a ntohs call. */
#define IPV4_GET_MF(p) \
    (uint8_t)((_IPV4_GET_IPOFFSET((p)) & 0x2000) >> 13)
#define IPV4_GET_IPTTL(p) \
     IPV4_GET_RAW_IPTTL(p->ip4h)
#define IPV4_GET_IPPROTO(p) \
    IPV4_GET_RAW_IPPROTO((p)->ip4h)

#define CLEAR_IPV4_PACKET(p) do { \
    (p)->ip4h = NULL; \
    (p)->level3_comp_csum = -1; \
    memset(&p->ip4vars, 0x00, sizeof(p->ip4vars)); \
} while (0)

enum IPV4OptionFlags {
    IPV4_OPT_FLAG_EOL = 0,
    IPV4_OPT_FLAG_NOP,
    IPV4_OPT_FLAG_RR,
    IPV4_OPT_FLAG_TS,
    IPV4_OPT_FLAG_QS,
    IPV4_OPT_FLAG_LSRR,
    IPV4_OPT_FLAG_SSRR,
    IPV4_OPT_FLAG_SID,
    IPV4_OPT_FLAG_SEC,
    IPV4_OPT_FLAG_CIPSO,
    IPV4_OPT_FLAG_RTRALT,
};

/* helper structure with parsed ipv4 info */
typedef struct IPV4Vars_
{
    int32_t comp_csum;     /* checksum computed over the ipv4 packet */

    uint16_t opt_cnt;
    uint16_t opts_set;
} IPV4Vars;


void DecodeIPV4RegisterTests(void);

/** ----- Inline functions ----- */
static inline uint16_t IPV4Checksum(uint16_t *, uint16_t, uint16_t);

/**
 * \brief Calculateor validate the checksum for the IP packet
 *
 * \param pkt  Pointer to the start of the IP packet
 * \param hlen Length of the IP header
 * \param init The current checksum if validating, 0 if generating.
 *
 * \retval csum For validation 0 will be returned for success, for calculation
 *    this will be the checksum.
 */
static inline uint16_t IPV4Checksum(uint16_t *pkt, uint16_t hlen, uint16_t init)
{
    uint32_t csum = init;

    csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[6] + pkt[7] +
        pkt[8] + pkt[9];

    hlen -= 20;
    pkt += 10;

    if (hlen == 0) {
        ;
    } else if (hlen == 4) {
        csum += pkt[0] + pkt[1];
    } else if (hlen == 8) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3];
    } else if (hlen == 12) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5];
    } else if (hlen == 16) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7];
    } else if (hlen == 20) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9];
    } else if (hlen == 24) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11];
    } else if (hlen == 28) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13];
    } else if (hlen == 32) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15];
    } else if (hlen == 36) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15] + pkt[16] + pkt[17];
    } else if (hlen == 40) {
        csum += pkt[0] + pkt[1] + pkt[2] + pkt[3] + pkt[4] + pkt[5] + pkt[6] +
            pkt[7] + pkt[8] + pkt[9] + pkt[10] + pkt[11] + pkt[12] + pkt[13] +
            pkt[14] + pkt[15] + pkt[16] + pkt[17] + pkt[18] + pkt[19];
    }

    csum = (csum >> 16) + (csum & 0x0000FFFF);
    csum += (csum >> 16);

    return (uint16_t) ~csum;
}

#endif /* __DECODE_IPV4_H__ */

