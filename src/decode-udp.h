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
 */

#ifndef __DECODE_UDP_H__
#define __DECODE_UDP_H__

#define UDP_HEADER_LEN         8

/* XXX RAW* needs to be really 'raw', so no ntohs there */
#define UDP_GET_RAW_LEN(udph)                ntohs((udph)->uh_len)
#define UDP_GET_RAW_SRC_PORT(udph)           ntohs((udph)->uh_sport)
#define UDP_GET_RAW_DST_PORT(udph)           ntohs((udph)->uh_dport)

#define UDP_GET_LEN(p)                       UDP_GET_RAW_LEN(p->udph)
#define UDP_GET_SRC_PORT(p)                  UDP_GET_RAW_SRC_PORT(p->udph)
#define UDP_GET_DST_PORT(p)                  UDP_GET_RAW_DST_PORT(p->udph)

/* UDP header structure */
typedef struct UDPHdr_
{
	uint16_t uh_sport;  /* source port */
	uint16_t uh_dport;  /* destination port */
	uint16_t uh_len;    /* length */
	uint16_t uh_sum;    /* checksum */
} __attribute__((__packed__)) UDPHdr;

typedef struct UDPVars_
{
} UDPVars;

#define CLEAR_UDP_PACKET(p) do { \
    (p)->udph = NULL; \
    (p)->level4_comp_csum = -1; \
} while (0)

void DecodeUDPV4RegisterTests(void);

/** ------ Inline function ------ */
static inline uint16_t UDPV4CalculateChecksum(uint16_t *, uint16_t *, uint16_t);
static inline uint16_t UDPV6CalculateChecksum(uint16_t *, uint16_t *, uint16_t);

/**
 * \brief Calculates the checksum for the UDP packet
 *
 * \param shdr Pointer to source address field from the IP packet.  Used as a
 *             part of the psuedoheader for computing the checksum
 * \param pkt  Pointer to the start of the UDP packet
 * \param hlen Total length of the UDP packet(header + payload)
 *
 * \retval csum Checksum for the UDP packet
 */
static inline uint16_t UDPV4CalculateChecksum(uint16_t *shdr, uint16_t *pkt,
                                              uint16_t tlen)
{
    uint16_t pad = 0;
    uint32_t csum = shdr[0];

    csum += shdr[1] + shdr[2] + shdr[3] + htons(17) + htons(tlen);

    csum += pkt[0] + pkt[1] + pkt[2];

    tlen -= 8;
    pkt += 4;

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

    uint16_t csum_u16 = (uint16_t)~csum;
    if (csum_u16 == 0)
        return 0xFFFF;
    else
        return csum_u16;
}

/**
 * \brief Calculates the checksum for the UDP packet
 *
 * \param shdr Pointer to source address field from the IPV6 packet.  Used as a
 *             part of the psuedoheader for computing the checksum
 * \param pkt  Pointer to the start of the UDP packet
 * \param tlen Total length of the UDP packet(header + payload)
 *
 * \retval csum Checksum for the UDP packet
 */
static inline uint16_t UDPV6CalculateChecksum(uint16_t *shdr, uint16_t *pkt,
                                              uint16_t tlen)
{
    uint16_t pad = 0;
    uint32_t csum = shdr[0];

    csum += shdr[1] + shdr[2] + shdr[3] + shdr[4] + shdr[5] + shdr[6] +
        shdr[7] + shdr[8] + shdr[9] + shdr[10] + shdr[11] + shdr[12] +
        shdr[13] + shdr[14] + shdr[15] + htons(17) + htons(tlen);

    csum += pkt[0] + pkt[1] + pkt[2];

    tlen -= 8;
    pkt += 4;

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

    uint16_t csum_u16 = (uint16_t)~csum;
    if (csum_u16 == 0)
        return 0xFFFF;
    else
        return csum_u16;
}


#endif /* __DECODE_UDP_H__ */
