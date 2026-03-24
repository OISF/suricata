/* Copyright (C) 2011 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 */

#ifndef SURICATA_DECODE_SCTP_H
#define SURICATA_DECODE_SCTP_H

/** size of the packet header without any chunk headers */
#define SCTP_HEADER_LEN 12

/** size of a chunk header (type + flags + length) */
#define SCTP_CHUNK_HDR_LEN 4

/** DATA chunk overhead before user data (chunk hdr + TSN + SID + SSN + PPID) */
#define SCTP_DATA_CHUNK_HDR_LEN 16

/* SCTP chunk types (RFC 4960 sec 3.2) */
#define SCTP_CHUNK_TYPE_DATA              0x00
#define SCTP_CHUNK_TYPE_INIT              0x01
#define SCTP_CHUNK_TYPE_INIT_ACK          0x02
#define SCTP_CHUNK_TYPE_SACK              0x03
#define SCTP_CHUNK_TYPE_HEARTBEAT         0x04
#define SCTP_CHUNK_TYPE_HB_ACK            0x05
#define SCTP_CHUNK_TYPE_ABORT             0x06
#define SCTP_CHUNK_TYPE_SHUTDOWN          0x07
#define SCTP_CHUNK_TYPE_SHUTDOWN_ACK      0x08
#define SCTP_CHUNK_TYPE_ERROR             0x09
#define SCTP_CHUNK_TYPE_COOKIE_ECHO       0x0A
#define SCTP_CHUNK_TYPE_COOKIE_ACK        0x0B
#define SCTP_CHUNK_TYPE_ECNE              0x0C
#define SCTP_CHUNK_TYPE_CWR               0x0D
#define SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE 0x0E
#define SCTP_CHUNK_TYPE_FORWARD_TSN       0xC0

typedef struct SCTPHdr_ {
    uint16_t sh_sport; /* source port */
    uint16_t sh_dport; /* destination port */
    uint32_t sh_vtag;  /* verification tag, defined per flow */
    uint32_t sh_sum;   /* checksum, computed via crc32 */
} __attribute__((__packed__)) SCTPHdr;

typedef struct SCTPChunkHdr_ {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
} __attribute__((__packed__)) SCTPChunkHdr;

typedef struct SCTPVars_ {
    uint16_t hlen;        /**< total header length (common header + chunks) */
    uint8_t first_chunk;  /**< type of the first chunk */
    uint8_t chunk_cnt;    /**< number of chunks parsed */
    uint16_t data_offset; /**< offset of first DATA user data from L4 start, 0 if none */
    uint16_t data_len;    /**< length of first DATA user data, 0 if none */
    bool has_init : 1;
    bool has_data : 1;
    bool has_abort : 1;
} SCTPVars;

#define SCTP_GET_RAW_SRC_PORT(sctph) SCNtohs((sctph)->sh_sport)
#define SCTP_GET_RAW_DST_PORT(sctph) SCNtohs((sctph)->sh_dport)
#define SCTP_GET_RAW_VTAG(sctph)     SCNtohl((sctph)->sh_vtag)
#define SCTP_GET_RAW_SUM(sctph)      SCNtohl((sctph)->sh_sum)

void DecodeSCTPRegisterTests(void);

#endif /* SURICATA_DECODE_SCTP_H */
