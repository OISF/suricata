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
 * \file
 *
 * \author Christian Tramnitz <christian@tramnitz.com>
 *
 */

#ifndef __DECODE_BATMAN_H__
#define __DECODE_BATMAN_H__

#include "decode.h"
#include "threadvars.h"

#define ETHERNET_TYPE_BATMAN     0x4305
#define ETH_ALEN                 6 /* Octets in one ethernet addr */
#define BATADV_VERSION_14        14 /* BATMAN-ADV definition for v14 coming from (v2013.4.0) packet.h  */
#define BATADV_VERSION_15        15 /* BATMAN-ADV definition for v15 coming from (v2019.1) include/uapi/linux/batadv_packet.h */
#define BATADV_MIN_PACKET_SIZE   9

#define BATADV_14_IV_OGM         0x01
#define BATADV_14_ICMP           0x02
#define BATADV_14_UNICAST        0x03
#define BATADV_14_BCAST          0x04
#define BATADV_14_VIS            0x05
#define BATADV_14_UNICAST_FRAG   0x06
#define BATADV_14_TT_QUERY       0x07
#define BATADV_14_ROAM_ADV       0x08
#define BATADV_14_UNICAST_4ADDR  0x09
#define BATADV_14_CODED          0x0a

/**
 * batadv_15_packettype - types for batman-adv encapsulated packets
 * @BATADV_IV_OGM: originator messages for B.A.T.M.A.N. IV
 * @BATADV_BCAST: broadcast packets carrying broadcast payload
 * @BATADV_CODED: network coded packets
 * @BATADV_ELP: echo location packets for B.A.T.M.A.N. V
 * @BATADV_OGM2: originator messages for B.A.T.M.A.N. V
 *
 * @BATADV_UNICAST: unicast packets carrying unicast payload traffic
 * @BATADV_UNICAST_FRAG: unicast packets carrying a fragment of the original
 *     payload packet
 * @BATADV_UNICAST_4ADDR: unicast packet including the originator address of
 *     the sender
 * @BATADV_ICMP: unicast packet like IP ICMP used for ping or traceroute
 * @BATADV_UNICAST_TVLV: unicast packet carrying TVLV containers
 */

#define BATADV_15_IV_OGM         0x00
#define BATADV_15_BCAST          0x01
#define BATADV_15_CODED          0x02
#define BATADV_15_ELP            0x03
#define BATADV_15_OGM2           0x04
#define BATADV_15_UNICAST        0x40
#define BATADV_15_UNICAST_FRAG   0x41
#define BATADV_15_UNICAST_4ADDR  0x42
#define BATADV_15_ICMP           0x43
#define BATADV_15_UNICAST_TVLV   0x44

typedef struct batadv_header {
    uint8_t  packet_type;
    uint8_t  version;  /* batman version field */
    uint8_t  ttl;
    /* the parent struct has to add a byte after the header to make
     * everything 4 bytes aligned again
     */
} batadv_header;


// BATADV_14_IV_OGM
typedef struct batadv_14_ogm_packet {
    struct batadv_header header;
    uint8_t  flags;    /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
    uint32_t   seqno;
    uint8_t  orig[ETH_ALEN];
    uint8_t  prev_sender[ETH_ALEN];
    uint8_t  gw_flags;  /* flags related to gateway class */
    uint8_t  tq;
    uint8_t  tt_num_changes;
    uint8_t  ttvn; /* translation table version number */
    uint16_t   tt_crc;
} __attribute__((__packed__)) batadv_14_ogm_packet;

#define BATADV_14_IV_OGM_HLEN sizeof(batadv_14_ogm_packet)

typedef struct batadv_14_icmp_packet {
    struct batadv_header header;
    uint8_t  msg_type; /* see ICMP message types above */
    uint8_t  dst[ETH_ALEN];
    uint8_t  orig[ETH_ALEN];
    uint16_t   seqno;
    uint8_t  uid;
    uint8_t  reserved;
} batadv_14_icmp_packet;

#define BATADV_14_ICMP_HLEN sizeof(batadv_14_icmp_packet)

#define BATADV_14_RR_LEN 16

/* icmp_packet_rr must start with all fields from imcp_packet
 * as this is assumed by code that handles ICMP packets
 */
typedef struct batadv_14_icmp_packet_rr {
    struct batadv_header header;
    uint8_t  msg_type; /* see ICMP message types above */
    uint8_t  dst[ETH_ALEN];
    uint8_t  orig[ETH_ALEN];
    uint16_t   seqno;
    uint8_t  uid;
    uint8_t  rr_cur;
    uint8_t  rr[BATADV_14_RR_LEN][ETH_ALEN];
} batadv_14_icmp_packet_rr;

#define BATADV_14_ICMPRR_HLEN sizeof(batadv_14_icmp_packet_rr)

/* All packet headers in front of an ethernet header have to be completely
 * divisible by 2 but not by 4 to make the payload after the ethernet
 * header again 4 bytes boundary aligned.
 *
 * A packing of 2 is necessary to avoid extra padding at the end of the struct
 * caused by a structure member which is larger than two bytes. Otherwise
 * the structure would not fulfill the previously mentioned rule to avoid the
 * misalignment of the payload after the ethernet header. It may also lead to
 * leakage of information when the padding it not initialized before sending.
 */
#pragma pack(2)

typedef struct batadv_unicast_packet {
    struct batadv_header header;
    uint8_t  ttvn; /* destination translation table version number */
    uint8_t  dest[ETH_ALEN];
    /* "4 bytes boundary + 2 bytes" long to make the payload after the
     * following ethernet header again 4 bytes boundary aligned
     */
} batadv_unicast_packet;

#define BATADV_14_UNICAST_HLEN sizeof(batadv_unicast_packet)

/**
 * struct batadv_unicast_4addr_packet - extended unicast packet
 * @u: common unicast packet header
 * @src: address of the source
 * @subtype: packet subtype
 */
typedef struct batadv_unicast_4addr_packet {
    struct batadv_unicast_packet u;
    uint8_t src[ETH_ALEN];
    uint8_t subtype;
    uint8_t reserved;
    /* "4 bytes boundary + 2 bytes" long to make the payload after the
     * following ethernet header again 4 bytes boundary aligned
     */
} batadv_unicast_4addr_packet;

#define BATADV_14_UNICAST4_HLEN sizeof(batadv_unicast_4addr_packet)

typedef struct batadv_unicast_frag_packet {
    struct batadv_header header;
    uint8_t  ttvn; /* destination translation table version number */
    uint8_t  dest[ETH_ALEN];
    uint8_t  flags;
    uint8_t  align;
    uint8_t  orig[ETH_ALEN];
    uint16_t   seqno;
} __attribute__((__packed__)) batadv_unicast_frag_packet;

#define BATADV_14_UNICAST_FRAG_HLEN sizeof(batadv_unicast_frag_packet)

typedef struct batadv_bcast_packet {
    struct batadv_header header;
    uint8_t  reserved;
    uint32_t   seqno;
    uint8_t  orig[ETH_ALEN];
    /* "4 bytes boundary + 2 bytes" long to make the payload after the
     * following ethernet header again 4 bytes boundary aligned
     */
} batadv_bcast_packet;

#define BATADV_14_BCAST_HLEN sizeof(batadv_bcast_packet)

#pragma pack()

typedef struct batadv_vis_packet {
    struct batadv_header header;
    uint8_t  vis_type;    /* which type of vis-participant sent this? */
    uint32_t   seqno;     /* sequence number */
    uint8_t  entries;     /* number of entries behind this struct */
    uint8_t  reserved;
    uint8_t  vis_orig[ETH_ALEN];     /* originator reporting its neighbors */
    uint8_t  target_orig[ETH_ALEN];  /* who should receive this packet */
    uint8_t  sender_orig[ETH_ALEN];  /* who sent or forwarded this packet */
} batadv_vis_packet;

#define BATADV_14_VIS_HLEN sizeof(batadv_vis_packet)

typedef struct batadv_tt_query_packet {
    struct batadv_header header;
    /* the flag field is a combination of:
     * - TT_REQUEST or TT_RESPONSE
     * - TT_FULL_TABLE
     */
    uint8_t  flags;
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    /* the ttvn field is:
     * if TT_REQUEST: ttvn that triggered the
     *                request
     * if TT_RESPONSE: new ttvn for the src
     *                 orig_node
     */
    uint8_t  ttvn;
    /* tt_data field is:
     * if TT_REQUEST: crc associated with the
     *                ttvn
     * if TT_RESPONSE: table_size
     */
    uint16_t tt_data;
} __attribute__((__packed__)) batadv_tt_query_packet;

#define BATADV_14_TTQUERY_HLEN sizeof(batadv_tt_query_packet)

typedef struct batadv_roam_adv_packet {
    struct batadv_header header;
    uint8_t  reserved;
    uint8_t  dst[ETH_ALEN];
    uint8_t  src[ETH_ALEN];
    uint8_t  client[ETH_ALEN];
} __attribute__((__packed__)) batadv_roam_adv_packet;

#define BATADV_14_ROAM_HLEN sizeof(batadv_roam_adv_packet)

typedef struct batadv_tt_change {
    uint8_t flags;
    uint8_t addr[ETH_ALEN];
} __attribute__((__packed__)) batadv_tt_change;

#define BATADV_14_TTCHANGE_HLEN sizeof(batadv_tt_change)

/**
 * struct batadv_coded_packet - network coded packet
 * @header: common batman packet header and ttl of first included packet
 * @reserved: Align following fields to 2-byte boundaries
 * @first_source: original source of first included packet
 * @first_orig_dest: original destinal of first included packet
 * @first_crc: checksum of first included packet
 * @first_ttvn: tt-version number of first included packet
 * @second_ttl: ttl of second packet
 * @second_dest: second receiver of this coded packet
 * @second_source: original source of second included packet
 * @second_orig_dest: original destination of second included packet
 * @second_crc: checksum of second included packet
 * @second_ttvn: tt version number of second included packet
 * @coded_len: length of network coded part of the payload
 */
typedef struct batadv_coded_packet {
    struct batadv_header header;
    uint8_t  first_ttvn;
    /* uint8_t  first_dest[ETH_ALEN]; - saved in mac header destination */
    uint8_t  first_source[ETH_ALEN];
    uint8_t  first_orig_dest[ETH_ALEN];
    uint32_t   first_crc;
    uint8_t  second_ttl;
    uint8_t  second_ttvn;
    uint8_t  second_dest[ETH_ALEN];
    uint8_t  second_source[ETH_ALEN];
    uint8_t  second_orig_dest[ETH_ALEN];
    uint32_t   second_crc;
    uint16_t   coded_len;
} batadv_coded_packet;

#define BATADV_14_CODED_HLEN sizeof(batadv_coded_packet)

#pragma pack(2)

/**
 * struct batadv_ogm_packet - ogm (routing protocol) packet
 * @packet_type: batman-adv packet type, part of the general header
 * @version: batman-adv protocol version, part of the genereal header
 * @ttl: time to live for this packet, part of the genereal header
 * @flags: contains routing relevant flags - see enum batadv_iv_flags
 * @seqno: sequence identification
 * @orig: address of the source node
 * @prev_sender: address of the previous sender
 * @reserved: reserved byte for alignment
 * @tq: transmission quality
 * @tvlv_len: length of tvlv data following the ogm header
 */
typedef struct batadv_15_ogm_packet {
    uint8_t   packet_type;
    uint8_t   version;
    uint8_t   ttl;
    uint8_t   flags;
    uint32_t seqno;
    uint8_t   orig[ETH_ALEN];
    uint8_t   prev_sender[ETH_ALEN];
    uint8_t   reserved;
    uint8_t   tq;
    uint16_t tvlv_len;
} batadv_15_ogm_packet;

#define BATADV_15_OGM_HLEN sizeof(batadv_15_ogm_packet)

/**
 * struct batadv_ogm2_packet - ogm2 (routing protocol) packet
 * @packet_type: batman-adv packet type, part of the general header
 * @version: batman-adv protocol version, part of the general header
 * @ttl: time to live for this packet, part of the general header
 * @flags: reserved for routing relevant flags - currently always 0
 * @seqno: sequence number
 * @orig: originator mac address
 * @tvlv_len: length of the appended tvlv buffer (in bytes)
 * @throughput: the currently flooded path throughput
 */
typedef struct batadv_15_ogm2_packet {
    uint8_t   packet_type;
    uint8_t   version;
    uint8_t   ttl;
    uint8_t   flags;
    uint32_t seqno;
    uint8_t   orig[ETH_ALEN];
    uint16_t tvlv_len;
    uint32_t throughput;
} batadv_15_ogm2_packet;

#define BATADV_15_OGM2_HLEN sizeof(batadv_15_ogm2_packet)

/**
 * struct batadv_elp_packet - elp (neighbor discovery) packet
 * @packet_type: batman-adv packet type, part of the general header
 * @version: batman-adv protocol version, part of the genereal header
 * @orig: originator mac address
 * @seqno: sequence number
 * @elp_interval: currently used ELP sending interval in ms
 */
typedef struct batadv_15_elp_packet {
    uint8_t   packet_type;
    uint8_t   version;
    uint8_t   orig[ETH_ALEN];
    uint32_t seqno;
    uint32_t elp_interval;
} batadv_15_elp_packet;

#define BATADV_15_ELP_HLEN sizeof(batadv_15_elp_packet)

/**
 * struct batadv_icmp_header - common members among all the ICMP packets
 * @packet_type: batman-adv packet type, part of the general header
 * @version: batman-adv protocol version, part of the genereal header
 * @ttl: time to live for this packet, part of the genereal header
 * @msg_type: ICMP packet type
 * @dst: address of the destination node
 * @orig: address of the source node
 * @uid: local ICMP socket identifier
 * @align: not used - useful for alignment purposes only
 *
 * This structure is used for ICMP packets parsing only and it is never sent
 * over the wire. The alignment field at the end is there to ensure that
 * members are padded the same way as they are in real packets.
 */
struct batadv_15_icmp_header {
    uint8_t packet_type;
    uint8_t version;
    uint8_t ttl;
    uint8_t msg_type; /* see ICMP message types above */
    uint8_t dst[ETH_ALEN];
    uint8_t orig[ETH_ALEN];
    uint8_t uid;
    uint8_t align[3];
} batadv_15_icmp_header;

#define BATADV_15_ICMPH_HLEN sizeof(batadv_15_icmp_header)

/**
 * struct batadv_icmp_packet - ICMP packet
 * @packet_type: batman-adv packet type, part of the general header
 * @version: batman-adv protocol version, part of the genereal header
 * @ttl: time to live for this packet, part of the genereal header
 * @msg_type: ICMP packet type
 * @dst: address of the destination node
 * @orig: address of the source node
 * @uid: local ICMP socket identifier
 * @reserved: not used - useful for alignment
 * @seqno: ICMP sequence number
 */
typedef struct batadv_15_icmp_packet {
    uint8_t   packet_type;
    uint8_t   version;
    uint8_t   ttl;
    uint8_t   msg_type; /* see ICMP message types above */
    uint8_t   dst[ETH_ALEN];
    uint8_t   orig[ETH_ALEN];
    uint8_t   uid;
    uint8_t   reserved;
    uint16_t seqno;
} batadv_15_icmp_packet;

#define BATADV_15_ICMPP_HLEN sizeof(batadv_15_icmp_packet)

/**
 * struct batadv_icmp_tp_packet - ICMP TP Meter packet
 * @packet_type: batman-adv packet type, part of the general header
 * @version: batman-adv protocol version, part of the genereal header
 * @ttl: time to live for this packet, part of the genereal header
 * @msg_type: ICMP packet type
 * @dst: address of the destination node
 * @orig: address of the source node
 * @uid: local ICMP socket identifier
 * @subtype: TP packet subtype (see batadv_icmp_tp_subtype)
 * @session: TP session identifier
 * @seqno: the TP sequence number
 * @timestamp: time when the packet has been sent. This value is filled in a
 *  TP_MSG and echoed back in the next TP_ACK so that the sender can compute the
 *  RTT. Since it is read only by the host which wrote it, there is no need to
 *  store it using network order
 */
typedef struct batadv_15_icmp_tp_packet {
    uint8_t   packet_type;
    uint8_t   version;
    uint8_t   ttl;
    uint8_t   msg_type; /* see ICMP message types above */
    uint8_t   dst[ETH_ALEN];
    uint8_t   orig[ETH_ALEN];
    uint8_t   uid;
    uint8_t   subtype;
    uint8_t   session[2];
    uint32_t seqno;
    uint32_t timestamp;
} batadv_icmp_tp_packet;

#define BATADV_15_ICMPTP_HLEN sizeof(batadv_15_icmp_tp_packet)

#define BATADV_15_RR_LEN 16

/**
 * struct batadv_icmp_packet_rr - ICMP RouteRecord packet
 * @packet_type: batman-adv packet type, part of the general header
 * @version: batman-adv protocol version, part of the genereal header
 * @ttl: time to live for this packet, part of the genereal header
 * @msg_type: ICMP packet type
 * @dst: address of the destination node
 * @orig: address of the source node
 * @uid: local ICMP socket identifier
 * @rr_cur: number of entries the rr array
 * @seqno: ICMP sequence number
 * @rr: route record array
 */
typedef struct batadv_15_icmp_packet_rr {
    uint8_t   packet_type;
    uint8_t   version;
    uint8_t   ttl;
    uint8_t   msg_type; /* see ICMP message types above */
    uint8_t   dst[ETH_ALEN];
    uint8_t   orig[ETH_ALEN];
    uint8_t   uid;
    uint8_t   rr_cur;
    uint16_t seqno;
    uint8_t   rr[BATADV_15_RR_LEN][ETH_ALEN];
} batadv_15_icmp_packet_rr;

#define BATADV_15_ICMP_HLEN sizeof(batadv_15_icmp_packet_rr)

/* All packet headers in front of an ethernet header have to be completely
 * divisible by 2 but not by 4 to make the payload after the ethernet
 * header again 4 bytes boundary aligned.
 *
 * A packing of 2 is necessary to avoid extra padding at the end of the struct
 * caused by a structure member which is larger than two bytes. Otherwise
 * the structure would not fulfill the previously mentioned rule to avoid the
 * misalignment of the payload after the ethernet header. It may also lead to
 * leakage of information when the padding it not initialized before sending.
 */

/**
 * struct batadv_unicast_packet - unicast packet for network payload
 * @packet_type: batman-adv packet type, part of the general header
 * @version: batman-adv protocol version, part of the genereal header
 * @ttl: time to live for this packet, part of the genereal header
 * @ttvn: translation table version number
 * @dest: originator destination of the unicast packet
 */
typedef struct batadv_15_unicast_packet {
    uint8_t packet_type;
    uint8_t version;
    uint8_t ttl;
    uint8_t ttvn; /* destination translation table version number */
    uint8_t dest[ETH_ALEN];
    /* "4 bytes boundary + 2 bytes" long to make the payload after the
     * following ethernet header again 4 bytes boundary aligned
     */
} batadv_15_unicast_packet;

#define BATADV_15_UNICAST_HLEN sizeof(batadv_15_unicast_packet)

/**
 * struct batadv_unicast_4addr_packet - extended unicast packet
 * @u: common unicast packet header
 * @src: address of the source
 * @subtype: packet subtype
 * @reserved: reserved byte for alignment
 */
typedef struct batadv_15_unicast_4addr_packet {
    struct batadv_unicast_packet u;
    uint8_t src[ETH_ALEN];
    uint8_t subtype;
    uint8_t reserved;
    /* "4 bytes boundary + 2 bytes" long to make the payload after the
     * following ethernet header again 4 bytes boundary aligned
     */
} batadv_15_unicast_4addr_packet;

#define BATADV_15_UNICAST4_HLEN sizeof(batadv_15_unicast_4addr_packet)

/**
 * struct batadv_frag_packet - fragmented packet
 * @packet_type: batman-adv packet type, part of the general header
 * @version: batman-adv protocol version, part of the genereal header
 * @ttl: time to live for this packet, part of the genereal header
 * @dest: final destination used when routing fragments
 * @orig: originator of the fragment used when merging the packet
 * @no: fragment number within this sequence
 * @priority: priority of frame, from ToS IP precedence or 802.1p
 * @reserved: reserved byte for alignment
 * @seqno: sequence identification
 * @total_size: size of the merged packet
 */
typedef struct batadv_15_frag_packet {
    uint8_t   packet_type;
    uint8_t   version;  /* batman version field */
    uint8_t   ttl;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t   no:4;
    uint8_t   priority:3;
    uint8_t   reserved:1;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t   reserved:1;
    uint8_t   priority:3;
    uint8_t   no:4;
#else
#error "unknown bitfield endianness"
#endif
    uint8_t   dest[ETH_ALEN];
    uint8_t   orig[ETH_ALEN];
    uint16_t seqno;
    uint16_t total_size;
} batadv_15_frag_packet;

#define BATADV_15_UNICAST_FRAG_HLEN sizeof(batadv_15_frag_packet)

/**
 * struct batadv_bcast_packet - broadcast packet for network payload
 * @packet_type: batman-adv packet type, part of the general header
 * @version: batman-adv protocol version, part of the genereal header
 * @ttl: time to live for this packet, part of the genereal header
 * @reserved: reserved byte for alignment
 * @seqno: sequence identification
 * @orig: originator of the broadcast packet
 */
typedef struct batadv_15_bcast_packet {
    uint8_t   packet_type;
    uint8_t   version;  /* batman version field */
    uint8_t   ttl;
    uint8_t   reserved;
    uint32_t seqno;
    uint8_t   orig[ETH_ALEN];
    /* "4 bytes boundary + 2 bytes" long to make the payload after the
     * following ethernet header again 4 bytes boundary aligned
     */
} batadv_15_bcast_packet;

#define BATADV_15_BCAST_HLEN sizeof(batadv_15_bcast_packet)

/**
 * struct batadv_coded_packet - network coded packet
 * @packet_type: batman-adv packet type, part of the general header
 * @version: batman-adv protocol version, part of the genereal header
 * @ttl: time to live for this packet, part of the genereal header
 * @first_source: original source of first included packet
 * @first_orig_dest: original destinal of first included packet
 * @first_crc: checksum of first included packet
 * @first_ttvn: tt-version number of first included packet
 * @second_ttl: ttl of second packet
 * @second_dest: second receiver of this coded packet
 * @second_source: original source of second included packet
 * @second_orig_dest: original destination of second included packet
 * @second_crc: checksum of second included packet
 * @second_ttvn: tt version number of second included packet
 * @coded_len: length of network coded part of the payload
 */
typedef struct batadv_15_coded_packet {
    uint8_t   packet_type;
    uint8_t   version;  /* batman version field */
    uint8_t   ttl;
    uint8_t   first_ttvn;
    /* uint8_t first_dest[ETH_ALEN]; - saved in mac header destination */
    uint8_t   first_source[ETH_ALEN];
    uint8_t   first_orig_dest[ETH_ALEN];
    uint32_t first_crc;
    uint8_t   second_ttl;
    uint8_t   second_ttvn;
    uint8_t   second_dest[ETH_ALEN];
    uint8_t   second_source[ETH_ALEN];
    uint8_t   second_orig_dest[ETH_ALEN];
    uint32_t second_crc;
    uint16_t coded_len;
} batadv_15_coded_packet;

#define BATADV_15_CODED_HLEN sizeof(batadv_15_coded_packet)

/**
 * struct batadv_unicast_tvlv_packet - generic unicast packet with tvlv payload
 * @packet_type: batman-adv packet type, part of the general header
 * @version: batman-adv protocol version, part of the genereal header
 * @ttl: time to live for this packet, part of the genereal header
 * @reserved: reserved field (for packet alignment)
 * @src: address of the source
 * @dst: address of the destination
 * @tvlv_len: length of tvlv data following the unicast tvlv header
 * @align: 2 bytes to align the header to a 4 byte boundary
 */
typedef struct batadv_15_unicast_tvlv_packet {
    uint8_t   packet_type;
    uint8_t   version;  /* batman version field */
    uint8_t   ttl;
    uint8_t   reserved;
    uint8_t   dst[ETH_ALEN];
    uint8_t   src[ETH_ALEN];
    uint16_t tvlv_len;
    uint16_t  align;
} batadv_15_unicast_tvlv_packet;

#define BATADV_15_TVLV_HLEN sizeof(batadv_15_unicast_tvlv_packet)

#pragma pack()

#endif /* __DECODE_BATMAN_H__ */
