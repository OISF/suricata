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
 * \file decode-gre.h
 *
 * \author Breno Silva <breno.silva@gmail.com>
 *
 * Generic Route Encapsulation (GRE) from RFC 1701.
 */

#ifndef __DECODE_GRE_H__
#define __DECODE_GRE_H__

#ifndef IPPROTO_GRE
#define IPPROTO_GRE 47
#endif


typedef struct GREHdr_
{
    uint8_t flags; /**< GRE packet flags */
    uint8_t version; /**< GRE version */
    uint16_t ether_type; /**< ether type of the encapsulated traffic */

} __attribute__((__packed__)) GREHdr;

/* Enhanced GRE header - https://tools.ietf.org/html/rfc2637#section-4.1 */
typedef struct GREPPtPHdr_ {
    GREHdr greh;             /** base GRE packet header */
    uint16_t payload_length; /** PPP payload length */
    uint16_t call_id;        /** PPP peer id */
} __attribute__((__packed__)) GREPPtPHd;

/* Generic Routing Encapsulation Source Route Entries (SREs).
 * The header is followed by a variable amount of Routing Information.
 */
typedef struct GRESreHdr_
{
    uint16_t af; /**< Address family */
    uint8_t sre_offset;
    uint8_t sre_length;
} __attribute__((__packed__)) GRESreHdr;

#define GRE_VERSION_0           0x0000
#define GRE_VERSION_1           0x0001

#define GRE_HDR_LEN             4
#define GRE_CHKSUM_LEN          2
#define GRE_OFFSET_LEN          2
#define GRE_KEY_LEN             4
#define GRE_SEQ_LEN             4
#define GRE_SRE_HDR_LEN         4
#define GRE_PROTO_PPP           0x880b

#define GRE_FLAG_ISSET_CHKSUM(r)    (r->flags & 0x80)
#define GRE_FLAG_ISSET_ROUTE(r)     (r->flags & 0x40)
#define GRE_FLAG_ISSET_KY(r)        (r->flags & 0x20)
#define GRE_FLAG_ISSET_SQ(r)        (r->flags & 0x10)
#define GRE_FLAG_ISSET_SSR(r)       (r->flags & 0x08)
#define GRE_FLAG_ISSET_RECUR(r)     (r->flags & 0x07)
#define GRE_GET_VERSION(r)   (r->version & 0x07)
#define GRE_GET_FLAGS(r)     (r->version & 0xF8)
#define GRE_GET_PROTO(r)     SCNtohs(r->ether_type)

#define GREV1_HDR_LEN           8
#define GREV1_ACK_LEN           4
#define GREV1_FLAG_ISSET_FLAGS(r)  (r->version & 0x78)
#define GREV1_FLAG_ISSET_ACK(r)    (r->version & 0x80)

void DecodeGRERegisterTests(void);

#endif /* __DECODE_GRE_H__ */

