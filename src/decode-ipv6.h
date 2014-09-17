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

#ifndef __DECODE_IPV6_H__
#define __DECODE_IPV6_H__

#define IPV6_HEADER_LEN            40
#define	IPV6_MAXPACKET	           65535 /* maximum packet size */
#define IPV6_MAX_OPT               40

typedef struct IPV6Hdr_
{
    union {
        struct ip6_un1_ {
            uint32_t ip6_un1_flow; /* 20 bits of flow-ID */
            uint16_t ip6_un1_plen; /* payload length */
            uint8_t  ip6_un1_nxt;  /* next header */
            uint8_t  ip6_un1_hlim; /* hop limit */
        } ip6_un1;
        uint8_t ip6_un2_vfc;   /* 4 bits version, top 4 bits class */
    } ip6_hdrun;

    union {
        struct {
            uint32_t ip6_src[4];
            uint32_t ip6_dst[4];
        } ip6_un2;
        uint16_t ip6_addrs[16];
    } ip6_hdrun2;
} __attribute__((__packed__)) IPV6Hdr;

#define s_ip6_src                       ip6_hdrun2.ip6_un2.ip6_src
#define s_ip6_dst                       ip6_hdrun2.ip6_un2.ip6_dst
#define s_ip6_addrs                     ip6_hdrun2.ip6_addrs

#define s_ip6_vfc                       ip6_hdrun.ip6_un2_vfc
#define s_ip6_flow                      ip6_hdrun.ip6_un1.ip6_un1_flow
#define s_ip6_plen                      ip6_hdrun.ip6_un1.ip6_un1_plen
#define s_ip6_nxt                       ip6_hdrun.ip6_un1.ip6_un1_nxt
#define s_ip6_hlim                      ip6_hdrun.ip6_un1.ip6_un1_hlim

#define IPV6_GET_RAW_VER(ip6h)          (((ip6h)->s_ip6_vfc & 0xf0) >> 4)
#define IPV6_GET_RAW_CLASS(ip6h)        ((ntohl((ip6h)->s_ip6_flow) & 0x0FF00000) >> 20)
#define IPV6_GET_RAW_FLOW(ip6h)         (ntohl((ip6h)->s_ip6_flow) & 0x000FFFFF)
#define IPV6_GET_RAW_NH(ip6h)           ((ip6h)->s_ip6_nxt)
#define IPV6_GET_RAW_PLEN(ip6h)         (ntohs((ip6h)->s_ip6_plen))
#define IPV6_GET_RAW_HLIM(ip6h)         ((ip6h)->s_ip6_hlim)

#define IPV6_SET_RAW_VER(ip6h, value)   ((ip6h)->s_ip6_vfc = (((ip6h)->s_ip6_vfc & 0x0f) | (value << 4)))
#define IPV6_SET_RAW_NH(ip6h, value)    ((ip6h)->s_ip6_nxt = (value))

#define IPV6_SET_L4PROTO(p,proto)       (p)->ip6vars.l4proto = proto


/* ONLY call these functions after making sure that:
 * 1. p->ip6h is set
 * 2. p->ip6h is valid (len is correct)
 */
#define IPV6_GET_VER(p) \
    IPV6_GET_RAW_VER((p)->ip6h)
#define IPV6_GET_CLASS(p) \
    IPV6_GET_RAW_CLASS((p)->ip6h)
#define IPV6_GET_FLOW(p) \
    IPV6_GET_RAW_FLOW((p)->ip6h)
#define IPV6_GET_NH(p) \
    (IPV6_GET_RAW_NH((p)->ip6h))
#define IPV6_GET_PLEN(p) \
    IPV6_GET_RAW_PLEN((p)->ip6h)
#define IPV6_GET_HLIM(p) \
    (IPV6_GET_RAW_HLIM((p)->ip6h))
/* XXX */
#define IPV6_GET_L4PROTO(p) \
    ((p)->ip6vars.l4proto)

/** \brief get the highest proto/next header field we know */
//#define IPV6_GET_UPPER_PROTO(p)         (p)->ip6eh.ip6_exthdrs_cnt ?
//    (p)->ip6eh.ip6_exthdrs[(p)->ip6eh.ip6_exthdrs_cnt - 1].next : IPV6_GET_NH((p))

/* helper structure with parsed ipv6 info */
typedef struct IPV6Vars_
{
    uint8_t ip_opts_len;
    uint8_t l4proto;      /* the proto after the extension headers
                            * store while decoding so we don't have
                            * to loop through the exthdrs all the time */
} IPV6Vars;

#define CLEAR_IPV6_PACKET(p) do { \
    (p)->ip6h = NULL; \
    (p)->ip6vars.ip_opts_len = 0; \
    (p)->ip6vars.l4proto = 0; \
    (p)->ip6eh.ip6fh = NULL; \
    (p)->ip6eh.fh_offset = 0; \
    (p)->ip6eh.ip6rh = NULL; \
    (p)->ip6eh.ip6eh = NULL; \
    (p)->ip6eh.ip6dh1 = NULL; \
    (p)->ip6eh.ip6dh2 = NULL; \
    (p)->ip6eh.ip6hh = NULL; \
    (p)->ip6eh.ip6_exthdrs_cnt = 0; \
} while (0)

/* Fragment header */
typedef struct IPV6FragHdr_
{
    uint8_t  ip6fh_nxt;             /* next header */
    uint8_t  ip6fh_reserved;        /* reserved field */
    uint16_t ip6fh_offlg;           /* offset, reserved, and flag */
    uint32_t ip6fh_ident;           /* identification */
} __attribute__((__packed__)) IPV6FragHdr;

#define IPV6_EXTHDR_GET_RAW_FH_NH(p)        ((p)->ip6eh.ip6fh->ip6fh_nxt)
#define IPV6_EXTHDR_GET_RAW_FH_HDRLEN(p)    sizeof(IPV6FragHdr)
#define IPV6_EXTHDR_GET_RAW_FH_OFFSET(p)    (ntohs((p)->ip6eh.ip6fh->ip6fh_offlg) & 0xFFF8)
#define IPV6_EXTHDR_GET_RAW_FH_FLAG(p)      (ntohs((p)->ip6eh.ip6fh->ip6fh_offlg) & 0x0001)
#define IPV6_EXTHDR_GET_RAW_FH_ID(p)        (ntohl((p)->ip6eh.ip6fh->ip6fh_ident))

#define IPV6_EXTHDR_GET_FH_NH(p)            IPV6_EXTHDR_GET_RAW_FH_NH((p))
#define IPV6_EXTHDR_GET_FH_HDRLEN(p)        IPV6_EXTHDR_GET_RAW_FH_HDRLEN((p))
#define IPV6_EXTHDR_GET_FH_OFFSET(p)        IPV6_EXTHDR_GET_RAW_FH_OFFSET((p))
#define IPV6_EXTHDR_GET_FH_FLAG(p)          IPV6_EXTHDR_GET_RAW_FH_FLAG((p))
#define IPV6_EXTHDR_GET_FH_ID(p)            IPV6_EXTHDR_GET_RAW_FH_ID((p))

/* rfc 1826 */
typedef struct IPV6AuthHdr_
{
    uint8_t ip6ah_nxt;              /* next header */
    uint8_t ip6ah_len;              /* header length in units of 8 bytes, not
                                        including first 8 bytes. */
    uint16_t ip6ah_reserved;        /* reserved for future use */
    uint32_t ip6ah_spi;             /* SECURITY PARAMETERS INDEX (SPI) */
    uint32_t ip6ah_seq;             /* sequence number */
} __attribute__((__packed__)) IPV6AuthHdr;

typedef struct IPV6EspHdr_
{
    uint32_t ip6esph_spi;           /* SECURITY PARAMETERS INDEX (SPI) */
    uint32_t ip6esph_seq;           /* sequence number */
} __attribute__((__packed__)) IPV6EspHdr;

typedef struct IPV6RouteHdr_
{
    uint8_t ip6rh_nxt;               /* next header */
    uint8_t ip6rh_len;               /* header length in units of 8 bytes, not
                                        including first 8 bytes. */
    uint8_t ip6rh_type;              /* routing type */
    uint8_t ip6rh_segsleft;          /* segments left */
#if 0
    struct in6_addr ip6rh0_addr[23];  /* type 0 addresses */
    uint8_t ip6rh0_num_addrs;        /* number of actual addresses in the
                                        array/packet. The array is guarranteed
                                        to be filled up to this number. */
#endif
} __attribute__((__packed__)) IPV6RouteHdr;

#define IPV6_EXTHDR_GET_RAW_RH_NH(p)        ((p)->ip6eh.ip6rh->ip6rh_nxt)
#define IPV6_EXTHDR_GET_RAW_RH_HDRLEN(p)    ((p)->ip6eh.ip6rh->ip6rh_len)
#define IPV6_EXTHDR_GET_RAW_RH_TYPE(p)      (ntohs((p)->ip6eh.ip6rh->ip6rh_type))
/* XXX */

#define IPV6_EXTHDR_GET_RH_NH(p)            IPV6_EXTHDR_GET_RAW_RH_NH((p))
#define IPV6_EXTHDR_GET_RH_HDRLEN(p)        IPV6_EXTHDR_GET_RAW_RH_HDRLEN((p))
#define IPV6_EXTHDR_GET_RH_TYPE(p)          IPV6_EXTHDR_GET_RAW_RH_TYPE((p))
/* XXX */


/* Hop-by-Hop header and Destination Options header use options that are
 * defined here. */

#define IPV6OPT_PAD1                  0x00
#define IPV6OPT_PADN                  0x01
#define IPV6OPT_RA                    0x05
#define IPV6OPT_JUMBO                 0xC2
#define IPV6OPT_HAO                   0xC9

/* Home Address Option */
typedef struct IPV6OptHAO_
{
    uint8_t ip6hao_type;             /* Option type */
    uint8_t ip6hao_len;              /* Option Data len (excludes type and len) */
    struct in6_addr ip6hao_hoa;       /* Home address. */
} IPV6OptHAO;

/* Router Alert Option */
typedef struct IPV6OptRA_
{
    uint8_t ip6ra_type;             /* Option type */
    uint8_t ip6ra_len;              /* Option Data len (excludes type and len) */
    uint16_t ip6ra_value;           /* Router Alert value */
} IPV6OptRA;

/* Jumbo Option */
typedef struct IPV6OptJumbo_
{
    uint8_t ip6j_type;             /* Option type */
    uint8_t ip6j_len;              /* Option Data len (excludes type and len) */
    uint32_t ip6j_payload_len;     /* Jumbo Payload Length */
} IPV6OptJumbo;

typedef struct IPV6HopOptsHdr_
{
    uint8_t ip6hh_nxt;              /* next header */
    uint8_t ip6hh_len;              /* header length in units of 8 bytes, not
                                       including first 8 bytes. */
} __attribute__((__packed__)) IPV6HopOptsHdr;

#define IPV6_EXTHDR_GET_RAW_HH_NH(p)        ((p)->ip6eh.ip6hh->ip6hh_nxt)
#define IPV6_EXTHDR_GET_RAW_HH_HDRLEN(p)    ((p)->ip6eh.ip6hh->ip6hh_len)
/* XXX */

#define IPV6_EXTHDR_GET_HH_NH(p)            IPV6_EXTHDR_GET_RAW_HH_NH((p))
#define IPV6_EXTHDR_GET_HH_HDRLEN(p)        IPV6_EXTHDR_GET_RAW_HH_HDRLEN((p))
/* XXX */

typedef struct IPV6DstOptsHdr_
{
    uint8_t ip6dh_nxt;              /* next header */
    uint8_t ip6dh_len;              /* header length in units of 8 bytes, not
                                       including first 8 bytes. */
} __attribute__((__packed__)) IPV6DstOptsHdr;

#define IPV6_EXTHDR_GET_RAW_DH1_NH(p)        ((p)->ip6eh.ip6dh1->ip6dh_nxt)
#define IPV6_EXTHDR_GET_RAW_DH1_HDRLEN(p)    ((p)->ip6eh.ip6dh1->ip6dh_len)
/* XXX */

#define IPV6_EXTHDR_GET_DH1_NH(p)            IPV6_EXTHDR_GET_RAW_DH1_NH((p))
#define IPV6_EXTHDR_GET_DH1_HDRLEN(p)        IPV6_EXTHDR_GET_RAW_DH1_HDRLEN((p))
/* XXX */

#define IPV6_EXTHDR_GET_RAW_DH2_NH(p)        ((p)->ip6eh.ip6dh2->ip6dh_nxt)
#define IPV6_EXTHDR_GET_RAW_DH2_HDRLEN(p)    ((p)->ip6eh.ip6dh2->ip6dh_len)
/* XXX */

#define IPV6_EXTHDR_GET_DH2_NH(p)            IPV6_EXTHDR_GET_RAW_DH2_NH((p))
#define IPV6_EXTHDR_GET_DH2_HDRLEN(p)        IPV6_EXTHDR_GET_RAW_DH2_HDRLEN((p))
/* XXX */

typedef struct IPV6GenOptHdr_
{
    uint8_t type;
    uint8_t next;
    uint8_t len;
    uint8_t *data;
}   IPV6GenOptHdr;

typedef struct IPV6ExtHdrs_
{
    const IPV6FragHdr    *ip6fh;
    /* In fh_offset we store the offset of this extension into the packet past
     * the ipv6 header. We use it in defrag for creating a defragmented packet
     * without the frag header */
    uint16_t      fh_offset;

    const IPV6RouteHdr   *ip6rh;
    const IPV6AuthHdr    *ip6ah;
    const IPV6EspHdr     *ip6eh;
    const IPV6DstOptsHdr *ip6dh1;
    const IPV6DstOptsHdr *ip6dh2;
    const IPV6HopOptsHdr *ip6hh;

    /* Hop-By-Hop options */
    IPV6OptHAO ip6hh_opt_hao;
    IPV6OptRA ip6hh_opt_ra;
    IPV6OptJumbo ip6hh_opt_jumbo;
    /* Dest Options 1 */
    IPV6OptHAO ip6dh1_opt_hao;
    IPV6OptRA ip6dh1_opt_ra;
    IPV6OptJumbo ip6dh1_opt_jumbo;
    /* Dest Options 2 */
    IPV6OptHAO ip6dh2_opt_hao;
    IPV6OptRA ip6dh2_opt_ra;
    IPV6OptJumbo ip6dh2_opt_jumbo;

    IPV6GenOptHdr ip6_exthdrs[IPV6_MAX_OPT];
    uint8_t ip6_exthdrs_cnt;

} IPV6ExtHdrs;

#define IPV6_EXTHDR_FH(p)             (p)->ip6eh.ip6fh
#define IPV6_EXTHDR_RH(p)             (p)->ip6eh.ip6rh
#define IPV6_EXTHDR_AH(p)             (p)->ip6eh.ip6ah
#define IPV6_EXTHDR_EH(p)             (p)->ip6eh.ip6eh
#define IPV6_EXTHDR_DH1(p)            (p)->ip6eh.ip6dh1
#define IPV6_EXTHDR_DH2(p)            (p)->ip6eh.ip6dh2
#define IPV6_EXTHDR_HH(p)             (p)->ip6eh.ip6hh

#define IPV6_EXTHDR_HH_HAO(p)         (p)->ip6eh.ip6hh_opt_hao
#define IPV6_EXTHDR_DH1_HAO(p)        (p)->ip6eh.ip6dh1_opt_hao
#define IPV6_EXTHDR_DH2_HAO(p)        (p)->ip6eh.ip6dh2_opt_hao
#define IPV6_EXTHDR_HH_RA(p)          (p)->ip6eh.ip6hh_opt_ra
#define IPV6_EXTHDR_DH1_RA(p)         (p)->ip6eh.ip6dh1_opt_ra
#define IPV6_EXTHDR_DH2_RA(p)         (p)->ip6eh.ip6dh2_opt_ra
#define IPV6_EXTHDR_HH_JUMBO(p)       (p)->ip6eh.ip6hh_opt_jumbo
#define IPV6_EXTHDR_DH1_JUMBO(p)      (p)->ip6eh.ip6dh1_opt_jumbo
#define IPV6_EXTHDR_DH2_JUMBO(p)      (p)->ip6eh.ip6dh2_opt_jumbo

#define IPV6_EXTHDR_SET_FH(p,pkt)     IPV6_EXTHDR_FH((p)) = (IPV6FragHdr *)pkt
#define IPV6_EXTHDR_ISSET_FH(p)       (IPV6_EXTHDR_FH((p)) != NULL)
#define IPV6_EXTHDR_SET_RH(p,pkt)     IPV6_EXTHDR_RH((p)) = (IPV6RouteHdr *)pkt
#define IPV6_EXTHDR_ISSET_RH(p)       (IPV6_EXTHDR_RH((p)) != NULL)
#define IPV6_EXTHDR_SET_AH(p,pkt)     IPV6_EXTHDR_AH((p)) = (IPV6AuthHdr *)pkt
#define IPV6_EXTHDR_ISSET_AH(p)       (IPV6_EXTHDR_AH((p)) != NULL)
#define IPV6_EXTHDR_SET_EH(p,pkt)     IPV6_EXTHDR_EH((p)) = (IPV6EspHdr *)pkt
#define IPV6_EXTHDR_ISSET_EH(p)       (IPV6_EXTHDR_EH((p)) != NULL)
#define IPV6_EXTHDR_SET_DH1(p,pkt)    IPV6_EXTHDR_DH1((p)) = (IPV6DstOptsHdr *)pkt
#define IPV6_EXTHDR_ISSET_DH1(p)      (IPV6_EXTHDR_DH1((p)) != NULL)
#define IPV6_EXTHDR_SET_DH2(p,pkt)    IPV6_EXTHDR_DH2((p)) = (IPV6DstOptsHdr *)pkt
#define IPV6_EXTHDR_ISSET_DH2(p)      (IPV6_EXTHDR_DH2((p)) != NULL)
#define IPV6_EXTHDR_SET_HH(p,pkt)     IPV6_EXTHDR_HH((p)) = (IPV6HopOptsHdr *)pkt
#define IPV6_EXTHDR_ISSET_HH(p)       (IPV6_EXTHDR_HH((p)) != NULL)

void DecodeIPV6RegisterTests(void);

#endif /* __DECODE_IPV6_H__ */

