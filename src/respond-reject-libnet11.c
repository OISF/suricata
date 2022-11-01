/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 *  \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *  \author William Metcalf <william.metcalf@gmail.com>
 *
 *  RespondRejectLibnet11 used to send out libnet based
 *  TCP resets and ICMP unreachables.
 *
 *  \todo calculate TTL base on average from stream tracking
 *  \todo come up with a way for users to specify icmp unreachable type
 *  \todo Possibly default to port unreachable for UDP traffic this seems
 *        to be the default in flexresp and iptables
 *  \todo implement ipv6 resets
 *  \todo implement pre-alloc resets for speed
 */

#include "suricata-common.h"
#include "suricata.h"

#include "decode.h"
#include "respond-reject.h"
#include "respond-reject-libnet11.h"
#include "util-device.h"

#ifdef HAVE_LIBNET11

#ifndef HAVE_LIBNET_INIT_CONST
#define LIBNET_INIT_CAST (char *)
#else
#define LIBNET_INIT_CAST
#endif

/* Globally configured device to use for sending resets in IDS mode. */
const char *g_reject_dev = NULL;
uint16_t g_reject_dev_mtu = 0;

/** set to true in main if we're setting caps. We need it here if we're using
  * reject rules as libnet 1.1 is not compatible with caps. */
extern int sc_set_caps;

#include <libnet.h>

thread_local libnet_t *t_c = NULL;
thread_local int t_inject_mode = -1;

typedef struct Libnet11Packet_ {
    uint32_t ack, seq;
    uint16_t window, dsize;
    uint8_t ttl;
    uint16_t id;
    uint32_t flow;
    uint8_t class;
    struct libnet_in6_addr src6, dst6;
    uint32_t src4, dst4;
    uint16_t sp, dp;
    uint16_t len;
    uint8_t *smac, *dmac;
} Libnet11Packet;

static inline libnet_t *GetCtx(const Packet *p, int injection_type)
{
    /* fast path: use cache ctx */
    if (t_c)
        return t_c;

    /* slow path: setup a new ctx */
    bool store_ctx = false;
    const char *devname = NULL;
    extern uint8_t host_mode;
    if (IS_SURI_HOST_MODE_SNIFFER_ONLY(host_mode)) {
        if (g_reject_dev != NULL) {
            if (p->datalink == LINKTYPE_ETHERNET)
                injection_type = t_inject_mode = LIBNET_LINK;
            devname = g_reject_dev;
            store_ctx = true;
        } else {
            devname = p->livedev ? p->livedev->dev : NULL;
        }
    }

    char ebuf[LIBNET_ERRBUF_SIZE];
    libnet_t *c = libnet_init(injection_type, LIBNET_INIT_CAST devname, ebuf);
    if (c == NULL) {
        SCLogError(SC_ERR_LIBNET_INIT,"libnet_init failed: %s", ebuf);
    }
    if (store_ctx) {
        t_c = c;
    }
    return c;
}

static inline void ClearCtx(libnet_t *c)
{
    if (t_c == c)
        libnet_clear_packet(c);
    else
        libnet_destroy(c);
}

void FreeCachedCtx(void)
{
    if (t_c) {
        libnet_destroy(t_c);
        t_c = NULL;
    }
}

static inline void SetupTCP(Packet *p, Libnet11Packet *lpacket, enum RejectDirection dir)
{
    switch (dir) {
        case REJECT_DIR_SRC:
            SCLogDebug("sending a tcp reset to src");
            /* We follow http://tools.ietf.org/html/rfc793#section-3.4 :
             *  If packet has no ACK, the seq number is 0 and the ACK is built
             *  the normal way. If packet has a ACK, the seq of the RST packet
             *  is equal to the ACK of incoming packet and the ACK is build
             *  using packet sequence number and size of the data. */
            if (TCP_GET_ACK(p) == 0) {
                lpacket->seq = 0;
                lpacket->ack = TCP_GET_SEQ(p) + lpacket->dsize + 1;
            } else {
                lpacket->seq = TCP_GET_ACK(p);
                lpacket->ack = TCP_GET_SEQ(p) + lpacket->dsize;
            }

            lpacket->sp = TCP_GET_DST_PORT(p);
            lpacket->dp = TCP_GET_SRC_PORT(p);
            break;
        case REJECT_DIR_DST:
        default:
            SCLogDebug("sending a tcp reset to dst");
            lpacket->seq = TCP_GET_SEQ(p);
            lpacket->ack = TCP_GET_ACK(p);

            lpacket->sp = TCP_GET_SRC_PORT(p);
            lpacket->dp = TCP_GET_DST_PORT(p);
            break;
    }
    lpacket->window = TCP_GET_WINDOW(p);
    //lpacket.seq += lpacket.dsize;
}

static inline int BuildTCP(libnet_t *c, Libnet11Packet *lpacket)
{
    /* build the package */
    if ((libnet_build_tcp(
                    lpacket->sp,           /* source port */
                    lpacket->dp,           /* dst port */
                    lpacket->seq,          /* seq number */
                    lpacket->ack,          /* ack number */
                    TH_RST|TH_ACK,         /* flags */
                    lpacket->window,       /* window size */
                    0,                     /* checksum */
                    0,                     /* urgent flag */
                    LIBNET_TCP_H,          /* header length */
                    NULL,                  /* payload */
                    0,                     /* payload length */
                    c,                     /* libnet context */
                    0)) < 0)               /* libnet ptag */
    {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_tcp %s", libnet_geterror(c));
        return -1;
    }
    return 0;
}

static inline int BuildIPv4(libnet_t *c, Libnet11Packet *lpacket, const uint8_t proto)
{
    if ((libnet_build_ipv4(
                    lpacket->len,                 /* entire packet length */
                    0,                            /* tos */
                    lpacket->id,                  /* ID */
                    0,                            /* fragmentation flags and offset */
                    lpacket->ttl,                 /* TTL */
                    proto,                        /* protocol */
                    0,                            /* checksum */
                    lpacket->src4,                /* source address */
                    lpacket->dst4,                /* destination address */
                    NULL,                         /* pointer to packet data (or NULL) */
                    0,                            /* payload length */
                    c,                            /* libnet context pointer */
                    0)) < 0)                      /* packet id */
    {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_ipv4 %s", libnet_geterror(c));
        return -1;
    }
    return 0;
}

static inline int BuildIPv6(libnet_t *c, Libnet11Packet *lpacket, const uint8_t proto)
{
    if ((libnet_build_ipv6(
                    lpacket->class,               /* traffic class */
                    lpacket->flow,                /* Flow label */
                    lpacket->len,                 /* payload length */
                    proto,                        /* next header */
                    lpacket->ttl,                 /* TTL */
                    lpacket->src6,                /* source address */
                    lpacket->dst6,                /* destination address */
                    NULL,                         /* pointer to packet data (or NULL) */
                    0,                            /* payload length */
                    c,                            /* libnet context pointer */
                    0)) < 0)                      /* packet id */
    {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_ipv6 %s", libnet_geterror(c));
        return -1;
    }
    return 0;
}

static inline void SetupEthernet(Packet *p, Libnet11Packet *lpacket, enum RejectDirection dir)
{
    switch (dir) {
        case REJECT_DIR_SRC:
            lpacket->smac = p->ethh->eth_dst;
            lpacket->dmac = p->ethh->eth_src;
            break;
        case REJECT_DIR_DST:
        default:
            lpacket->smac = p->ethh->eth_src;
            lpacket->dmac = p->ethh->eth_dst;
            break;
    }
}

static inline int BuildEthernet(libnet_t *c, Libnet11Packet *lpacket, uint16_t proto)
{
    if ((libnet_build_ethernet(lpacket->dmac,lpacket->smac, proto , NULL, 0, c, 0)) < 0) {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_ethernet %s", libnet_geterror(c));
        return -1;
    }
    return 0;
}

static inline int BuildEthernetVLAN(libnet_t *c, Libnet11Packet *lpacket, uint16_t proto, uint16_t vlan_id)
{
    if (libnet_build_802_1q(
                lpacket->dmac, lpacket->smac, ETHERTYPE_VLAN,
                0x000, 0x000, vlan_id, proto,
                NULL,                                   /* payload */
                0,                                      /* payload size */
                c,                                      /* libnet handle */
                0) < 0)
    {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_802_1q %s", libnet_geterror(c));
        return -1;
    }
    return 0;
}

int RejectSendLibnet11IPv4TCP(ThreadVars *tv, Packet *p, void *data, enum RejectDirection dir)
{
    Libnet11Packet lpacket;
    int result;

    /* fill in struct defaults */
    lpacket.ttl = 0;
    lpacket.id = 0;
    lpacket.flow = 0;
    lpacket.class = 0;

    if (p->tcph == NULL)
        return 1;

    libnet_t *c = GetCtx(p, LIBNET_RAW4);
    if (c == NULL)
        return 1;

    lpacket.len = LIBNET_IPV4_H + LIBNET_TCP_H;
    lpacket.dsize = p->payload_len;

    switch (dir) {
        case REJECT_DIR_SRC:
            lpacket.src4 = GET_IPV4_DST_ADDR_U32(p);
            lpacket.dst4 = GET_IPV4_SRC_ADDR_U32(p);
            break;
        case REJECT_DIR_DST:
        default:
            lpacket.src4 = GET_IPV4_SRC_ADDR_U32(p);
            lpacket.dst4 = GET_IPV4_DST_ADDR_U32(p);
            break;
    }
    /* TODO come up with ttl calc function */
    lpacket.ttl = 64;

    SetupTCP(p, &lpacket, dir);

    if (BuildTCP(c, &lpacket) < 0)
        goto cleanup;

    if (BuildIPv4(c, &lpacket, IPPROTO_TCP) < 0)
        goto cleanup;

    if (t_inject_mode == LIBNET_LINK) {
        SetupEthernet(p, &lpacket, dir);

        if (p->vlan_idx == 1) {
            if (BuildEthernetVLAN(c, &lpacket, ETHERNET_TYPE_IP, p->vlan_id[0]) < 0)
                goto cleanup;
        } else {
            if (BuildEthernet(c, &lpacket, ETHERNET_TYPE_IP) < 0)
                goto cleanup;
        }
    }

    result = libnet_write(c);
    if (result == -1) {
        SCLogError(SC_ERR_LIBNET_WRITE_FAILED,"libnet_write failed: %s", libnet_geterror(c));
        goto cleanup;
    }

cleanup:
    ClearCtx(c);
    return 0;
}

int RejectSendLibnet11IPv4ICMP(ThreadVars *tv, Packet *p, void *data, enum RejectDirection dir)
{
    Libnet11Packet lpacket;
    int result;

    /* fill in struct defaults */
    lpacket.ttl = 0;
    lpacket.id = 0;
    lpacket.flow = 0;
    lpacket.class = 0;
    const uint16_t iplen = IPV4_GET_IPLEN(p);
    if (g_reject_dev_mtu >= ETHERNET_HEADER_LEN + LIBNET_IPV4_H + 8) {
        lpacket.len = MIN(g_reject_dev_mtu - ETHERNET_HEADER_LEN, (LIBNET_IPV4_H + iplen));
    } else {
        lpacket.len = LIBNET_IPV4_H + MIN(8,iplen); // 8 bytes is the minimum we have to attach
    }
    lpacket.dsize = lpacket.len - (LIBNET_IPV4_H + LIBNET_ICMPV4_H);

    libnet_t *c = GetCtx(p, LIBNET_RAW4);
    if (c == NULL)
        return 1;

    switch (dir) {
        case REJECT_DIR_SRC:
            lpacket.src4 = GET_IPV4_DST_ADDR_U32(p);
            lpacket.dst4 = GET_IPV4_SRC_ADDR_U32(p);
            break;
        case REJECT_DIR_DST:
        default:
            lpacket.src4 = GET_IPV4_SRC_ADDR_U32(p);
            lpacket.dst4 = GET_IPV4_DST_ADDR_U32(p);
            break;
    }

    /* TODO come up with ttl calc function */
    lpacket.ttl = 64;

    /* build the package */
    if ((libnet_build_icmpv4_unreach(
                    ICMP_DEST_UNREACH,        /* type */
                    ICMP_HOST_ANO,            /* code */
                    0,                        /* checksum */
                    (uint8_t *)p->ip4h,       /* payload */
                    lpacket.dsize,            /* payload length */
                    c,                        /* libnet context */
                    0)) < 0)                  /* libnet ptag */
    {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_icmpv4_unreach %s", libnet_geterror(c));
        goto cleanup;
    }

    if (BuildIPv4(c, &lpacket, IPPROTO_ICMP) < 0)
        goto cleanup;

    if (t_inject_mode == LIBNET_LINK) {
        SetupEthernet(p, &lpacket, dir);

        if (p->vlan_idx == 1) {
            if (BuildEthernetVLAN(c, &lpacket, ETHERNET_TYPE_IP, p->vlan_id[0]) < 0)
                goto cleanup;
        } else {
            if (BuildEthernet(c, &lpacket, ETHERNET_TYPE_IP) < 0)
                goto cleanup;
        }
    }

    result = libnet_write(c);
    if (result == -1) {
        SCLogError(SC_ERR_LIBNET_WRITE_FAILED,"libnet_write_raw_ipv4 failed: %s", libnet_geterror(c));
        goto cleanup;
    }

cleanup:
    ClearCtx(c);
    return 0;
}

int RejectSendLibnet11IPv6TCP(ThreadVars *tv, Packet *p, void *data, enum RejectDirection dir)
{
    Libnet11Packet lpacket;
    int result;

    /* fill in struct defaults */
    lpacket.ttl = 0;
    lpacket.id = 0;
    lpacket.flow = 0;
    lpacket.class = 0;

    if (p->tcph == NULL)
       return 1;

    libnet_t *c = GetCtx(p, LIBNET_RAW6);
    if (c == NULL)
        return 1;

    lpacket.len = LIBNET_IPV6_H + LIBNET_TCP_H;
    lpacket.dsize = p->payload_len;

    switch (dir) {
        case REJECT_DIR_SRC:
            memcpy(lpacket.src6.libnet_s6_addr, GET_IPV6_DST_ADDR(p), 16);
            memcpy(lpacket.dst6.libnet_s6_addr, GET_IPV6_SRC_ADDR(p), 16);
            break;
        case REJECT_DIR_DST:
        default:
            memcpy(lpacket.src6.libnet_s6_addr, GET_IPV6_SRC_ADDR(p), 16);
            memcpy(lpacket.dst6.libnet_s6_addr, GET_IPV6_DST_ADDR(p), 16);
            break;
    }
    /* TODO come up with ttl calc function */
    lpacket.ttl = 64;

    SetupTCP(p, &lpacket, dir);

    BuildTCP(c, &lpacket);

    if (BuildIPv6(c, &lpacket, IPPROTO_ICMP) < 0)
        goto cleanup;

    if (t_inject_mode == LIBNET_LINK) {
        SetupEthernet(p, &lpacket, dir);
        if (p->vlan_idx == 1) {
            if (BuildEthernetVLAN(c, &lpacket, ETHERNET_TYPE_IPV6, p->vlan_id[0]) < 0)
                goto cleanup;
        } else {
            if (BuildEthernet(c, &lpacket, ETHERNET_TYPE_IPV6) < 0)
                goto cleanup;
        }
    }

    result = libnet_write(c);
    if (result == -1) {
        SCLogError(SC_ERR_LIBNET_WRITE_FAILED,"libnet_write failed: %s", libnet_geterror(c));
        goto cleanup;
    }

cleanup:
    ClearCtx(c);
    return 0;
}

#ifdef HAVE_LIBNET_ICMPV6_UNREACH
int RejectSendLibnet11IPv6ICMP(ThreadVars *tv, Packet *p, void *data, enum RejectDirection dir)
{
    Libnet11Packet lpacket;
    int result;

    /* fill in struct defaults */
    lpacket.ttl = 0;
    lpacket.id = 0;
    lpacket.flow = 0;
    lpacket.class = 0;
    const uint16_t iplen = IPV6_GET_PLEN(p);
    if (g_reject_dev_mtu >= ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 8) {
        lpacket.len = IPV6_HEADER_LEN + MIN(g_reject_dev_mtu - ETHERNET_HEADER_LEN, iplen);
    } else {
        lpacket.len = IPV6_HEADER_LEN + MIN(8, iplen);
    }
    lpacket.dsize = lpacket.len - LIBNET_ICMPV6_H;

    libnet_t *c = GetCtx(p, LIBNET_RAW6);
    if (c == NULL)
        return 1;

    switch (dir) {
        case REJECT_DIR_SRC:
            memcpy(lpacket.src6.libnet_s6_addr, GET_IPV6_DST_ADDR(p), 16);
            memcpy(lpacket.dst6.libnet_s6_addr, GET_IPV6_SRC_ADDR(p), 16);
            break;
        case REJECT_DIR_DST:
        default:
            memcpy(lpacket.src6.libnet_s6_addr, GET_IPV6_SRC_ADDR(p), 16);
            memcpy(lpacket.dst6.libnet_s6_addr, GET_IPV6_DST_ADDR(p), 16);
            break;
    }

    /* TODO come up with ttl calc function */
    lpacket.ttl = 64;

    /* build the package */
    if ((libnet_build_icmpv6_unreach(
                    ICMP6_DST_UNREACH,        /* type */
                    ICMP6_DST_UNREACH_ADMIN,  /* code */
                    0,                        /* checksum */
                    (uint8_t *)p->ip6h,       /* payload */
                    lpacket.dsize,            /* payload length */
                    c,                        /* libnet context */
                    0)) < 0)                  /* libnet ptag */
    {
        SCLogError(SC_ERR_LIBNET_BUILD_FAILED,"libnet_build_icmpv6_unreach %s", libnet_geterror(c));
        goto cleanup;
    }

    if (BuildIPv6(c, &lpacket, IPPROTO_ICMPV6) < 0)
        goto cleanup;

    if (t_inject_mode == LIBNET_LINK) {
        SetupEthernet(p, &lpacket, dir);
        if (p->vlan_idx == 1) {
            if (BuildEthernetVLAN(c, &lpacket, ETHERNET_TYPE_IPV6, p->vlan_id[0]) < 0)
                goto cleanup;
        } else {
            if (BuildEthernet(c, &lpacket, ETHERNET_TYPE_IPV6) < 0)
                goto cleanup;
        }
    }

    result = libnet_write(c);
    if (result == -1) {
        SCLogError(SC_ERR_LIBNET_WRITE_FAILED,"libnet_write_raw_ipv6 failed: %s", libnet_geterror(c));
        goto cleanup;
    }

cleanup:
    ClearCtx(c);
    return 0;
}

#else /* HAVE_LIBNET_ICMPV6_UNREACH */

int RejectSendLibnet11IPv6ICMP(ThreadVars *tv, Packet *p, void *data, enum RejectDirection dir)
{
    SCLogError(SC_ERR_LIBNET_NOT_ENABLED, "Libnet ICMPv6 based rejects are disabled."
                "Usually this means that you don't have a patched libnet installed,"
                " or configure couldn't find it.");
    return 0;
}
#endif /* HAVE_LIBNET_ICMPV6_UNREACH */


#else

int RejectSendLibnet11IPv4TCP(ThreadVars *tv, Packet *p, void *data, enum RejectDirection dir)
{
    SCLogError(SC_ERR_LIBNET_NOT_ENABLED, "Libnet based rejects are disabled."
                "Usually this means that you don't have libnet installed,"
                " or configure couldn't find it.");
    return 0;
}

int RejectSendLibnet11IPv4ICMP(ThreadVars *tv, Packet *p, void *data, enum RejectDirection dir)
{
    SCLogError(SC_ERR_LIBNET_NOT_ENABLED, "Libnet based rejects are disabled."
                "Usually this means that you don't have libnet installed,"
                " or configure couldn't find it.");
    return 0;
}

int RejectSendLibnet11IPv6TCP(ThreadVars *tv, Packet *p, void *data, enum RejectDirection dir)
{
    SCLogError(SC_ERR_LIBNET_NOT_ENABLED, "Libnet based rejects are disabled."
                "Usually this means that you don't have libnet installed,"
                " or configure couldn't find it.");
    return 0;
}

int RejectSendLibnet11IPv6ICMP(ThreadVars *tv, Packet *p, void *data, enum RejectDirection dir)
{
    SCLogError(SC_ERR_LIBNET_NOT_ENABLED, "Libnet based rejects are disabled."
                "Usually this means that you don't have libnet installed,"
                " or configure couldn't find it.");
    return 0;
}

void FreeCachedCtx(void)
{
    SCLogDebug("no libhnet support");
}

#endif /* HAVE_LIBNET11 */
