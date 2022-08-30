/* Copyright (C) 2018-2022 Open Information Security Foundation
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

#include <stddef.h>
#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/filter.h>

#include "bpf_helpers.h"

/* vlan tracking: set it to 0 if you don't use VLAN for flow tracking */
#define VLAN_TRACKING    1

#define LINUX_VERSION_CODE 263682

struct flowv4_keys {
    __u32 src;
    __u32 dst;
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u8 ip_proto:1;
    __u16 vlan0:15;
    __u16 vlan1;
};

struct flowv6_keys {
    __u32 src[4];
    __u32 dst[4];
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u8 ip_proto:1;
    __u16 vlan0:15;
    __u16 vlan1;
};

struct pair {
    __u64 packets;
    __u64 bytes;
};

struct bpf_map_def SEC("maps") flow_table_v4 = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(struct flowv4_keys),
    .value_size = sizeof(struct pair),
    .max_entries = 32768,
};

struct bpf_map_def SEC("maps") flow_table_v6 = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(struct flowv6_keys),
    .value_size = sizeof(struct pair),
    .max_entries = 32768,
};

struct vlan_hdr {
    __u16	h_vlan_TCI;
    __u16	h_vlan_encapsulated_proto;
};

/**
 * IPv4 filter
 *
 * \return 0 to drop packet out and -1 to accept it
 */
static __always_inline int ipv4_filter(struct __sk_buff *skb, __u16 vlan0, __u16 vlan1)
{
    __u32 nhoff, verlen;
    struct flowv4_keys tuple;
    struct pair *value;
    __u16 port;
    __u8 ip_proto;

    nhoff = skb->cb[0];

    ip_proto = load_byte(skb, nhoff + offsetof(struct iphdr, protocol));
    /* only support TCP and UDP for now */
    switch (ip_proto) {
        case IPPROTO_TCP:
            tuple.ip_proto = 1;
            break;
        case IPPROTO_UDP:
            tuple.ip_proto = 0;
            break;
        default:
            return -1;
    }
    
    tuple.src = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
    tuple.dst = load_word(skb, nhoff + offsetof(struct iphdr, daddr));

    verlen = load_byte(skb, nhoff + 0/*offsetof(struct iphdr, ihl)*/);
    nhoff += (verlen & 0xF) << 2;
    tuple.ports = load_word(skb, nhoff);
    port = tuple.port16[1];
    tuple.port16[1] = tuple.port16[0];
    tuple.port16[0] = port;
    tuple.vlan0 = vlan0;
    tuple.vlan1 = vlan1;

#if 0
    if ((tuple.port16[0] == 22) || (tuple.port16[1] == 22))
    {
        __u16 sp = tuple.port16[0];
        //__u16 dp = tuple.port16[1];
        char fmt[] = "Parsed SSH flow: %u %d -> %u\n";
        bpf_trace_printk(fmt, sizeof(fmt), tuple.src, sp, tuple.dst);
    }
#endif
    /* Test if src is in hash */
    value = bpf_map_lookup_elem(&flow_table_v4, &tuple);
    if (value) {
#if 0
        {
            __u16 sp = tuple.port16[0];
            //__u16 dp = tuple.port16[1];
            char bfmt[] = "Found flow: %u %d -> %u\n";
            bpf_trace_printk(bfmt, sizeof(bfmt), tuple.src, sp, tuple.dst);
        }
#endif
        value->packets++;
        value->bytes += skb->len;
        return 0;
    }
    return -1;
}

/**
 * IPv6 filter
 *
 * \return 0 to drop packet out and -1 to accept it
 */
static __always_inline int ipv6_filter(struct __sk_buff *skb, __u16 vlan0, __u16 vlan1)
{
    __u32 nhoff;
    __u8 nhdr;
    struct flowv6_keys tuple;
    struct pair *value;
    __u16 port;

    nhoff = skb->cb[0];

    /* get next header */
    nhdr = load_byte(skb, nhoff + offsetof(struct ipv6hdr, nexthdr));

    /* only support direct TCP and UDP for now */
    switch (nhdr) {
        case IPPROTO_TCP:
            tuple.ip_proto = 1;
            break;
        case IPPROTO_UDP:
            tuple.ip_proto = 0;
            break;
        default:
            return -1;
    }

    tuple.src[0] = load_word(skb, nhoff + offsetof(struct ipv6hdr, saddr));
    tuple.src[1] = load_word(skb, nhoff + offsetof(struct ipv6hdr, saddr) + 4);
    tuple.src[2] = load_word(skb, nhoff + offsetof(struct ipv6hdr, saddr) + 8);
    tuple.src[3] = load_word(skb, nhoff + offsetof(struct ipv6hdr, saddr) + 12);
    tuple.dst[0] = load_word(skb, nhoff + offsetof(struct ipv6hdr, daddr));
    tuple.dst[1] = load_word(skb, nhoff + offsetof(struct ipv6hdr, daddr) + 4);
    tuple.dst[2] = load_word(skb, nhoff + offsetof(struct ipv6hdr, daddr) + 8);
    tuple.dst[3] = load_word(skb, nhoff + offsetof(struct ipv6hdr, daddr) + 12);

    /* Parse TCP */
    tuple.ports = load_word(skb, nhoff + 40 /* IPV6_HEADER_LEN */);
    port = tuple.port16[1];
    tuple.port16[1] = tuple.port16[0];
    tuple.port16[0] = port;

    tuple.vlan0 = vlan0;
    tuple.vlan1 = vlan1;

    //char fmt[] = "Now Got IPv6 port %u and %u\n";
    //bpf_trace_printk(fmt, sizeof(fmt), tuple.port16[0], tuple.port16[1]);
    /* Test if src is in hash */
    value = bpf_map_lookup_elem(&flow_table_v6, &tuple);
    if (value) {
        //char fmt[] = "Got a match IPv6: %u and %u\n";
        //bpf_trace_printk(fmt, sizeof(fmt), tuple.port16[0], tuple.port16[1]);
        value->packets++;
        value->bytes += skb->len;
        return 0;
    }
    return -1;
}

/**
 * filter function
 *
 * It is loaded in kernel by Suricata that uses the section name specified
 * by the SEC call to find it in the Elf binary object and load it.
 *
 * \return 0 to drop packet out and -1 to accept it
 */
int SEC("filter") hashfilter(struct __sk_buff *skb) {
    __u32 nhoff = ETH_HLEN;

    __u16 proto = load_half(skb, offsetof(struct ethhdr, h_proto));
    __u16 vlan0 = skb->vlan_tci & 0x0fff;
    __u16 vlan1 = 0;

    if (proto == ETH_P_8021AD || proto == ETH_P_8021Q) {
        proto = load_half(skb, nhoff + offsetof(struct vlan_hdr,
                          h_vlan_encapsulated_proto));
#if VLAN_TRACKING
        /* one vlan layer is stripped by OS so get vlan 1 at first pass */
        vlan1 = load_half(skb, nhoff + offsetof(struct vlan_hdr,
                          h_vlan_TCI)) & 0x0fff;
#endif
        nhoff += sizeof(struct vlan_hdr);
    }

    skb->cb[0] = nhoff;
    switch (proto) {
        case ETH_P_IP:
            return ipv4_filter(skb, vlan0, vlan1);
        case ETH_P_IPV6:
            return ipv6_filter(skb, vlan0, vlan1);
        default:
#if 0
            {
                char fmt[] = "Got proto %u\n";
                bpf_trace_printk(fmt, sizeof(fmt), h_proto);
                break;
            }
#else
            break;
#endif
    }
    return -1;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;
