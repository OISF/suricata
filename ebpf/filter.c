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

#define DEBUG 0

#define LINUX_VERSION_CODE 263682

struct bpf_map_def SEC("maps") ipv4_drop = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 32768,
};

struct vlan_hdr {
    __u16   h_vlan_TCI;
    __u16   h_vlan_encapsulated_proto;
};

static __always_inline int ipv4_filter(struct __sk_buff *skb)
{
    __u32 nhoff;
    __u32 *value;
    __u32 ip = 0;

    nhoff = skb->cb[0];

    ip = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
    value = bpf_map_lookup_elem(&ipv4_drop, &ip);
    if (value) {
#if DEBUG
        char fmt[] = "Found value for saddr: %u\n";
        bpf_trace_printk(fmt, sizeof(fmt), value);
#endif
        *value = *value + 1;
        return 0;
    }

    ip = load_word(skb, nhoff + offsetof(struct iphdr, daddr));
    value = bpf_map_lookup_elem(&ipv4_drop, &ip);
    if (value) {
#if DEBUG
        char fmt[] = "Found value for daddr: %u\n";
        bpf_trace_printk(fmt, sizeof(fmt), value);
#endif
        *value = *value + 1;
        return 0;
    }

#if DEBUG
    char fmt[] = "Nothing so ok\n";
    bpf_trace_printk(fmt, sizeof(fmt));
#endif
    return -1;
}

static __always_inline int ipv6_filter(struct __sk_buff *skb)
{
    return -1;
}

int SEC("filter") hashfilter(struct __sk_buff *skb)
{
    __u32 nhoff = ETH_HLEN;

    __u16 proto = load_half(skb, offsetof(struct ethhdr, h_proto));

    if (proto == ETH_P_8021AD || proto == ETH_P_8021Q) {
        proto = load_half(skb, nhoff + offsetof(struct vlan_hdr,
                          h_vlan_encapsulated_proto));
        nhoff += sizeof(struct vlan_hdr);
    }

    skb->cb[0] = nhoff;
    switch (proto) {
        case ETH_P_IP:
            return ipv4_filter(skb);
        case ETH_P_IPV6:
            return ipv6_filter(skb);
        default:
            break;
    }
    return -1;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;
