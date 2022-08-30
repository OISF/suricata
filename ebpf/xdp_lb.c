/* Copyright (C) 2019-2022 Open Information Security Foundation
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

#define KBUILD_MODNAME "foo"
#include <stddef.h>
#include <linux/bpf.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
/* Workaround to avoid the need of 32bit headers */
#define _LINUX_IF_H
#define IFNAMSIZ 16
#include <linux/if_tunnel.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_helpers.h"

#include "hash_func01.h"

#define LINUX_VERSION_CODE 263682

/* Hashing initval */
#define INITVAL 15485863

/* Increase CPUMAP_MAX_CPUS if ever you have more than 128 CPUs */
#define CPUMAP_MAX_CPUS 128

struct vlan_hdr {
    __u16	h_vlan_TCI;
    __u16	h_vlan_encapsulated_proto;
};

/* Special map type that can XDP_REDIRECT frames to another CPU */
struct bpf_map_def SEC("maps") cpu_map = {
    .type		= BPF_MAP_TYPE_CPUMAP,
    .key_size	= sizeof(__u32),
    .value_size	= sizeof(__u32),
    .max_entries	= CPUMAP_MAX_CPUS,
};

struct bpf_map_def SEC("maps") cpus_available = {
    .type		= BPF_MAP_TYPE_ARRAY,
    .key_size	= sizeof(__u32),
    .value_size	= sizeof(__u32),
    .max_entries	= CPUMAP_MAX_CPUS,
};

struct bpf_map_def SEC("maps") cpus_count = {
    .type		= BPF_MAP_TYPE_ARRAY,
    .key_size	= sizeof(__u32),
    .value_size	= sizeof(__u32),
    .max_entries	= 1,
};

static int __always_inline hash_ipv4(void *data, void *data_end)
{
    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 key0 = 0;
    __u32 cpu_dest;
    __u32 *cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
    __u32 *cpu_selected;
    __u32 cpu_hash;

    /* IP-pairs hit same CPU */
    cpu_hash = iph->saddr + iph->daddr;
    cpu_hash = SuperFastHash((char *)&cpu_hash, 4, INITVAL);

    if (cpu_max && *cpu_max) {
        cpu_dest = cpu_hash % *cpu_max;
        cpu_selected = bpf_map_lookup_elem(&cpus_available, &cpu_dest);
        if (!cpu_selected)
            return XDP_ABORTED;
        cpu_dest = *cpu_selected;
        return bpf_redirect_map(&cpu_map, cpu_dest, 0);
    } else {
        return XDP_PASS;
    }
}

static int __always_inline hash_ipv6(void *data, void *data_end)
{
    struct ipv6hdr *ip6h = data;
    if ((void *)(ip6h + 1) > data_end)
        return XDP_PASS;

    __u32 key0 = 0;
    __u32 cpu_dest;
    __u32 *cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
    __u32 *cpu_selected;
    __u32 cpu_hash;

    /* IP-pairs hit same CPU */
    cpu_hash  = ip6h->saddr.s6_addr32[0] + ip6h->daddr.s6_addr32[0];
    cpu_hash += ip6h->saddr.s6_addr32[1] + ip6h->daddr.s6_addr32[1];
    cpu_hash += ip6h->saddr.s6_addr32[2] + ip6h->daddr.s6_addr32[2];
    cpu_hash += ip6h->saddr.s6_addr32[3] + ip6h->daddr.s6_addr32[3];
    cpu_hash = SuperFastHash((char *)&cpu_hash, 4, INITVAL);

    if (cpu_max && *cpu_max) {
        cpu_dest = cpu_hash % *cpu_max;
        cpu_selected = bpf_map_lookup_elem(&cpus_available, &cpu_dest);
        if (!cpu_selected)
            return XDP_ABORTED;
        cpu_dest = *cpu_selected;
        return bpf_redirect_map(&cpu_map, cpu_dest, 0);
    } else {
        return XDP_PASS;
    }

    return XDP_PASS;
}

static int __always_inline filter_gre(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    struct iphdr *iph = data + nh_off;
    __u16 proto;
    struct gre_hdr {
        __be16 flags;
        __be16 proto;
    };

    nh_off += sizeof(struct iphdr);
    struct gre_hdr *grhdr = (struct gre_hdr *)(iph + 1);

    if ((void *)(grhdr + 1) > data_end)
        return XDP_PASS;

    if (grhdr->flags & (GRE_VERSION|GRE_ROUTING))
        return XDP_PASS;

    nh_off += 4;
    proto = grhdr->proto;
    if (grhdr->flags & GRE_CSUM)
        nh_off += 4;
    if (grhdr->flags & GRE_KEY)
        nh_off += 4;
    if (grhdr->flags & GRE_SEQ)
        nh_off += 4;

    /* Update offset to skip ERPSAN header if we have one */
    if (proto == __constant_htons(ETH_P_ERSPAN)) {
        nh_off += 8;
    }

    if (data + nh_off > data_end)
        return XDP_PASS;
    if (bpf_xdp_adjust_head(ctx, 0 + nh_off))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* we have now data starting at Ethernet header */
    struct ethhdr *eth = data;
    proto = eth->h_proto;
    /* we want to hash on IP so we need to get to ip hdr */
    nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
        return XDP_PASS;

    /* we need to increase offset and update protocol
     * in the case we have VLANs */
    if (proto == __constant_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vhdr = (struct vlan_hdr *)(data + nh_off);
        if ((void *)(vhdr + 1) > data_end)
            return XDP_PASS;
        proto = vhdr->h_vlan_encapsulated_proto;
        nh_off += sizeof(struct vlan_hdr);
    }

    if (data + nh_off > data_end)
        return XDP_PASS;
    /* proto should now be IP style */
    if (proto == __constant_htons(ETH_P_IP)) {
        return hash_ipv4(data + nh_off, data_end);
    } else if (proto == __constant_htons(ETH_P_IPV6)) {
        return hash_ipv6(data + nh_off, data_end);
    } else
        return XDP_PASS;
}

static int __always_inline filter_ipv4(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    struct iphdr *iph = data + nh_off;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol == IPPROTO_GRE) {
        return filter_gre(ctx, data, nh_off, data_end);
    }
    return hash_ipv4(data + nh_off, data_end);
}

static int __always_inline filter_ipv6(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    struct ipv6hdr *ip6h = data + nh_off;
    return hash_ipv6((void *)ip6h, data_end);
}

int SEC("xdp") xdp_loadfilter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u16 h_proto;
    __u64 nh_off;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return XDP_PASS;

    h_proto = eth->h_proto;

#if 0
    if (h_proto != __constant_htons(ETH_P_IP)) {
        char fmt[] = "Current proto: %u\n";
        bpf_trace_printk(fmt, sizeof(fmt), h_proto);
    }
#endif
    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }
    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == __constant_htons(ETH_P_IP))
        return filter_ipv4(ctx, data, nh_off, data_end);
    else if (h_proto == __constant_htons(ETH_P_IPV6))
        return filter_ipv6(ctx, data, nh_off, data_end);

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;
