/* Copyright (C) 2018 Open Information Security Foundation
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
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <linux/bpf.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_helpers.h"

#include "hash_func01.h"

#define LINUX_VERSION_CODE 263682

/* Hashing initval */
#define INITVAL 15485863

#define CPUMAP_MAX_CPUS     64

struct vlan_hdr {
    __u16	h_vlan_TCI;
    __u16	h_vlan_encapsulated_proto;
} __attribute__((__aligned__(8))) ;

struct flowv4_keys {
    __u32 src;
    __u32 dst;
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u32 ip_proto;
} __attribute__((__aligned__(8)));

struct flowv6_keys {
    __u32 src[4];
    __u32 dst[4];
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u32 ip_proto;
} __attribute__((__aligned__(8)));

struct pair {
    uint64_t time;
    uint64_t packets;
    uint64_t bytes;
} __attribute__((__aligned__(8)));

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

struct bpf_map_def SEC("maps") tx_peer = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") tx_peer_int = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 1,
};

static __always_inline int get_sport(void *trans_data, void *data_end,
        uint8_t protocol)
{
    struct tcphdr *th;
    struct udphdr *uh;

    switch (protocol) {
        case IPPROTO_TCP:
            th = (struct tcphdr *)trans_data;
            if ((void *)(th + 1) > data_end)
                return -1;
            return th->source;
        case IPPROTO_UDP:
            uh = (struct udphdr *)trans_data;
            if ((void *)(uh + 1) > data_end)
                return -1;
            return uh->dest;
        default:
            return 0;
    }
}

static __always_inline int get_dport(void *trans_data, void *data_end,
        uint8_t protocol)
{
    struct tcphdr *th;
    struct udphdr *uh;

    switch (protocol) {
        case IPPROTO_TCP:
            th = (struct tcphdr *)trans_data;
            if ((void *)(th + 1) > data_end)
                return -1;
            return th->dest;
        case IPPROTO_UDP:
            uh = (struct udphdr *)trans_data;
            if ((void *)(uh + 1) > data_end)
                return -1;
            return uh->dest;
        default:
            return 0;
    }
}

static int __always_inline filter_ipv4(void *data, __u64 nh_off, void *data_end)
{
    struct iphdr *iph = data + nh_off;
    int dport;
    int sport;
    struct flowv4_keys tuple;
    struct pair *value;
    uint32_t cpu_dest;
    uint32_t key0 = 0;
    uint32_t *cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
    uint32_t *cpu_selected;
    uint32_t cpu_hash;
    int *iface_peer;
    int tx_port = 0;

    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    tuple.ip_proto = (uint32_t) iph->protocol;
    tuple.src = iph->saddr;
    tuple.dst = iph->daddr;

    dport = get_dport(iph + 1, data_end, iph->protocol);
    if (dport == -1)
        return XDP_PASS;

    sport = get_sport(iph + 1, data_end, iph->protocol);
    if (sport == -1)
        return XDP_PASS;

    tuple.port16[0] = (uint16_t)sport;
    tuple.port16[1] = (uint16_t)dport;
    value = bpf_map_lookup_elem(&flow_table_v4, &tuple);
#if 0
    {
        char fmt[] = "Current flow src: %u:%d\n";
        char fmt1[] = "Current flow dst: %u:%d\n";
        bpf_trace_printk(fmt, sizeof(fmt), tuple.src, tuple.port16[0]);
        bpf_trace_printk(fmt1, sizeof(fmt1), tuple.dst, tuple.port16[1]);
    }
#endif
    if (value) {
#if 0
        char fmt[] = "Found flow v4: %u %d -> %d\n";
        bpf_trace_printk(fmt, sizeof(fmt), tuple.src, sport, dport);
        char fmt[] = "Data: t:%lu p:%lu n:%lu\n";
        bpf_trace_printk(fmt, sizeof(fmt), value->time, value->packets, value->bytes);
#endif
        value->time = bpf_ktime_get_ns();
        value->packets++;
        value->bytes += data_end - data;

        iface_peer = bpf_map_lookup_elem(&tx_peer_int, &key0);
        if (!iface_peer) {
            return XDP_DROP;
        } else {
            return bpf_redirect_map(&tx_peer, tx_port, 0);
        }
    }

    /* IP-pairs + protocol (UDP/TCP/ICMP) hit same CPU */
    cpu_hash = tuple.src + tuple.dst;
    cpu_hash = SuperFastHash((char *)&cpu_hash, 4, INITVAL + iph->protocol);

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

static int __always_inline filter_ipv6(void *data, __u64 nh_off, void *data_end)
{
    struct ipv6hdr *ip6h = data + nh_off;
    int dport;
    int sport;
    struct flowv6_keys tuple;
    struct pair *value;
    uint32_t cpu_dest;
    uint32_t key0 = 0;
    int *cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
    uint32_t *cpu_selected;
    uint32_t cpu_hash;
    int tx_port = 0;
    int *iface_peer;

    if ((void *)(ip6h + 1) > data_end)
        return 0;
    if (!((ip6h->nexthdr == IPPROTO_UDP) || (ip6h->nexthdr == IPPROTO_TCP)))
        return XDP_PASS;

    dport = get_dport(ip6h + 1, data_end, ip6h->nexthdr);
    if (dport == -1)
        return XDP_PASS;

    sport = get_sport(ip6h + 1, data_end, ip6h->nexthdr);
    if (sport == -1)
        return XDP_PASS;

    tuple.ip_proto = ip6h->nexthdr;
    __builtin_memcpy(tuple.src, ip6h->saddr.s6_addr32, sizeof(tuple.src));
    __builtin_memcpy(tuple.dst, ip6h->daddr.s6_addr32, sizeof(tuple.dst));
    tuple.port16[0] = sport;
    tuple.port16[1] = dport;

    value = bpf_map_lookup_elem(&flow_table_v6, &tuple);
    if (value) {
#if 0
        char fmt6[] = "Found IPv6 flow: %d -> %d\n";
        bpf_trace_printk(fmt6, sizeof(fmt6), sport, dport);
#endif
        value->packets++;
        value->bytes += data_end - data;
        value->time = bpf_ktime_get_ns();

        iface_peer = bpf_map_lookup_elem(&tx_peer_int, &key0);
        if (!iface_peer) {
            return XDP_DROP;
        } else {
            return bpf_redirect_map(&tx_peer, tx_port, 0);
        }
    }

    /* IP-pairs + protocol (UDP/TCP/ICMP) hit same CPU */
    cpu_hash  = tuple.src[0] + tuple.dst[0];
    cpu_hash += tuple.src[1] + tuple.dst[1];
    cpu_hash += tuple.src[2] + tuple.dst[2];
    cpu_hash += tuple.src[3] + tuple.dst[3];
    cpu_hash = SuperFastHash((char *)&cpu_hash, 4, ip6h->nexthdr);

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

int SEC("xdp") xdp_hashfilter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    int rc = XDP_PASS;
    uint16_t h_proto;
	uint64_t nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	h_proto = eth->h_proto;

	if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if (h_proto == __constant_htons(ETH_P_IP))
		return filter_ipv4(data, nh_off, data_end);
	else if (h_proto == __constant_htons(ETH_P_IPV6))
		return filter_ipv6(data, nh_off, data_end);
	else
		rc = XDP_PASS;

    return rc;
}

char __license[] SEC("license") = "GPL";

uint32_t __version SEC("version") = LINUX_VERSION_CODE;
