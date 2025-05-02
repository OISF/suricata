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

#include <bpf/bpf_helpers.h>

#include "hash_func01.h"

#define LINUX_VERSION_CODE 263682

/* Hashing initval */
#define INITVAL 15485863

/* Set BUILD_CPUMAP to 0 if you want to run XDP bypass on kernel
 * older than 4.15 */
#define BUILD_CPUMAP        1
/* Increase CPUMAP_MAX_CPUS if ever you have more than 64 CPUs */
#define CPUMAP_MAX_CPUS     64

/* Set to 1 to bypass encrypted packets of TLS sessions. Suricata will
 * be blind to these packets or forged packets looking alike. */
#define ENCRYPTED_TLS_BYPASS    0

/* Set it to 0 if for example you plan to use the XDP filter in a
 * network card that don't support per CPU value (like netronome) */
#define USE_PERCPU_HASH     1
/* Set it to 0 if your XDP subsystem don't handle XDP_REDIRECT (like netronome) */
#define GOT_TX_PEER         1

/* set to non 0 to load balance in hardware mode on RSS_QUEUE_NUMBERS queues
 * and unset BUILD_CPUMAP (number must be a power of 2 for netronome) */
#define RSS_QUEUE_NUMBERS   32

/* no vlan tracking: set it to 0 if you don't use VLAN for tracking. Can
 * also be used as workaround of some hardware offload issue */
#define VLAN_TRACKING    1

/* erspan stripping: set it to 1 if you want to strip encapsulating erspan */
#define ERSPAN_STRIP 0

/* vxlan port configurable */
#define VXLAN_PORT 0xb512

/* vxlan stripping: set it to 1 if you want to strip encapsulating vxlan */
#define VXLAN_STRIP 0

struct vlan_hdr {
    __u16	h_vlan_TCI;
    __u16	h_vlan_encapsulated_proto;
};

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

struct {
#if USE_PERCPU_HASH
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#else
    __uint(type, BPF_MAP_TYPE_HASH);
#endif
    __type(key, struct flowv4_keys);
    __type(value, struct pair);
    __uint(max_entries, 32768);
} flow_table_v4 SEC(".maps");

struct {
#if USE_PERCPU_HASH
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#else
    __uint(type, BPF_MAP_TYPE_HASH);
#endif
    __type(key, struct flowv6_keys);
    __type(value, struct pair);
    __uint(max_entries, 32768);
} flow_table_v6 SEC(".maps");

#if ENCRYPTED_TLS_BYPASS
struct {
#if USE_PERCPU_HASH
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
#else
    __uint(type, BPF_MAP_TYPE_ARRAY);
#endif
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} tls_bypass_count SEC(".maps");
#endif

#if BUILD_CPUMAP
/* Special map type that can XDP_REDIRECT frames to another CPU */
struct {
    __uint(type, BPF_MAP_TYPE_CPUMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, CPUMAP_MAX_CPUS);
} cpu_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, CPUMAP_MAX_CPUS);
} cpus_available SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} cpus_count SEC(".maps");
#endif

#if GOT_TX_PEER
/* Map has only one element as we don't handle any sort of
 * routing for now. Key value set by user space is 0 and
 * value is the peer interface. */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
} tx_peer SEC(".maps");

/* single entry to indicate if we have peer, key value
 * set in user space is 0. It is only used to see if
 * a interface has a peer we need to send the information to */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
} tx_peer_int SEC(".maps");
#endif

#define USE_GLOBAL_BYPASS   0
#if USE_GLOBAL_BYPASS
/* single entry to indicate if global bypass switch is on */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, char);
    __type(value, char);
    __uint(max_entries, 1);
} global_bypass SEC(".maps");
#endif


static __always_inline int get_sport(void *trans_data, void *data_end,
        __u8 protocol)
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
            return uh->source;
        default:
            return 0;
    }
}

static __always_inline int get_dport(void *trans_data, void *data_end,
        __u8 protocol)
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

static int __always_inline filter_ipv4_final(
        struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end, __u16 vlan0, __u16 vlan1)
{
    struct iphdr *iph = data + nh_off;
    int dport;
    int sport;
    struct flowv4_keys tuple;
    struct pair *value;
#if BUILD_CPUMAP || GOT_TX_PEER
    __u32 key0 = 0;
#endif
#if ENCRYPTED_TLS_BYPASS
    __u32 key1 = 0;
    __u32 *tls_count = NULL;
#endif
#if BUILD_CPUMAP
    __u32 cpu_dest;
    __u32 *cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
    __u32 *cpu_selected;
    __u32 cpu_hash;
#endif
#if GOT_TX_PEER
    int *iface_peer;
    int tx_port = 0;
#endif

    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol == IPPROTO_TCP) {
        tuple.ip_proto = 1;
    } else {
        tuple.ip_proto = 0;
    }
    tuple.src = iph->saddr;
    tuple.dst = iph->daddr;

    dport = get_dport(iph + 1, data_end, iph->protocol);
    if (dport == -1)
        return XDP_PASS;

    sport = get_sport(iph + 1, data_end, iph->protocol);
    if (sport == -1)
        return XDP_PASS;

    tuple.port16[0] = (__u16)sport;
    tuple.port16[1] = (__u16)dport;

    tuple.vlan0 = vlan0;
    tuple.vlan1 = vlan1;

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
#if USE_PERCPU_HASH
        value->packets++;
        value->bytes += data_end - data;
#else
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, data_end - data);
#endif

#if GOT_TX_PEER
        iface_peer = bpf_map_lookup_elem(&tx_peer_int, &key0);
        if (!iface_peer) {
            return XDP_DROP;
        } else {
            return bpf_redirect_map(&tx_peer, tx_port, 0);
        }
#else
        return XDP_DROP;
#endif
    }

#if ENCRYPTED_TLS_BYPASS
    if ((dport == __constant_ntohs(443)) || (sport == __constant_ntohs(443))) {
        __u8 *app_data;
        /* drop application data for tls 1.2 */
        /* FIXME better parsing */
        nh_off += sizeof(struct iphdr) + sizeof(struct tcphdr);
        if (data_end > data + nh_off + 4) {
            app_data = data + nh_off;
            if (app_data[0] == 0x17 && app_data[1] == 0x3 && app_data[2] == 0x3) {
                tls_count = bpf_map_lookup_elem(&tls_bypass_count, &key1);
                if (tls_count) {
#if USE_PERCPU_HASH
                    tls_count++;
#else
                    __sync_fetch_and_add(tls_count, 1);
#endif
                }
#if GOT_TX_PEER
                iface_peer = bpf_map_lookup_elem(&tx_peer_int, &key0);
                if (!iface_peer) {
                    return XDP_DROP;
                } else {
                    return bpf_redirect_map(&tx_peer, tx_port, 0);
                }
#else
                return XDP_DROP;
#endif
            }
        }
    }
#endif

#if BUILD_CPUMAP
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
#else
#if RSS_QUEUE_NUMBERS
    /* IP-pairs + protocol (UDP/TCP/ICMP) hit same CPU */
    __u32 xdp_hash = tuple.src + tuple.dst;
    xdp_hash = SuperFastHash((char *)&xdp_hash, 4, INITVAL + iph->protocol);
    ctx->rx_queue_index = xdp_hash % RSS_QUEUE_NUMBERS;
#endif
    return XDP_PASS;
#endif
}

static int __always_inline filter_ipv6(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end, __u16 vlan0, __u16 vlan1)
{
    struct ipv6hdr *ip6h = data + nh_off;
    int dport;
    int sport;
    struct flowv6_keys tuple;
    struct pair *value;
#if BUILD_CPUMAP || GOT_TX_PEER
    __u32 key0 = 0;
#endif
#if BUILD_CPUMAP
    __u32 cpu_dest;
    int *cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
    __u32 *cpu_selected;
    __u32 cpu_hash;
#endif
#if GOT_TX_PEER
    int tx_port = 0;
    int *iface_peer;
#endif

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

    if (ip6h->nexthdr == IPPROTO_TCP) {
        tuple.ip_proto = 1;
    } else {
        tuple.ip_proto = 0;
    }
    __builtin_memcpy(tuple.src, ip6h->saddr.s6_addr32, sizeof(tuple.src));
    __builtin_memcpy(tuple.dst, ip6h->daddr.s6_addr32, sizeof(tuple.dst));
    tuple.port16[0] = sport;
    tuple.port16[1] = dport;

    tuple.vlan0 = vlan0;
    tuple.vlan1 = vlan1;

    value = bpf_map_lookup_elem(&flow_table_v6, &tuple);
    if (value) {
#if 0
        char fmt6[] = "Found IPv6 flow: %d -> %d\n";
        bpf_trace_printk(fmt6, sizeof(fmt6), sport, dport);
#endif
#if USE_PERCPU_HASH
        value->packets++;
        value->bytes += data_end - data;
#else
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, data_end - data);
#endif

#if GOT_TX_PEER
        iface_peer = bpf_map_lookup_elem(&tx_peer_int, &key0);
        if (!iface_peer) {
            return XDP_DROP;
        } else {
            return bpf_redirect_map(&tx_peer, tx_port, 0);
        }
#else
        return XDP_DROP;
#endif
    }

#if BUILD_CPUMAP
    /* IP-pairs + protocol (UDP/TCP/ICMP) hit same CPU */
    cpu_hash  = tuple.src[0] + tuple.dst[0];
    cpu_hash += tuple.src[1] + tuple.dst[1];
    cpu_hash += tuple.src[2] + tuple.dst[2];
    cpu_hash += tuple.src[3] + tuple.dst[3];
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
#else
#if RSS_QUEUE_NUMBERS
    /* IP-pairs + protocol (UDP/TCP/ICMP) hit same CPU */
    __u32 xdp_hash  = tuple.src[0] + tuple.dst[0];
    xdp_hash += tuple.src[1] + tuple.dst[1];
    xdp_hash += tuple.src[2] + tuple.dst[2];
    xdp_hash += tuple.src[3] + tuple.dst[3];
    xdp_hash = SuperFastHash((char *)&xdp_hash, 4, INITVAL);
    ctx->rx_queue_index = xdp_hash % RSS_QUEUE_NUMBERS;
#endif

    return XDP_PASS;
#endif
}

static int __always_inline filter_erspan(
        struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    struct erspan_hdr {
        __be16 ver_vlan;
        __be16 flags_spanid;
        __be32 padding;
    };
    __u16 vlan0 = 0;
    __u16 h_proto;
    __u16 flags_spanid;

    struct erspan_hdr *erhdr = (struct erspan_hdr *)(data + nh_off);
    if ((void *)(erhdr + 1) > data_end)
        return XDP_PASS;

    if ((erhdr->ver_vlan & 0xF0) != 0x10) {
        // only handle ERSPAN 2
        return XDP_PASS;
    }
    flags_spanid = erhdr->flags_spanid;
    if ((flags_spanid & 0x1800) == 0x800) {
        // do not handle ISL encapsulated
        return XDP_PASS;
    }
#if VLAN_TRACKING
    if ((flags_spanid & 0x1800) == 0x1000) {
        vlan0 = erhdr->ver_vlan & 0xFFF;
    }
#endif
    nh_off += 8;
#if ERSPAN_STRIP
    if (bpf_xdp_adjust_head(ctx, nh_off))
        return XDP_PASS;
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    nh_off = 0;
#endif
    if (data + nh_off + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data + nh_off;
    nh_off += sizeof(*eth);

    h_proto = eth->h_proto;

    if ((flags_spanid & 0x1800) == 0x1800 && (h_proto == __constant_htons(ETH_P_8021Q) ||
                                                     h_proto == __constant_htons(ETH_P_8021AD))) {
        struct vlan_hdr *vhdr;

        if (data + nh_off + sizeof(struct vlan_hdr) > data_end)
            return XDP_PASS;
        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        h_proto = vhdr->h_vlan_encapsulated_proto;
#if VLAN_TRACKING
        vlan0 = vhdr->h_vlan_TCI & 0x0fff;
#endif
    }
    if (h_proto == __constant_htons(ETH_P_IP))
        return filter_ipv4_final(ctx, data, nh_off, data_end, vlan0, 0);
    else if (h_proto == __constant_htons(ETH_P_IPV6))
        return filter_ipv6(ctx, data, nh_off, data_end, vlan0, 0);
    return XDP_PASS;
}

static int __always_inline filter_gre(
        struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end, __u16 vlan0, __u16 vlan1)
{
    struct gre_hdr {
        __be16 flags;
        __be16 proto;
    };
    __u16 proto;

    struct gre_hdr *grhdr = (struct gre_hdr *)(data + nh_off);

    if ((void *)(grhdr + 1) > data_end)
        return XDP_PASS;

    // only GRE version 0 without routing
    if (grhdr->flags & (GRE_VERSION | GRE_ROUTING))
        return XDP_PASS;

    nh_off += 4;
    if (grhdr->flags & GRE_CSUM)
        nh_off += 4;
    if (grhdr->flags & GRE_KEY)
        nh_off += 4;
    if (grhdr->flags & GRE_SEQ)
        nh_off += 4;
    if (data + nh_off > data_end)
        return XDP_PASS;

    proto = grhdr->proto;
    // only handle erspan over gre
    if (proto == __constant_htons(ETH_P_ERSPAN)) {
        return filter_erspan(ctx, data, nh_off, data_end);
    }
    return XDP_PASS;
}

struct vxlanhdr {
    __be16 flags;
    __be16 gdp;
    __u8 vni0;
    __u8 vni1;
    __u8 vni2;
    __u8 res;
};

static int __always_inline filter_vxlan(
        struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    __u16 vlan0 = 0;
    __u16 h_proto;
    nh_off += sizeof(struct vxlanhdr);

#if VXLAN_STRIP
    if (bpf_xdp_adjust_head(ctx, nh_off))
        return XDP_PASS;
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    nh_off = 0;
#endif

    if (data + nh_off + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data + nh_off;
    nh_off += sizeof(*eth);

    h_proto = eth->h_proto;

    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        if (data + nh_off + sizeof(struct vlan_hdr) > data_end)
            return XDP_PASS;
        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        h_proto = vhdr->h_vlan_encapsulated_proto;
#if VLAN_TRACKING
        vlan0 = vhdr->h_vlan_TCI & 0x0fff;
#endif
    }
    if (h_proto == __constant_htons(ETH_P_IP))
        return filter_ipv4_final(ctx, data, nh_off, data_end, vlan0, 0);
    else if (h_proto == __constant_htons(ETH_P_IPV6))
        return filter_ipv6(ctx, data, nh_off, data_end, vlan0, 0);
    return XDP_PASS;
}

static int __always_inline filter_ipv4(
        struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end, __u16 vlan0, __u16 vlan1)
{
    struct iphdr *iph = data + nh_off;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol == IPPROTO_GRE) {
        nh_off += sizeof(struct iphdr);
        return filter_gre(ctx, data, nh_off, data_end, vlan0, vlan1);
    } else if (iph->protocol == IPPROTO_UDP) {
        if (data + nh_off + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct vxlanhdr) +
                        sizeof(struct ethhdr) <=
                data_end) {
            struct udphdr *uh = (struct udphdr *)(data + nh_off + sizeof(struct iphdr));
            if (uh->dest == VXLAN_PORT) {
                struct vxlanhdr *vh = (struct vxlanhdr *)(data + nh_off + sizeof(struct iphdr) +
                                                          sizeof(struct udphdr));
                // check vni is present and reserved is 0
                if ((vh->flags & 0xDEFF) == 8 && vh->res == 0) {
                    nh_off += sizeof(struct iphdr) + sizeof(struct udphdr);
                    return filter_vxlan(ctx, data, nh_off, data_end);
                }
            }
        }
    }
    return filter_ipv4_final(ctx, data, nh_off, data_end, vlan0, vlan1);
}

int SEC("xdp") xdp_hashfilter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u16 h_proto;
    __u64 nh_off;
    __u16 vlan0 = 0;
    __u16 vlan1 = 0;
#if USE_GLOBAL_BYPASS
    int *iface_peer;
    char *g_switch = 0;
    char key0;
    int tx_port = 0;

    g_switch = bpf_map_lookup_elem(&global_bypass, &key0);
    if (g_switch && *g_switch) {
        iface_peer = bpf_map_lookup_elem(&tx_peer_int, &key0);
        if (!iface_peer) {
            return XDP_DROP;
        } else {
            return bpf_redirect_map(&tx_peer, tx_port, 0);
        }
    }
#endif

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return XDP_PASS;

    h_proto = eth->h_proto;

    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
#if VLAN_TRACKING
        vlan0 = vhdr->h_vlan_TCI & 0x0fff;
#else
        vlan0 = 0;
#endif
    }
    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
#if VLAN_TRACKING
        vlan1 = vhdr->h_vlan_TCI & 0x0fff;
#else
        vlan1 = 0;
#endif
    }

    if (h_proto == __constant_htons(ETH_P_IP))
        return filter_ipv4(ctx, data, nh_off, data_end, vlan0, vlan1);
    else if (h_proto == __constant_htons(ETH_P_IPV6))
        return filter_ipv6(ctx, data, nh_off, data_end, vlan0, vlan1);

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;
