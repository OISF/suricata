/* Copyright (C) 2019 Open Information Security Foundation
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

#ifdef ENABLE_EAST_WEST_FILTER
#include "east_west_filter.h"
#endif

#ifndef DEBUG
#define DEBUG 0
#endif

/* Sizes (in bytes) of various GRE/ERSPAN optional protocol options.
 */
#define GRE_CSUM_SIZE   (2)
#define GRE_OFFSET_SIZE (2)
#define GRE_KEY_SIZE    (4)
#define GRE_SEQ_SIZE    (4)
#define GRE_ERSPAN_TYPE_II_HEADER_SIZE (8)

/* Both are required in order to ensure *everything* is inlined.  The kernel version that 
 * we're using doesn't support calling functions in XDP, so it must appear as a single function.
 * Kernel 4.16+ support function calls:
 * https://stackoverflow.com/questions/70529753/clang-bpf-attribute-always-inline-does-not-working
 */
#define INLINE __always_inline __attribute__((always_inline))

#define DPRINTF(fmt_str, args...) \
    if (DEBUG) { \
        char fmt[] = fmt_str; \
        bpf_trace_printk(fmt, sizeof(fmt), args); \
    }

#define DPRINTF_ALWAYS(fmt_str, args...) \
    { \
        char fmt[] = fmt_str; \
        bpf_trace_printk(fmt, sizeof(fmt), args); \
    }

/* The ifndef's around CTX_GET_*() allow the UT's to override them */
#ifndef CTX_GET_DATA
#define CTX_GET_DATA(ctx) (void*)(long)ctx->data
#endif

#ifndef CTX_GET_DATA_END
#define CTX_GET_DATA_END(ctx) (void*)(long)ctx->data_end
#endif

#define LINUX_VERSION_CODE 263682

/* Hashing initval */
#define INITVAL 15485863

/* Increase CPUMAP_MAX_CPUS if ever you have more than 64 CPUs */
#define CPUMAP_MAX_CPUS     64

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

static INLINE __u16 ntohs(__u16 val) {
    return ((val & 0xff00) >> 8) + ((val & 0x00ff) << 8);
}

static INLINE int get_sport(void *trans_data, void *data_end, __u8 protocol)
{
    struct tcphdr *th;
    struct udphdr *uh;

    switch (protocol) {
        case IPPROTO_TCP:
            th = (struct tcphdr *)trans_data;
            if ((void *)(th + 1) > data_end) {
                return -1;
            }
            return th->source;
        case IPPROTO_UDP:
            uh = (struct udphdr *)trans_data;
            if ((void *)(uh + 1) > data_end) {
                return -1;
            }
            return uh->source;
        default:
            return 0;
    }
}

static INLINE int get_dport(void *trans_data, void *data_end, __u8 protocol)
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

static int INLINE hash_ipv4(void *data, void *data_end)
{
    DPRINTF("hash_ipv4 %d\n", (int)(data_end - data));

    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

#ifdef ENABLE_EAST_WEST_FILTER
    if (is_east_west(iph->saddr) && is_east_west(iph->daddr)) {
        return XDP_DROP;
    }
#endif

    void* layer4 = data + (iph->ihl << 2);

    __u32 key0 = 0;
    __u32 cpu_dest;
    __u32 *cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
    __u32 *cpu_selected;

    int dport = get_dport(layer4, data_end, iph->protocol);
    if (dport == -1) {
        return XDP_PASS;
    }

    int sport = get_sport(layer4, data_end, iph->protocol);
    if (sport == -1) {
        return XDP_PASS;
    }

    DPRINTF("Flow proto  %d id %d\n", iph->protocol, iph->id);
    DPRINTF("     src %x:%d\n", iph->saddr, ntohs(sport));
    DPRINTF("     dst %x:%d\n", iph->daddr, ntohs(dport));

     __u32 cpu_hash;
     __u64 cpu_hash_input = 0;

    /* 
     * Sort the client/server parts of the 5-tuple for a symmetric hash
     *
     * NOTE: saddr and daddr are in network order (i.e., big endian), and we're running 
     * an on Intel (little endian), which means the least significant bits contain the 
     * network portion of the IP address, which we intentionally add the layer 4 port  
     * on top of it.
     * This does two things:
     *   - it uses the full 5-tuple for hashing
     *   - creates more entropy by distrupting the fairly static network bits
     */
    if (iph->saddr > iph->daddr) {
        ((__u32*)&cpu_hash_input)[0] = iph->saddr + sport;
        ((__u32*)&cpu_hash_input)[1] = iph->daddr + dport;

        cpu_hash = SuperFastHash((char *)&cpu_hash_input, 8, INITVAL + iph->protocol);
    } else {
        ((__u32*)&cpu_hash_input)[0] = iph->daddr + dport;
        ((__u32*)&cpu_hash_input)[1] = iph->saddr + sport;

        cpu_hash = SuperFastHash((char *)&cpu_hash_input, 8, INITVAL + iph->protocol);
    }

    if (cpu_max && *cpu_max) {
        cpu_dest = cpu_hash % *cpu_max;

        DPRINTF("    hash %x to %d\n", cpu_hash, cpu_dest);
        cpu_selected = bpf_map_lookup_elem(&cpus_available, &cpu_dest);
        if (!cpu_selected) {
            return XDP_ABORTED;
        }
        cpu_dest = *cpu_selected;
        return bpf_redirect_map(&cpu_map, cpu_dest, 0);
    } else {
        return XDP_PASS;
    }
}

static int INLINE sort128(__u64 *source, __u64 *dest)
{
    return (source[0] < dest[0]) | ((source[0] == dest[0]) & (source[1] < dest[1]));
}

static int INLINE hash_ipv6(void *data, void *data_end)
{
    struct ipv6hdr *ip6h = data;
    if ((void *)(ip6h + 1) > data_end) {
        return XDP_PASS;
    }

    /**
     * TODO: we will likely eventually need to support a set 
     * of IPV6 header extension; the UDP or TCP header wont 
     * *always* be the next header after the IP header...
     */

    void* layer4 = (void*)(ip6h + 1);
    int dport = get_dport(layer4, data_end, ip6h->nexthdr);
    if (dport == -1) {
        return XDP_PASS;
    }

    int sport = get_sport(layer4, data_end, ip6h->nexthdr);
    if (sport == -1) {
        return XDP_PASS;
    }

    __u32 key0 = 0;
    __u32 cpu_dest;
    __u32 *cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
    __u32 *cpu_selected;

    __u64 ip_hash_input;
    __u32 cpu_hash;

    /*
     * IPV6 addresses are 128 bits, commonly expressed as a series of up to 
     * 8 16-bit words; but very rarely are all 16-bit words defined.  Typically 
     * the middle words are unset/zero.
     * 
     * Additionally, like IPV4, the upper bits consist of more static network/routing 
     * bits, while the lower bits identify individual interfaces/hosts, which 
     * tend to be more variable.
     * 
     * So, in order to create more entropy, we can merge source and dest 
     * addresses in opposite orders -- colliding static bits with more dynamic bits 
     * in both sides of the hash input.  However, to keep flow symmetry, we 
     * must do this identically for each side of a flow, so we must have a way 
     * to consistently choose which address is added in 0-1 order, and which is 
     * added in 1-0 order.
     * 
     * For IPV4 addresses, we simply sorted them, which can also work here, 
     * although sorting 128 bits is a bit more involved and requires our own 
     * function.
     * 
     * NOTE that we're sorting the address in network order; this doens't matter, 
     * as long as it's consistent.
     */
    __u64 *source = (__u64 *)&ip6h->saddr;
    __u64 *dest   = (__u64 *)&ip6h->daddr;
    if (sort128(source, dest)) {
        ip_hash_input = source[0] + dest[1] + sport;
        ip_hash_input += source[1] + dest[0] + dport;
    } else {
        ip_hash_input = dest[0] + source[1] + dport;
        ip_hash_input += dest[1] + source[0] + sport;
    }
    cpu_hash = SuperFastHash((char *)&ip_hash_input, 8, INITVAL + ip6h->nexthdr);

    if (cpu_max && *cpu_max) {
        cpu_dest = cpu_hash % *cpu_max;
        cpu_selected = bpf_map_lookup_elem(&cpus_available, &cpu_dest);
        if (!cpu_selected) {
            return XDP_ABORTED;
        }
        cpu_dest = *cpu_selected;
        return bpf_redirect_map(&cpu_map, cpu_dest, 0);
    } else {
        return XDP_PASS;
    }

    return XDP_PASS;
}

static int INLINE filter_gre(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    struct iphdr *iph = data + nh_off;
    __be16 proto;
    struct gre_hdr {
        __be16 flags;
        __be16 proto;
    };

    nh_off += iph->ihl << 2;
    /* need to save this off before we advance the packet beyond it, else the bpf verifier 
     * will catch this and refuse to load our program
     */
    int pkt_id = iph->id;

    struct gre_hdr *grhdr = (struct gre_hdr *)(data + nh_off);

    if ((void *)(grhdr + 1) > data_end) {
        DPRINTF_ALWAYS("malformed gre %d", __LINE__);
        return XDP_PASS;
    }

    if (grhdr->flags & (GRE_VERSION|GRE_ROUTING)) {
        DPRINTF_ALWAYS("unsupported gre flags %x on %d",grhdr->flags, __LINE__);
        return XDP_PASS;
    }

    nh_off += 4;
    proto = grhdr->proto;
    if (grhdr->flags & GRE_CSUM) {
        nh_off += GRE_CSUM_SIZE + GRE_OFFSET_SIZE;
    }
    if (grhdr->flags & GRE_KEY) {
        nh_off += GRE_KEY_SIZE;
    }
    if (grhdr->flags & GRE_SEQ) {
        nh_off += GRE_SEQ_SIZE;
    }

    /* Update offset to skip ERSPAN header if we have one */
    if (proto == __constant_htons(ETH_P_ERSPAN)) {
        // If sequence is set, then an ERSPAN header follows, otherwise the 
        // inner ether header follows...
        if(grhdr->flags & GRE_SEQ) {
            nh_off += GRE_ERSPAN_TYPE_II_HEADER_SIZE;
        }
    }

    if (data + nh_off > data_end) {
        DPRINTF_ALWAYS("malformed gre %d", __LINE__);
        return XDP_PASS;
    }

    if (bpf_xdp_adjust_head(ctx, 0 + nh_off)) {
        DPRINTF_ALWAYS("malformed gre %d", __LINE__);
        return XDP_PASS;
    }

    data = CTX_GET_DATA(ctx);
    data_end = CTX_GET_DATA_END(ctx);

    /* we have new data starting at Ethernet header */
    struct ethhdr *eth = data;
    proto = eth->h_proto;
    /* we want to hash on IP so we need to get to ip hdr */
    nh_off = sizeof(*eth);

    if (data + nh_off > data_end) {
        DPRINTF_ALWAYS("malformed gre %d", __LINE__);
        return XDP_PASS;
    }

    if (proto == __constant_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vhdr = (struct vlan_hdr *)(data + nh_off);
        if ((void *)(vhdr + 1) > data_end) {
            DPRINTF_ALWAYS("malformed gre %d", __LINE__);
            return XDP_PASS;
        }
        proto = vhdr->h_vlan_encapsulated_proto;
        nh_off += sizeof(struct vlan_hdr);
    }

    if (proto == __constant_htons(ETH_P_IP)) {
        return hash_ipv4(data + nh_off, data_end);
    } else if (proto == __constant_htons(ETH_P_IPV6)) {
        return hash_ipv6(data + nh_off, data_end);
    } else {
        /* This packet isn't IPV4 or IPV6... it's likely still a legit ether type, but we intentionally 
         * keep the packet handling light here, so even though we don't understand it, return it to the 
         * network stack (we've already advanced past the GRE/ERSPAN headers to the encapsulated ethernet 
         * frame, so chances are the linux stack, and suricata, know what to do with it)
         */
        DPRINTF("GRE unknown inner proto %d id %d\n", ntohs(proto), ntohs(pkt_id));
        return XDP_PASS;
    }
}

static int INLINE filter_ipv4(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    struct iphdr *iph = data + nh_off;
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    if (iph->protocol == IPPROTO_GRE) {
        return filter_gre(ctx, data, nh_off, data_end);
    }
    return hash_ipv4(data + nh_off, data_end);
}

static int INLINE filter_ipv6(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end)
{
    struct ipv6hdr *ip6h = data + nh_off;
    return hash_ipv6((void *)ip6h, data_end);
}

int SEC("xdp") xdp_loadfilter(struct xdp_md *ctx)
{
    void *data_end = CTX_GET_DATA_END(ctx);
    void *data = CTX_GET_DATA(ctx);
    struct ethhdr *eth = data;
    __u16 h_proto;
    __u64 nh_off;

    DPRINTF("Packet %d len\n", (int)(data_end - data));

    nh_off = sizeof(*eth); 
    if (data + nh_off > data_end) {
        return XDP_PASS;
    }

    h_proto = eth->h_proto;

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

    if (h_proto == __constant_htons(ETH_P_IP)) {
        return filter_ipv4(ctx, data, nh_off, data_end);
    }
    else if (h_proto == __constant_htons(ETH_P_IPV6)) {
        return filter_ipv6(ctx, data, nh_off, data_end);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;
