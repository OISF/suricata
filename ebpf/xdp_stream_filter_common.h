/*
 * Stream filter code that's used both in the standalone XDP stream filter
 * (which is handy for debugging) and in xdp_lb.
 */

#ifndef _XDP_STREAM_FILTER_COMMON_H
#define _XDP_STREAM_FILTER_COMMON_H

#include "xdp_common.h"


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


static int INLINE stream_filter_ipv4(struct xdp_md *ctx, struct iphdr *iph, void *data, void *data_end, __u16 sport, __u16 dport, __u16 vlan0, __u16 vlan1)
{
    struct flowv4_keys tuple;
    struct pair *value;

    /* 
     * This code assumes basic sanity checks were performed by the caller. 
     * IE: if ((void *)(iph + 1) > data_end) {
     */

    if (iph->protocol == IPPROTO_TCP) {
        tuple.ip_proto = 1;
    } else {
        tuple.ip_proto = 0;
    }
    tuple.src = iph->saddr;
    tuple.dst = iph->daddr;

    tuple.port16[0] = (__u16)sport;
    tuple.port16[1] = (__u16)dport;

    tuple.vlan0 = vlan0;
    tuple.vlan1 = vlan1;

    value = (struct pair*)bpf_map_lookup_elem(&flow_table_v4, &tuple);
    if (value) {
        /* Assumes per-cpu hash. */
        value->packets++;
        value->bytes += (__u64*)data_end - (__u64*)data;

        DPRINTF("flow_table_v4 MATCH! Stream packets: %d, size: %d\n", value->packets, value->bytes);

        /* Drop the packets in mirroring mode. Internal tap mode TBD. Until 
         * there is a means for this code to determine if we're in internal_tap
         * mode, we'll assume 'mirroring'.
         */
        DPRINTF("Assuming mirroring mode. Packet DROPPED. %d -> %d\n", ntohs(tuple.port16[0]), ntohs(tuple.port16[1]));
        return XDP_DROP;
    } else {
        DPRINTF("No entry in v4 table for %d -> %d\n", ntohs(tuple.port16[0]), ntohs(tuple.port16[1]));
        trace_ipv4(tuple.src);
        trace_ipv4(tuple.dst);

        /* 
         * Trace the tuple bytes for comparision with bpftool ouptput.
         *
         * bpftool command line: 
         *  sudo ./bpftool --pretty map dump name flow_table_v4
         * 
         * For Focal, get bpftool here: https://github.com/libbpf/bpftool/releases/tag/v7.2.0
         * I was unsuccessful getting the version provided by apt to work, and according to
         * Google that's a common problem.
         */
        DPRINTF("Tuple bytes follow (size: %d):\n", sizeof(struct flowv4_keys));
        trace_bytes(&tuple, sizeof(struct flowv4_keys));
    }

    return XDP_PASS;
}

static int INLINE stream_filter_ipv6(struct xdp_md *ctx, struct ipv6hdr *ip6h, void *data, void *data_end, __u16 sport, __u16 dport, __u16 vlan0, __u16 vlan1)
{
    struct flowv6_keys tuple;
    struct pair *value;

    if ((void *)(ip6h + 1) > data_end)
        return 0;
    if (!((ip6h->nexthdr == IPPROTO_UDP) || (ip6h->nexthdr == IPPROTO_TCP)))
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
        value->packets++;
        value->bytes += data_end - data;
        DPRINTF("flow_table_v6 MATCH! Assuming mirroring mode. Packet DROPPED. %d -> %d\n", ntohs(tuple.port16[0]), ntohs(tuple.port16[1]));
        return XDP_DROP;
    } else {
        DPRINTF("No entry in v6 table for %d -> %d\n", ntohs(tuple.port16[0]), ntohs(tuple.port16[1]));
    }

    DPRINTF("stream_filter_ipv6, vlan0: %x, vlan1: %x\n", vlan0, vlan1);
    return XDP_PASS;
}

#endif /* _XDP_STREAM_FILTER_COMMON_H */