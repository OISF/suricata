//#include <bcc/proto.h>
#include <stdint.h>
#include <stddef.h>
#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/filter.h>

#include "bpf_helpers.h"

#define LINUX_VERSION_CODE 263682

struct flowv4_keys {
    __be32 src;
    __be32 dst;
    union {
        __be32 ports;
        __be16 port16[2];
    };
    __u32 ip_proto;
};

struct pair {
    uint64_t time;
    uint64_t packets;
    uint64_t bytes;
};

struct bpf_map_def SEC("maps") flow_table_v4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flowv4_keys),
    .value_size = sizeof(struct pair),
    .max_entries = 32768,
};

static __always_inline int ipv4_filter(struct __sk_buff *skb)
{
    uint32_t nhoff, verlen;
    struct flowv4_keys tuple;
    struct pair *value;
    uint16_t port;

    nhoff = skb->cb[0];

    tuple.src = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
    tuple.dst = load_word(skb, nhoff + offsetof(struct iphdr, daddr));

    verlen = load_byte(skb, nhoff + 0/*offsetof(struct iphdr, ihl)*/);
    nhoff += (verlen & 0xF) << 2;
    tuple.ports = load_word(skb, nhoff);
    port = tuple.port16[1];
    tuple.port16[1] = tuple.port16[0];
    tuple.port16[0] = port;
    tuple.ip_proto = 6;

#if 0
    if ((tuple.port16[0] == 22) || (tuple.port16[1] == 22))
    {
        uint16_t sp = tuple.port16[0];
        //uint16_t dp = tuple.port16[1];
        char fmt[] = "Parsed SSH flow: %u %d -> %u\n";
        bpf_trace_printk(fmt, sizeof(fmt), tuple.src, sp, tuple.dst);
    }
#endif
    /* Test if src is in hash */
    value = bpf_map_lookup_elem(&flow_table_v4, &tuple);
    if (value) {
#if 0
        {
            uint16_t sp = tuple.port16[0];
            //uint16_t dp = tuple.port16[1];
            char bfmt[] = "Found flow: %u %d -> %u\n";
            bpf_trace_printk(bfmt, sizeof(bfmt), tuple.src, sp, tuple.dst);
        }
#endif
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, skb->len);
        value->time = bpf_ktime_get_ns();
        return 0;
    }
    return -1;
}

static __always_inline int ipv6_filter(struct __sk_buff *skb)
{
    uint32_t nhoff;

    nhoff = skb->cb[0];
    return -1;
}

int SEC("filter") hashfilter(struct __sk_buff *skb) {
    __u32 nhoff = BPF_LL_OFF + ETH_HLEN;

    skb->cb[0] = nhoff;
    switch (skb->protocol) {
        case __constant_htons(ETH_P_IP):
            return ipv4_filter(skb);
        case __constant_htons(ETH_P_IPV6):
            return ipv6_filter(skb);
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

uint32_t __version SEC("version") = LINUX_VERSION_CODE;
