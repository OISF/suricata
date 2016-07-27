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

struct pair {
    uint64_t packets;
    uint64_t bytes;
};

struct bpf_map_def SEC("maps") ip_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct pair),
    .max_entries = 4096,
};

static __always_inline int ipv4_filter(struct __sk_buff *skb)
{
    uint32_t nhoff;
    uint32_t src, dst;
    struct pair *value;

    nhoff = skb->cb[0];
    src = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
    dst = load_word(skb, nhoff + offsetof(struct iphdr, daddr));

#if 0
    char fmt[] = "Got addr: %u -> %u\n";
    bpf_trace_printk(fmt, sizeof(fmt), src, dst);
    char fmt2[] = "Got hash %u\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), src + dst);
#endif

    /* Test if src is in hash */
    value = bpf_map_lookup_elem(&ip_table, &src);
    if (value) {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, skb->len);
        return 0;
    }

#if 0
    /* Test if dst is in hash */
	value = bpf_map_lookup_elem(&ip_table, &dst);
    if (value) {
		__sync_fetch_and_add(&value->packets, 1);
		__sync_fetch_and_add(&value->bytes, skb->len);
        return 0;
    }
#endif
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
