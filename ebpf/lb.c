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

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif

static __always_inline int ipv4_hash(struct __sk_buff *skb)
{
    uint32_t nhoff;
    uint32_t src, dst;

    nhoff = skb->cb[0];
    src = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
    dst = load_word(skb, nhoff + offsetof(struct iphdr, daddr));

#if 0
    char fmt[] = "Got addr: %u -> %u\n";
    bpf_trace_printk(fmt, sizeof(fmt), src, dst);
    char fmt2[] = "Got hash %u\n";
    bpf_trace_printk(fmt2, sizeof(fmt2), src + dst);
#endif
    return  src + dst;
}

static __always_inline int ipv6_hash(struct __sk_buff *skb)
{
    uint32_t nhoff;
    uint32_t src, dst, hash;

    nhoff = skb->cb[0];
    hash = 0;
    src = load_word(skb, nhoff + offsetof(struct ipv6hdr, saddr) + 4 * 0 );
    dst = load_word(skb, nhoff + offsetof(struct ipv6hdr, daddr) + 4 * 0 );
    hash += src + dst;

    src = load_word(skb, nhoff + offsetof(struct ipv6hdr, saddr) + 4 * 1 );
    dst = load_word(skb, nhoff + offsetof(struct ipv6hdr, daddr) + 4 * 1 );
    hash += src + dst;

    src = load_word(skb, nhoff + offsetof(struct ipv6hdr, saddr) + 4 * 2 );
    dst = load_word(skb, nhoff + offsetof(struct ipv6hdr, daddr) + 4 * 2 );
    hash += src + dst;

    src = load_word(skb, nhoff + offsetof(struct ipv6hdr, saddr) + 4 * 3 );
    dst = load_word(skb, nhoff + offsetof(struct ipv6hdr, daddr) + 4 * 3 );
    hash += src + dst;

    return hash;
}

int  __section("loadbalancer") lb(struct __sk_buff *skb) {
    __u32 nhoff = BPF_LL_OFF + ETH_HLEN;

    skb->cb[0] = nhoff;

    switch (skb->protocol) {
        case __constant_htons(ETH_P_IP):
            return ipv4_hash(skb);
        case __constant_htons(ETH_P_IPV6):
            return ipv6_hash(skb);
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
    /* hash on proto by default */
    return skb->protocol;
}

char __license[] __section("license") = "GPL";

uint32_t __version __section("version") = LINUX_VERSION_CODE;
