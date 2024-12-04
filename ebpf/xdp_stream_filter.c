/* Standalone stream filter implementation. */

#include "xdp_common.h"

/* Implementation of the stream filter functions, which are also used by xdp_lb.c. */
#include "xdp_stream_filter_common.h"

static int INLINE filter_ipv4(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end, __u16 vlan0, __u16 vlan1)
{
    int sport;
    int dport;

    struct iphdr *iph = data + nh_off;
    if ((void *)(iph + 1) > data_end) {
        DPRINTF("Ignoring packet. iph: %d, data_end: %d\n", iph, data_end);
        return XDP_PASS;
    }

    dport = get_dport(iph + 1, data_end, iph->protocol);
    if (dport == -1)
        return XDP_PASS;

    sport = get_sport(iph + 1, data_end, iph->protocol);
    if (sport == -1)
        return XDP_PASS;


    return stream_filter_ipv4(ctx, iph, data, data_end, sport, dport, vlan0, vlan1);
}

static int INLINE filter_ipv6(struct xdp_md *ctx, void *data, __u64 nh_off, void *data_end, __u16 vlan0, __u16 vlan1)
{
    int sport;
    int dport;

    struct ipv6hdr *ip6h = data + nh_off;
    if ((void *)(ip6h + 1) > data_end) {
        DPRINTF("Ignoring packet. iph: %d, data_end: %d\n", ip6h, data_end);
        return XDP_PASS;
    }

    dport = get_dport(ip6h + 1, data_end, ip6h->nexthdr);
    if (dport == -1)
        return XDP_PASS;

    sport = get_sport(ip6h + 1, data_end, ip6h->nexthdr);
    if (sport == -1)
        return XDP_PASS;

    return stream_filter_ipv6(ctx, ip6h, data, data_end, sport, dport, vlan0, vlan1);
}

#include "xdp_load_filter.h"

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;