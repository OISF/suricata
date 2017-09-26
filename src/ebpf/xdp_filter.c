//#include <bcc/proto.h>
#define KBUILD_MODNAME "foo"
#include <stdint.h>
#include <stddef.h>
#include <linux/bpf.h>

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "bpf_helpers.h"

#define LINUX_VERSION_CODE 263682

struct vlan_hdr {
    __be16	h_vlan_TCI;
    __be16	h_vlan_encapsulated_proto;
};

struct flowv4_keys {
    __be32 src;
    __be32 dst;
    union {
        __be32 ports;
        __be16 port16[2];
    };
    __u32 ip_proto;
};

struct flowv6_keys {
    __be32 src[4];
    __be32 dst[4];
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

struct bpf_map_def SEC("maps") flow_table_v6 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flowv6_keys),
    .value_size = sizeof(struct pair),
    .max_entries = 32768,
};

static int parse_ipv4(void *data, __u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;

	if ((void *)(iph + 1) > data_end)
		return 0;
	return iph->protocol;
}

static int parse_ipv6(void *data, __u64 nh_off, void *data_end)
{
	struct ipv6hdr *ip6h = data + nh_off;

	if ((void *)(ip6h + 1) > data_end)
		return 0;
	return ip6h->nexthdr;
}

int SEC("xdp") xdp_hashfilter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    int rc = XDP_PASS;
    uint16_t h_proto;
	uint64_t nh_off;
	uint32_t ipproto = IPPROTO_TCP;

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
		ipproto = parse_ipv4(data, nh_off, data_end);
	else if (h_proto == __constant_htons(ETH_P_IPV6))
		ipproto = parse_ipv6(data, nh_off, data_end);
	else
		rc = XDP_DROP;

    if (ipproto == IPPROTO_UDP)
        rc = XDP_DROP;

    return rc;
}

char __license[] SEC("license") = "GPL";

uint32_t __version SEC("version") = LINUX_VERSION_CODE;
