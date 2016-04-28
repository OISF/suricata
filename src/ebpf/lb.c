//#include <bcc/proto.h>
#include <stdint.h>
#include <stddef.h>
#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/ip.h>

#include "bpf_helpers.h"

#define IPPROTO_TCP 6
#define LINUX_VERSION_CODE 263682

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif

int __section("loadbalancer") lb(struct __sk_buff *skb) {
    uint8_t proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
	if (proto == IPPROTO_TCP) {
        return 1;
    } 
    return 0;
}

char __license[] __section("license") = "GPL";

uint32_t __version __section("version") = LINUX_VERSION_CODE;
