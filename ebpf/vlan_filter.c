#include <stdint.h>
#include <stddef.h>
#include <linux/bpf.h>

#include "bpf_helpers.h"

#define LINUX_VERSION_CODE 263682

int SEC("filter") hashfilter(struct __sk_buff *skb) {
    uint16_t vlan_id = skb->vlan_tci & 0x0fff;
    /* accept VLAN 2 and 4 and drop the rest */
    switch (vlan_id) {
        case 2:
        case 4:
            return -1;
        default:
            return 0;
    }
    return 0;
}

char __license[] SEC("license") = "GPL";

uint32_t __version SEC("version") = LINUX_VERSION_CODE;
