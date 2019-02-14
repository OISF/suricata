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

#include <stddef.h>
#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/filter.h>

#include "bpf_helpers.h"

#define DEBUG 0

#define LINUX_VERSION_CODE 263682

struct bpf_map_def SEC("maps") ipv4_drop = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 32768,
};

int SEC("filter") hashfilter(struct __sk_buff *skb) {
    __u32 nhoff = ETH_HLEN;
    __u32 ip = 0;
    __u32 *value;

    ip = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
    value = bpf_map_lookup_elem(&ipv4_drop, &ip);
    if (value) {
#if DEBUG
        char fmt[] = "Found value for saddr: %u\n";
        bpf_trace_printk(fmt, sizeof(fmt), value);
#endif
        __sync_fetch_and_add(value, 1);
        return 0;
    }

    ip = load_word(skb, nhoff + offsetof(struct iphdr, daddr));
    value = bpf_map_lookup_elem(&ipv4_drop, &ip);
    if (value) {
#if DEBUG
        char fmt[] = "Found value for daddr: %u\n";
        bpf_trace_printk(fmt, sizeof(fmt), value);
#endif
        __sync_fetch_and_add(value, 1);
        return 0;
    }

#if DEBUG
    char fmt[] = "Nothing so ok\n";
    bpf_trace_printk(fmt, sizeof(fmt));
#endif
    return -1;
}

char __license[] SEC("license") = "GPL";

__u32 __version SEC("version") = LINUX_VERSION_CODE;
