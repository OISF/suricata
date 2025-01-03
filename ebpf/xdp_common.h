/*
 * Code that's common to multiple XDP programs. Duh.
 */

#ifndef _XDP_COMMON_H
#define _XDP_COMMON_H

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
#include <bpf/bpf_helpers.h>
#include "network_headers.h"

#ifdef DEBUG
    #if DEBUG == 0
    #undef DEBUG
    #endif
#else
/* #define DEBUG 1 */
#endif

/* Both are required in order to ensure *everything* is inlined.  The kernel version that 
 * we're using doesn't support calling functions in XDP, so it must appear as a single function.
 * Kernel 4.16+ support function calls:
 * https://stackoverflow.com/questions/70529753/clang-bpf-attribute-always-inline-does-not-working
 */
#define INLINE __always_inline __attribute__((always_inline))

#ifdef DEBUG
#define DPRINTF(fmt_str, args...) { \
    char fmt[] = fmt_str; \
    bpf_trace_printk(fmt, sizeof(fmt), args); \
}
#else
#define DPRINTF(fmt_str, args...)
#endif

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

#ifdef DEBUG
static void INLINE trace_ipv4(__u32 ip) {
    DPRINTF("%d.%d.<next line>\n", (ip & 0x000000ff), (ip & 0x0000ff00) >> 8);
    DPRINTF("%d.%d\n", (ip & 0x00ff0000) >> 16, (ip & 0xff000000) >> 24);
}

/* 
 * Trace the tuple char-by-char for comparision with bpftool ouptput.
 * Output is spread over multiple lines due to the limited number of args to
 * bpf_trace_printk.
 * 
 * Unfortunately, the version of bpf_trace_printk that we're using doesn't seem
 * to support %x, so hex conversion is left as an exercise for the user.
 */
static void trace_bytes(void *data, __u16 len) {
    __u16 i = 0;
    for (; i + 3 < len; i += 3) {
        /* Three seems to be the most args we can pass to bpf_trace_printk. */
        DPRINTF("%d %d %d\n", *((unsigned char*)data + i), *((unsigned char*)data + i + 1), *((unsigned char*)data + i + 2));
    }

    /* Get the remaining few bytes, if not evenly divisible by 3. */
    for (; i < len; i++) {
        DPRINTF("%d\n", *((unsigned char*)data + i));
    }
}
#else
#define trace_ipv4(ip)
#define trace_bytes(data, len)
#endif

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

#endif /* _XDP_COMMON_H */
