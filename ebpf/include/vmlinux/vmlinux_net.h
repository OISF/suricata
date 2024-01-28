#ifndef __VMLINUX_NET_H__
#define __VMLINUX_NET_H__

typedef __u32 __wsum;

struct nf_conn {
    unsigned long status;
};

enum ip_conntrack_status {
    /* Connection is confirmed: originating packet has left box */
    IPS_CONFIRMED_BIT = 3,
    IPS_CONFIRMED = (1 << IPS_CONFIRMED_BIT),
};

#endif /* __VMLINUX_NET_H__ */
