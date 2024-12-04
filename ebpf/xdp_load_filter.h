/* #include at the end of an XDP filter implementation, after filter_ip4 and
 * filter_ipb6 have been defined.
 */

#ifndef _XDP_LOAD_FILTER_H
#define _XDP_LOAD_FILTER_H

/* Keeps VSCode JIT/intellisense happy. (It has an include guard.) */
#include "xdp_common.h"

int SEC("xdp") xdp_loadfilter(struct xdp_md *ctx)
{
    void *data_end = CTX_GET_DATA_END(ctx);
    void *data = CTX_GET_DATA(ctx);
    struct ethhdr *eth = data;
    __u16 h_proto;
    __u64 nh_off;

    /* Used by the stream filter look up flows. */
    __u16 vlan0 = 0;
    __u16 vlan1 = 0;

    DPRINTF("Packet %d len\n", (int)(data_end - data));

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end) {
        return XDP_PASS;
    }

    h_proto = eth->h_proto;

    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
        vlan0 = vhdr->h_vlan_TCI & 0x0fff;
        DPRINTF("nh_off %x vhdr->h_vlan_TCI %x\n", nh_off, vhdr->h_vlan_TCI);
        DPRINTF("vlan0 %x\n", vlan0);
    }
    if (h_proto == __constant_htons(0x88e7)) {
        IEEE8021ahHdr *hdr;

        hdr = data + nh_off;
        nh_off += sizeof(IEEE8021ahHdr);
        if (data + nh_off > data_end)
            return XDP_PASS;

        h_proto = hdr->type;
        DPRINTF("802.1ah next header %x\n", ntohs(h_proto));
    }
    if (h_proto == __constant_htons(ETH_P_8021Q) || h_proto == __constant_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end)
            return XDP_PASS;
        h_proto = vhdr->h_vlan_encapsulated_proto;
        vlan1 = vhdr->h_vlan_TCI & 0x0fff;
        DPRINTF("vlan1 %x\n", vlan1);
    }

    if (h_proto == __constant_htons(ETH_P_IP)) {
        return filter_ipv4(ctx, data, nh_off, data_end, vlan0, vlan1);
    }
    else if (h_proto == __constant_htons(ETH_P_IPV6)) {
        return filter_ipv6(ctx, data, nh_off, data_end, vlan0, vlan1);
    }

    return XDP_PASS;
}

#endif /* _XDP_LOAD_FILTER_H */