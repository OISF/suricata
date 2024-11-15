#ifndef __EBPF_NETWORK_HEADERS__
#define __EBPF_NETWORK_HEADERS__

struct vlan_hdr {
    __u16	h_vlan_TCI;
    __u16	h_vlan_encapsulated_proto;
};

typedef struct IEEE8021ahHdr_ {
    __u32 flags;
    __u8 c_destination[6];
    __u8 c_source[6];
    __u16 type;              /**< next protocol */
}  __attribute__((__packed__)) IEEE8021ahHdr;

#endif

