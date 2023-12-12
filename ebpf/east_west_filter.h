
#define htonl __constant_ntohl

static __always_inline
__u32 is_east_west (__u32 addr) {
    if( ((addr & htonl(0xff000000)) == htonl(0x0a000000)) || 
        ((addr & htonl(0xffff0000)) == htonl(0xc0a80000)) ||
        ((addr & htonl(0xfff00000)) == htonl(0xac100000))
    ) {
        return 1;
    } 
    return 0;
}