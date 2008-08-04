#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static u_int32_t cidrs[33];

void CIDRInit(void) {
    int i = 0;

    /* skip 0 as it will result in 0xffffffff */
    cidrs[0] = 0;
    for (i = 1; i < 33; i++) {
        cidrs[i] = htonl(0xFFFFFFFF << (32 - i));
        //printf("CIDRInit: cidrs[%02d] = 0x%08X\n", i, cidrs[i]);
    }
}

u_int32_t CIDRGet(int cidr) {
    if (cidr < 0 || cidr > 32)
        return 0;
    return cidrs[cidr];
}

