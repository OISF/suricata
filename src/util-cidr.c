#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static u_int32_t cidrs[33];

void CIDRInit(void) {
    int i = 0;

    for (i = 0; i < 33; i++) {
        cidrs[i] = htonl(0xFFFFFFFF << (32 - i));
        printf("CIDRInit: cidrs[%02d] = 0x%08X\n", i, cidrs[i]);
    }
}

u_int32_t CIDRGet(int cidr) {
    return cidrs[cidr];
}

