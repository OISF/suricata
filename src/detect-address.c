/* Address part of the detection engine. */

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"

int DetectAddressSetup (Signature *s, SigMatch *m, char *sidstr);
void DetectAddressTests (void);

void DetectAddressRegister (void) {
    sigmatch_table[DETECT_ADDRESS].name = "address";
    sigmatch_table[DETECT_ADDRESS].Match = NULL;
    sigmatch_table[DETECT_ADDRESS].Setup = DetectAddressSetup;
    sigmatch_table[DETECT_ADDRESS].Free = NULL;
    sigmatch_table[DETECT_ADDRESS].RegisterTests = DetectAddressTests;
}

typedef struct DetectAddressData_ {
    u_int8_t family;
    u_int32_t ip[4];
    u_int32_t mask[4];
} DetectAddressData;

/* a is ... than b */
enum {
    ADDRESS_ER = -1, /* error e.g. compare ipv4 and ipv6 */
    ADDRESS_LT,      /* smaller              [aaa] [bbb] */
    ADDRESS_EQ,      /* exactly equal        [abababab]  */
    ADDRESS_ES,      /* within               [bb[aaa]bb] and [[abab]bbb] and [bbb[abab]] */
    ADDRESS_EB,      /* completely overlaps  [aa[bbb]aa] and [[baba]aaa] and [aaa[baba]] */
    ADDRESS_GT,      /* bigger               [bbb] [aaa] */
};

int AddressCmpIPv4(DetectAddressData *a, DetectAddressData *b) {
    u_int32_t net_a, net_b, brd_a, brd_b;

    brd_a = net_a = a->ip[0] & a->mask[0];
    brd_a |=~ a->mask[0];

    brd_b = net_b = b->ip[0] & b->mask[0];
    brd_b |=~ b->mask[0];

    net_a = ntohl(net_a);
    brd_a = ntohl(brd_a);

    net_b = ntohl(net_b);
    brd_b = ntohl(brd_b);

//    printf("\nnet_a 0x%08X, brd_a 0x%08X: %08u %08u\n", net_a, brd_a, net_a, brd_a);
//    printf("net_b 0x%08X, brd_b 0x%08X: %08u %08u\n", net_b, brd_b, net_b, brd_b);

    /* ADDRESS_EQ */
    if (a->ip[0] == b->ip[0] && a->mask[0] == b->mask[0]) {
//        printf("ADDRESS_EQ\n");
        return ADDRESS_EQ;
    } else if (net_a == net_b && brd_a == brd_b) {
//        printf("ADDRESS_EQ\n");
        return ADDRESS_EQ;
    /* ADDRESS_ES */
    } else if (net_a >= net_b && net_a < brd_b && brd_a <= brd_b) {
//        printf("ADDRESS_ES\n");
        return ADDRESS_ES;
    /* ADDRESS_EB */
    } else if (net_a <= net_b && brd_a >= brd_b) {
//        printf("ADDRESS_EB\n");
        return ADDRESS_EB;
    } else if (net_a < net_b && brd_a <= net_b) {
//        printf("ADDRESS_LT\n");
        return ADDRESS_LT;
    } else if (net_a >= brd_b) {
//        printf("ADDRESS_GT\n");
        return ADDRESS_GT;
    } else {
        /* should be unreachable */
//        printf("Internal Error: should be unreachable\n");
    }

//    printf ("ADDRESS_ER\n");
    return ADDRESS_ER;
}

/* return: 1 lt, 0 not lt */
static int AddressIPv6Lt(u_int32_t *a, u_int32_t *b) {
    int i = 0;

    for (i = 0; i < 4; i++) {
        if (a[i] < b[i])
            return 1;
    }

    return 0;
}

/* return: 1 gt, 0 not gt */
static int AddressIPv6Gt(u_int32_t *a, u_int32_t *b) {
    int i = 0;

    for (i = 0; i < 4; i++) {
        if (a[i] > b[i])
            return 1;
    }

    return 0;
}

/* return: 1 eq, 0 not eq */
static int AddressIPv6Eq(u_int32_t *a, u_int32_t *b) {
    int i = 0;

    for (i = 0; i < 4; i++) {
        if (a[i] != b[i])
            return 0;
    }

    return 1;
}

/* return: 1 le, 0 not le */
static int AddressIPv6Le(u_int32_t *a, u_int32_t *b) {
    int i = 0;

    if (AddressIPv6Eq(a,b) == 1)
        return 1;

    for (i = 0; i < 4; i++) {
        if (a[i] < b[i])
            return 1;
    }

    return 0;
}

/* return: 1 ge, 0 not ge */
static int AddressIPv6Ge(u_int32_t *a, u_int32_t *b) {
    int i = 0;

    if (AddressIPv6Eq(a,b) == 1)
        return 1;

    for (i = 0; i < 4; i++) {
        if (a[i] > b[i])
            return 1;
    }

    return 0;
}

int AddressCmpIPv6(DetectAddressData *a, DetectAddressData *b) {
    u_int32_t net_a[4], net_b[4], brd_a[4], brd_b[4];

    brd_a[0] = net_a[0] = a->ip[0] & a->mask[0];
    brd_a[1] = net_a[1] = a->ip[1] & a->mask[1];
    brd_a[2] = net_a[2] = a->ip[2] & a->mask[2];
    brd_a[3] = net_a[3] = a->ip[3] & a->mask[3];

    brd_a[0] |=~ a->mask[0];
    brd_a[1] |=~ a->mask[1];
    brd_a[2] |=~ a->mask[2];
    brd_a[3] |=~ a->mask[3];

    brd_b[0] = net_b[0] = b->ip[0] & b->mask[0];
    brd_b[1] = net_b[1] = b->ip[1] & b->mask[1];
    brd_b[2] = net_b[2] = b->ip[2] & b->mask[2];
    brd_b[3] = net_b[3] = b->ip[3] & b->mask[3];

    brd_b[0] |=~ b->mask[0];
    brd_b[1] |=~ b->mask[1];
    brd_b[2] |=~ b->mask[2];
    brd_b[3] |=~ b->mask[3];

    /* ADDRESS_EQ */
    if (AddressIPv6Eq(a->ip, b->ip) == 1 &&
        AddressIPv6Eq(a->mask, b->mask) == 1) {
//        printf("ADDRESS_EQ\n");
        return ADDRESS_EQ;
    } else if (AddressIPv6Eq(net_a, net_b) == 1 &&
               AddressIPv6Eq(brd_a, brd_b) == 1) {
//        printf("ADDRESS_EQ\n");
        return ADDRESS_EQ;
    /* ADDRESS_ES */
    } else if (AddressIPv6Ge(net_a, net_b) == 1 &&
               AddressIPv6Lt(net_a, brd_b) == 1 &&
               AddressIPv6Le(brd_a, brd_b) == 1) {
//        printf("ADDRESS_ES\n");
        return ADDRESS_ES;
    /* ADDRESS_EB */
    } else if (AddressIPv6Le(net_a, net_b) == 1 &&
               AddressIPv6Ge(brd_a, brd_b) == 1) {
//        printf("ADDRESS_EB\n");
        return ADDRESS_EB;
    } else if (AddressIPv6Lt(net_a, net_b) == 1 &&
               AddressIPv6Le(brd_a, net_b) == 1) {
//        printf("ADDRESS_LT\n");
        return ADDRESS_LT;
    } else if (AddressIPv6Ge(net_a, brd_b) == 1) {
//        printf("ADDRESS_GT\n");
        return ADDRESS_GT;
    } else {
        /* should be unreachable */
//        printf("Internal Error: should be unreachable\n");
    }

//    printf ("ADDRESS_ER\n");
    return ADDRESS_ER;
}

int AddressCmp(DetectAddressData *a, DetectAddressData *b) {
    if (a->family != b->family)
        return ADDRESS_ER;

    if (a->family == AF_INET)
        return AddressCmpIPv4(a,b);
    else if (a->family == AF_INET6)
        return AddressCmpIPv6(a,b);

    return ADDRESS_ER;
}

void ParseIPv6CIDR(int cidr, struct in6_addr *in6) {
    int i = 0;

    //printf("CIDR: %d\n", cidr);

    memset(in6, 0, sizeof(struct in6_addr));

    while (cidr > 8) {
        in6->s6_addr[i] = 0xff;
        cidr -= 8;
        i++;
    }

    while (cidr > 0) {
        in6->s6_addr[i] |= 0x80;
        if (--cidr > 0)
             in6->s6_addr[i] = in6->s6_addr[i] >> 1;
    }
}

int AddressParse(DetectAddressData *dd, char *str) {
    char *ip = strdup(str);
    char *mask = NULL;
    char *ip6 = NULL;
    int r = 0;

    if ((ip6 = strchr(str,':')) == NULL) {
        /* IPv4 Address */
        struct in_addr in;

        dd->family = AF_INET;

        if ((mask = strchr(ip, '/')) != NULL)  {
            /* 1.2.3.4/xxx format (either dotted or cidr notation */
            ip[mask - ip] = '\0';
            mask++;

            char *t = NULL;
            if ((t = strchr (mask,'.')) == NULL) {
                /* 1.2.3.4/24 format */

                int cidr = atoi(mask);
                dd->mask[0] = CIDRGet(cidr);
            } else {
                /* 1.2.3.4/255.255.255.0 format */
                r = inet_pton(AF_INET, mask, &in);
                if (r <= 0) {
                    goto error;
                }
        
                dd->mask[0] = in.s_addr;
                //printf("AddressParse: dd->mask %X\n", dd->mask);
            }

            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0) {
                goto error;
            }
        
            dd->ip[0] = in.s_addr;
            //printf("AddressParse: dd->ip %X\n", dd->ip);
        } else {
            /* 1.2.3.4 format */
            dd->mask[0] = 0xffffffff;

            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0) {
                goto error;
            }
        
            dd->ip[0] = in.s_addr;
            //printf("AddressParse: dd->ip %X\n", dd->ip);
        }
    } else {
        /* IPv6 Address */
        struct in6_addr in6, mask6;

        dd->family = AF_INET6;

        if ((mask = strchr(ip, '/')) != NULL)  {
            ip[mask - ip] = '\0';
            mask++;

            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0) {
                goto error;
            }
            memcpy(&dd->ip, &in6.s6_addr, sizeof(dd->ip));

            ParseIPv6CIDR(atoi(mask), &mask6);
            memcpy(&dd->mask, &mask6.s6_addr, sizeof(dd->mask));
/*
            int i;
            printf("ip6   0x");
            for (i = 0; i < 16; i++)
                printf("%02X", in6.s6_addr[i]);
            printf("\n");

            printf("mask6 0x");
            for (i = 0; i < 16; i++)
                printf("%02X", mask6.s6_addr[i]);
            printf("\n");
*/
        } else {
            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0) {
                goto error;
            }

            memcpy(&dd->ip, &in6.s6_addr, sizeof(dd->ip));
            dd->mask[0] = 0xffffffff;
            dd->mask[1] = 0xffffffff;
            dd->mask[2] = 0xffffffff;
            dd->mask[3] = 0xffffffff;
        }

    }

    return 0;

error:
    if (ip) free(ip);
    return -1;
}

DetectAddressData *DetectAddressParse(char *str) {
    DetectAddressData *dd;

    dd = malloc(sizeof(DetectAddressData));
    if (dd == NULL) {
        printf("DetectAddressSetup malloc failed\n");
        goto error;
    }

    if (AddressParse(dd, str) < 0) {
        goto error;
    }

    return dd;

error:
    if (dd) free(dd);
    return NULL;
}

int DetectAddressSetup (Signature *s, SigMatch *m, char *addressstr)
{
    char *str = addressstr;
    char dubbed = 0;

    /* strip "'s */
    if (addressstr[0] == '\"' && addressstr[strlen(addressstr)-1] == '\"') {
        str = strdup(addressstr+1);
        str[strlen(addressstr)-2] = '\0';
        dubbed = 1;
    }


    if (dubbed) free(str);
    return 0;
}

void DetectAddressFree(DetectAddressData *dd) {
    free(dd);
}

int DetectAddressMatch (DetectAddressData *dd, Address *a) {
    if (dd->family != a->family)
        return 0;

    switch (a->family) {
        case AF_INET:
            if ((dd->ip[0] & dd->mask[0]) == (a->addr_data32[0] & dd->mask[0])) {
                return 1;
            } else {
                return 0;
            }
            break;
        case AF_INET6:
            //printf("\n0x%08X 0x%08X\n", dd->ip[0] & dd->mask[0], a->addr_data32[0] & dd->mask[0]);
            //printf("0x%08X 0x%08X\n", dd->ip[1] & dd->mask[1], a->addr_data32[1] & dd->mask[1]);
            //printf("0x%08X 0x%08X\n", dd->ip[2] & dd->mask[2], a->addr_data32[2] & dd->mask[2]);
            //printf("0x%08X 0x%08X\n", dd->ip[3] & dd->mask[3], a->addr_data32[3] & dd->mask[3]);

            if ((dd->ip[0] & dd->mask[0]) == (a->addr_data32[0] & dd->mask[0]) &&
                (dd->ip[1] & dd->mask[1]) == (a->addr_data32[1] & dd->mask[1]) &&
                (dd->ip[2] & dd->mask[2]) == (a->addr_data32[2] & dd->mask[2]) &&
                (dd->ip[3] & dd->mask[3]) == (a->addr_data32[3] & dd->mask[3]))
            {
                return 1;
            } else {
                return 0;
            }
            break;
    }

    return 0;
}


/* TESTS */

int AddressTestParse01 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("1.2.3.4");
    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse02 (void) {
    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("1.2.3.4");
    if (dd) {
        if (dd->mask[0] != 0xffffffff ||
            dd->ip[0]   != 0x04030201) {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse03 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("1.2.3.4/255.255.255.0");
    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse04 (void) {
    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("1.2.3.4/255.255.255.0");
    if (dd) {
        if (dd->mask[0] != 0x00ffffff ||
            dd->ip[0]   != 0x04030201) {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse05 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("1.2.3.4/24");
    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse06 (void) {
    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("1.2.3.4/24");
    if (dd) {
        if (dd->mask[0] != 0x00ffffff ||
            dd->ip[0]   != 0x04030201) {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse07 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/3");
    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse08 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/3");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->mask[0] != 0x000000E0 || dd->mask[1] != 0x00000000 ||
            dd->mask[2] != 0x00000000 || dd->mask[3] != 0x00000000)
        {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse09 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::1/128");
    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse10 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/128");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->mask[0] != 0xFFFFFFFF || dd->mask[1] != 0xFFFFFFFF ||
            dd->mask[2] != 0xFFFFFFFF || dd->mask[3] != 0xFFFFFFFF)
        {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse11 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/48");
    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse12 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/48");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->mask[0] != 0xFFFFFFFF || dd->mask[1] != 0x0000FFFF ||
            dd->mask[2] != 0x00000000 || dd->mask[3] != 0x00000000)
        {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}
int AddressTestParse13 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/16");
    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse14 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/16");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->mask[0] != 0x0000FFFF || dd->mask[1] != 0x00000000 ||
            dd->mask[2] != 0x00000000 || dd->mask[3] != 0x00000000)
        {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse15 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/0");
    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse16 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/0");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->mask[0] != 0x00000000 || dd->mask[1] != 0x00000000 ||
            dd->mask[2] != 0x00000000 || dd->mask[3] != 0x00000000)
        {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch01 (void) {
    struct in_addr in;
    Address a;

    inet_pton(AF_INET, "1.2.3.4", &in);

    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("1.2.3.4/24");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 0)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch02 (void) {
    struct in_addr in;
    Address a;

    inet_pton(AF_INET, "1.2.3.127", &in);

    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("1.2.3.4/25");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 0)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch03 (void) {
    struct in_addr in;
    Address a;

    inet_pton(AF_INET, "1.2.3.128", &in);

    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("1.2.3.4/25");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 1)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch04 (void) {
    struct in_addr in;
    Address a;

    inet_pton(AF_INET, "1.2.2.255", &in);

    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("1.2.3.4/25");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 1)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch05 (void) {
    struct in_addr in;
    Address a;

    inet_pton(AF_INET, "1.2.3.4", &in);

    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("1.2.3.4/32");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 0)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch06 (void) {
    struct in_addr in;
    Address a;

    inet_pton(AF_INET, "1.2.3.4", &in);

    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("0.0.0.0/0.0.0.0");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 0)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch07 (void) {
    struct in6_addr in6;
    Address a;

    inet_pton(AF_INET6, "2001::1", &in6);
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("2001::/3");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 0)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch08 (void) {
    struct in6_addr in6;
    Address a;

    inet_pton(AF_INET6, "1999:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &in6);
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("2001::/3");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 1)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch09 (void) {
    struct in6_addr in6;
    Address a;

    inet_pton(AF_INET6, "2001::2", &in6);
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("2001::1/128");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 1)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch10 (void) {
    struct in6_addr in6;
    Address a;

    inet_pton(AF_INET6, "2001::2", &in6);
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("2001::1/126");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 0)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch11 (void) {
    struct in6_addr in6;
    Address a;

    inet_pton(AF_INET6, "2001::3", &in6);
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("2001::1/127");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 1)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestCmp01 (void) {
    DetectAddressData *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParse("192.168.0.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParse("192.168.0.0/255.255.255.0");
    if (db == NULL) goto error;

    if (AddressCmp(da,db) != ADDRESS_EQ)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp02 (void) {
    DetectAddressData *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParse("192.168.0.0/255.255.0.0");
    if (da == NULL) goto error;
    db = DetectAddressParse("192.168.0.0/255.255.255.0");
    if (db == NULL) goto error;

    if (AddressCmp(da,db) != ADDRESS_EB)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp03 (void) {
    DetectAddressData *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParse("192.168.0.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParse("192.168.0.0/255.255.0.0");
    if (db == NULL) goto error;

    if (AddressCmp(da,db) != ADDRESS_ES)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp04 (void) {
    DetectAddressData *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParse("192.168.0.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParse("192.168.1.0/255.255.255.0");
    if (db == NULL) goto error;

    if (AddressCmp(da,db) != ADDRESS_LT)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp05 (void) {
    DetectAddressData *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParse("192.168.1.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParse("192.168.0.0/255.255.255.0");
    if (db == NULL) goto error;

    if (AddressCmp(da,db) != ADDRESS_GT)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp06 (void) {
    DetectAddressData *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParse("192.168.1.0/255.255.0.0");
    if (da == NULL) goto error;
    db = DetectAddressParse("192.168.0.0/255.255.0.0");
    if (db == NULL) goto error;

    if (AddressCmp(da,db) != ADDRESS_EQ)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp07 (void) {
    DetectAddressData *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParse("2001::/3");
    if (da == NULL) goto error;
    db = DetectAddressParse("2001::1/3");
    if (db == NULL) goto error;

    if (AddressCmp(da,db) != ADDRESS_EQ)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp08 (void) {
    DetectAddressData *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParse("2001::/3");
    if (da == NULL) goto error;
    db = DetectAddressParse("2001::/8");
    if (db == NULL) goto error;

    if (AddressCmp(da,db) != ADDRESS_EB)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp09 (void) {
    DetectAddressData *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParse("2001::/8");
    if (da == NULL) goto error;
    db = DetectAddressParse("2001::/3");
    if (db == NULL) goto error;

    if (AddressCmp(da,db) != ADDRESS_ES)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp10 (void) {
    DetectAddressData *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParse("2001:1:2:3:0:0:0:0/64");
    if (da == NULL) goto error;
    db = DetectAddressParse("2001:1:2:4:0:0:0:0/64");
    if (db == NULL) goto error;

    if (AddressCmp(da,db) != ADDRESS_LT)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp11 (void) {
    DetectAddressData *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParse("2001:1:2:4:0:0:0:0/64");
    if (da == NULL) goto error;
    db = DetectAddressParse("2001:1:2:3:0:0:0:0/64");
    if (db == NULL) goto error;

    if (AddressCmp(da,db) != ADDRESS_GT)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp12 (void) {
    DetectAddressData *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParse("2001:1:2:3:1:0:0:0/64");
    if (da == NULL) goto error;
    db = DetectAddressParse("2001:1:2:3:2:0:0:0/64");
    if (db == NULL) goto error;

    if (AddressCmp(da,db) != ADDRESS_EQ)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestIPv6Gt01 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 0, 2, 3, 4 };

    if (AddressIPv6Gt(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Gt02 (void) {
    int result = 0;

    u_int32_t a[4] = { 0, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Gt(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Gt03 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Gt(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Gt04 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 5 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Gt(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Lt01 (void) {
    int result = 0;

    u_int32_t a[4] = { 0, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Lt(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Lt02 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 0, 2, 3, 4 };

    if (AddressIPv6Lt(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Lt03 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Lt(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Lt04 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 5 };

    if (AddressIPv6Lt(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Eq01 (void) {
    int result = 0;

    u_int32_t a[4] = { 0, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Eq(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Eq02 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 0, 2, 3, 4 };

    if (AddressIPv6Eq(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Eq03 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Eq(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Eq04 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 5 };

    if (AddressIPv6Eq(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Le01 (void) {
    int result = 0;

    u_int32_t a[4] = { 0, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Le(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Le02 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 0, 2, 3, 4 };

    if (AddressIPv6Le(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Le03 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Le(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Le04 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 5 };

    if (AddressIPv6Le(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Ge01 (void) {
    int result = 0;

    u_int32_t a[4] = { 0, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Ge(a,b) == 0)
        result = 1;

    return result;
}

int AddressTestIPv6Ge02 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 0, 2, 3, 4 };

    if (AddressIPv6Ge(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Ge03 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 4 };

    if (AddressIPv6Ge(a,b) == 1)
        result = 1;

    return result;
}

int AddressTestIPv6Ge04 (void) {
    int result = 0;

    u_int32_t a[4] = { 1, 2, 3, 4 };
    u_int32_t b[4] = { 1, 2, 3, 5 };

    if (AddressIPv6Ge(a,b) == 0)
        result = 1;

    return result;
}

void DetectAddressTests(void) {
    UtRegisterTest("AddressTestParse01", AddressTestParse01, 1);
    UtRegisterTest("AddressTestParse02", AddressTestParse02, 1);
    UtRegisterTest("AddressTestParse03", AddressTestParse03, 1);
    UtRegisterTest("AddressTestParse04", AddressTestParse04, 1);
    UtRegisterTest("AddressTestParse05", AddressTestParse05, 1);
    UtRegisterTest("AddressTestParse06", AddressTestParse06, 1);
    UtRegisterTest("AddressTestParse07", AddressTestParse07, 1);
    UtRegisterTest("AddressTestParse08", AddressTestParse08, 1);
    UtRegisterTest("AddressTestParse09", AddressTestParse09, 1);
    UtRegisterTest("AddressTestParse10", AddressTestParse10, 1);
    UtRegisterTest("AddressTestParse11", AddressTestParse11, 1);
    UtRegisterTest("AddressTestParse12", AddressTestParse12, 1);
    UtRegisterTest("AddressTestParse13", AddressTestParse13, 1);
    UtRegisterTest("AddressTestParse14", AddressTestParse14, 1);
    UtRegisterTest("AddressTestParse15", AddressTestParse15, 1);
    UtRegisterTest("AddressTestParse16", AddressTestParse16, 1);

    UtRegisterTest("AddressTestMatch01", AddressTestMatch01, 1);
    UtRegisterTest("AddressTestMatch02", AddressTestMatch02, 1);
    UtRegisterTest("AddressTestMatch03", AddressTestMatch03, 1);
    UtRegisterTest("AddressTestMatch04", AddressTestMatch04, 1);
    UtRegisterTest("AddressTestMatch05", AddressTestMatch05, 1);
    UtRegisterTest("AddressTestMatch06", AddressTestMatch06, 1);
    UtRegisterTest("AddressTestMatch07", AddressTestMatch07, 1);
    UtRegisterTest("AddressTestMatch08", AddressTestMatch08, 1);
    UtRegisterTest("AddressTestMatch09", AddressTestMatch09, 1);
    UtRegisterTest("AddressTestMatch10", AddressTestMatch10, 1);
    UtRegisterTest("AddressTestMatch11", AddressTestMatch11, 1);

    UtRegisterTest("AddressTestCmp01",   AddressTestCmp01, 1);
    UtRegisterTest("AddressTestCmp02",   AddressTestCmp02, 1);
    UtRegisterTest("AddressTestCmp03",   AddressTestCmp03, 1);
    UtRegisterTest("AddressTestCmp04",   AddressTestCmp04, 1);
    UtRegisterTest("AddressTestCmp05",   AddressTestCmp05, 1);
    UtRegisterTest("AddressTestCmp06",   AddressTestCmp06, 1);

    UtRegisterTest("AddressTestCmp07",   AddressTestCmp07, 1);
    UtRegisterTest("AddressTestCmp08",   AddressTestCmp08, 1);
    UtRegisterTest("AddressTestCmp09",   AddressTestCmp09, 1);
    UtRegisterTest("AddressTestCmp10",   AddressTestCmp10, 1);
    UtRegisterTest("AddressTestCmp11",   AddressTestCmp11, 1);
    UtRegisterTest("AddressTestCmp12",   AddressTestCmp12, 1);

    UtRegisterTest("AddressTestIPv6Gt01",   AddressTestIPv6Gt01, 1);
    UtRegisterTest("AddressTestIPv6Gt02",   AddressTestIPv6Gt02, 1);
    UtRegisterTest("AddressTestIPv6Gt03",   AddressTestIPv6Gt03, 1);
    UtRegisterTest("AddressTestIPv6Gt04",   AddressTestIPv6Gt04, 1);

    UtRegisterTest("AddressTestIPv6Lt01",   AddressTestIPv6Lt01, 1);
    UtRegisterTest("AddressTestIPv6Lt02",   AddressTestIPv6Lt02, 1);
    UtRegisterTest("AddressTestIPv6Lt03",   AddressTestIPv6Lt03, 1);
    UtRegisterTest("AddressTestIPv6Lt04",   AddressTestIPv6Lt04, 1);

    UtRegisterTest("AddressTestIPv6Eq01",   AddressTestIPv6Eq01, 1);
    UtRegisterTest("AddressTestIPv6Eq02",   AddressTestIPv6Eq02, 1);
    UtRegisterTest("AddressTestIPv6Eq03",   AddressTestIPv6Eq03, 1);
    UtRegisterTest("AddressTestIPv6Eq04",   AddressTestIPv6Eq04, 1);

    UtRegisterTest("AddressTestIPv6Le01",   AddressTestIPv6Le01, 1);
    UtRegisterTest("AddressTestIPv6Le02",   AddressTestIPv6Le02, 1);
    UtRegisterTest("AddressTestIPv6Le03",   AddressTestIPv6Le03, 1);
    UtRegisterTest("AddressTestIPv6Le04",   AddressTestIPv6Le04, 1);

    UtRegisterTest("AddressTestIPv6Ge01",   AddressTestIPv6Ge01, 1);
    UtRegisterTest("AddressTestIPv6Ge02",   AddressTestIPv6Ge02, 1);
    UtRegisterTest("AddressTestIPv6Ge03",   AddressTestIPv6Ge03, 1);
    UtRegisterTest("AddressTestIPv6Ge04",   AddressTestIPv6Ge04, 1);
}


