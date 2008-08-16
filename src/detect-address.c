/* Address part of the detection engine.
 *
 * Copyright (c) 2008 Victor Julien
 *
 * TODO move this out of the detection plugin structure */

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"

#include "detect-address.h"
#include "detect-address-ipv4.h"
#include "detect-address-ipv6.h"

int DetectAddressSetup (Signature *s, SigMatch *m, char *sidstr);
void DetectAddressTests (void);

void DetectAddressRegister (void) {
    sigmatch_table[DETECT_ADDRESS].name = "address";
    sigmatch_table[DETECT_ADDRESS].Match = NULL;
    sigmatch_table[DETECT_ADDRESS].Setup = DetectAddressSetup;
    sigmatch_table[DETECT_ADDRESS].Free = NULL;
    sigmatch_table[DETECT_ADDRESS].RegisterTests = DetectAddressTests;
}

/* prototypes */
DetectAddressData *DetectAddressParse(char *);
void DetectAddressDataPrint(DetectAddressData *);
int AddressCmp(DetectAddressData *, DetectAddressData *);
int AddressCut(DetectAddressData *, DetectAddressData *, DetectAddressData **);
int AddressCutNot(DetectAddressData *, DetectAddressData **);


DetectAddressGroup *DetectAddressGroupInit(void) {
    DetectAddressGroup *ag = malloc(sizeof(DetectAddressGroup));
    if (ag == NULL) {
        return NULL;
    }
    memset(ag,0,sizeof(DetectAddressGroup));

    return ag;
}

void DetectAddressGroupFree(DetectAddressGroup *ag) {
    if (ag != NULL) {
        if (ag->ad != NULL) {
            DetectAddressDataFree(ag->ad);
        }
        free(ag);
    }
}

void DetectAddressGroupPrintList(DetectAddressGroup *head) {
    DetectAddressGroup *cur;

    printf("list:\n");
    if (head != NULL) {
        for (cur = head; cur != NULL; cur = cur->next) {
             DetectAddressDataPrint(cur->ad);
        }
    }
    printf("endlist\n");
}

void DetectAddressGroupCleanupList (DetectAddressGroup *head) {
    if (head == NULL)
        return;

    DetectAddressGroup *cur, *next;

    for (cur = head; cur != NULL; ) {
         next = cur->next;

         DetectAddressGroupFree(cur);
         cur = next;
    }

    head = NULL;
}

/* helper functions for DetectAddressGroupInsert:
 * set & get the head ptr
 */
static int SetHeadPtr(DetectAddressGroupsHead *gh, DetectAddressGroup *newhead) {
    if (newhead->ad->flags & ADDRESS_FLAG_ANY)
        gh->any_head = newhead;
    else if (newhead->ad->family == AF_INET)
        gh->ipv4_head = newhead;
    else if (newhead->ad->family == AF_INET6)
        gh->ipv6_head = newhead;
    else
        return -1;

    return 0;
}

static DetectAddressGroup *GetHeadPtr(DetectAddressGroupsHead *gh, DetectAddressData *new) {
    DetectAddressGroup *head = NULL;

    if (new->flags & ADDRESS_FLAG_ANY)
        head = gh->any_head;
    else if (new->family == AF_INET)
        head = gh->ipv4_head;
    else if (new->family == AF_INET6)
        head = gh->ipv6_head;

    return head;
}

int DetectAddressGroupInsert(DetectAddressGroupsHead *gh, DetectAddressData *new) {
    DetectAddressGroup *head = NULL;

    /* get our head ptr based on the address we want to insert */
    head = GetHeadPtr(gh,new);

    /* see if it already exists or overlaps with existing ag's */
    if (head != NULL) {
        DetectAddressGroup *ag = NULL,*cur = NULL;
        int r = 0;

        for (cur = head; cur != NULL; cur = cur->next) {
            r = AddressCmp(new,cur->ad);
            if (r == ADDRESS_ER) {
                printf("ADDRESS_ER\n");
                goto error;
            } 
            /* if so, handle that */
            if (r == ADDRESS_EQ) {
                /* exact overlap/match, we don't need to do a thing
                 */
                return 0;
            } else if (r == ADDRESS_GT) {
                /* only add it now if we are bigger than the last
                 * group. Otherwise we'll handle it later. */
                if (cur->next == NULL) {
                    /* append */
                    ag = DetectAddressGroupInit();
                    if (ag == NULL) {
                        goto error;
                    }
                    ag->ad = new;

                    /* put in the list */
                    ag->prev = cur;
                    cur->next = ag;
                    return 0;
                }
            } else if (r == ADDRESS_LT) {
                /* see if we need to insert the ag anywhere */

                ag = DetectAddressGroupInit();
                if (ag == NULL) {
                    goto error;
                }
                ag->ad = new;

                /* put in the list */
                if (cur->prev != NULL)
                    cur->prev->next = ag;
                ag->prev = cur->prev;
                ag->next = cur;
                cur->prev = ag;

                /* update head if required */
                if (head == cur) {
                    head = ag;

                    if (SetHeadPtr(gh,head) < 0)
                        goto error;
                }
                return 0;

            /* alright, those were the simple cases, 
             * lets handle the more complex ones now */

            } else if (r == ADDRESS_ES) {
                DetectAddressData *c = NULL;
                r = AddressCut(cur->ad,new,&c);
                DetectAddressGroupInsert(gh, new);
                if (c) DetectAddressGroupInsert(gh, c);
            } else if (r == ADDRESS_EB) {
                DetectAddressData *c = NULL;
                r = AddressCut(cur->ad,new,&c);
                DetectAddressGroupInsert(gh, new);
                if (c) DetectAddressGroupInsert(gh, c);
            } else if (r == ADDRESS_LE) {
                DetectAddressData *c = NULL;
                r = AddressCut(cur->ad,new,&c);
                DetectAddressGroupInsert(gh, new);
                if (c) DetectAddressGroupInsert(gh, c);
            } else if (r == ADDRESS_GE) {
                DetectAddressData *c = NULL;
                r = AddressCut(cur->ad,new,&c);
                DetectAddressGroupInsert(gh, new);
                if (c) DetectAddressGroupInsert(gh, c);
            }
        }

    /* head is NULL, so get a group and set head to it */
    } else {
        head = DetectAddressGroupInit();
        if (head == NULL) {
            goto error;
        }
        head->ad = new;

        if (SetHeadPtr(gh,head) < 0)
            goto error;
    }

    return 0;
error:
    /* XXX */
    return -1;
}

int DetectAddressGroupSetup(DetectAddressGroupsHead *gh, char *s) {
    DetectAddressData  *ad = NULL;

    /* parse the address */
    ad = DetectAddressParse(s);
    if (ad == NULL) {
        printf("DetectAddressParse error \"%s\"\n",s);
        goto error;
    }

    /* handle the not case, we apply the negation
     * then insert the part(s) */
    if (ad->flags & ADDRESS_FLAG_NOT) {
        DetectAddressData *ad2 = NULL;

        if (AddressCutNot(ad,&ad2) < 0) {
            goto error;
        }

        /* normally a 'not' will result in two ad's
         * unless the 'not' is on the start or end
         * of the address space (e.g. 0.0.0.0 or
         * 255.255.255.255). */
        if (ad2 != NULL) {
            if (DetectAddressGroupInsert(gh, ad2) < 0)
                goto error;
        }
    }

    if (DetectAddressGroupInsert(gh, ad) < 0)
        goto error;

    return 0;

error:
    printf("DetectAddressGroupSetup error\n");
    /* XXX cleanup */
    return -1;
}

DetectAddressGroupsHead *DetectAddressGroupsHeadInit(void) {
    DetectAddressGroupsHead *gh = malloc(sizeof(DetectAddressGroupsHead));
    if (gh == NULL) {
        return NULL;
    }
    memset(gh,0,sizeof(DetectAddressGroupsHead));

    return gh;
}

void DetectAddressGroupsHeadFree(DetectAddressGroupsHead *gh) {
    if (gh != NULL) {
        DetectAddressGroupCleanupList(gh->ipv4_head);
        DetectAddressGroupCleanupList(gh->ipv6_head);
        free(gh);
    }
}

int AddressCut(DetectAddressData *a, DetectAddressData *b, DetectAddressData **c) {
    if (a->family == AF_INET) {
        return AddressCutIPv4(a,b,c);
    } else if (a->family == AF_INET6) {
        return AddressCutIPv6(a,b,c);
    }

    return -1;
}

int AddressCutNot(DetectAddressData *a, DetectAddressData **b) {
    if (a->family == AF_INET) {
        return AddressCutNotIPv4(a,b);
    } else if (a->family == AF_INET6) {
        return AddressCutNotIPv6(a,b);
    }

    return -1;
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

void DetectAddressParseIPv6CIDR(int cidr, struct in6_addr *in6) {
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
    char *ipdup = strdup(str);
    char *ip2 = NULL;
    char *mask = NULL;
    char *ip6 = NULL;
    int r = 0;

    /* first handle 'any' */
    if (strcasecmp(str,"any") == 0) {
        dd->flags |= ADDRESS_FLAG_ANY;
        return 0;
    }

    /* we dup so we can put a nul-termination in it later */
    char *ip = ipdup;

    /* handle the negation case */
    if (ip[0] == '!') {
        dd->flags |= ADDRESS_FLAG_NOT;
        ip++;
    }

    /* see if the address is an ipv4 or ipv6 address */
    if ((ip6 = strchr(str,':')) == NULL) {
        /* IPv4 Address */
        struct in_addr in;

        dd->family = AF_INET;

        if ((mask = strchr(ip, '/')) != NULL)  {
            /* 1.2.3.4/xxx format (either dotted or cidr notation */
            ip[mask - ip] = '\0';
            mask++;
            u_int32_t ip4addr = 0;
            u_int32_t netmask = 0;

            char *t = NULL;
            if ((t = strchr (mask,'.')) == NULL) {
                /* 1.2.3.4/24 format */

                int cidr = atoi(mask);
                netmask = CIDRGet(cidr);
            } else {
                /* 1.2.3.4/255.255.255.0 format */
                r = inet_pton(AF_INET, mask, &in);
                if (r <= 0) {
                    goto error;
                }
        
                netmask = in.s_addr;
                //printf("AddressParse: dd->ip2 %X\n", dd->ip2);
            }

            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0) {
                goto error;
            }
        
            ip4addr = in.s_addr;

            dd->ip[0] = dd->ip2[0] = ip4addr & netmask;
            dd->ip2[0] |=~ netmask;

            //printf("AddressParse: dd->ip %X\n", dd->ip);
        } else if ((ip2 = strchr(ip, '-')) != NULL)  {
            /* 1.2.3.4-1.2.3.6 range format */
            ip[ip2 - ip] = '\0';
            ip2++;

            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0) {
                goto error;
            }
            dd->ip[0] = in.s_addr;

            r = inet_pton(AF_INET, ip2, &in);
            if (r <= 0) {
                goto error;
            }
            dd->ip2[0] = in.s_addr;

            /* a>b is illegal, a=b is ok */
            if (ntohl(dd->ip[0]) > ntohl(dd->ip2[0])) {
                goto error;
            }

        } else {
            /* 1.2.3.4 format */
            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0) {
                goto error;
            }
            /* single host */
            dd->ip[0] = in.s_addr;
            dd->ip2[0] = in.s_addr;
            //printf("AddressParse: dd->ip %X\n", dd->ip);
        }
    } else {
        /* IPv6 Address */
        struct in6_addr in6, mask6;
        u_int32_t ip6addr[4], netmask[4];

        dd->family = AF_INET6;

        if ((mask = strchr(ip, '/')) != NULL)  {
            ip[mask - ip] = '\0';
            mask++;

            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0) {
                goto error;
            }
            memcpy(&ip6addr, &in6.s6_addr, sizeof(ip6addr));

            DetectAddressParseIPv6CIDR(atoi(mask), &mask6);
            memcpy(&netmask, &mask6.s6_addr, sizeof(netmask));

            dd->ip2[0] = dd->ip[0] = ip6addr[0] & netmask[0];
            dd->ip2[1] = dd->ip[1] = ip6addr[1] & netmask[1];
            dd->ip2[2] = dd->ip[2] = ip6addr[2] & netmask[2];
            dd->ip2[3] = dd->ip[3] = ip6addr[3] & netmask[3];

            dd->ip2[0] |=~ netmask[0];
            dd->ip2[1] |=~ netmask[1];
            dd->ip2[2] |=~ netmask[2];
            dd->ip2[3] |=~ netmask[3];
        } else if ((ip2 = strchr(ip, '-')) != NULL)  {
            /* 2001::1-2001::4 range format */
            ip[ip2 - ip] = '\0';
            ip2++;

            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0) {
                goto error;
            }
            memcpy(dd->ip, &in6.s6_addr, sizeof(ip6addr));

            r = inet_pton(AF_INET6, ip2, &in6);
            if (r <= 0) {
                goto error;
            }
            memcpy(dd->ip2, &in6.s6_addr, sizeof(ip6addr));

            /* a>b is illegal, a=b is ok */
            if (AddressIPv6Gt(dd->ip, dd->ip2)) {
                goto error;
            }

        } else {
            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0) {
                goto error;
            }

            memcpy(&dd->ip, &in6.s6_addr, sizeof(dd->ip));
            memcpy(&dd->ip2, &in6.s6_addr, sizeof(dd->ip2));
        }

    }

    free(ipdup);
    return 0;

error:
    if (ipdup) free(ipdup);
    return -1;
}

DetectAddressData *DetectAddressParse(char *str) {
    DetectAddressData *dd;

    dd = DetectAddressDataInit();
    if (dd == NULL) {
        goto error;
    }

    if (AddressParse(dd, str) < 0) {
        goto error;
    }

    return dd;

error:
    if (dd) DetectAddressDataFree(dd);
    return NULL;
}

DetectAddressData *DetectAddressDataInit(void) {
    DetectAddressData *dd;

    dd = malloc(sizeof(DetectAddressData));
    if (dd == NULL) {
        printf("DetectAddressSetup malloc failed\n");
        goto error;
    }
    memset(dd,0,sizeof(DetectAddressData));

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

void DetectAddressDataFree(DetectAddressData *dd) {
    if (dd) free(dd);
}

int DetectAddressMatch (DetectAddressData *dd, Address *a) {
    if (dd->family != a->family)
        return 0;

    switch (a->family) {
        case AF_INET:
            if (a->addr_data32[0] >= dd->ip[0] &&
                a->addr_data32[0] <= dd->ip2[0]) {
                return 1;
            } else {
                return 0;
            }
            break;
        case AF_INET6:
            if (AddressIPv6Ge(a->addr_data32, dd->ip) == 1 &&
                AddressIPv6Le(a->addr_data32, dd->ip2) == 1) {
                return 1;
            } else {
                return 0;
            }
            break;
    }

    return 0;
}

void DetectAddressDataPrint(DetectAddressData *ad) {
    if (ad == NULL)
        return;

    if (ad->family == AF_INET) {
        struct in_addr in;
        char s[16];

        memcpy(&in, &ad->ip[0], sizeof(in));
        inet_ntop(AF_INET, &in, s, sizeof(s));
        printf("%s/", s);
        memcpy(&in, &ad->ip2[0], sizeof(in));
        inet_ntop(AF_INET, &in, s, sizeof(s));
        printf("%s\n", s);
    } else if (ad->family == AF_INET6) {
        struct in6_addr in6;
        char s[66];

        memcpy(&in6, &ad->ip, sizeof(in6));
        inet_ntop(AF_INET6, &in6, s, sizeof(s));
        printf("%s/", s);
        memcpy(&in6, &ad->ip2, sizeof(in6));
        inet_ntop(AF_INET6, &in6, s, sizeof(s));
        printf("%s\n", s);
    }
}


/* TESTS */

int AddressTestParse01 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("1.2.3.4");
    if (dd) {
        DetectAddressDataFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse02 (void) {
    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("1.2.3.4");
    if (dd) {
        if (dd->ip2[0] != 0x04030201 ||
            dd->ip[0]   != 0x04030201) {
            result = 0;
        }

        DetectAddressDataFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse03 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("1.2.3.4/255.255.255.0");
    if (dd) {
        DetectAddressDataFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse04 (void) {
    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("1.2.3.4/255.255.255.0");
    if (dd) {
        if (dd->ip2[0] != 0xff030201 ||
            dd->ip[0]   != 0x00030201) {
            result = 0;
        }

        DetectAddressDataFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse05 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("1.2.3.4/24");
    if (dd) {
        DetectAddressDataFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse06 (void) {
    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("1.2.3.4/24");
    if (dd) {
        if (dd->ip2[0] != 0xff030201 ||
            dd->ip[0]   != 0x00030201) {
            result = 0;
        }

        DetectAddressDataFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse07 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/3");
    if (dd) {
        DetectAddressDataFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse08 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/3");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000020 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->ip2[0] != 0xFFFFFF3F || dd->ip2[1] != 0xFFFFFFFF ||
            dd->ip2[2] != 0xFFFFFFFF || dd->ip2[3] != 0xFFFFFFFF)
        {
            DetectAddressDataPrint(dd);
            result = 0;
        }

        DetectAddressDataFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse09 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::1/128");
    if (dd) {
        DetectAddressDataFree(dd);
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

            dd->ip2[0] != 0x00000120 || dd->ip2[1] != 0x00000000 ||
            dd->ip2[2] != 0x00000000 || dd->ip2[3] != 0x00000000)
        {
            DetectAddressDataPrint(dd);
            result = 0;
        }

        DetectAddressDataFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse11 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/48");
    if (dd) {
        DetectAddressDataFree(dd);
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

            dd->ip2[0] != 0x00000120 || dd->ip2[1] != 0xFFFF0000 ||
            dd->ip2[2] != 0xFFFFFFFF || dd->ip2[3] != 0xFFFFFFFF)
        {
            DetectAddressDataPrint(dd);
            result = 0;
        }

        DetectAddressDataFree(dd);
        return result;
    }

    return 0;
}
int AddressTestParse13 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/16");
    if (dd) {
        DetectAddressDataFree(dd);
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

            dd->ip2[0] != 0xFFFF0120 || dd->ip2[1] != 0xFFFFFFFF ||
            dd->ip2[2] != 0xFFFFFFFF || dd->ip2[3] != 0xFFFFFFFF)
        {
            result = 0;
        }

        DetectAddressDataFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse15 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/0");
    if (dd) {
        DetectAddressDataFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse16 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::/0");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000000 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->ip2[0] != 0xFFFFFFFF || dd->ip2[1] != 0xFFFFFFFF ||
            dd->ip2[2] != 0xFFFFFFFF || dd->ip2[3] != 0xFFFFFFFF)
        {
            result = 0;
        }

        DetectAddressDataFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse17 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("1.2.3.4-1.2.3.6");
    if (dd) {
        DetectAddressDataFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse18 (void) {
    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("1.2.3.4-1.2.3.6");
    if (dd) {
        if (dd->ip2[0] != 0x06030201 ||
            dd->ip[0]   != 0x04030201) {
            result = 0;
        }

        DetectAddressDataFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse19 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("1.2.3.6-1.2.3.4");
    if (dd) {
        DetectAddressDataFree(dd);
        return 0;
    }

    return 1;
}

int AddressTestParse20 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::1-2001::4");
    if (dd) {
        DetectAddressDataFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse21 (void) {
    DetectAddressData *dd = NULL;
    int result = 1;

    dd = DetectAddressParse("2001::1-2001::4");
    if (dd) {
        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x01000000 ||

            dd->ip2[0] != 0x00000120 || dd->ip2[1] != 0x00000000 ||
            dd->ip2[2] != 0x00000000 || dd->ip2[3] != 0x04000000)
        {
            result = 0;
        }

        DetectAddressDataFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse22 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("2001::4-2001::1");
    if (dd) {
        DetectAddressDataFree(dd);
        return 0;
    }

    return 1;
}

int AddressTestParse23 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("any");
    if (dd) {
        DetectAddressDataFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse24 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("Any");
    if (dd) {
        DetectAddressDataFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse25 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("ANY");
    if (dd) {
        DetectAddressDataFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse26 (void) {
    int result = 0;
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("any");
    if (dd) {
        if (dd->flags & ADDRESS_FLAG_ANY)
            result = 1;

        DetectAddressDataFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse27 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("!192.168.0.1");
    if (dd) {
        DetectAddressDataFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse28 (void) {
    int result = 0;
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("!1.2.3.4");
    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip[0] == 0x04030201) {
            result = 1;
        }

        DetectAddressDataFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse29 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("!1.2.3.0/24");
    if (dd) {
        DetectAddressDataFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse30 (void) {
    int result = 0;
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("!1.2.3.4/24");
    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip[0] == 0x00030201 &&
            dd->ip2[0] == 0xFF030201) {
            result = 1;
        }

        DetectAddressDataFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse31 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("!any");
    if (dd) {
        DetectAddressDataFree(dd);
        return 0;
    }

    return 1;
}

int AddressTestParse32 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("!2001::1");
    if (dd) {
        DetectAddressDataFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse33 (void) {
    int result = 0;
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("!2001::1");
    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip[0] == 0x00000120 && dd->ip[1] == 0x00000000 &&
            dd->ip[2] == 0x00000000 && dd->ip[3] == 0x01000000) {
            result = 1;
        }

        DetectAddressDataFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse34 (void) {
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("!2001::/16");
    if (dd) {
        DetectAddressDataFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse35 (void) {
    int result = 0;
    DetectAddressData *dd = NULL;
    dd = DetectAddressParse("!2001::/16");
    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip[0] == 0x00000120 && dd->ip[1] == 0x00000000 &&
            dd->ip[2] == 0x00000000 && dd->ip[3] == 0x00000000 &&

            dd->ip2[0] == 0xFFFF0120 && dd->ip2[1] == 0xFFFFFFFF &&
            dd->ip2[2] == 0xFFFFFFFF && dd->ip2[3] == 0xFFFFFFFF)
        {
            result = 1;
        }

        DetectAddressDataFree(dd);
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

        DetectAddressDataFree(dd);
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

        DetectAddressDataFree(dd);
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

        DetectAddressDataFree(dd);
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

        DetectAddressDataFree(dd);
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

        DetectAddressDataFree(dd);
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

        DetectAddressDataFree(dd);
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

        DetectAddressDataFree(dd);
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
        if (DetectAddressMatch(dd,&a) == 1) {
            result = 0;
        }
        DetectAddressDataFree(dd);
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

        DetectAddressDataFree(dd);
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

        DetectAddressDataFree(dd);
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

        DetectAddressDataFree(dd);
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

    DetectAddressDataFree(da);
    DetectAddressDataFree(db);
    return result;

error:
    if (da) DetectAddressDataFree(da);
    if (db) DetectAddressDataFree(db);
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

    DetectAddressDataFree(da);
    DetectAddressDataFree(db);
    return result;

error:
    if (da) DetectAddressDataFree(da);
    if (db) DetectAddressDataFree(db);
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

    DetectAddressDataFree(da);
    DetectAddressDataFree(db);
    return result;

error:
    if (da) DetectAddressDataFree(da);
    if (db) DetectAddressDataFree(db);
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

    DetectAddressDataFree(da);
    DetectAddressDataFree(db);
    return result;

error:
    if (da) DetectAddressDataFree(da);
    if (db) DetectAddressDataFree(db);
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

    DetectAddressDataFree(da);
    DetectAddressDataFree(db);
    return result;

error:
    if (da) DetectAddressDataFree(da);
    if (db) DetectAddressDataFree(db);
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

    DetectAddressDataFree(da);
    DetectAddressDataFree(db);
    return result;

error:
    if (da) DetectAddressDataFree(da);
    if (db) DetectAddressDataFree(db);
    return 0;
}

int AddressTestCmpIPv407 (void) {
    DetectAddressData *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParse("192.168.1.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParse("192.168.1.128-192.168.2.128");
    if (db == NULL) goto error;

    if (AddressCmp(da,db) != ADDRESS_LE)
        result = 0;

    DetectAddressDataFree(da);
    DetectAddressDataFree(db);
    return result;

error:
    if (da) DetectAddressDataFree(da);
    if (db) DetectAddressDataFree(db);
    return 0;
}

int AddressTestCmpIPv408 (void) {
    DetectAddressData *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParse("192.168.1.128-192.168.2.128");
    if (da == NULL) goto error;
    db = DetectAddressParse("192.168.1.0/255.255.255.0");
    if (db == NULL) goto error;

    if (AddressCmp(da,db) != ADDRESS_GE)
        result = 0;

    DetectAddressDataFree(da);
    DetectAddressDataFree(db);
    return result;

error:
    if (da) DetectAddressDataFree(da);
    if (db) DetectAddressDataFree(db);
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

    DetectAddressDataFree(da);
    DetectAddressDataFree(db);
    return result;

error:
    if (da) DetectAddressDataFree(da);
    if (db) DetectAddressDataFree(db);
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

    DetectAddressDataFree(da);
    DetectAddressDataFree(db);
    return result;

error:
    if (da) DetectAddressDataFree(da);
    if (db) DetectAddressDataFree(db);
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

    DetectAddressDataFree(da);
    DetectAddressDataFree(db);
    return result;

error:
    if (da) DetectAddressDataFree(da);
    if (db) DetectAddressDataFree(db);
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

    DetectAddressDataFree(da);
    DetectAddressDataFree(db);
    return result;

error:
    if (da) DetectAddressDataFree(da);
    if (db) DetectAddressDataFree(db);
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

    DetectAddressDataFree(da);
    DetectAddressDataFree(db);
    return result;

error:
    if (da) DetectAddressDataFree(da);
    if (db) DetectAddressDataFree(db);
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

    DetectAddressDataFree(da);
    DetectAddressDataFree(db);
    return result;

error:
    if (da) DetectAddressDataFree(da);
    if (db) DetectAddressDataFree(db);
    return 0;
}

int AddressTestAddressGroupSetup01 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "1.2.3.4");
        if (r == 0) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup02 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "1.2.3.4");
        if (r == 0 && gh->ipv4_head != NULL) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup03 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "1.2.3.4");
        if (r == 0 && gh->ipv4_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv4_head;

            r = DetectAddressGroupSetup(gh, "1.2.3.3");
            if (r == 0 && gh->ipv4_head != prev_head &&
                gh->ipv4_head != NULL && gh->ipv4_head->next == prev_head)
            {
                result = 1;
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup04 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "1.2.3.4");
        if (r == 0 && gh->ipv4_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv4_head;

            r = DetectAddressGroupSetup(gh, "1.2.3.3");
            if (r == 0 && gh->ipv4_head != prev_head &&
                gh->ipv4_head != NULL && gh->ipv4_head->next == prev_head)
            {
                DetectAddressGroup *prev_head = gh->ipv4_head;

                r = DetectAddressGroupSetup(gh, "1.2.3.2");
                if (r == 0 && gh->ipv4_head != prev_head &&
                    gh->ipv4_head != NULL && gh->ipv4_head->next == prev_head)
                {
                    result = 1;
                }
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup05 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "1.2.3.2");
        if (r == 0 && gh->ipv4_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv4_head;

            r = DetectAddressGroupSetup(gh, "1.2.3.3");
            if (r == 0 && gh->ipv4_head == prev_head &&
                gh->ipv4_head != NULL && gh->ipv4_head->next != prev_head)
            {
                DetectAddressGroup *prev_head = gh->ipv4_head;

                r = DetectAddressGroupSetup(gh, "1.2.3.4");
                if (r == 0 && gh->ipv4_head == prev_head &&
                    gh->ipv4_head != NULL && gh->ipv4_head->next != prev_head)
                {
                    result = 1;
                }
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup06 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "1.2.3.2");
        if (r == 0 && gh->ipv4_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv4_head;

            r = DetectAddressGroupSetup(gh, "1.2.3.2");
            if (r == 0 && gh->ipv4_head == prev_head &&
                gh->ipv4_head != NULL && gh->ipv4_head->next == NULL)
            {
                result = 1;
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup07 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "10.0.0.0/8");
        if (r == 0 && gh->ipv4_head != NULL) {
            r = DetectAddressGroupSetup(gh, "10.10.10.10");
            if (r == 0 && gh->ipv4_head != NULL &&
                gh->ipv4_head->next != NULL &&
                gh->ipv4_head->next->next != NULL)
            {
                result = 1;
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup08 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "10.10.10.10");
        if (r == 0 && gh->ipv4_head != NULL) {
            r = DetectAddressGroupSetup(gh, "10.0.0.0/8");
            if (r == 0 && gh->ipv4_head != NULL &&
                gh->ipv4_head->next != NULL &&
                gh->ipv4_head->next->next != NULL)
            {
                result = 1;
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup09 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "10.10.10.0/24");
        if (r == 0 && gh->ipv4_head != NULL) {
            r = DetectAddressGroupSetup(gh, "10.10.10.10-10.10.11.1");
            if (r == 0 && gh->ipv4_head != NULL &&
                gh->ipv4_head->next != NULL &&
                gh->ipv4_head->next->next != NULL)
            {
                result = 1;
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup10 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "10.10.10.10-10.10.11.1");
        if (r == 0 && gh->ipv4_head != NULL) {
            r = DetectAddressGroupSetup(gh, "10.10.10.0/24");
            if (r == 0 && gh->ipv4_head != NULL &&
                gh->ipv4_head->next != NULL &&
                gh->ipv4_head->next->next != NULL)
            {
                result = 1;
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup11 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "10.10.10.10-10.10.11.1");
        if (r == 0) {
            r = DetectAddressGroupSetup(gh, "10.10.10.0/24");
            if (r == 0) {
                r = DetectAddressGroupSetup(gh, "0.0.0.0/0");
                if (r == 0) {
                    DetectAddressGroup *one = gh->ipv4_head, *two = one->next,
                                       *three = two->next, *four = three->next,
                                       *five = four->next;

                    /* result should be:
                     * 0.0.0.0/10.10.9.255
                     * 10.10.10.0/10.10.10.9
                     * 10.10.10.10/10.10.10.255
                     * 10.10.11.0/10.10.11.1
                     * 10.10.11.2/255.255.255.255
                     */
                    if (one->ad->ip[0]   == 0x00000000 && one->ad->ip2[0]   == 0xFF090A0A &&
                        two->ad->ip[0]   == 0x000A0A0A && two->ad->ip2[0]   == 0x090A0A0A &&
                        three->ad->ip[0] == 0x0A0A0A0A && three->ad->ip2[0] == 0xFF0A0A0A &&
                        four->ad->ip[0]  == 0x000B0A0A && four->ad->ip2[0]  == 0x010B0A0A &&
                        five->ad->ip[0]  == 0x020B0A0A && five->ad->ip2[0]  == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup12 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "10.10.10.10-10.10.11.1");
        if (r == 0) {
            r = DetectAddressGroupSetup(gh, "0.0.0.0/0");
            if (r == 0) {
                r = DetectAddressGroupSetup(gh, "10.10.10.0/24");
                if (r == 0) {
                    DetectAddressGroup *one = gh->ipv4_head, *two = one->next,
                                       *three = two->next, *four = three->next,
                                       *five = four->next;

                    /* result should be:
                     * 0.0.0.0/10.10.9.255
                     * 10.10.10.0/10.10.10.9
                     * 10.10.10.10/10.10.10.255
                     * 10.10.11.0/10.10.11.1
                     * 10.10.11.2/255.255.255.255
                     */
                    if (one->ad->ip[0]   == 0x00000000 && one->ad->ip2[0]   == 0xFF090A0A &&
                        two->ad->ip[0]   == 0x000A0A0A && two->ad->ip2[0]   == 0x090A0A0A &&
                        three->ad->ip[0] == 0x0A0A0A0A && three->ad->ip2[0] == 0xFF0A0A0A &&
                        four->ad->ip[0]  == 0x000B0A0A && four->ad->ip2[0]  == 0x010B0A0A &&
                        five->ad->ip[0]  == 0x020B0A0A && five->ad->ip2[0]  == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup13 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "0.0.0.0/0");
        if (r == 0) {
            r = DetectAddressGroupSetup(gh, "10.10.10.10-10.10.11.1");
            if (r == 0) {
                r = DetectAddressGroupSetup(gh, "10.10.10.0/24");
                if (r == 0) {
                    DetectAddressGroup *one = gh->ipv4_head, *two = one->next,
                                       *three = two->next, *four = three->next,
                                       *five = four->next;

                    /* result should be:
                     * 0.0.0.0/10.10.9.255
                     * 10.10.10.0/10.10.10.9
                     * 10.10.10.10/10.10.10.255
                     * 10.10.11.0/10.10.11.1
                     * 10.10.11.2/255.255.255.255
                     */
                    if (one->ad->ip[0]   == 0x00000000 && one->ad->ip2[0]   == 0xFF090A0A &&
                        two->ad->ip[0]   == 0x000A0A0A && two->ad->ip2[0]   == 0x090A0A0A &&
                        three->ad->ip[0] == 0x0A0A0A0A && three->ad->ip2[0] == 0xFF0A0A0A &&
                        four->ad->ip[0]  == 0x000B0A0A && four->ad->ip2[0]  == 0x010B0A0A &&
                        five->ad->ip[0]  == 0x020B0A0A && five->ad->ip2[0]  == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetupIPv414 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "!1.2.3.4");
        if (r == 0) {
            DetectAddressGroup *one = gh->ipv4_head;
            DetectAddressGroup *two = one ? one->next : NULL;

            if (one && two) {
                /* result should be:
                 * 0.0.0.0/1.2.3.3
                 * 1.2.3.5/255.255.255.255
                 */
                if (one->ad->ip[0]   == 0x00000000 && one->ad->ip2[0]   == 0x03030201 &&
                    two->ad->ip[0]   == 0x05030201 && two->ad->ip2[0]   == 0xFFFFFFFF) {
                    result = 1;
                }
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetupIPv415 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "!0.0.0.0");
        if (r == 0) {
            DetectAddressGroup *one = gh->ipv4_head;

            if (one && one->next == NULL) {
                /* result should be:
                 * 0.0.0.1/255.255.255.255
                 */
                if (one->ad->ip[0]   == 0x01000000 && one->ad->ip2[0]   == 0xFFFFFFFF) {
                    result = 1;
                }
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetupIPv416 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "!255.255.255.255");
        if (r == 0) {
            DetectAddressGroup *one = gh->ipv4_head;

            if (one && one->next == NULL) {
                /* result should be:
                 * 0.0.0.0/255.255.255.254
                 */
                if (one->ad->ip[0]   == 0x00000000 && one->ad->ip2[0]   == 0xFEFFFFFF) {
                    result = 1;
                }
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup14 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "2001::1");
        if (r == 0) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup15 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "2001::1");
        if (r == 0 && gh->ipv6_head != NULL) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup16 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "2001::4");
        if (r == 0 && gh->ipv6_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv6_head;

            r = DetectAddressGroupSetup(gh, "2001::3");
            if (r == 0 && gh->ipv6_head != prev_head &&
                gh->ipv6_head != NULL && gh->ipv6_head->next == prev_head)
            {
                result = 1;
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup17 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "2001::4");
        if (r == 0 && gh->ipv6_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv6_head;

            r = DetectAddressGroupSetup(gh, "2001::3");
            if (r == 0 && gh->ipv6_head != prev_head &&
                gh->ipv6_head != NULL && gh->ipv6_head->next == prev_head)
            {
                DetectAddressGroup *prev_head = gh->ipv6_head;

                r = DetectAddressGroupSetup(gh, "2001::2");
                if (r == 0 && gh->ipv6_head != prev_head &&
                    gh->ipv6_head != NULL && gh->ipv6_head->next == prev_head)
                {
                    result = 1;
                }
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup18 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "2001::2");
        if (r == 0 && gh->ipv6_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv6_head;

            r = DetectAddressGroupSetup(gh, "2001::3");
            if (r == 0 && gh->ipv6_head == prev_head &&
                gh->ipv6_head != NULL && gh->ipv6_head->next != prev_head)
            {
                DetectAddressGroup *prev_head = gh->ipv6_head;

                r = DetectAddressGroupSetup(gh, "2001::4");
                if (r == 0 && gh->ipv6_head == prev_head &&
                    gh->ipv6_head != NULL && gh->ipv6_head->next != prev_head)
                {
                    result = 1;
                }
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup19 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "2001::2");
        if (r == 0 && gh->ipv6_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv6_head;

            r = DetectAddressGroupSetup(gh, "2001::2");
            if (r == 0 && gh->ipv6_head == prev_head &&
                gh->ipv6_head != NULL && gh->ipv6_head->next == NULL)
            {
                result = 1;
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup20 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "2000::/3");
        if (r == 0 && gh->ipv6_head != NULL) {
            r = DetectAddressGroupSetup(gh, "2001::4");
            if (r == 0 && gh->ipv6_head != NULL &&
                gh->ipv6_head->next != NULL &&
                gh->ipv6_head->next->next != NULL)
            {
                result = 1;
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup21 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "2001::4");
        if (r == 0 && gh->ipv6_head != NULL) {
            r = DetectAddressGroupSetup(gh, "2000::/3");
            if (r == 0 && gh->ipv6_head != NULL &&
                gh->ipv6_head->next != NULL &&
                gh->ipv6_head->next->next != NULL)
            {
                result = 1;
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup22 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "2000::/3");
        if (r == 0 && gh->ipv6_head != NULL) {
            r = DetectAddressGroupSetup(gh, "2001::4-2001::6");
            if (r == 0 && gh->ipv6_head != NULL &&
                gh->ipv6_head->next != NULL &&
                gh->ipv6_head->next->next != NULL)
            {
                result = 1;
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup23 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "2001::4-2001::6");
        if (r == 0 && gh->ipv6_head != NULL) {
            r = DetectAddressGroupSetup(gh, "2000::/3");
            if (r == 0 && gh->ipv6_head != NULL &&
                gh->ipv6_head->next != NULL &&
                gh->ipv6_head->next->next != NULL)
            {
                result = 1;
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup24 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "2001::4-2001::6");
        if (r == 0) {
            r = DetectAddressGroupSetup(gh, "2001::/3");
            if (r == 0) {
                r = DetectAddressGroupSetup(gh, "::/0");
                if (r == 0) {
                    DetectAddressGroup *one = gh->ipv6_head, *two = one->next,
                                       *three = two->next, *four = three->next,
                                       *five = four->next;
                    if (one->ad->ip[0]   == 0x00000000 &&
                        one->ad->ip[1]   == 0x00000000 &&
                        one->ad->ip[2]   == 0x00000000 &&
                        one->ad->ip[3]   == 0x00000000 &&
                        one->ad->ip2[0]   == 0xFFFFFF1F &&
                        one->ad->ip2[1]   == 0xFFFFFFFF &&
                        one->ad->ip2[2]   == 0xFFFFFFFF &&
                        one->ad->ip2[3]   == 0xFFFFFFFF &&

                        two->ad->ip[0]   == 0x00000020 &&
                        two->ad->ip[1]   == 0x00000000 &&
                        two->ad->ip[2]   == 0x00000000 &&
                        two->ad->ip[3]   == 0x00000000 &&
                        two->ad->ip2[0]   == 0x00000120 &&
                        two->ad->ip2[1]   == 0x00000000 &&
                        two->ad->ip2[2]   == 0x00000000 &&
                        two->ad->ip2[3]   == 0x03000000 &&

                        three->ad->ip[0] == 0x00000120 &&
                        three->ad->ip[1] == 0x00000000 &&
                        three->ad->ip[2] == 0x00000000 &&
                        three->ad->ip[3] == 0x04000000 &&
                        three->ad->ip2[0] == 0x00000120 &&
                        three->ad->ip2[1] == 0x00000000 &&
                        three->ad->ip2[2] == 0x00000000 &&
                        three->ad->ip2[3] == 0x06000000 &&

                        four->ad->ip[0]  == 0x00000120 &&
                        four->ad->ip[1]  == 0x00000000 &&
                        four->ad->ip[2]  == 0x00000000 &&
                        four->ad->ip[3]  == 0x07000000 &&
                        four->ad->ip2[0]  == 0xFFFFFF3F &&
                        four->ad->ip2[1]  == 0xFFFFFFFF &&
                        four->ad->ip2[2]  == 0xFFFFFFFF &&
                        four->ad->ip2[3]  == 0xFFFFFFFF &&

                        five->ad->ip[0]  == 0x00000040 && 
                        five->ad->ip[1]  == 0x00000000 && 
                        five->ad->ip[2]  == 0x00000000 && 
                        five->ad->ip[3]  == 0x00000000 && 
                        five->ad->ip2[0]  == 0xFFFFFFFF &&
                        five->ad->ip2[1]  == 0xFFFFFFFF &&
                        five->ad->ip2[2]  == 0xFFFFFFFF &&
                        five->ad->ip2[3]  == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup25 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "2001::4-2001::6");
        if (r == 0) {
            r = DetectAddressGroupSetup(gh, "::/0");
            if (r == 0) {
                r = DetectAddressGroupSetup(gh, "2001::/3");
                if (r == 0) {
                    DetectAddressGroup *one = gh->ipv6_head, *two = one->next,
                                       *three = two->next, *four = three->next,
                                       *five = four->next;
                    if (one->ad->ip[0]   == 0x00000000 &&
                        one->ad->ip[1]   == 0x00000000 &&
                        one->ad->ip[2]   == 0x00000000 &&
                        one->ad->ip[3]   == 0x00000000 &&
                        one->ad->ip2[0]   == 0xFFFFFF1F &&
                        one->ad->ip2[1]   == 0xFFFFFFFF &&
                        one->ad->ip2[2]   == 0xFFFFFFFF &&
                        one->ad->ip2[3]   == 0xFFFFFFFF &&

                        two->ad->ip[0]   == 0x00000020 &&
                        two->ad->ip[1]   == 0x00000000 &&
                        two->ad->ip[2]   == 0x00000000 &&
                        two->ad->ip[3]   == 0x00000000 &&
                        two->ad->ip2[0]   == 0x00000120 &&
                        two->ad->ip2[1]   == 0x00000000 &&
                        two->ad->ip2[2]   == 0x00000000 &&
                        two->ad->ip2[3]   == 0x03000000 &&

                        three->ad->ip[0] == 0x00000120 &&
                        three->ad->ip[1] == 0x00000000 &&
                        three->ad->ip[2] == 0x00000000 &&
                        three->ad->ip[3] == 0x04000000 &&
                        three->ad->ip2[0] == 0x00000120 &&
                        three->ad->ip2[1] == 0x00000000 &&
                        three->ad->ip2[2] == 0x00000000 &&
                        three->ad->ip2[3] == 0x06000000 &&

                        four->ad->ip[0]  == 0x00000120 &&
                        four->ad->ip[1]  == 0x00000000 &&
                        four->ad->ip[2]  == 0x00000000 &&
                        four->ad->ip[3]  == 0x07000000 &&
                        four->ad->ip2[0]  == 0xFFFFFF3F &&
                        four->ad->ip2[1]  == 0xFFFFFFFF &&
                        four->ad->ip2[2]  == 0xFFFFFFFF &&
                        four->ad->ip2[3]  == 0xFFFFFFFF &&

                        five->ad->ip[0]  == 0x00000040 && 
                        five->ad->ip[1]  == 0x00000000 && 
                        five->ad->ip[2]  == 0x00000000 && 
                        five->ad->ip[3]  == 0x00000000 && 
                        five->ad->ip2[0]  == 0xFFFFFFFF &&
                        five->ad->ip2[1]  == 0xFFFFFFFF &&
                        five->ad->ip2[2]  == 0xFFFFFFFF &&
                        five->ad->ip2[3]  == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup26 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupSetup(gh, "::/0");
        if (r == 0) {
            r = DetectAddressGroupSetup(gh, "2001::4-2001::6");
            if (r == 0) {
                r = DetectAddressGroupSetup(gh, "2001::/3");
                if (r == 0) {
                    DetectAddressGroup *one = gh->ipv6_head, *two = one->next,
                                       *three = two->next, *four = three->next,
                                       *five = four->next;
                    if (one->ad->ip[0]   == 0x00000000 &&
                        one->ad->ip[1]   == 0x00000000 &&
                        one->ad->ip[2]   == 0x00000000 &&
                        one->ad->ip[3]   == 0x00000000 &&
                        one->ad->ip2[0]   == 0xFFFFFF1F &&
                        one->ad->ip2[1]   == 0xFFFFFFFF &&
                        one->ad->ip2[2]   == 0xFFFFFFFF &&
                        one->ad->ip2[3]   == 0xFFFFFFFF &&

                        two->ad->ip[0]   == 0x00000020 &&
                        two->ad->ip[1]   == 0x00000000 &&
                        two->ad->ip[2]   == 0x00000000 &&
                        two->ad->ip[3]   == 0x00000000 &&
                        two->ad->ip2[0]   == 0x00000120 &&
                        two->ad->ip2[1]   == 0x00000000 &&
                        two->ad->ip2[2]   == 0x00000000 &&
                        two->ad->ip2[3]   == 0x03000000 &&

                        three->ad->ip[0] == 0x00000120 &&
                        three->ad->ip[1] == 0x00000000 &&
                        three->ad->ip[2] == 0x00000000 &&
                        three->ad->ip[3] == 0x04000000 &&
                        three->ad->ip2[0] == 0x00000120 &&
                        three->ad->ip2[1] == 0x00000000 &&
                        three->ad->ip2[2] == 0x00000000 &&
                        three->ad->ip2[3] == 0x06000000 &&

                        four->ad->ip[0]  == 0x00000120 &&
                        four->ad->ip[1]  == 0x00000000 &&
                        four->ad->ip[2]  == 0x00000000 &&
                        four->ad->ip[3]  == 0x07000000 &&
                        four->ad->ip2[0]  == 0xFFFFFF3F &&
                        four->ad->ip2[1]  == 0xFFFFFFFF &&
                        four->ad->ip2[2]  == 0xFFFFFFFF &&
                        four->ad->ip2[3]  == 0xFFFFFFFF &&

                        five->ad->ip[0]  == 0x00000040 && 
                        five->ad->ip[1]  == 0x00000000 && 
                        five->ad->ip[2]  == 0x00000000 && 
                        five->ad->ip[3]  == 0x00000000 && 
                        five->ad->ip2[0]  == 0xFFFFFFFF &&
                        five->ad->ip2[1]  == 0xFFFFFFFF &&
                        five->ad->ip2[2]  == 0xFFFFFFFF &&
                        five->ad->ip2[3]  == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestCutIPv401(void) {
    DetectAddressData *a, *b, *c;
    a = DetectAddressParse("1.2.3.0/255.255.255.0");
    b = DetectAddressParse("1.2.2.0-1.2.3.4");

    if (AddressCut(a,b,&c) == -1) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int AddressTestCutIPv402(void) {
    DetectAddressData *a, *b, *c;
    a = DetectAddressParse("1.2.3.0/255.255.255.0");
    b = DetectAddressParse("1.2.2.0-1.2.3.4");

    if (AddressCut(a,b,&c) == -1) {
        goto error;
    }

    if (c == NULL) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int AddressTestCutIPv403(void) {
    DetectAddressData *a, *b, *c;
    a = DetectAddressParse("1.2.3.0/255.255.255.0");
    b = DetectAddressParse("1.2.2.0-1.2.3.4");

    if (AddressCut(a,b,&c) == -1) {
        goto error;
    }

    if (c == NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00020201 && a->ip2[0] != 0xff020201) {
        goto error;
    }
    if (b->ip[0] != 0x00030201 && b->ip2[0] != 0x04030201) {
        goto error;
    }
    if (c->ip[0] != 0x05030201 && c->ip2[0] != 0xff030201) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int AddressTestCutIPv404(void) {
    DetectAddressData *a, *b, *c;
    a = DetectAddressParse("1.2.3.3-1.2.3.6");
    b = DetectAddressParse("1.2.3.0-1.2.3.5");

    if (AddressCut(a,b,&c) == -1) {
        goto error;
    }

    if (c == NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00030201 && a->ip2[0] != 0x02030201) {
        goto error;
    }
    if (b->ip[0] != 0x03030201 && b->ip2[0] != 0x04030201) {
        goto error;
    }
    if (c->ip[0] != 0x05030201 && c->ip2[0] != 0x06030201) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int AddressTestCutIPv405(void) {
    DetectAddressData *a, *b, *c;
    a = DetectAddressParse("1.2.3.3-1.2.3.6");
    b = DetectAddressParse("1.2.3.0-1.2.3.9");

    if (AddressCut(a,b,&c) == -1) {
        goto error;
    }

    if (c == NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00030201 && a->ip2[0] != 0x02030201) {
        goto error;
    }
    if (b->ip[0] != 0x03030201 && b->ip2[0] != 0x06030201) {
        goto error;
    }
    if (c->ip[0] != 0x07030201 && c->ip2[0] != 0x09030201) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int AddressTestCutIPv406(void) {
    DetectAddressData *a, *b, *c;
    a = DetectAddressParse("1.2.3.0-1.2.3.9");
    b = DetectAddressParse("1.2.3.3-1.2.3.6");

    if (AddressCut(a,b,&c) == -1) {
        goto error;
    }

    if (c == NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00030201 && a->ip2[0] != 0x02030201) {
        goto error;
    }
    if (b->ip[0] != 0x03030201 && b->ip2[0] != 0x06030201) {
        goto error;
    }
    if (c->ip[0] != 0x07030201 && c->ip2[0] != 0x09030201) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int AddressTestCutIPv407(void) {
    DetectAddressData *a, *b, *c;
    a = DetectAddressParse("1.2.3.0-1.2.3.6");
    b = DetectAddressParse("1.2.3.0-1.2.3.9");

    if (AddressCut(a,b,&c) == -1) {
        goto error;
    }

    if (c != NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00030201 && a->ip2[0] != 0x06030201) {
        goto error;
    }
    if (b->ip[0] != 0x07030201 && b->ip2[0] != 0x09030201) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int AddressTestCutIPv408(void) {
    DetectAddressData *a, *b, *c;
    a = DetectAddressParse("1.2.3.3-1.2.3.9");
    b = DetectAddressParse("1.2.3.0-1.2.3.9");

    if (AddressCut(a,b,&c) == -1) {
        goto error;
    }

    if (c != NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00030201 && a->ip2[0] != 0x02030201) {
        goto error;
    }
    if (b->ip[0] != 0x03030201 && b->ip2[0] != 0x09030201) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int AddressTestCutIPv409(void) {
    DetectAddressData *a, *b, *c;
    a = DetectAddressParse("1.2.3.0-1.2.3.9");
    b = DetectAddressParse("1.2.3.0-1.2.3.6");

    if (AddressCut(a,b,&c) == -1) {
        goto error;
    }

    if (c != NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00030201 && a->ip2[0] != 0x06030201) {
        goto error;
    }
    if (b->ip[0] != 0x07030201 && b->ip2[0] != 0x09030201) {
        goto error;
    }

    return 1;
error:
    return 0;
}

int AddressTestCutIPv410(void) {
    DetectAddressData *a, *b, *c;
    a = DetectAddressParse("1.2.3.0-1.2.3.9");
    b = DetectAddressParse("1.2.3.3-1.2.3.9");

    if (AddressCut(a,b,&c) == -1) {
        goto error;
    }

    if (c != NULL) {
        goto error;
    }

    if (a->ip[0] != 0x00030201 && a->ip2[0] != 0x02030201) {
        goto error;
    }
    if (b->ip[0] != 0x03030201 && b->ip2[0] != 0x09030201) {
        goto error;
    }

    return 1;
error:
    return 0;
}

void DetectAddressTests(void) {
    DetectAddressIPv6Tests();

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
    UtRegisterTest("AddressTestParse17", AddressTestParse17, 1);
    UtRegisterTest("AddressTestParse18", AddressTestParse18, 1);
    UtRegisterTest("AddressTestParse19", AddressTestParse19, 1);
    UtRegisterTest("AddressTestParse20", AddressTestParse20, 1);
    UtRegisterTest("AddressTestParse21", AddressTestParse21, 1);
    UtRegisterTest("AddressTestParse22", AddressTestParse22, 1);
    UtRegisterTest("AddressTestParse23", AddressTestParse23, 1);
    UtRegisterTest("AddressTestParse24", AddressTestParse24, 1);
    UtRegisterTest("AddressTestParse25", AddressTestParse25, 1);
    UtRegisterTest("AddressTestParse26", AddressTestParse26, 1);
    UtRegisterTest("AddressTestParse27", AddressTestParse27, 1);
    UtRegisterTest("AddressTestParse28", AddressTestParse28, 1);
    UtRegisterTest("AddressTestParse29", AddressTestParse29, 1);
    UtRegisterTest("AddressTestParse30", AddressTestParse30, 1);
    UtRegisterTest("AddressTestParse31", AddressTestParse31, 1);
    UtRegisterTest("AddressTestParse32", AddressTestParse32, 1);
    UtRegisterTest("AddressTestParse33", AddressTestParse33, 1);
    UtRegisterTest("AddressTestParse34", AddressTestParse34, 1);
    UtRegisterTest("AddressTestParse35", AddressTestParse35, 1);

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
    UtRegisterTest("AddressTestCmpIPv407", AddressTestCmpIPv407, 1);
    UtRegisterTest("AddressTestCmpIPv408", AddressTestCmpIPv408, 1);

    UtRegisterTest("AddressTestCmp07",   AddressTestCmp07, 1);
    UtRegisterTest("AddressTestCmp08",   AddressTestCmp08, 1);
    UtRegisterTest("AddressTestCmp09",   AddressTestCmp09, 1);
    UtRegisterTest("AddressTestCmp10",   AddressTestCmp10, 1);
    UtRegisterTest("AddressTestCmp11",   AddressTestCmp11, 1);
    UtRegisterTest("AddressTestCmp12",   AddressTestCmp12, 1);

    UtRegisterTest("AddressTestAddressGroupSetup01", AddressTestAddressGroupSetup01, 1);
    UtRegisterTest("AddressTestAddressGroupSetup02", AddressTestAddressGroupSetup02, 1);
    UtRegisterTest("AddressTestAddressGroupSetup03", AddressTestAddressGroupSetup03, 1);
    UtRegisterTest("AddressTestAddressGroupSetup04", AddressTestAddressGroupSetup04, 1);
    UtRegisterTest("AddressTestAddressGroupSetup05", AddressTestAddressGroupSetup05, 1);
    UtRegisterTest("AddressTestAddressGroupSetup06", AddressTestAddressGroupSetup06, 1);
    UtRegisterTest("AddressTestAddressGroupSetup07", AddressTestAddressGroupSetup07, 1);
    UtRegisterTest("AddressTestAddressGroupSetup08", AddressTestAddressGroupSetup08, 1);
    UtRegisterTest("AddressTestAddressGroupSetup09", AddressTestAddressGroupSetup09, 1);
    UtRegisterTest("AddressTestAddressGroupSetup10", AddressTestAddressGroupSetup10, 1);
    UtRegisterTest("AddressTestAddressGroupSetup11", AddressTestAddressGroupSetup11, 1);
    UtRegisterTest("AddressTestAddressGroupSetup12", AddressTestAddressGroupSetup12, 1);
    UtRegisterTest("AddressTestAddressGroupSetup13", AddressTestAddressGroupSetup13, 1);
    UtRegisterTest("AddressTestAddressGroupSetupIPv414", AddressTestAddressGroupSetupIPv414, 1);
    UtRegisterTest("AddressTestAddressGroupSetupIPv415", AddressTestAddressGroupSetupIPv415, 1);
    UtRegisterTest("AddressTestAddressGroupSetupIPv416", AddressTestAddressGroupSetupIPv416, 1);

    UtRegisterTest("AddressTestAddressGroupSetup14", AddressTestAddressGroupSetup14, 1);
    UtRegisterTest("AddressTestAddressGroupSetup15", AddressTestAddressGroupSetup15, 1);
    UtRegisterTest("AddressTestAddressGroupSetup16", AddressTestAddressGroupSetup16, 1);
    UtRegisterTest("AddressTestAddressGroupSetup17", AddressTestAddressGroupSetup17, 1);
    UtRegisterTest("AddressTestAddressGroupSetup18", AddressTestAddressGroupSetup18, 1);
    UtRegisterTest("AddressTestAddressGroupSetup19", AddressTestAddressGroupSetup19, 1);
    UtRegisterTest("AddressTestAddressGroupSetup20", AddressTestAddressGroupSetup20, 1);
    UtRegisterTest("AddressTestAddressGroupSetup21", AddressTestAddressGroupSetup21, 1);
    UtRegisterTest("AddressTestAddressGroupSetup22", AddressTestAddressGroupSetup22, 1);
    UtRegisterTest("AddressTestAddressGroupSetup23", AddressTestAddressGroupSetup23, 1);
    UtRegisterTest("AddressTestAddressGroupSetup24", AddressTestAddressGroupSetup24, 1);
    UtRegisterTest("AddressTestAddressGroupSetup25", AddressTestAddressGroupSetup25, 1);
    UtRegisterTest("AddressTestAddressGroupSetup26", AddressTestAddressGroupSetup26, 1);

    UtRegisterTest("AddressTestCutIPv401", AddressTestCutIPv401, 1);
    UtRegisterTest("AddressTestCutIPv402", AddressTestCutIPv402, 1);
    UtRegisterTest("AddressTestCutIPv403", AddressTestCutIPv403, 1);
    UtRegisterTest("AddressTestCutIPv404", AddressTestCutIPv404, 1);
    UtRegisterTest("AddressTestCutIPv405", AddressTestCutIPv405, 1);
    UtRegisterTest("AddressTestCutIPv406", AddressTestCutIPv406, 1);
    UtRegisterTest("AddressTestCutIPv407", AddressTestCutIPv407, 1);
    UtRegisterTest("AddressTestCutIPv408", AddressTestCutIPv408, 1);
    UtRegisterTest("AddressTestCutIPv409", AddressTestCutIPv409, 1);
    UtRegisterTest("AddressTestCutIPv410", AddressTestCutIPv410, 1);
}


