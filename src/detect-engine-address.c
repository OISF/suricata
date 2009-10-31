/* Address part of the detection engine.
 *
 * Copyright (c) 2008 Victor Julien
 *
 * TODO move this out of the detection plugin structure
 *      rename to detect-engine-address.c
 *
 *
 */

#include "eidps-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-address-ipv4.h"
#include "detect-engine-address-ipv6.h"
#include "detect-engine-port.h"

#include "util-debug.h"

//#define DEBUG

int DetectAddressSetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *sidstr);
void DetectAddressTests (void);

void DetectAddressRegister (void) {
    sigmatch_table[DETECT_ADDRESS].name = "__address__";
    sigmatch_table[DETECT_ADDRESS].Match = NULL;
    sigmatch_table[DETECT_ADDRESS].Setup = NULL;
    sigmatch_table[DETECT_ADDRESS].Free = NULL;
    sigmatch_table[DETECT_ADDRESS].RegisterTests = DetectAddressTests;
}

/* prototypes */
void DetectAddressPrint(DetectAddressGroup *);
static int DetectAddressGroupCutNot(DetectAddressGroup *, DetectAddressGroup **);
static int DetectAddressGroupCut(DetectEngineCtx *, DetectAddressGroup *, DetectAddressGroup *, DetectAddressGroup **);

/** memory usage counters
 * \todo not MT safe */
#ifdef DEBUG
static uint32_t detect_address_group_memory = 0;
static uint32_t detect_address_group_init_cnt = 0;
static uint32_t detect_address_group_free_cnt = 0;

static uint32_t detect_address_group_head_memory = 0;
static uint32_t detect_address_group_head_init_cnt = 0;
static uint32_t detect_address_group_head_free_cnt = 0;
#endif

DetectAddressGroup *DetectAddressGroupInit(void) {
    DetectAddressGroup *ag = malloc(sizeof(DetectAddressGroup));
    if (ag == NULL) {
        return NULL;
    }
    memset(ag,0,sizeof(DetectAddressGroup));
#ifdef DEBUG
    detect_address_group_memory += sizeof(DetectAddressGroup);
    detect_address_group_init_cnt++;
#endif
    return ag;
}

/** \brief free a DetectAddressGroup object */
void DetectAddressGroupFree(DetectAddressGroup *ag) {
    if (ag == NULL)
        return;

    SCLogDebug("ag %p, sh %p", ag, ag->sh);

    /* only free the head if we have the original */
    if (ag->sh != NULL && !(ag->flags & ADDRESS_SIGGROUPHEAD_COPY)) {
        SCLogDebug("- ag %p, sh %p not a copy, so call SigGroupHeadFree", ag, ag->sh);
        SigGroupHeadFree(ag->sh);
    }
    ag->sh = NULL;

    if (!(ag->flags & ADDRESS_HAVEPORT)) {
        SCLogDebug("- ag %p dst_gh %p", ag, ag->dst_gh);

        if (ag->dst_gh != NULL) {
            DetectAddressGroupsHeadFree(ag->dst_gh);
        }
        ag->dst_gh = NULL;
    } else {
        SCLogDebug("- ag %p port %p", ag, ag->port);

        if (ag->port != NULL && !(ag->flags & ADDRESS_PORTS_COPY)) {
            SCLogDebug("- ag %p port %p, not a copy so call DetectPortCleanupList", ag, ag->port);
            DetectPortCleanupList(ag->port);
        }
        ag->port = NULL;
    }
#ifdef DEBUG
    detect_address_group_memory -= sizeof(DetectAddressGroup);
    detect_address_group_free_cnt++;
#endif
    free(ag);
}

/** \brief simple copy, no sgh and stuff */
DetectAddressGroup *DetectAddressGroupCopy(DetectAddressGroup *orig) {
    DetectAddressGroup *ag = DetectAddressGroupInit();
    if (ag == NULL) {
        return NULL;
    }

    ag->flags = orig->flags;
    ag->family = orig->family;

    if (ag->family == AF_INET) {
        ag->ip[0] = orig->ip[0];
        ag->ip2[0] = orig->ip2[0];
    } else if (ag->family == AF_INET6) {
        ag->ip[0] = orig->ip[0];
        ag->ip[1] = orig->ip[1];
        ag->ip[2] = orig->ip[2];
        ag->ip[3] = orig->ip[3];
        ag->ip2[0] = orig->ip2[0];
        ag->ip2[1] = orig->ip2[1];
        ag->ip2[2] = orig->ip2[2];
        ag->ip2[3] = orig->ip2[3];
    }

    ag->cnt = 1;
    return ag;
}

void DetectAddressGroupPrintMemory(void) {
#ifdef DEBUG
    printf(" * Address group memory stats (DetectAddressGroup %" PRIuMAX "):\n", (uintmax_t)sizeof(DetectAddressGroup));
    printf("  - detect_address_group_memory %" PRIu32 "\n", detect_address_group_memory);
    printf("  - detect_address_group_init_cnt %" PRIu32 "\n", detect_address_group_init_cnt);
    printf("  - detect_address_group_free_cnt %" PRIu32 "\n", detect_address_group_free_cnt);
    printf("  - outstanding groups %" PRIu32 "\n", detect_address_group_init_cnt - detect_address_group_free_cnt);
    printf(" * Address group memory stats done\n");
    printf(" * Address group head memory stats (DetectAddressGroupsHead %" PRIuMAX "):\n", (uintmax_t)sizeof(DetectAddressGroupsHead));
    printf("  - detect_address_group_head_memory %" PRIu32 "\n", detect_address_group_head_memory);
    printf("  - detect_address_group_head_init_cnt %" PRIu32 "\n", detect_address_group_head_init_cnt);
    printf("  - detect_address_group_head_free_cnt %" PRIu32 "\n", detect_address_group_head_free_cnt);
    printf("  - outstanding groups %" PRIu32 "\n", detect_address_group_head_init_cnt - detect_address_group_head_free_cnt);
    printf(" * Address group head memory stats done\n");
    printf(" X Total %" PRIu32 "\n", detect_address_group_memory + detect_address_group_head_memory);
#endif
}

/** \brief lookup a address in a group list
 *  used to see if the exact same address group exists in the list
 *  returns a ptr to the match, or NULL if no match
 *  \todo hash/hashlist
 */
DetectAddressGroup *DetectAddressLookupInList(DetectAddressGroup *head, DetectAddressGroup *gr) {
    DetectAddressGroup *cur;

    if (head != NULL) {
        for (cur = head; cur != NULL; cur = cur->next) {
             if (DetectAddressCmp(cur, gr) == ADDRESS_EQ)
                 return cur;
        }
    }

    return NULL;
}

void DetectAddressGroupPrintList(DetectAddressGroup *head) {
    DetectAddressGroup *cur;

    printf("list:\n");
    if (head != NULL) {
        for (cur = head; cur != NULL; cur = cur->next) {
             printf("SIGS %6u ", cur->sh ? cur->sh->sig_cnt : 0);

             DetectAddressPrint(cur);

             printf("\n");
        }
    }
    printf("endlist\n");
}

void DetectAddressGroupCleanupList (DetectAddressGroup *head) {
    //SCLogDebug("head %p", head);

    if (head == NULL)
        return;

    DetectAddressGroup *cur, *next;

    for (cur = head; cur != NULL; ) {
         next = cur->next;
         DetectAddressGroupFree(cur);
         cur = next;
    }
}

/* do a sorted insert, where the top of the list should be the biggest
 * network/range.
 *
 * XXX current sorting only works for overlapping nets */
int DetectAddressGroupAdd(DetectAddressGroup **head, DetectAddressGroup *ag) {
    DetectAddressGroup *cur, *prev_cur = NULL;

    if (*head != NULL) {
        for (cur = *head; cur != NULL; cur = cur->next) {
            prev_cur = cur;

            int r = DetectAddressCmp(ag, cur);
            if (r == ADDRESS_EB) {
                /* insert here */
                ag->prev = cur->prev;
                ag->next = cur;

                cur->prev = ag;
                if (*head == cur) {
                    *head = ag;
                } else {
                    ag->prev->next = ag;
                }
                return 0;
            }
        }
        ag->prev = prev_cur;
        if (prev_cur != NULL)
            prev_cur->next = ag;
    } else {
        *head = ag;
    }

    return 0;
}

/* helper function for DetectAddress(Group)Insert:
 * set & get the head ptr
 */
static int SetHeadPtr(DetectAddressGroupsHead *gh, DetectAddressGroup *newhead) {
    if (newhead->flags & ADDRESS_FLAG_ANY)
        gh->any_head = newhead;
    else if (newhead->family == AF_INET)
        gh->ipv4_head = newhead;
    else if (newhead->family == AF_INET6)
        gh->ipv6_head = newhead;
    else {
        SCLogDebug("newhead->family %u not supported", newhead->family);
        return -1;
    }

    return 0;
}

static DetectAddressGroup *GetHeadPtr(DetectAddressGroupsHead *gh, DetectAddressGroup *new) {
    DetectAddressGroup *head = NULL;

    if (new->flags & ADDRESS_FLAG_ANY)
        head = gh->any_head;
    else if (new->family == AF_INET)
        head = gh->ipv4_head;
    else if (new->family == AF_INET6)
        head = gh->ipv6_head;

    return head;
}

//#define DBG
/* Same as DetectAddressInsert, but then for inserting a address group
 * object. This also makes sure SigGroupContainer lists are handled
 * correctly.
 *
 * returncodes
 * -1: error
 *  0: not inserted, memory of new is freed
 *  1: inserted
 * */
int DetectAddressGroupInsert(DetectEngineCtx *de_ctx, DetectAddressGroupsHead *gh, DetectAddressGroup *new) {
    DetectAddressGroup *head = NULL;

    if (new == NULL)
        return 0;

    BUG_ON(new->family == 0 && !(new->flags & ADDRESS_FLAG_ANY));

    /* get our head ptr based on the address we want to insert */
    head = GetHeadPtr(gh,new);

    /* see if it already exists or overlaps with existing ag's */
    if (head != NULL) {
        DetectAddressGroup *cur = NULL;
        int r = 0;

        for (cur = head; cur != NULL; cur = cur->next) {
            r = DetectAddressCmp(new,cur);
            BUG_ON(r == ADDRESS_ER);

            /* if so, handle that */
            if (r == ADDRESS_EQ) {
                /* exact overlap/match */
                if (cur != new) {
                    DetectPort *port = new->port;
                    for ( ; port != NULL; port = port->next) {
                        DetectPortInsertCopy(de_ctx,&cur->port,port);
                    }
                    SigGroupHeadCopySigs(de_ctx,new->sh,&cur->sh);
                    cur->cnt += new->cnt;
                    DetectAddressGroupFree(new);
                    return 0;
                }
                return 1;
            } else if (r == ADDRESS_GT) {
                /* only add it now if we are bigger than the last
                 * group. Otherwise we'll handle it later. */
                if (cur->next == NULL) {
                    /* put in the list */
                    new->prev = cur;
                    cur->next = new;
                    return 1;
                }
            } else if (r == ADDRESS_LT) {
                /* see if we need to insert the ag anywhere */
                /* put in the list */
                if (cur->prev != NULL)
                    cur->prev->next = new;
                new->prev = cur->prev;
                new->next = cur;
                cur->prev = new;

                /* update head if required */
                if (head == cur) {
                    head = new;

                    if (SetHeadPtr(gh,head) < 0)
                        goto error;
                }
                return 1;

            /* alright, those were the simple cases,
             * lets handle the more complex ones now */

            } else if (r == ADDRESS_ES) {
                DetectAddressGroup *c = NULL;
                r = DetectAddressGroupCut(de_ctx, cur,new,&c);
                if (r == -1)
                    goto error;

                DetectAddressGroupInsert(de_ctx, gh, new);
                if (c != NULL) {
                    DetectAddressGroupInsert(de_ctx, gh, c);
                }
                return 1;
            } else if (r == ADDRESS_EB) {
                DetectAddressGroup *c = NULL;
                r = DetectAddressGroupCut(de_ctx, cur,new,&c);
                if (r == -1)
                    goto error;

                //printf("DetectAddressGroupCut returned %" PRId32 "\n", r);
                DetectAddressGroupInsert(de_ctx, gh, new);
                if (c != NULL) {
                    DetectAddressGroupInsert(de_ctx, gh, c);
                }
                return 1;
            } else if (r == ADDRESS_LE) {
                DetectAddressGroup *c = NULL;
                r = DetectAddressGroupCut(de_ctx, cur,new,&c);
                if (r == -1)
                    goto error;

                DetectAddressGroupInsert(de_ctx, gh, new);
                if (c != NULL) {
                    DetectAddressGroupInsert(de_ctx, gh, c);
                }
                return 1;
            } else if (r == ADDRESS_GE) {
                DetectAddressGroup *c = NULL;
                r = DetectAddressGroupCut(de_ctx, cur,new,&c);
                if (r == -1)
                    goto error;

                DetectAddressGroupInsert(de_ctx, gh, new);
                if (c != NULL) {
                    DetectAddressGroupInsert(de_ctx, gh, c);
                }
                return 1;
            }
        }

    /* head is NULL, so get a group and set head to it */
    } else {
        head = new;
        if (SetHeadPtr(gh,head) < 0) {
            SCLogDebug("SetHeadPtr failed");
            goto error;
        }
    }

    return 1;
error:
    /* XXX */
    return -1;
}

/** \brief Join two addresses together */
int DetectAddressGroupJoin(DetectEngineCtx *de_ctx, DetectAddressGroup *target, DetectAddressGroup *source) {
    if (target == NULL || source == NULL)
        return -1;

    if (target->family != source->family)
        return -1;

    target->cnt += source->cnt;
    SigGroupHeadCopySigs(de_ctx, source->sh,&target->sh);

    DetectPort *port = source->port;
    for ( ; port != NULL; port = port->next) {
        DetectPortInsertCopy(de_ctx,&target->port, port);
    }

    if (target->family == AF_INET) {
        return DetectAddressGroupJoinIPv4(de_ctx, target,source);
    } else if (target->family == AF_INET6) {
        return DetectAddressGroupJoinIPv6(de_ctx, target,source);
    }

    return -1;
}

static void DetectAddressParseIPv6CIDR(int cidr, struct in6_addr *in6) {
    int i = 0;

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

static int DetectAddressParseString(DetectAddressGroup *dd, char *str) {
    char *ipdup = strdup(str);
    char *ip2 = NULL;
    char *mask = NULL;
    int r = 0;

    SCLogDebug("str %s", str);

    /* first handle 'any' */
    if (strcasecmp(str,"any") == 0) {
        dd->flags |= ADDRESS_FLAG_ANY;
        free(ipdup);

        SCLogDebug("address is \'any\'");
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
    if ((strchr(str,':')) == NULL) {
        /* IPv4 Address */
        struct in_addr in;

        dd->family = AF_INET;

        if ((mask = strchr(ip, '/')) != NULL)  {
            /* 1.2.3.4/xxx format (either dotted or cidr notation */
            ip[mask - ip] = '\0';
            mask++;
            uint32_t ip4addr = 0;
            uint32_t netmask = 0;

            if ((strchr (mask,'.')) == NULL) {
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
                //printf("AddressParse: dd->ip2 %" PRIX32 "\n", dd->ip2);
            }

            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0) {
                goto error;
            }

            ip4addr = in.s_addr;

            dd->ip[0] = dd->ip2[0] = ip4addr & netmask;
            dd->ip2[0] |=~ netmask;

            //printf("AddressParse: dd->ip %" PRIX32 "\n", dd->ip);
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
            //printf("AddressParse: dd->ip %" PRIX32 "\n", dd->ip);
        }
    } else {
        /* IPv6 Address */
        struct in6_addr in6, mask6;
        uint32_t ip6addr[4], netmask[4];

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

    BUG_ON(dd->family == 0);
    return 0;

error:
    if (ipdup) free(ipdup);
    return -1;
}

/** \brief Simply parse a address and return a DetectAddressGroup */
static DetectAddressGroup *DetectAddressParseSingle(char *str) {
    DetectAddressGroup *dd;

    SCLogDebug("str %s", str);

    dd = DetectAddressGroupInit();
    if (dd == NULL) {
        goto error;
    }

    if (DetectAddressParseString(dd, str) < 0) {
        SCLogDebug("AddressParse failed");
        goto error;
    }

    return dd;

error:
    if (dd != NULL)
        DetectAddressGroupFree(dd);
    return NULL;
}

/** \brief setup a single address string */
int DetectAddressGroupSetup(DetectAddressGroupsHead *gh, char *s) {
    DetectAddressGroup *ad = NULL;
    int r = 0;

    SCLogDebug("gh %p, s %s", gh, s);

    /* parse the address */
    ad = DetectAddressParseSingle(s);
    if (ad == NULL) {
        printf("DetectAddressParse error \"%s\"\n",s);
        goto error;
    }

    /* handle the not case, we apply the negation
     * then insert the part(s) */
    if (ad->flags & ADDRESS_FLAG_NOT) {
        DetectAddressGroup *ad2 = NULL;

        if (DetectAddressGroupCutNot(ad, &ad2) < 0) {
            SCLogDebug("DetectAddressGroupCutNot failed");
            goto error;
        }

        /* normally a 'not' will result in two ad's
         * unless the 'not' is on the start or end
         * of the address space (e.g. 0.0.0.0 or
         * 255.255.255.255). */
        if (ad2 != NULL) {
            if (DetectAddressGroupInsert(NULL, gh, ad2) < 0) {
                SCLogDebug("DetectAddressGroupInsert failed");
                goto error;
            }
        }
    }

    r = DetectAddressGroupInsert(NULL, gh, ad);
    if (r < 0) {
        SCLogDebug("DetectAddressGroupInsert failed");
        goto error;
    }
    SCLogDebug("r %d",r);

    /* if any, insert 0.0.0.0/0 and ::/0 as well */
    if (r == 1 && ad->flags & ADDRESS_FLAG_ANY) {
        SCLogDebug("adding 0.0.0.0/0 and ::/0 as we\'re handling \'any\'");

        ad = DetectAddressParseSingle("0.0.0.0/0");
        if (ad == NULL)
            goto error;

        BUG_ON(ad->family == 0);

        if (DetectAddressGroupInsert(NULL, gh, ad) < 0) {
            SCLogDebug("DetectAddressGroupInsert failed");
            goto error;
        }
        ad = DetectAddressParseSingle("::/0");
        if (ad == NULL)
            goto error;

        BUG_ON(ad->family == 0);

        if (DetectAddressGroupInsert(NULL, gh, ad) < 0) {
            SCLogDebug("DetectAddressGroupInsert failed");
            goto error;
        }
    }
    return 0;

error:
    printf("DetectAddressGroupSetup error\n");
    /* XXX cleanup */
    return -1;
}

/* XXX error handling */
int DetectAddressParse2(DetectAddressGroupsHead *gh,
                        DetectAddressGroupsHead *ghn,
                        char *s, int negate) {
    int i, x;
    int o_set = 0, n_set = 0;
    int depth = 0;
    size_t size = strlen(s);
    char address[1024] = "";

    SCLogDebug("s %s negate %s", s, negate ? "true" : "false");

    for (i = 0, x = 0; i < size && x < sizeof(address); i++) {
        address[x] = s[i];
        x++;

        if (!o_set && s[i] == '!') {
            n_set = 1;
            x--;
        } else if (s[i] == '[') {
            if (!o_set) {
                o_set = 1;
                x = 0;
            }
            depth++;
        } else if (s[i] == ']') {
            if (depth == 1) {
                address[x - 1] = '\0';
                x = 0;

                if (DetectAddressParse2(gh, ghn, address, negate? negate: n_set) < 0)
                    goto error;
                n_set = 0;
            }
            depth--;
        } else if (depth == 0 && s[i] == ',') {
            if (o_set == 1) {
                o_set = 0;
            } else {
                address[x - 1] = '\0';

                if (negate == 0 && n_set == 0) {
                    if (DetectAddressGroupSetup(gh, address) < 0)
                        goto error;
                } else {
                    if (DetectAddressGroupSetup(ghn, address) < 0)
                        goto error;
                }
                n_set = 0;
            }
            x = 0;
        } else if (depth == 0 && i == size - 1) {
            address[x] = '\0';
            x = 0;

            if (negate == 0 && n_set == 0) {
                if (DetectAddressGroupSetup(gh, address) < 0)
                    goto error;
            } else {
                if (DetectAddressGroupSetup(ghn, address) < 0)
                    goto error;
            }
            n_set = 0;
        }
    }

    return 0;
error:
    return -1;
}

/** \brief See if the addresses and ranges in a group head cover the entire
 *         ip space.
 *  \param gh group head to check
 *  \retval 0 no
 *  \retval 1 yes
 *  \todo do the same for IPv6
 *  \internal
 */
static int DetectAddressGroupIsCompleteIPSpace(DetectAddressGroupsHead *gh) {
    int r = DetectAddressGroupIsCompleteIPSpaceIPv4(gh->ipv4_head);
    if (r == 1) {
        return 1;
    }

    return 0;
}

/** \brief Merge the + and the - list (+ positive match, - 'not' match) */
int DetectAddressGroupMergeNot(DetectAddressGroupsHead *gh, DetectAddressGroupsHead *ghn) {
    DetectAddressGroup *ad;
    DetectAddressGroup *ag, *ag2;
    int r = 0;

    SCLogDebug("gh->ipv4_head %p, ghn->ipv4_head %p", gh->ipv4_head, ghn->ipv4_head);

    /* check if the negated list covers the entire ip space. If so
       the user screwed up the rules/vars. */
    if (DetectAddressGroupIsCompleteIPSpace(ghn) == 1) {
        printf("DetectAddressGroupMergeNot: complete IP space negated\n");
        goto error;
    }

    /* step 0: if the gh list is empty, but the ghn list isn't
     * we have a pure not thingy. In that case we add a 0.0.0.0/0
     * first. */
    if (gh->ipv4_head == NULL && ghn->ipv4_head != NULL) {
        r = DetectAddressGroupSetup(gh,"0.0.0.0/0");
        if (r < 0) {
            SCLogDebug("DetectAddressGroupSetup for 0.0.0.0/0 failed");
            goto error;
        }
    }
    /* ... or ::/0 for ipv6 */
    if (gh->ipv6_head == NULL && ghn->ipv6_head != NULL) {
        r = DetectAddressGroupSetup(gh,"::/0");
        if (r < 0) {
            SCLogDebug("DetectAddressGroupSetup for ::/0 failed");
            goto error;
        }
    }

    /* step 1: insert our ghn members into the gh list */
    for (ag = ghn->ipv4_head; ag != NULL; ag = ag->next) {
        /* work with a copy of the ad so we can easily clean up
         * the ghn group later. */
        ad = DetectAddressGroupCopy(ag);
        if (ad == NULL) {
            SCLogDebug("DetectAddressGroupCopy failed");
            goto error;
        }

        r = DetectAddressGroupInsert(NULL, gh, ad);
        if (r < 0) {
            SCLogDebug("DetectAddressGroupInsert failed");
            goto error;
        }
    }
    /* ... and the same for ipv6 */
    for (ag = ghn->ipv6_head; ag != NULL; ag = ag->next) {
        /* work with a copy of the ad so we can easily clean up
         * the ghn group later. */
        ad = DetectAddressGroupCopy(ag);
        if (ad == NULL) {
            SCLogDebug("DetectAddressGroupCopy failed");
            goto error;
        }

        r = DetectAddressGroupInsert(NULL, gh, ad);
        if (r < 0) {
            SCLogDebug("DetectAddressGroupInsert failed");
            goto error;
        }
    }

    /* step 2: pull the address blocks that match our 'not' blocks */
    for (ag = ghn->ipv4_head; ag != NULL; ag = ag->next) {
        SCLogDebug("ag %p", ag);
        DetectAddressPrint(ag);

        for (ag2 = gh->ipv4_head; ag2 != NULL; ) {
            SCLogDebug("ag2 %p", ag2);
            DetectAddressPrint(ag2);

            r = DetectAddressCmp(ag, ag2);
            if (r == ADDRESS_EQ || r == ADDRESS_EB) { /* XXX more ??? */
                if (ag2->prev == NULL) {
                    gh->ipv4_head = ag2->next;
                } else {
                    ag2->prev->next = ag2->next;
                }

                if (ag2->next != NULL) {
                    ag2->next->prev = ag2->prev;
                }

                /* store the next ptr and remove the group */
                DetectAddressGroup *next_ag2 = ag2->next;
                DetectAddressGroupFree(ag2);
                ag2 = next_ag2;
            } else {
                ag2 = ag2->next;
            }
        }
    }
    /* ... and the same for ipv6 */
    for (ag = ghn->ipv6_head; ag != NULL; ag = ag->next) {
        for (ag2 = gh->ipv6_head; ag2 != NULL; ) {
            r = DetectAddressCmp(ag, ag2);
            if (r == ADDRESS_EQ || r == ADDRESS_EB) { /* XXX more ??? */
                if (ag2->prev == NULL) {
                    gh->ipv6_head = ag2->next;
                } else {
                    ag2->prev->next = ag2->next;
                }

                if (ag2->next != NULL) {
                    ag2->next->prev = ag2->prev;
                }

                /* store the next ptr and remove the group */
                DetectAddressGroup *next_ag2 = ag2->next;
                DetectAddressGroupFree(ag2);
                ag2 = next_ag2;
            } else {
                ag2 = ag2->next;
            }
        }
    }

    /* if the result is that we have no addresses we return error */
    if (gh->ipv4_head == NULL && gh->ipv6_head == NULL) {
        printf("no addresses left after merging addresses and not-addresses\n");
        goto error;
    }

    return 0;
error:
    return -1;
}

/* XXX rename this so 'Group' is out of the name */
int DetectAddressGroupParse(DetectAddressGroupsHead *gh, char *str) {
    int r;

    SCLogDebug("gh %p, str %s", gh, str);

    DetectAddressGroupsHead *ghn = DetectAddressGroupsHeadInit();
    if (ghn == NULL) {
        SCLogDebug("DetectAddressGroupsHeadInit for ghn failed");
        goto error;
    }

    r = DetectAddressParse2(gh, ghn, str,/* start with negate no */0);
    if (r < 0) {
        SCLogDebug("DetectAddressParse2 returned %d", r);
        goto error;
    }

    SCLogDebug("gh->ipv4_head %p, ghn->ipv4_head %p", gh->ipv4_head, ghn->ipv4_head);

    /* merge the 'not' address groups */
    if (DetectAddressGroupMergeNot(gh, ghn) < 0) {
        SCLogDebug("DetectAddressGroupMergeNot failed");
        goto error;
    }

    /* free the temp negate head */
    DetectAddressGroupsHeadFree(ghn);
    return 0;

error:
    DetectAddressGroupsHeadFree(ghn);
    return -1;
}

DetectAddressGroupsHead *DetectAddressGroupsHeadInit(void) {
    DetectAddressGroupsHead *gh = malloc(sizeof(DetectAddressGroupsHead));
    if (gh == NULL)
        return NULL;
    memset(gh, 0, sizeof(DetectAddressGroupsHead));

#ifdef DEBUG
    detect_address_group_head_init_cnt++;
    detect_address_group_head_memory += sizeof(DetectAddressGroupsHead);
#endif

    return gh;
}

void DetectAddressGroupsHeadCleanup(DetectAddressGroupsHead *gh) {
    //SCLogDebug("gh %p", gh);

    if (gh != NULL) {
        DetectAddressGroupCleanupList(gh->any_head);
        gh->any_head = NULL;
        DetectAddressGroupCleanupList(gh->ipv4_head);
        gh->ipv4_head = NULL;
        DetectAddressGroupCleanupList(gh->ipv6_head);
        gh->ipv6_head = NULL;
    }
}

void DetectAddressGroupsHeadFree(DetectAddressGroupsHead *gh) {
    //SCLogDebug("gh %p", gh);

    if (gh != NULL) {
        DetectAddressGroupsHeadCleanup(gh);
        free(gh);
#ifdef DEBUG
        detect_address_group_head_free_cnt++;
        detect_address_group_head_memory -= sizeof(DetectAddressGroupsHead);
#endif
    }
}

int DetectAddressGroupCut(DetectEngineCtx *de_ctx, DetectAddressGroup *a, DetectAddressGroup *b, DetectAddressGroup **c) {
    if (a->family == AF_INET) {
        return DetectAddressGroupCutIPv4(de_ctx, a,b,c);
    } else if (a->family == AF_INET6) {
        return DetectAddressGroupCutIPv6(de_ctx, a,b,c);
    }

    return -1;
}

/** \retval 0 ok
 *  \retval -1 error */
int DetectAddressGroupCutNot(DetectAddressGroup *a, DetectAddressGroup **b) {
    if (a->family == AF_INET) {
        return DetectAddressGroupCutNotIPv4(a,b);
    } else if (a->family == AF_INET6) {
        return DetectAddressGroupCutNotIPv6(a,b);
    }

    return -1;
}

int DetectAddressCmp(DetectAddressGroup *a, DetectAddressGroup *b) {
    if (a->family != b->family)
        return ADDRESS_ER;

    /* check any */
    if (a->flags & ADDRESS_FLAG_ANY && b->flags & ADDRESS_FLAG_ANY)
        return ADDRESS_EQ;
    else if (a->family == AF_INET)
        return DetectAddressGroupCmpIPv4(a, b);
    else if (a->family == AF_INET6)
        return DetectAddressGroupCmpIPv6(a, b);

    return ADDRESS_ER;
}

int DetectAddressMatch (DetectAddressGroup *dd, Address *a) {
    if (dd->family != a->family)
        return 0;

    switch (a->family) {
        case AF_INET:
            /* XXX figure out a way to not need to do this ntohl
             * if we switch to Address inside DetectAddressData
             * we can do uint8_t checks */
            if (ntohl(a->addr_data32[0]) >= ntohl(dd->ip[0]) &&
                ntohl(a->addr_data32[0]) <= ntohl(dd->ip2[0])) {
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

void DetectAddressPrint(DetectAddressGroup *gr) {
    if (gr == NULL)
        return;

    if (gr->flags & ADDRESS_FLAG_ANY) {
        printf("ANY");
    } else if (gr->family == AF_INET) {
        struct in_addr in;
        char ip[16], mask[16];

        memcpy(&in, &gr->ip[0], sizeof(in));
        inet_ntop(AF_INET, &in, ip, sizeof(ip));
        memcpy(&in, &gr->ip2[0], sizeof(in));
        inet_ntop(AF_INET, &in, mask, sizeof(mask));

        SCLogDebug("%s/%s", ip, mask);
    } else if (gr->family == AF_INET6) {
        struct in6_addr in6;
        char ip[66], mask[66];

        memcpy(&in6, &gr->ip, sizeof(in6));
        inet_ntop(AF_INET6, &in6, ip, sizeof(ip));
        memcpy(&in6, &gr->ip2, sizeof(in6));
        inet_ntop(AF_INET6, &in6, mask, sizeof(mask));

        SCLogDebug("%s/%s", ip, mask);
    }
}

/** \brief find the group matching address in a group head */
DetectAddressGroup *
DetectAddressLookupInHead(DetectAddressGroupsHead *gh, Address *a) {
    DetectAddressGroup *g;

    //printf("DetectAddressLookupGroup: start %p\n", gh);

    if (gh == NULL)
        return NULL;

    //printf("DetectAddressLookupGroup: gh 4%p 6%p a%p\n", gh->ipv4_head, gh->ipv6_head, gh->any_head);

    /* XXX should we really do this check every time we run
     * this function? */
    if (a->family == AF_INET)
        g = gh->ipv4_head;
    else if (a->family == AF_INET6)
        g = gh->ipv6_head;
    else
        g = gh->any_head;

    //printf("g %p\n", g);

    for ( ; g != NULL; g = g->next) {
        //printf("DetectAddressLookupGroup: checking \n"); DetectAddressDataPrint(g->ad2); printf("\n");
        if (DetectAddressMatch(g,a) == 1) {
            return g;
        }
    }

    return NULL;
}

/* TESTS */


#ifdef UNITTESTS
int AddressTestParse01 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("1.2.3.4");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse02 (void) {
    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("1.2.3.4");
    if (dd) {
        if (dd->ip2[0] != 0x04030201 ||
            dd->ip[0]  != 0x04030201) {
            result = 0;
        }

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse03 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("1.2.3.4/255.255.255.0");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse04 (void) {
    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("1.2.3.4/255.255.255.0");
    if (dd) {
        if (dd->ip2[0] != 0xff030201 ||
            dd->ip[0]  != 0x00030201) {
            result = 0;
        }

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse05 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("1.2.3.4/24");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse06 (void) {
    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("1.2.3.4/24");
    if (dd) {
        if (dd->ip2[0] != 0xff030201 ||
            dd->ip[0]  != 0x00030201) {
            result = 0;
        }

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse07 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("2001::/3");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse08 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("2001::/3");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000020 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->ip2[0] != 0xFFFFFF3F || dd->ip2[1] != 0xFFFFFFFF ||
            dd->ip2[2] != 0xFFFFFFFF || dd->ip2[3] != 0xFFFFFFFF)
        {
            DetectAddressPrint(dd);
            result = 0;
        }

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse09 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("2001::1/128");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse10 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("2001::/128");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->ip2[0] != 0x00000120 || dd->ip2[1] != 0x00000000 ||
            dd->ip2[2] != 0x00000000 || dd->ip2[3] != 0x00000000)
        {
            DetectAddressPrint(dd);
            result = 0;
        }

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse11 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("2001::/48");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse12 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("2001::/48");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->ip2[0] != 0x00000120 || dd->ip2[1] != 0xFFFF0000 ||
            dd->ip2[2] != 0xFFFFFFFF || dd->ip2[3] != 0xFFFFFFFF)
        {
            DetectAddressPrint(dd);
            result = 0;
        }

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}
int AddressTestParse13 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("2001::/16");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse14 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("2001::/16");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->ip2[0] != 0xFFFF0120 || dd->ip2[1] != 0xFFFFFFFF ||
            dd->ip2[2] != 0xFFFFFFFF || dd->ip2[3] != 0xFFFFFFFF)
        {
            result = 0;
        }

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse15 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("2001::/0");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse16 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("2001::/0");
    if (dd) {
        int result = 1;

        if (dd->ip[0] != 0x00000000 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x00000000 ||

            dd->ip2[0] != 0xFFFFFFFF || dd->ip2[1] != 0xFFFFFFFF ||
            dd->ip2[2] != 0xFFFFFFFF || dd->ip2[3] != 0xFFFFFFFF)
        {
            result = 0;
        }

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse17 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("1.2.3.4-1.2.3.6");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse18 (void) {
    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("1.2.3.4-1.2.3.6");
    if (dd) {
        if (dd->ip2[0] != 0x06030201 ||
            dd->ip[0]  != 0x04030201) {
            result = 0;
        }

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse19 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("1.2.3.6-1.2.3.4");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 0;
    }

    return 1;
}

int AddressTestParse20 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("2001::1-2001::4");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse21 (void) {
    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("2001::1-2001::4");
    if (dd) {
        if (dd->ip[0] != 0x00000120 || dd->ip[1] != 0x00000000 ||
            dd->ip[2] != 0x00000000 || dd->ip[3] != 0x01000000 ||

            dd->ip2[0] != 0x00000120 || dd->ip2[1] != 0x00000000 ||
            dd->ip2[2] != 0x00000000 || dd->ip2[3] != 0x04000000)
        {
            result = 0;
        }

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse22 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("2001::4-2001::1");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 0;
    }

    return 1;
}

int AddressTestParse23 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("any");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse24 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("Any");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse25 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("ANY");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse26 (void) {
    int result = 0;
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("any");
    if (dd) {
        if (dd->flags & ADDRESS_FLAG_ANY)
            result = 1;

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse27 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("!192.168.0.1");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse28 (void) {
    int result = 0;
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("!1.2.3.4");
    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip[0] == 0x04030201) {
            result = 1;
        }

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse29 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("!1.2.3.0/24");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse30 (void) {
    int result = 0;
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("!1.2.3.4/24");
    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip[0] == 0x00030201 &&
            dd->ip2[0] == 0xFF030201) {
            result = 1;
        }

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}

/** \test make sure !any is rejected */
int AddressTestParse31 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("!any");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 0;
    }

    return 1;
}

int AddressTestParse32 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("!2001::1");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse33 (void) {
    int result = 0;
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("!2001::1");
    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip[0] == 0x00000120 && dd->ip[1] == 0x00000000 &&
            dd->ip[2] == 0x00000000 && dd->ip[3] == 0x01000000) {
            result = 1;
        }

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse34 (void) {
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("!2001::/16");
    if (dd) {
        DetectAddressGroupFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse35 (void) {
    int result = 0;
    DetectAddressGroup *dd = NULL;
    dd = DetectAddressParseSingle("!2001::/16");
    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip[0] == 0x00000120 && dd->ip[1] == 0x00000000 &&
            dd->ip[2] == 0x00000000 && dd->ip[3] == 0x00000000 &&

            dd->ip2[0] == 0xFFFF0120 && dd->ip2[1] == 0xFFFFFFFF &&
            dd->ip2[2] == 0xFFFFFFFF && dd->ip2[3] == 0xFFFFFFFF)
        {
            result = 1;
        }

        DetectAddressGroupFree(dd);
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

    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("1.2.3.4/24");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 0)
            result = 0;

        DetectAddressGroupFree(dd);
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

    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("1.2.3.4/25");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 0)
            result = 0;

        DetectAddressGroupFree(dd);
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

    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("1.2.3.4/25");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 1)
            result = 0;

        DetectAddressGroupFree(dd);
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

    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("1.2.3.4/25");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 1)
            result = 0;

        DetectAddressGroupFree(dd);
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

    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("1.2.3.4/32");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 0)
            result = 0;

        DetectAddressGroupFree(dd);
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

    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("0.0.0.0/0.0.0.0");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 0)
            result = 0;

        DetectAddressGroupFree(dd);
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

    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("2001::/3");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 0)
            result = 0;

        DetectAddressGroupFree(dd);
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

    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("2001::/3");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 1) {
            result = 0;
        }
        DetectAddressGroupFree(dd);
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

    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("2001::1/128");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 1)
            result = 0;

        DetectAddressGroupFree(dd);
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

    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("2001::1/126");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 0)
            result = 0;

        DetectAddressGroupFree(dd);
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

    DetectAddressGroup *dd = NULL;
    int result = 1;

    dd = DetectAddressParseSingle("2001::1/127");
    if (dd) {
        if (DetectAddressMatch(dd,&a) == 1)
            result = 0;

        DetectAddressGroupFree(dd);
        return result;
    }

    return 0;
}

int AddressTestCmp01 (void) {
    DetectAddressGroup *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.0.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.0.0/255.255.255.0");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da,db) != ADDRESS_EQ)
        result = 0;

    DetectAddressGroupFree(da);
    DetectAddressGroupFree(db);
    return result;

error:
    if (da) DetectAddressGroupFree(da);
    if (db) DetectAddressGroupFree(db);
    return 0;
}

int AddressTestCmp02 (void) {
    DetectAddressGroup *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.0.0/255.255.0.0");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.0.0/255.255.255.0");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da,db) != ADDRESS_EB)
        result = 0;

    DetectAddressGroupFree(da);
    DetectAddressGroupFree(db);
    return result;

error:
    if (da) DetectAddressGroupFree(da);
    if (db) DetectAddressGroupFree(db);
    return 0;
}

int AddressTestCmp03 (void) {
    DetectAddressGroup *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.0.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.0.0/255.255.0.0");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da,db) != ADDRESS_ES)
        result = 0;

    DetectAddressGroupFree(da);
    DetectAddressGroupFree(db);
    return result;

error:
    if (da) DetectAddressGroupFree(da);
    if (db) DetectAddressGroupFree(db);
    return 0;
}

int AddressTestCmp04 (void) {
    DetectAddressGroup *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.0.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.1.0/255.255.255.0");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da,db) != ADDRESS_LT)
        result = 0;

    DetectAddressGroupFree(da);
    DetectAddressGroupFree(db);
    return result;

error:
    if (da) DetectAddressGroupFree(da);
    if (db) DetectAddressGroupFree(db);
    return 0;
}

int AddressTestCmp05 (void) {
    DetectAddressGroup *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.1.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.0.0/255.255.255.0");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da,db) != ADDRESS_GT)
        result = 0;

    DetectAddressGroupFree(da);
    DetectAddressGroupFree(db);
    return result;

error:
    if (da) DetectAddressGroupFree(da);
    if (db) DetectAddressGroupFree(db);
    return 0;
}

int AddressTestCmp06 (void) {
    DetectAddressGroup *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.1.0/255.255.0.0");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.0.0/255.255.0.0");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da,db) != ADDRESS_EQ)
        result = 0;

    DetectAddressGroupFree(da);
    DetectAddressGroupFree(db);
    return result;

error:
    if (da) DetectAddressGroupFree(da);
    if (db) DetectAddressGroupFree(db);
    return 0;
}

int AddressTestCmpIPv407 (void) {
    DetectAddressGroup *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.1.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.1.128-192.168.2.128");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da,db) != ADDRESS_LE)
        result = 0;

    DetectAddressGroupFree(da);
    DetectAddressGroupFree(db);
    return result;

error:
    if (da) DetectAddressGroupFree(da);
    if (db) DetectAddressGroupFree(db);
    return 0;
}

int AddressTestCmpIPv408 (void) {
    DetectAddressGroup *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.1.128-192.168.2.128");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.1.0/255.255.255.0");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da,db) != ADDRESS_GE)
        result = 0;

    DetectAddressGroupFree(da);
    DetectAddressGroupFree(db);
    return result;

error:
    if (da) DetectAddressGroupFree(da);
    if (db) DetectAddressGroupFree(db);
    return 0;
}

int AddressTestCmp07 (void) {
    DetectAddressGroup *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("2001::/3");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("2001::1/3");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da,db) != ADDRESS_EQ)
        result = 0;

    DetectAddressGroupFree(da);
    DetectAddressGroupFree(db);
    return result;

error:
    if (da) DetectAddressGroupFree(da);
    if (db) DetectAddressGroupFree(db);
    return 0;
}

int AddressTestCmp08 (void) {
    DetectAddressGroup *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("2001::/3");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("2001::/8");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da,db) != ADDRESS_EB)
        result = 0;

    DetectAddressGroupFree(da);
    DetectAddressGroupFree(db);
    return result;

error:
    if (da) DetectAddressGroupFree(da);
    if (db) DetectAddressGroupFree(db);
    return 0;
}

int AddressTestCmp09 (void) {
    DetectAddressGroup *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("2001::/8");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("2001::/3");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da,db) != ADDRESS_ES)
        result = 0;

    DetectAddressGroupFree(da);
    DetectAddressGroupFree(db);
    return result;

error:
    if (da) DetectAddressGroupFree(da);
    if (db) DetectAddressGroupFree(db);
    return 0;
}

int AddressTestCmp10 (void) {
    DetectAddressGroup *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("2001:1:2:3:0:0:0:0/64");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("2001:1:2:4:0:0:0:0/64");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da,db) != ADDRESS_LT)
        result = 0;

    DetectAddressGroupFree(da);
    DetectAddressGroupFree(db);
    return result;

error:
    if (da) DetectAddressGroupFree(da);
    if (db) DetectAddressGroupFree(db);
    return 0;
}

int AddressTestCmp11 (void) {
    DetectAddressGroup *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("2001:1:2:4:0:0:0:0/64");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("2001:1:2:3:0:0:0:0/64");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da,db) != ADDRESS_GT)
        result = 0;

    DetectAddressGroupFree(da);
    DetectAddressGroupFree(db);
    return result;

error:
    if (da) DetectAddressGroupFree(da);
    if (db) DetectAddressGroupFree(db);
    return 0;
}

int AddressTestCmp12 (void) {
    DetectAddressGroup *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("2001:1:2:3:1:0:0:0/64");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("2001:1:2:3:2:0:0:0/64");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da,db) != ADDRESS_EQ)
        result = 0;

    DetectAddressGroupFree(da);
    DetectAddressGroupFree(db);
    return result;

error:
    if (da) DetectAddressGroupFree(da);
    if (db) DetectAddressGroupFree(db);
    return 0;
}

int AddressTestAddressGroupSetup01 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupParse(gh, "1.2.3.4");
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
        int r = DetectAddressGroupParse(gh, "1.2.3.4");
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
        int r = DetectAddressGroupParse(gh, "1.2.3.4");
        if (r == 0 && gh->ipv4_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv4_head;

            r = DetectAddressGroupParse(gh, "1.2.3.3");
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
        int r = DetectAddressGroupParse(gh, "1.2.3.4");
        if (r == 0 && gh->ipv4_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv4_head;

            r = DetectAddressGroupParse(gh, "1.2.3.3");
            if (r == 0 && gh->ipv4_head != prev_head &&
                gh->ipv4_head != NULL && gh->ipv4_head->next == prev_head)
            {
                DetectAddressGroup *prev_head = gh->ipv4_head;

                r = DetectAddressGroupParse(gh, "1.2.3.2");
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
        int r = DetectAddressGroupParse(gh, "1.2.3.2");
        if (r == 0 && gh->ipv4_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv4_head;

            r = DetectAddressGroupParse(gh, "1.2.3.3");
            if (r == 0 && gh->ipv4_head == prev_head &&
                gh->ipv4_head != NULL && gh->ipv4_head->next != prev_head)
            {
                DetectAddressGroup *prev_head = gh->ipv4_head;

                r = DetectAddressGroupParse(gh, "1.2.3.4");
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
        int r = DetectAddressGroupParse(gh, "1.2.3.2");
        if (r == 0 && gh->ipv4_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv4_head;

            r = DetectAddressGroupParse(gh, "1.2.3.2");
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
        int r = DetectAddressGroupParse(gh, "10.0.0.0/8");
        if (r == 0 && gh->ipv4_head != NULL) {
            r = DetectAddressGroupParse(gh, "10.10.10.10");
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
        int r = DetectAddressGroupParse(gh, "10.10.10.10");
        if (r == 0 && gh->ipv4_head != NULL) {
            r = DetectAddressGroupParse(gh, "10.0.0.0/8");
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
        int r = DetectAddressGroupParse(gh, "10.10.10.0/24");
        if (r == 0 && gh->ipv4_head != NULL) {
            r = DetectAddressGroupParse(gh, "10.10.10.10-10.10.11.1");
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
        int r = DetectAddressGroupParse(gh, "10.10.10.10-10.10.11.1");
        if (r == 0 && gh->ipv4_head != NULL) {
            r = DetectAddressGroupParse(gh, "10.10.10.0/24");
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
        int r = DetectAddressGroupParse(gh, "10.10.10.10-10.10.11.1");
        if (r == 0) {
            r = DetectAddressGroupParse(gh, "10.10.10.0/24");
            if (r == 0) {
                r = DetectAddressGroupParse(gh, "0.0.0.0/0");
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
                    if (one->ip[0]   == 0x00000000 && one->ip2[0]   == 0xFF090A0A &&
                        two->ip[0]   == 0x000A0A0A && two->ip2[0]   == 0x090A0A0A &&
                        three->ip[0] == 0x0A0A0A0A && three->ip2[0] == 0xFF0A0A0A &&
                        four->ip[0]  == 0x000B0A0A && four->ip2[0]  == 0x010B0A0A &&
                        five->ip[0]  == 0x020B0A0A && five->ip2[0]  == 0xFFFFFFFF) {
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
        int r = DetectAddressGroupParse(gh, "10.10.10.10-10.10.11.1");
        if (r == 0) {
            r = DetectAddressGroupParse(gh, "0.0.0.0/0");
            if (r == 0) {
                r = DetectAddressGroupParse(gh, "10.10.10.0/24");
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
                    if (one->ip[0]   == 0x00000000 && one->ip2[0]   == 0xFF090A0A &&
                        two->ip[0]   == 0x000A0A0A && two->ip2[0]   == 0x090A0A0A &&
                        three->ip[0] == 0x0A0A0A0A && three->ip2[0] == 0xFF0A0A0A &&
                        four->ip[0]  == 0x000B0A0A && four->ip2[0]  == 0x010B0A0A &&
                        five->ip[0]  == 0x020B0A0A && five->ip2[0]  == 0xFFFFFFFF) {
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
        int r = DetectAddressGroupParse(gh, "0.0.0.0/0");
        if (r == 0) {
            r = DetectAddressGroupParse(gh, "10.10.10.10-10.10.11.1");
            if (r == 0) {
                r = DetectAddressGroupParse(gh, "10.10.10.0/24");
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
                    if (one->ip[0]   == 0x00000000 && one->ip2[0]   == 0xFF090A0A &&
                        two->ip[0]   == 0x000A0A0A && two->ip2[0]   == 0x090A0A0A &&
                        three->ip[0] == 0x0A0A0A0A && three->ip2[0] == 0xFF0A0A0A &&
                        four->ip[0]  == 0x000B0A0A && four->ip2[0]  == 0x010B0A0A &&
                        five->ip[0]  == 0x020B0A0A && five->ip2[0]  == 0xFFFFFFFF) {
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
        int r = DetectAddressGroupParse(gh, "!1.2.3.4");
        if (r == 0) {
            DetectAddressGroup *one = gh->ipv4_head;
            DetectAddressGroup *two = one ? one->next : NULL;

            if (one && two) {
                /* result should be:
                 * 0.0.0.0/1.2.3.3
                 * 1.2.3.5/255.255.255.255
                 */
                if (one->ip[0]   == 0x00000000 && one->ip2[0]   == 0x03030201 &&
                    two->ip[0]   == 0x05030201 && two->ip2[0]   == 0xFFFFFFFF) {
                    result = 1;
                } else {
                    printf("unexpected addresses: ");
                }
            } else {
                printf("one %p two %p: ", one, two);
            }
        } else {
            printf("DetectAddressGroupParse returned %d, expected 0: ", r);
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetupIPv415 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupParse(gh, "!0.0.0.0");
        if (r == 0) {
            DetectAddressGroup *one = gh->ipv4_head;

            if (one && one->next == NULL) {
                /* result should be:
                 * 0.0.0.1/255.255.255.255
                 */
                if (one->ip[0]   == 0x01000000 && one->ip2[0]   == 0xFFFFFFFF) {
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
        int r = DetectAddressGroupParse(gh, "!255.255.255.255");
        if (r == 0) {
            DetectAddressGroup *one = gh->ipv4_head;

            if (one && one->next == NULL) {
                /* result should be:
                 * 0.0.0.0/255.255.255.254
                 */
                if (one->ip[0]   == 0x00000000 && one->ip2[0]   == 0xFEFFFFFF) {
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
        int r = DetectAddressGroupParse(gh, "2001::1");
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
        int r = DetectAddressGroupParse(gh, "2001::1");
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
        int r = DetectAddressGroupParse(gh, "2001::4");
        if (r == 0 && gh->ipv6_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv6_head;

            r = DetectAddressGroupParse(gh, "2001::3");
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
        int r = DetectAddressGroupParse(gh, "2001::4");
        if (r == 0 && gh->ipv6_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv6_head;

            r = DetectAddressGroupParse(gh, "2001::3");
            if (r == 0 && gh->ipv6_head != prev_head &&
                gh->ipv6_head != NULL && gh->ipv6_head->next == prev_head)
            {
                DetectAddressGroup *prev_head = gh->ipv6_head;

                r = DetectAddressGroupParse(gh, "2001::2");
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
        int r = DetectAddressGroupParse(gh, "2001::2");
        if (r == 0 && gh->ipv6_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv6_head;

            r = DetectAddressGroupParse(gh, "2001::3");
            if (r == 0 && gh->ipv6_head == prev_head &&
                gh->ipv6_head != NULL && gh->ipv6_head->next != prev_head)
            {
                DetectAddressGroup *prev_head = gh->ipv6_head;

                r = DetectAddressGroupParse(gh, "2001::4");
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
        int r = DetectAddressGroupParse(gh, "2001::2");
        if (r == 0 && gh->ipv6_head != NULL) {
            DetectAddressGroup *prev_head = gh->ipv6_head;

            r = DetectAddressGroupParse(gh, "2001::2");
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
        int r = DetectAddressGroupParse(gh, "2000::/3");
        if (r == 0 && gh->ipv6_head != NULL) {
            r = DetectAddressGroupParse(gh, "2001::4");
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
        int r = DetectAddressGroupParse(gh, "2001::4");
        if (r == 0 && gh->ipv6_head != NULL) {
            r = DetectAddressGroupParse(gh, "2000::/3");
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
        int r = DetectAddressGroupParse(gh, "2000::/3");
        if (r == 0 && gh->ipv6_head != NULL) {
            r = DetectAddressGroupParse(gh, "2001::4-2001::6");
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
        int r = DetectAddressGroupParse(gh, "2001::4-2001::6");
        if (r == 0 && gh->ipv6_head != NULL) {
            r = DetectAddressGroupParse(gh, "2000::/3");
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
        int r = DetectAddressGroupParse(gh, "2001::4-2001::6");
        if (r == 0) {
            r = DetectAddressGroupParse(gh, "2001::/3");
            if (r == 0) {
                r = DetectAddressGroupParse(gh, "::/0");
                if (r == 0) {
                    DetectAddressGroup *one = gh->ipv6_head, *two = one->next,
                                       *three = two->next, *four = three->next,
                                       *five = four->next;
                    if (one->ip[0]   == 0x00000000 &&
                        one->ip[1]   == 0x00000000 &&
                        one->ip[2]   == 0x00000000 &&
                        one->ip[3]   == 0x00000000 &&
                        one->ip2[0]   == 0xFFFFFF1F &&
                        one->ip2[1]   == 0xFFFFFFFF &&
                        one->ip2[2]   == 0xFFFFFFFF &&
                        one->ip2[3]   == 0xFFFFFFFF &&

                        two->ip[0]   == 0x00000020 &&
                        two->ip[1]   == 0x00000000 &&
                        two->ip[2]   == 0x00000000 &&
                        two->ip[3]   == 0x00000000 &&
                        two->ip2[0]   == 0x00000120 &&
                        two->ip2[1]   == 0x00000000 &&
                        two->ip2[2]   == 0x00000000 &&
                        two->ip2[3]   == 0x03000000 &&

                        three->ip[0] == 0x00000120 &&
                        three->ip[1] == 0x00000000 &&
                        three->ip[2] == 0x00000000 &&
                        three->ip[3] == 0x04000000 &&
                        three->ip2[0] == 0x00000120 &&
                        three->ip2[1] == 0x00000000 &&
                        three->ip2[2] == 0x00000000 &&
                        three->ip2[3] == 0x06000000 &&

                        four->ip[0]  == 0x00000120 &&
                        four->ip[1]  == 0x00000000 &&
                        four->ip[2]  == 0x00000000 &&
                        four->ip[3]  == 0x07000000 &&
                        four->ip2[0]  == 0xFFFFFF3F &&
                        four->ip2[1]  == 0xFFFFFFFF &&
                        four->ip2[2]  == 0xFFFFFFFF &&
                        four->ip2[3]  == 0xFFFFFFFF &&

                        five->ip[0]  == 0x00000040 && 
                        five->ip[1]  == 0x00000000 && 
                        five->ip[2]  == 0x00000000 && 
                        five->ip[3]  == 0x00000000 && 
                        five->ip2[0]  == 0xFFFFFFFF &&
                        five->ip2[1]  == 0xFFFFFFFF &&
                        five->ip2[2]  == 0xFFFFFFFF &&
                        five->ip2[3]  == 0xFFFFFFFF) {
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
        int r = DetectAddressGroupParse(gh, "2001::4-2001::6");
        if (r == 0) {
            r = DetectAddressGroupParse(gh, "::/0");
            if (r == 0) {
                r = DetectAddressGroupParse(gh, "2001::/3");
                if (r == 0) {
                    DetectAddressGroup *one = gh->ipv6_head, *two = one->next,
                                       *three = two->next, *four = three->next,
                                       *five = four->next;
                    if (one->ip[0]   == 0x00000000 &&
                        one->ip[1]   == 0x00000000 &&
                        one->ip[2]   == 0x00000000 &&
                        one->ip[3]   == 0x00000000 &&
                        one->ip2[0]   == 0xFFFFFF1F &&
                        one->ip2[1]   == 0xFFFFFFFF &&
                        one->ip2[2]   == 0xFFFFFFFF &&
                        one->ip2[3]   == 0xFFFFFFFF &&

                        two->ip[0]   == 0x00000020 &&
                        two->ip[1]   == 0x00000000 &&
                        two->ip[2]   == 0x00000000 &&
                        two->ip[3]   == 0x00000000 &&
                        two->ip2[0]   == 0x00000120 &&
                        two->ip2[1]   == 0x00000000 &&
                        two->ip2[2]   == 0x00000000 &&
                        two->ip2[3]   == 0x03000000 &&

                        three->ip[0] == 0x00000120 &&
                        three->ip[1] == 0x00000000 &&
                        three->ip[2] == 0x00000000 &&
                        three->ip[3] == 0x04000000 &&
                        three->ip2[0] == 0x00000120 &&
                        three->ip2[1] == 0x00000000 &&
                        three->ip2[2] == 0x00000000 &&
                        three->ip2[3] == 0x06000000 &&

                        four->ip[0]  == 0x00000120 &&
                        four->ip[1]  == 0x00000000 &&
                        four->ip[2]  == 0x00000000 &&
                        four->ip[3]  == 0x07000000 &&
                        four->ip2[0]  == 0xFFFFFF3F &&
                        four->ip2[1]  == 0xFFFFFFFF &&
                        four->ip2[2]  == 0xFFFFFFFF &&
                        four->ip2[3]  == 0xFFFFFFFF &&

                        five->ip[0]  == 0x00000040 && 
                        five->ip[1]  == 0x00000000 && 
                        five->ip[2]  == 0x00000000 && 
                        five->ip[3]  == 0x00000000 && 
                        five->ip2[0]  == 0xFFFFFFFF &&
                        five->ip2[1]  == 0xFFFFFFFF &&
                        five->ip2[2]  == 0xFFFFFFFF &&
                        five->ip2[3]  == 0xFFFFFFFF) {
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
        int r = DetectAddressGroupParse(gh, "::/0");
        if (r == 0) {
            r = DetectAddressGroupParse(gh, "2001::4-2001::6");
            if (r == 0) {
                r = DetectAddressGroupParse(gh, "2001::/3");
                if (r == 0) {
                    DetectAddressGroup *one = gh->ipv6_head, *two = one->next,
                                       *three = two->next, *four = three->next,
                                       *five = four->next;
                    if (one->ip[0]   == 0x00000000 &&
                        one->ip[1]   == 0x00000000 &&
                        one->ip[2]   == 0x00000000 &&
                        one->ip[3]   == 0x00000000 &&
                        one->ip2[0]   == 0xFFFFFF1F &&
                        one->ip2[1]   == 0xFFFFFFFF &&
                        one->ip2[2]   == 0xFFFFFFFF &&
                        one->ip2[3]   == 0xFFFFFFFF &&

                        two->ip[0]   == 0x00000020 &&
                        two->ip[1]   == 0x00000000 &&
                        two->ip[2]   == 0x00000000 &&
                        two->ip[3]   == 0x00000000 &&
                        two->ip2[0]   == 0x00000120 &&
                        two->ip2[1]   == 0x00000000 &&
                        two->ip2[2]   == 0x00000000 &&
                        two->ip2[3]   == 0x03000000 &&

                        three->ip[0] == 0x00000120 &&
                        three->ip[1] == 0x00000000 &&
                        three->ip[2] == 0x00000000 &&
                        three->ip[3] == 0x04000000 &&
                        three->ip2[0] == 0x00000120 &&
                        three->ip2[1] == 0x00000000 &&
                        three->ip2[2] == 0x00000000 &&
                        three->ip2[3] == 0x06000000 &&

                        four->ip[0]  == 0x00000120 &&
                        four->ip[1]  == 0x00000000 &&
                        four->ip[2]  == 0x00000000 &&
                        four->ip[3]  == 0x07000000 &&
                        four->ip2[0]  == 0xFFFFFF3F &&
                        four->ip2[1]  == 0xFFFFFFFF &&
                        four->ip2[2]  == 0xFFFFFFFF &&
                        four->ip2[3]  == 0xFFFFFFFF &&

                        five->ip[0]  == 0x00000040 && 
                        five->ip[1]  == 0x00000000 && 
                        five->ip[2]  == 0x00000000 && 
                        five->ip[3]  == 0x00000000 && 
                        five->ip2[0]  == 0xFFFFFFFF &&
                        five->ip2[1]  == 0xFFFFFFFF &&
                        five->ip2[2]  == 0xFFFFFFFF &&
                        five->ip2[3]  == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup27 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupParse(gh, "[1.2.3.4]");
        if (r == 0) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup28 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupParse(gh, "[1.2.3.4,4.3.2.1]");
        if (r == 0) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup29 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupParse(gh, "[1.2.3.4,4.3.2.1,10.10.10.10]");
        if (r == 0) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup30 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupParse(gh, "[[1.2.3.4,2.3.4.5],4.3.2.1,[10.10.10.10,11.11.11.11]]");
        if (r == 0) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup31 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupParse(gh, "[[1.2.3.4,[2.3.4.5,3.4.5.6]],4.3.2.1,[10.10.10.10,[11.11.11.11,12.12.12.12]]]");
        if (r == 0) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup32 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupParse(gh, "[[1.2.3.4,[2.3.4.5,[3.4.5.6,4.5.6.7]]],4.3.2.1,[10.10.10.10,[11.11.11.11,[12.12.12.12,13.13.13.13]]]]");
        if (r == 0) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup33 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupParse(gh, "![1.1.1.1,[2.2.2.2,[3.3.3.3,4.4.4.4]]]");
        if (r == 0) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup34 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupParse(gh, "[1.0.0.0/8,![1.1.1.1,[1.2.1.1,1.3.1.1]]]");
        if (r == 0) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup35 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupParse(gh, "[1.0.0.0/8,[2.0.0.0/8,![1.1.1.1,2.2.2.2]]]");
        if (r == 0) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup36 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupParse(gh, "[1.0.0.0/8,[2.0.0.0/8,[3.0.0.0/8,!1.1.1.1]]]");
        if (r == 0) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup37 (void) {
    int result = 0;

    DetectAddressGroupsHead *gh = DetectAddressGroupsHeadInit();
    if (gh != NULL) {
        int r = DetectAddressGroupParse(gh, "[0.0.0.0/0,::/0]");
        if (r == 0) {
            result = 1;
        }

        DetectAddressGroupsHeadFree(gh);
    }
    return result;
}

int AddressTestCutIPv401(void) {
    DetectAddressGroup *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0/255.255.255.0");
    b = DetectAddressParseSingle("1.2.2.0-1.2.3.4");

    if (DetectAddressGroupCut(NULL,a,b,&c) == -1) {
        goto error;
    }

    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 1;
error:
    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 0;
}

int AddressTestCutIPv402(void) {
    DetectAddressGroup *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0/255.255.255.0");
    b = DetectAddressParseSingle("1.2.2.0-1.2.3.4");

    if (DetectAddressGroupCut(NULL,a,b,&c) == -1) {
        goto error;
    }

    if (c == NULL) {
        goto error;
    }

    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 1;
error:
    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 0;
}

int AddressTestCutIPv403(void) {
    DetectAddressGroup *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0/255.255.255.0");
    b = DetectAddressParseSingle("1.2.2.0-1.2.3.4");

    if (DetectAddressGroupCut(NULL,a,b,&c) == -1) {
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

    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 1;
error:
    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 0;
}

int AddressTestCutIPv404(void) {
    DetectAddressGroup *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.3-1.2.3.6");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.5");

    if (DetectAddressGroupCut(NULL,a,b,&c) == -1) {
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

    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 1;
error:
    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 0;
}

int AddressTestCutIPv405(void) {
    DetectAddressGroup *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.3-1.2.3.6");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.9");

    if (DetectAddressGroupCut(NULL,a,b,&c) == -1) {
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

    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 1;
error:
    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 0;
}

int AddressTestCutIPv406(void) {
    DetectAddressGroup *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0-1.2.3.9");
    b = DetectAddressParseSingle("1.2.3.3-1.2.3.6");

    if (DetectAddressGroupCut(NULL,a,b,&c) == -1) {
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

    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 1;
error:
    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 0;
}

int AddressTestCutIPv407(void) {
    DetectAddressGroup *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0-1.2.3.6");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.9");

    if (DetectAddressGroupCut(NULL,a,b,&c) == -1) {
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

    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 1;
error:
    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 0;
}

int AddressTestCutIPv408(void) {
    DetectAddressGroup *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.3-1.2.3.9");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.9");

    if (DetectAddressGroupCut(NULL,a,b,&c) == -1) {
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

    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 1;
error:
    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 0;
}

int AddressTestCutIPv409(void) {
    DetectAddressGroup *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0-1.2.3.9");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.6");

    if (DetectAddressGroupCut(NULL,a,b,&c) == -1) {
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

    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 1;
error:
    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 0;
}

int AddressTestCutIPv410(void) {
    DetectAddressGroup *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0-1.2.3.9");
    b = DetectAddressParseSingle("1.2.3.3-1.2.3.9");

    if (DetectAddressGroupCut(NULL,a,b,&c) == -1) {
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

    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 1;
error:
    DetectAddressGroupFree(a);
    DetectAddressGroupFree(b);
    DetectAddressGroupFree(c);
    return 0;
}
#endif /* UNITTESTS */

void DetectAddressTests(void) {
#ifdef UNITTESTS
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

    UtRegisterTest("AddressTestAddressGroupSetup27", AddressTestAddressGroupSetup27, 1);
    UtRegisterTest("AddressTestAddressGroupSetup28", AddressTestAddressGroupSetup28, 1);
    UtRegisterTest("AddressTestAddressGroupSetup29", AddressTestAddressGroupSetup29, 1);
    UtRegisterTest("AddressTestAddressGroupSetup30", AddressTestAddressGroupSetup30, 1);
    UtRegisterTest("AddressTestAddressGroupSetup31", AddressTestAddressGroupSetup31, 1);
    UtRegisterTest("AddressTestAddressGroupSetup32", AddressTestAddressGroupSetup32, 1);
    UtRegisterTest("AddressTestAddressGroupSetup33", AddressTestAddressGroupSetup33, 1);
    UtRegisterTest("AddressTestAddressGroupSetup34", AddressTestAddressGroupSetup34, 1);
    UtRegisterTest("AddressTestAddressGroupSetup35", AddressTestAddressGroupSetup35, 1);
    UtRegisterTest("AddressTestAddressGroupSetup36", AddressTestAddressGroupSetup36, 1);
    UtRegisterTest("AddressTestAddressGroupSetup37", AddressTestAddressGroupSetup37, 1);

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
#endif /* UNITTESTS */
}


