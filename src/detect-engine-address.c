/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Address part of the detection engine.
 *
 * \todo Move this out of the detection plugin structure
 *       rename to detect-engine-address.c
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-cidr.h"
#include "util-unittest.h"
#include "util-rule-vars.h"
#include "conf.h"
#include "conf-yaml-loader.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-address-ipv4.h"
#include "detect-engine-address-ipv6.h"
#include "detect-engine-port.h"

#include "util-debug.h"
#include "util-print.h"

/* prototypes */
void DetectAddressPrint(DetectAddress *);
static int DetectAddressCutNot(DetectAddress *, DetectAddress **);
static int DetectAddressCut(DetectEngineCtx *, DetectAddress *, DetectAddress *,
                            DetectAddress **);
int DetectAddressMergeNot(DetectAddressHead *gh, DetectAddressHead *ghn);

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

/**
 * \brief Creates and returns a new instance of a DetectAddress.
 *
 * \retval ag Pointer to the newly created DetectAddress on success;
 *            NULL on failure.
 */
DetectAddress *DetectAddressInit(void)
{
    DetectAddress *ag = SCMalloc(sizeof(DetectAddress));
    if (unlikely(ag == NULL))
        return NULL;
    memset(ag, 0, sizeof(DetectAddress));

#ifdef DEBUG
    detect_address_group_memory += sizeof(DetectAddress);
    detect_address_group_init_cnt++;
#endif

    return ag;
}

/**
 * \brief Frees a DetectAddress instance.
 *
 * \param ag Pointer to the DetectAddress instance to be freed.
 */
void DetectAddressFree(DetectAddress *ag)
{
    if (ag == NULL)
        return;

    SCLogDebug("ag %p, sh %p", ag, ag->sh);

    /* only free the head if we have the original */
    if (ag->sh != NULL && !(ag->flags & ADDRESS_SIGGROUPHEAD_COPY)) {
        SCLogDebug("- ag %p, sh %p not a copy, so call SigGroupHeadFree", ag,
                   ag->sh);
        SigGroupHeadFree(ag->sh);
    }
    ag->sh = NULL;

    if (!(ag->flags & ADDRESS_HAVEPORT)) {
        SCLogDebug("- ag %p dst_gh %p", ag, ag->dst_gh);

        if (ag->dst_gh != NULL)
            DetectAddressHeadFree(ag->dst_gh);
        ag->dst_gh = NULL;
    } else {
        SCLogDebug("- ag %p port %p", ag, ag->port);

        if (ag->port != NULL && !(ag->flags & ADDRESS_PORTS_COPY)) {
            SCLogDebug("- ag %p port %p, not a copy so call DetectPortCleanupList",
                       ag, ag->port);
            DetectPortCleanupList(ag->port);
        }
        ag->port = NULL;
    }
#ifdef DEBUG
    detect_address_group_memory -= sizeof(DetectAddress);
    detect_address_group_free_cnt++;
#endif
    SCFree(ag);

    return;
}

/**
 * \brief Copies the contents of one Address group in DetectAddress and returns
 *        a new instance of the DetectAddress that contains the copied address.
 *
 * \param orig Pointer to the instance of DetectAddress that contains the
 *             address data to be copied to the new instance.
 *
 * \retval ag Pointer to the new instance of DetectAddress that contains the
 *            copied address.
 */
DetectAddress *DetectAddressCopy(DetectAddress *orig)
{
    DetectAddress *ag = DetectAddressInit();
    if (ag == NULL)
        return NULL;

    ag->flags = orig->flags;

    COPY_ADDRESS(&orig->ip, &ag->ip);
    COPY_ADDRESS(&orig->ip2, &ag->ip2);

    ag->cnt = 1;

    return ag;
}

/**
 * \brief Prints the memory statistics for the detection-engine-address section.
 */
void DetectAddressPrintMemory(void)
{
#ifdef DEBUG
    SCLogDebug(" * Address group memory stats (DetectAddress %" PRIuMAX "):",
               (uintmax_t)sizeof(DetectAddress));
    SCLogDebug("  - detect_address_group_memory %" PRIu32,
               detect_address_group_memory);
    SCLogDebug("  - detect_address_group_init_cnt %" PRIu32,
               detect_address_group_init_cnt);
    SCLogDebug("  - detect_address_group_free_cnt %" PRIu32,
               detect_address_group_free_cnt);
    SCLogDebug("  - outstanding groups %" PRIu32,
               detect_address_group_init_cnt - detect_address_group_free_cnt);
    SCLogDebug(" * Address group memory stats done");
    SCLogDebug(" * Address group head memory stats (DetectAddressHead %" PRIuMAX "):",
               (uintmax_t)sizeof(DetectAddressHead));
    SCLogDebug("  - detect_address_group_head_memory %" PRIu32,
               detect_address_group_head_memory);
    SCLogDebug("  - detect_address_group_head_init_cnt %" PRIu32,
               detect_address_group_head_init_cnt);
    SCLogDebug("  - detect_address_group_head_free_cnt %" PRIu32,
               detect_address_group_head_free_cnt);
    SCLogDebug("  - outstanding groups %" PRIu32,
               (detect_address_group_head_init_cnt -
                detect_address_group_head_free_cnt));
    SCLogDebug(" * Address group head memory stats done");
    SCLogDebug(" X Total %" PRIu32 "\n", (detect_address_group_memory +
                                         detect_address_group_head_memory));
#endif

    return;
}

/**
 * \brief Used to check if a DetectAddress list contains an instance with
 *        a similar DetectAddress.  The comparison done is not the one that
 *        checks the memory for the same instance, but one that checks that the
 *        two instances hold the same content.
 *
 * \param head Pointer to the DetectAddress list.
 * \param ad   Pointer to the DetectAddress that has to be checked for in
 *             the DetectAddress list.
 *
 * \retval cur Returns a pointer to the DetectAddress on a match; NULL if
 *             no match.
 */
DetectAddress *DetectAddressLookupInList(DetectAddress *head, DetectAddress *gr)
{
    DetectAddress *cur;

    if (head != NULL) {
        for (cur = head; cur != NULL; cur = cur->next) {
             if (DetectAddressCmp(cur, gr) == ADDRESS_EQ)
                 return cur;
        }
    }

    return NULL;
}

/**
 * \brief Prints the address data information for all the DetectAddress
 *        instances in the DetectAddress list sent as the argument.
 *
 * \param head Pointer to a list of DetectAddress instances.
 */
void DetectAddressPrintList(DetectAddress *head)
{
    DetectAddress *cur;

    SCLogInfo("list:");
    if (head != NULL) {
        for (cur = head; cur != NULL; cur = cur->next) {
             SCLogInfo("SIGS %6u ", cur->sh ? cur->sh->sig_cnt : 0);
             DetectAddressPrint(cur);
        }
    }
    SCLogInfo("endlist");

    return;
}

/**
 * \brief Frees a list of DetectAddress instances.
 *
 * \param head Pointer to a list of DetectAddress instances to be freed.
 */
void DetectAddressCleanupList(DetectAddress *head)
{
    DetectAddress *cur, *next;

    if (head == NULL)
        return;

    for (cur = head; cur != NULL; ) {
        next = cur->next;
        cur->next = NULL;
        DetectAddressFree(cur);
        cur = next;
    }

    return;
}

/**
 * \brief Do a sorted insert, where the top of the list should be the biggest
 *        network/range.
 *
 *        XXX current sorting only works for overlapping nets
 *
 * \param head Pointer to the list of DetectAddress.
 * \param ag   Pointer to the DetectAddress that has to be added to the
 *             above list.
 *
 * \retval  0 On successfully inserting the DetectAddress.
 * \retval -1 On failure.
 */

int DetectAddressAdd(DetectAddress **head, DetectAddress *ag)
{
    DetectAddress *cur, *prev_cur = NULL;
    int r = 0;

    if (*head != NULL) {
        for (cur = *head; cur != NULL; cur = cur->next) {
            prev_cur = cur;
            r = DetectAddressCmp(ag, cur);
            if (r == ADDRESS_EB) {
                /* insert here */
                ag->prev = cur->prev;
                ag->next = cur;

                cur->prev = ag;
                if (*head == cur)
                    *head = ag;
                else
                    ag->prev->next = ag;

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

/**
 * \internal
 * \brief Helper function for DetectAddressInsert.  Sets one of the
 *        DetectAddressHead head pointers, to the DetectAddress argument
 *        based on its address family.
 *
 * \param gh      Pointer to the DetectAddressHead.
 * \param newhead Pointer to the DetectAddress.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int SetHeadPtr(DetectAddressHead *gh, DetectAddress *newhead)
{
    if (newhead->flags & ADDRESS_FLAG_ANY) {
        gh->any_head = newhead;
    } else if (newhead->ip.family == AF_INET) {
        gh->ipv4_head = newhead;
    } else if (newhead->ip.family == AF_INET6) {
        gh->ipv6_head = newhead;
    } else {
        SCLogDebug("newhead->family %u not supported", newhead->ip.family);
        return -1;
    }

    return 0;
}

/**
 * \internal
 * \brief Returns the DetectAddress head from the DetectAddressHeads,
 *        based on the address family of the incoming DetectAddress arg.
 *
 * \param gh  Pointer to the DetectAddressHead.
 * \param new Pointer to the DetectAddress.
 *
 * \retval head Pointer to the DetectAddress(the head from
 *              DetectAddressHead).
 */
static DetectAddress *GetHeadPtr(DetectAddressHead *gh, DetectAddress *new)
{
    DetectAddress *head = NULL;

    if (new->flags & ADDRESS_FLAG_ANY)
        head = gh->any_head;
    else if (new->ip.family == AF_INET)
        head = gh->ipv4_head;
    else if (new->ip.family == AF_INET6)
        head = gh->ipv6_head;

    return head;
}

/**
 * \brief Same as DetectAddressInsert, but then for inserting a address group
 *        object. This also makes sure SigGroupContainer lists are handled
 *        correctly.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param gh     Pointer to the DetectAddressHead list to which it has to
 *               be inserted.
 * \param new    Pointer to the DetectAddress, that has to be inserted.
 *
 * \retval  1 On successfully inserting it.
 * \retval -1 On error.
 * \retval  0 Not inserted, memory of new is freed.
 */
int DetectAddressInsert(DetectEngineCtx *de_ctx, DetectAddressHead *gh,
                        DetectAddress *new)
{
    DetectAddress *head = NULL;
    DetectAddress *cur = NULL;
    DetectAddress *c = NULL;
    int r = 0;

    if (new == NULL)
        return 0;

    BUG_ON(new->ip.family == 0 && !(new->flags & ADDRESS_FLAG_ANY));

    /* get our head ptr based on the address we want to insert */
    head = GetHeadPtr(gh, new);

    /* see if it already exists or overlaps with existing ag's */
    if (head != NULL) {
        cur = NULL;

        for (cur = head; cur != NULL; cur = cur->next) {
            r = DetectAddressCmp(new, cur);
            BUG_ON(r == ADDRESS_ER);

            /* if so, handle that */
            if (r == ADDRESS_EQ) {
                /* exact overlap/match */
                if (cur != new) {
                    DetectPort *port = new->port;
                    for ( ; port != NULL; port = port->next)
                        DetectPortInsertCopy(de_ctx, &cur->port, port);
                    SigGroupHeadCopySigs(de_ctx, new->sh, &cur->sh);
                    cur->cnt += new->cnt;
                    DetectAddressFree(new);

                    return 0;
                }

                return 1;
            } else if (r == ADDRESS_GT) {
                /* only add it now if we are bigger than the last group.
                 * Otherwise we'll handle it later. */
                if (cur->next == NULL) {
                    /* put in the list */
                    new->prev = cur;
                    cur->next = new;

                    return 1;
                }
            } else if (r == ADDRESS_LT) {
                /* see if we need to insert the ag anywhere put in the list */
                if (cur->prev != NULL)
                    cur->prev->next = new;
                new->prev = cur->prev;
                new->next = cur;
                cur->prev = new;

                /* update head if required */
                if (head == cur) {
                    head = new;

                    if (SetHeadPtr(gh, head) < 0)
                        goto error;
                }

                return 1;
            /* alright, those were the simple cases, lets handle the more
             * complex ones now */
            } else if (r == ADDRESS_ES) {
                c = NULL;
                r = DetectAddressCut(de_ctx, cur, new, &c);
                if (r == -1)
                    goto error;

                DetectAddressInsert(de_ctx, gh, new);
                if (c != NULL)
                    DetectAddressInsert(de_ctx, gh, c);

                return 1;
            } else if (r == ADDRESS_EB) {
                c = NULL;
                r = DetectAddressCut(de_ctx, cur, new, &c);
                if (r == -1)
                    goto error;

                DetectAddressInsert(de_ctx, gh, new);
                if (c != NULL)
                    DetectAddressInsert(de_ctx, gh, c);

                return 1;
            } else if (r == ADDRESS_LE) {
                c = NULL;
                r = DetectAddressCut(de_ctx, cur, new, &c);
                if (r == -1)
                    goto error;

                DetectAddressInsert(de_ctx, gh, new);
                if (c != NULL)
                    DetectAddressInsert(de_ctx, gh, c);

                return 1;
            } else if (r == ADDRESS_GE) {
                c = NULL;
                r = DetectAddressCut(de_ctx, cur,new,&c);
                if (r == -1)
                    goto error;

                DetectAddressInsert(de_ctx, gh, new);
                if (c != NULL)
                    DetectAddressInsert(de_ctx, gh, c);

                return 1;
            }
        }

    /* head is NULL, so get a group and set head to it */
    } else {
        head = new;
        if (SetHeadPtr(gh, head) < 0) {
            SCLogDebug("SetHeadPtr failed");
            goto error;
        }
    }

    return 1;

error:
    /* XXX */
    return -1;
}

/**
 * \brief Join two addresses groups together.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param target Pointer to the target address group.
 * \param source Pointer to the source address group.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int DetectAddressJoin(DetectEngineCtx *de_ctx, DetectAddress *target,
                      DetectAddress *source)
{
    DetectPort *port = NULL;

    if (target == NULL || source == NULL)
        return -1;

    if (target->ip.family != source->ip.family)
        return -1;

    target->cnt += source->cnt;
    SigGroupHeadCopySigs(de_ctx, source->sh, &target->sh);

    port = source->port;
    for ( ; port != NULL; port = port->next)
        DetectPortInsertCopy(de_ctx, &target->port, port);

    if (target->ip.family == AF_INET)
        return DetectAddressJoinIPv4(de_ctx, target, source);
    else if (target->ip.family == AF_INET6)
        return DetectAddressJoinIPv6(de_ctx, target, source);

    return -1;
}

/**
 * \internal
 * \brief Creates a cidr ipv6 netblock, based on the cidr netblock value.
 *
 *        For example if we send a cidr of 7 as argument, an ipv6 address
 *        mask of the value FE:00:00:00:00:00:00:00 is created and updated
 *        in the argument struct in6_addr *in6.
 *
 * \todo I think for the final section: while (cidr > 0), we can simply
 *       replace it with a
 *       if (cidr > 0) {
 *           in6->s6_addr[i] = -1 << (8 - cidr);
 *
 * \param cidr The value of the cidr.
 * \param in6  Pointer to an ipv6 address structure(struct in6_addr) which will
 *             hold the cidr netblock result.
 */
static void DetectAddressParseIPv6CIDR(int cidr, struct in6_addr *in6)
{
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

    return;
}

/**
 * \internal
 * \brief Parses an ipv4/ipv6 address string and updates the result into the
 *        DetectAddress instance sent as the argument.
 *
 * \param dd  Pointer to the DetectAddress instance which should be updated with
 *            the address range details from the parsed ip string.
 * \param str Pointer to address string that has to be parsed.
 *
 * \retval  0 On successfully parsing the address string.
 * \retval -1 On failure.
 */
int DetectAddressParseString(DetectAddress *dd, char *str)
{
    char *ip = NULL;
    char *ip2 = NULL;
    char *mask = NULL;
    int r = 0;
    char ipstr[256];

    while (*str != '\0' && *str == ' ')
        str++;

    /* first handle 'any' */
    if (strcasecmp(str, "any") == 0) {
        dd->flags |= ADDRESS_FLAG_ANY;
        SCLogDebug("address is \'any\'");
        return 0;
    }

    strlcpy(ipstr, str, sizeof(ipstr));
    SCLogDebug("str %s", str);

    /* we work with a copy so that we can put a
     * nul-termination in it later */
    ip = ipstr;

    /* handle the negation case */
    if (ip[0] == '!') {
        dd->flags |= ADDRESS_FLAG_NOT;
        ip++;
    }

    /* see if the address is an ipv4 or ipv6 address */
    if ((strchr(str, ':')) == NULL) {
        /* IPv4 Address */
        struct in_addr in;

        dd->ip.family = AF_INET;

        if ((mask = strchr(ip, '/')) != NULL)  {
            /* 1.2.3.4/xxx format (either dotted or cidr notation */
            ip[mask - ip] = '\0';
            mask++;
            uint32_t ip4addr = 0;
            uint32_t netmask = 0;
            size_t u = 0;

            if ((strchr (mask, '.')) == NULL) {
                /* 1.2.3.4/24 format */

                for (u = 0; u < strlen(mask); u++) {
                    if(!isdigit((unsigned char)mask[u]))
                        goto error;
                }

                int cidr = atoi(mask);
                if (cidr < 0 || cidr > 32)
                    goto error;

                netmask = CIDRGet(cidr);
            } else {
                /* 1.2.3.4/255.255.255.0 format */
                r = inet_pton(AF_INET, mask, &in);
                if (r <= 0)
                    goto error;

                netmask = in.s_addr;
            }

            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0)
                goto error;

            ip4addr = in.s_addr;

            dd->ip.addr_data32[0] = dd->ip2.addr_data32[0] = ip4addr & netmask;
            dd->ip2.addr_data32[0] |=~ netmask;
        } else if ((ip2 = strchr(ip, '-')) != NULL)  {
            /* 1.2.3.4-1.2.3.6 range format */
            ip[ip2 - ip] = '\0';
            ip2++;

            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0)
                goto error;
            dd->ip.addr_data32[0] = in.s_addr;

            r = inet_pton(AF_INET, ip2, &in);
            if (r <= 0)
                goto error;
            dd->ip2.addr_data32[0] = in.s_addr;

            /* a > b is illegal, a = b is ok */
            if (ntohl(dd->ip.addr_data32[0]) > ntohl(dd->ip2.addr_data32[0]))
                goto error;
        } else {
            /* 1.2.3.4 format */
            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0)
                goto error;
            /* single host */
            dd->ip.addr_data32[0] = in.s_addr;
            dd->ip2.addr_data32[0] = in.s_addr;
        }
    } else {
        /* IPv6 Address */
        struct in6_addr in6, mask6;
        uint32_t ip6addr[4], netmask[4];

        dd->ip.family = AF_INET6;

        if ((mask = strchr(ip, '/')) != NULL)  {
            ip[mask - ip] = '\0';
            mask++;

            int cidr = atoi(mask);
            if (cidr < 0 || cidr > 128)
                    goto error;

            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0)
                goto error;
            memcpy(&ip6addr, &in6.s6_addr, sizeof(ip6addr));

            DetectAddressParseIPv6CIDR(cidr, &mask6);
            memcpy(&netmask, &mask6.s6_addr, sizeof(netmask));

            dd->ip2.addr_data32[0] = dd->ip.addr_data32[0] = ip6addr[0] & netmask[0];
            dd->ip2.addr_data32[1] = dd->ip.addr_data32[1] = ip6addr[1] & netmask[1];
            dd->ip2.addr_data32[2] = dd->ip.addr_data32[2] = ip6addr[2] & netmask[2];
            dd->ip2.addr_data32[3] = dd->ip.addr_data32[3] = ip6addr[3] & netmask[3];

            dd->ip2.addr_data32[0] |=~ netmask[0];
            dd->ip2.addr_data32[1] |=~ netmask[1];
            dd->ip2.addr_data32[2] |=~ netmask[2];
            dd->ip2.addr_data32[3] |=~ netmask[3];
        } else if ((ip2 = strchr(ip, '-')) != NULL)  {
            /* 2001::1-2001::4 range format */
            ip[ip2 - ip] = '\0';
            ip2++;

            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0)
                goto error;
            memcpy(&dd->ip.address, &in6.s6_addr, sizeof(ip6addr));

            r = inet_pton(AF_INET6, ip2, &in6);
            if (r <= 0)
                goto error;
            memcpy(&dd->ip2.address, &in6.s6_addr, sizeof(ip6addr));

            /* a > b is illegal, a=b is ok */
            if (AddressIPv6Gt(&dd->ip, &dd->ip2))
                goto error;
        } else {
            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0)
                goto error;

            memcpy(&dd->ip.address, &in6.s6_addr, sizeof(dd->ip.address));
            memcpy(&dd->ip2.address, &in6.s6_addr, sizeof(dd->ip2.address));
        }

    }

    BUG_ON(dd->ip.family == 0);

    return 0;

error:
    return -1;
}

/**
 * \internal
 * \brief Simply parse an address and return a DetectAddress instance containing
 *        the address ranges of the parsed ip addressstring
 *
 * \param str Pointer to a character string containing the ip address
 *
 * \retval dd Pointer to the DetectAddress instance containing the address
 *            range details from the parsed ip string
 */
static DetectAddress *DetectAddressParseSingle(char *str)
{
    DetectAddress *dd;

    SCLogDebug("str %s", str);

    dd = DetectAddressInit();
    if (dd == NULL)
        goto error;

    if (DetectAddressParseString(dd, str) < 0) {
        SCLogDebug("AddressParse failed");
        goto error;
    }

    return dd;

error:
    if (dd != NULL)
        DetectAddressFree(dd);
    return NULL;
}

/**
 * \brief Setup a single address string, parse it and add the resulting
 *        Address-Range(s) to the AddessHead(DetectAddressHead instance).
 *
 * \param gh Pointer to the Address-Head(DetectAddressHead) to which the
 *           resulting Address-Range(s) from the parsed ip string has to
 *           be added.
 * \param s  Pointer to the ip address string to be parsed.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int DetectAddressSetup(DetectAddressHead *gh, char *s)
{
    DetectAddress *ad = NULL;
    DetectAddress *ad2 = NULL;
    int r = 0;
    char any = FALSE;

    SCLogDebug("gh %p, s %s", gh, s);

    /* parse the address */
    ad = DetectAddressParseSingle(s);
    if (ad == NULL) {
        SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC,
                "failed to parse address \"%s\"", s);
        return -1;
    }

    if (ad->flags & ADDRESS_FLAG_ANY)
        any = TRUE;

    /* handle the not case, we apply the negation then insert the part(s) */
    if (ad->flags & ADDRESS_FLAG_NOT) {
        ad2 = NULL;

        if (DetectAddressCutNot(ad, &ad2) < 0) {
            SCLogDebug("DetectAddressCutNot failed");
            goto error;
        }

        /* normally a 'not' will result in two ad's unless the 'not' is on the start or end
         * of the address space (e.g. 0.0.0.0 or 255.255.255.255). */
        if (ad2 != NULL) {
            if (DetectAddressInsert(NULL, gh, ad2) < 0) {
                SCLogDebug("DetectAddressInsert failed");
                goto error;
            }
        }
    }

    r = DetectAddressInsert(NULL, gh, ad);
    if (r < 0) {
        SCLogDebug("DetectAddressInsert failed");
        goto error;
    }
    SCLogDebug("r %d",r);

    /* if any, insert 0.0.0.0/0 and ::/0 as well */
    if (r == 1 && any == TRUE) {
        SCLogDebug("adding 0.0.0.0/0 and ::/0 as we\'re handling \'any\'");

        ad = DetectAddressParseSingle("0.0.0.0/0");
        if (ad == NULL)
            goto error;

        BUG_ON(ad->ip.family == 0);

        if (DetectAddressInsert(NULL, gh, ad) < 0) {
            SCLogDebug("DetectAddressInsert failed");
            goto error;
        }
        ad = DetectAddressParseSingle("::/0");
        if (ad == NULL)
            goto error;

        BUG_ON(ad->ip.family == 0);

        if (DetectAddressInsert(NULL, gh, ad) < 0) {
            SCLogDebug("DetectAddressInsert failed");
            goto error;
        }
    }
    return 0;

error:
    SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC, "DetectAddressSetup error");
    /* XXX cleanup */
    return -1;
}

/**
 * \brief Parses an address string and updates the 2 address heads with the
 *        address data.
 *
 * \todo We don't seem to be handling negated cases, like [addr,![!addr,addr]],
 *       since we pass around negate without keeping a count of ! with depth.
 *       Can solve this by keeping a count of the negations with depth, so that
 *       an even no of negations would count as no negation and an odd no of
 *       negations would count as a negation.
 *
 * \param gh     Pointer to the address head that should hold address ranges
 *               that are not negated.
 * \param ghn    Pointer to the address head that should hold address ranges
 *               that are negated.
 * \param s      Pointer to the character string holding the address to be
 *               parsed.
 * \param negate Flag that indicates if the receieved address string is negated
 *               or not.  0 if it is not, 1 it it is.
 *
 * \retval  0 On successfully parsing.
 * \retval -1 On failure.
 */
static int DetectAddressParse2(const DetectEngineCtx *de_ctx,
        DetectAddressHead *gh, DetectAddressHead *ghn,
        char *s, int negate)
{
    size_t x = 0;
    size_t u = 0;
    int o_set = 0, n_set = 0, d_set = 0;
    int depth = 0;
    size_t size = strlen(s);
    char address[8196] = "";
    char *rule_var_address = NULL;
    char *temp_rule_var_address = NULL;

    SCLogDebug("s %s negate %s", s, negate ? "true" : "false");

    for (u = 0, x = 0; u < size && x < sizeof(address); u++) {
        if (x == (sizeof(address) - 1)) {
            SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC, "Hit the address buffer"
                       " limit for the supplied address.  Invalidating sig.  "
                       "Please file a bug report on this.");
            goto error;
        }
        address[x] = s[u];
        x++;

        if (!o_set && s[u] == '!') {
            n_set = 1;
            x--;
        } else if (s[u] == '[') {
            if (!o_set) {
                o_set = 1;
                x = 0;
            }
            depth++;
        } else if (s[u] == ']') {
            if (depth == 1) {
                address[x - 1] = '\0';
                x = 0;
                SCLogDebug("address %s negate %d, n_set %d", address, negate, n_set);
                if (((negate + n_set) % 2) == 0) {
                    /* normal block */
                    SCLogDebug("normal block");

                    if (DetectAddressParse2(de_ctx, gh, ghn, address, (negate + n_set) % 2) < 0)
                        goto error;
                } else {
                    /* negated block
                     *
                     * Extra steps are necessary. First consider it as a normal
                     * (non-negated) range. Merge the + and - ranges if
                     * applicable. Then insert the result into the ghn list. */
                    SCLogDebug("negated block");

                    DetectAddressHead tmp_gh = { NULL, NULL, NULL };
                    DetectAddressHead tmp_ghn = { NULL, NULL, NULL };

                    if (DetectAddressParse2(de_ctx, &tmp_gh, &tmp_ghn, address, 0) < 0)
                        goto error;

                    DetectAddress *tmp_ad;
                    DetectAddress *tmp_ad2;
#ifdef DEBUG
                    SCLogDebug("tmp_gh: IPv4");
                    for (tmp_ad = tmp_gh.ipv4_head; tmp_ad; tmp_ad = tmp_ad->next) {
                        DetectAddressPrint(tmp_ad);
                    }
                    SCLogDebug("tmp_ghn: IPv4");
                    for (tmp_ad = tmp_ghn.ipv4_head; tmp_ad; tmp_ad = tmp_ad->next) {
                        DetectAddressPrint(tmp_ad);
                    }
                    SCLogDebug("tmp_gh: IPv6");
                    for (tmp_ad = tmp_gh.ipv6_head; tmp_ad; tmp_ad = tmp_ad->next) {
                        DetectAddressPrint(tmp_ad);
                    }
                    SCLogDebug("tmp_ghn: IPv6");
                    for (tmp_ad = tmp_ghn.ipv6_head; tmp_ad; tmp_ad = tmp_ad->next) {
                        DetectAddressPrint(tmp_ad);
                    }
#endif
                    if (DetectAddressMergeNot(&tmp_gh, &tmp_ghn) < 0)
                        goto error;

                    SCLogDebug("merged succesfully");

                    /* insert the IPv4 addresses into the negated list */
                    for (tmp_ad = tmp_gh.ipv4_head; tmp_ad; tmp_ad = tmp_ad->next) {
                        /* work with a copy of the address group */
                        tmp_ad2 = DetectAddressCopy(tmp_ad);
                        if (tmp_ad2 == NULL) {
                            SCLogDebug("DetectAddressCopy failed");
                            goto error;
                        }
                        DetectAddressPrint(tmp_ad2);
                        DetectAddressInsert(NULL, ghn, tmp_ad2);
                    }

                    /* insert the IPv6 addresses into the negated list */
                    for (tmp_ad = tmp_gh.ipv6_head; tmp_ad; tmp_ad = tmp_ad->next) {
                        /* work with a copy of the address group */
                        tmp_ad2 = DetectAddressCopy(tmp_ad);
                        if (tmp_ad2 == NULL) {
                            SCLogDebug("DetectAddressCopy failed");
                            goto error;
                        }
                        DetectAddressPrint(tmp_ad2);
                        DetectAddressInsert(NULL, ghn, tmp_ad2);
                    }

                    DetectAddressHeadCleanup(&tmp_gh);
                    DetectAddressHeadCleanup(&tmp_ghn);
                }
                n_set = 0;
            }
            depth--;
        } else if (depth == 0 && s[u] == ',') {
            if (o_set == 1) {
                o_set = 0;
            } else if (d_set == 1) {
                address[x - 1] = '\0';

                rule_var_address = SCRuleVarsGetConfVar(de_ctx, address,
                                                        SC_RULE_VARS_ADDRESS_GROUPS);
                if (rule_var_address == NULL)
                    goto error;
                if (strlen(rule_var_address) == 0) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "variable %s resolved "
                            "to nothing. This is likely a misconfiguration. "
                            "Note that a negated address needs to be quoted, "
                            "\"!$HOME_NET\" instead of !$HOME_NET. See issue #295.", s);
                    goto error;
                }
                SCLogDebug("rule_var_address %s", rule_var_address);
                temp_rule_var_address = rule_var_address;
                if ((negate + n_set) % 2) {
                    temp_rule_var_address = SCMalloc(strlen(rule_var_address) + 3);
                    if (unlikely(temp_rule_var_address == NULL))
                        goto error;
                    snprintf(temp_rule_var_address, strlen(rule_var_address) + 3,
                             "[%s]", rule_var_address);
                }
                DetectAddressParse2(de_ctx, gh, ghn, temp_rule_var_address,
                                    (negate + n_set) % 2);
                d_set = 0;
                n_set = 0;
                if (temp_rule_var_address != rule_var_address)
                    SCFree(temp_rule_var_address);
            } else {
                address[x - 1] = '\0';

                if (!((negate + n_set) % 2)) {
                    SCLogDebug("DetectAddressSetup into gh, %s", address);
                    if (DetectAddressSetup(gh, address) < 0)
                        goto error;
                } else {
                    SCLogDebug("DetectAddressSetup into ghn, %s", address);
                    if (DetectAddressSetup(ghn, address) < 0)
                        goto error;
                }
                n_set = 0;
            }
            x = 0;
        } else if (depth == 0 && s[u] == '$') {
            d_set = 1;
        } else if (depth == 0 && u == size - 1) {
            if (x == sizeof(address)) {
                address[x - 1] = '\0';
            } else {
                address[x] = '\0';
            }
            x = 0;

            if (d_set == 1) {
                rule_var_address = SCRuleVarsGetConfVar(de_ctx, address,
                                                        SC_RULE_VARS_ADDRESS_GROUPS);
                if (rule_var_address == NULL)
                    goto error;
                if (strlen(rule_var_address) == 0) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "variable %s resolved "
                            "to nothing. This is likely a misconfiguration. "
                            "Note that a negated address needs to be quoted, "
                            "\"!$HOME_NET\" instead of !$HOME_NET. See issue #295.", s);
                    goto error;
                }
                SCLogDebug("rule_var_address %s", rule_var_address);
                temp_rule_var_address = rule_var_address;
                if ((negate + n_set) % 2) {
                    temp_rule_var_address = SCMalloc(strlen(rule_var_address) + 3);
                    if (unlikely(temp_rule_var_address == NULL))
                        goto error;
                    snprintf(temp_rule_var_address, strlen(rule_var_address) + 3,
                            "[%s]", rule_var_address);
                }
                if (DetectAddressParse2(de_ctx, gh, ghn, temp_rule_var_address,
                                    (negate + n_set) % 2) < 0) {
                    SCLogDebug("DetectAddressParse2 hates us");
                    goto error;
                }
                d_set = 0;
                if (temp_rule_var_address != rule_var_address)
                    SCFree(temp_rule_var_address);
            } else {
                if (!((negate + n_set) % 2)) {
                    SCLogDebug("DetectAddressSetup into gh, %s", address);
                    if (DetectAddressSetup(gh, address) < 0) {
                        SCLogDebug("DetectAddressSetup gh fail");
                        goto error;
                    }
                } else {
                    SCLogDebug("DetectAddressSetup into ghn, %s", address);
                    if (DetectAddressSetup(ghn, address) < 0) {
                        SCLogDebug("DetectAddressSetup ghn fail");
                        goto error;
                    }
                }
            }
            n_set = 0;
        }
    }
    if (depth > 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "not every address block was "
                "properly closed in \"%s\", %d missing closing brackets (]). "
                "Note: problem might be in a variable.", s, depth);
        goto error;
    } else if (depth < 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "not every address block was "
                "properly opened in \"%s\", %d missing opening brackets ([). "
                "Note: problem might be in a variable.", s, depth*-1);
        goto error;
    }

    return 0;

error:
    return -1;
}

/**
 * \internal
 * \brief See if the addresses and ranges in an address head cover the
 *        entire ip space.
 *
 * \param gh Pointer to the DetectAddressHead to check.
 *
 * \retval 0 No.
 * \retval 1 Yes.
 *
 * \todo do the same for IPv6
 */
static int DetectAddressIsCompleteIPSpace(DetectAddressHead *gh)
{
    int r = DetectAddressIsCompleteIPSpaceIPv4(gh->ipv4_head);
    if (r == 1)
        return 1;

    return 0;
}

/**
 * \brief Merge the + and the - list (+ positive match, - 'not' match)
 *
 * \param gh  Pointer to the address head containing the non-NOT groups.
 * \param ghn Pointer to the address head containing the NOT groups.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int DetectAddressMergeNot(DetectAddressHead *gh, DetectAddressHead *ghn)
{
    DetectAddress *ad;
    DetectAddress *ag, *ag2;
    int r = 0;

    SCLogDebug("gh->ipv4_head %p, ghn->ipv4_head %p", gh->ipv4_head,
               ghn->ipv4_head);

    /* check if the negated list covers the entire ip space. If so
     * the user screwed up the rules/vars. */
    if (DetectAddressIsCompleteIPSpace(ghn) == 1) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Complete IP space negated. "
                   "Rule address range is NIL. Probably have a !any or "
                   "an address range that supplies a NULL address range");
        goto error;
    }

    /* step 0: if the gh list is empty, but the ghn list isn't we have a pure
     * not thingy. In that case we add a 0.0.0.0/0 first. */
    if (gh->ipv4_head == NULL && ghn->ipv4_head != NULL) {
        r = DetectAddressSetup(gh, "0.0.0.0/0");
        if (r < 0) {
            SCLogDebug("DetectAddressSetup for 0.0.0.0/0 failed");
            goto error;
        }
    }
    /* ... or ::/0 for ipv6 */
    if (gh->ipv6_head == NULL && ghn->ipv6_head != NULL) {
        r = DetectAddressSetup(gh, "::/0");
        if (r < 0) {
            SCLogDebug("DetectAddressSetup for ::/0 failed");
            goto error;
        }
    }

    /* step 1: insert our ghn members into the gh list */
    for (ag = ghn->ipv4_head; ag != NULL; ag = ag->next) {
        /* work with a copy of the ad so we can easily clean up the ghn group
         * later. */
        ad = DetectAddressCopy(ag);
        if (ad == NULL) {
            SCLogDebug("DetectAddressCopy failed");
            goto error;
        }

        r = DetectAddressInsert(NULL, gh, ad);
        if (r < 0) {
            SCLogDebug("DetectAddressInsert failed");
            goto error;
        }
    }
    /* ... and the same for ipv6 */
    for (ag = ghn->ipv6_head; ag != NULL; ag = ag->next) {
        /* work with a copy of the ad so we can easily clean up the ghn group
         * later. */
        ad = DetectAddressCopy(ag);
        if (ad == NULL) {
            SCLogDebug("DetectAddressCopy failed");
            goto error;
        }

        r = DetectAddressInsert(NULL, gh, ad);
        if (r < 0) {
            SCLogDebug("DetectAddressInsert failed");
            goto error;
        }
    }
#ifdef DEBUG
    DetectAddress *tmp_ad;
    for (tmp_ad = gh->ipv6_head; tmp_ad; tmp_ad = tmp_ad->next) {
        DetectAddressPrint(tmp_ad);
    }
#endif
    int ipv4_applied = 0;
    int ipv6_applied = 0;

    /* step 2: pull the address blocks that match our 'not' blocks */
    for (ag = ghn->ipv4_head; ag != NULL; ag = ag->next) {
        SCLogDebug("ag %p", ag);
        DetectAddressPrint(ag);

        int applied = 0;
        for (ag2 = gh->ipv4_head; ag2 != NULL; ) {
            SCLogDebug("ag2 %p", ag2);
            DetectAddressPrint(ag2);

            r = DetectAddressCmp(ag, ag2);
            /* XXX more ??? */
            if (r == ADDRESS_EQ || r == ADDRESS_EB) {
                if (ag2->prev == NULL)
                    gh->ipv4_head = ag2->next;
                else
                    ag2->prev->next = ag2->next;

                if (ag2->next != NULL)
                    ag2->next->prev = ag2->prev;

                /* store the next ptr and remove the group */
                DetectAddress *next_ag2 = ag2->next;
                DetectAddressFree(ag2);
                ag2 = next_ag2;
                applied = 1;
            } else {
                ag2 = ag2->next;
            }
        }

        if (applied) {
            ipv4_applied++;
        }
    }
    /* ... and the same for ipv6 */
    for (ag = ghn->ipv6_head; ag != NULL; ag = ag->next) {
        int applied = 0;
        for (ag2 = gh->ipv6_head; ag2 != NULL; ) {
            r = DetectAddressCmp(ag, ag2);
            if (r == ADDRESS_EQ || r == ADDRESS_EB) { /* XXX more ??? */
                if (ag2->prev == NULL)
                    gh->ipv6_head = ag2->next;
                else
                    ag2->prev->next = ag2->next;

                if (ag2->next != NULL)
                    ag2->next->prev = ag2->prev;

                /* store the next ptr and remove the group */
                DetectAddress *next_ag2 = ag2->next;
                DetectAddressFree(ag2);
                ag2 = next_ag2;

                SCLogDebug("applied");
                applied = 1;
            } else {
                ag2 = ag2->next;
            }
        }
        if (applied) {
            ipv6_applied++;
        }
    }
#ifdef DEBUG
    for (tmp_ad = gh->ipv6_head; tmp_ad; tmp_ad = tmp_ad->next) {
        DetectAddressPrint(tmp_ad);
    }
    for (tmp_ad = ghn->ipv6_head; tmp_ad; tmp_ad = tmp_ad->next) {
        DetectAddressPrint(tmp_ad);
    }
#endif
    if (ghn->ipv4_head != NULL || ghn->ipv6_head != NULL) {
        int cnt = 0;
        DetectAddress *ad;
        for (ad = ghn->ipv4_head; ad; ad = ad->next)
            cnt++;

        if (ipv4_applied != cnt) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "not all IPv4 negations "
                    "could be applied: %d != %d", cnt, ipv4_applied);
            goto error;
        }

        cnt = 0;
        for (ad = ghn->ipv6_head; ad; ad = ad->next)
            cnt++;

        if (ipv6_applied != cnt) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "not all IPv6 negations "
                    "could be applied: %d != %d", cnt, ipv6_applied);
            goto error;
        }
    }

    /* if the result is that we have no addresses we return error */
    if (gh->ipv4_head == NULL && gh->ipv6_head == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "no addresses left after "
                "merging addresses and negated addresses");
        goto error;
    }

    return 0;

error:
    return -1;
}

int DetectAddressTestConfVars(void)
{
    SCLogDebug("Testing address conf vars for any misconfigured values");

    ConfNode *address_vars_node = ConfGetNode("vars.address-groups");
    if (address_vars_node == NULL) {
        return 0;
    }

    ConfNode *seq_node;
    TAILQ_FOREACH(seq_node, &address_vars_node->head, next) {
        SCLogDebug("Testing %s - %s", seq_node->name, seq_node->val);

        DetectAddressHead *gh = DetectAddressHeadInit();
        if (gh == NULL) {
            goto error;
        }
        DetectAddressHead *ghn = DetectAddressHeadInit();
        if (ghn == NULL) {
            goto error;
        }

        if (seq_node->val == NULL) {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                       "Address var \"%s\" probably has a sequence(something "
                       "in brackets) value set without any quotes. Please "
                       "quote it using \"..\".", seq_node->name);
            goto error;
        }

        int r = DetectAddressParse2(NULL, gh, ghn, seq_node->val, /* start with negate no */0);
        if (r < 0) {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                        "failed to parse address var \"%s\" with value \"%s\". "
                        "Please check it's syntax", seq_node->name, seq_node->val);
            goto error;
        }

        if (DetectAddressIsCompleteIPSpace(ghn)) {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                       "address var - \"%s\" has the complete IP space negated "
                       "with it's value \"%s\".  Rule address range is NIL. "
                       "Probably have a !any or an address range that supplies "
                       "a NULL address range", seq_node->name, seq_node->val);
            goto error;
        }

        if (gh != NULL)
            DetectAddressHeadFree(gh);
        if (ghn != NULL)
            DetectAddressHeadFree(ghn);
    }

    return 0;
 error:
    return -1;
}

/**
 * \brief Parses an address group sent as a character string and updates the
 *        DetectAddressHead sent as the argument with the relevant address
 *        ranges from the parsed string.
 *
 * \param gh  Pointer to the DetectAddressHead.
 * \param str Pointer to the character string containing the address group
 *            that has to be parsed.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int DetectAddressParse(const DetectEngineCtx *de_ctx,
                       DetectAddressHead *gh, char *str)
{
    int r;
    DetectAddressHead *ghn = NULL;

    SCLogDebug("gh %p, str %s", gh, str);

    if (str == NULL) {
        SCLogDebug("DetectAddressParse can not be run with NULL address");
        goto error;
    }

    ghn = DetectAddressHeadInit();
    if (ghn == NULL) {
        SCLogDebug("DetectAddressHeadInit for ghn failed");
        goto error;
    }

    r = DetectAddressParse2(de_ctx, gh, ghn, str, /* start with negate no */0);
    if (r < 0) {
        SCLogDebug("DetectAddressParse2 returned %d", r);
        goto error;
    }

    SCLogDebug("gh->ipv4_head %p, ghn->ipv4_head %p", gh->ipv4_head,
               ghn->ipv4_head);

    /* merge the 'not' address groups */
    if (DetectAddressMergeNot(gh, ghn) < 0) {
        SCLogDebug("DetectAddressMergeNot failed");
        goto error;
    }

    /* free the temp negate head */
    DetectAddressHeadFree(ghn);
    return 0;

error:
    if (ghn != NULL)
        DetectAddressHeadFree(ghn);
    return -1;
}

/**
 * \brief Returns a new instance of DetectAddressHead.
 *
 * \retval gh Pointer to the new instance of DetectAddressHead.
 */
DetectAddressHead *DetectAddressHeadInit(void)
{
    DetectAddressHead *gh = SCMalloc(sizeof(DetectAddressHead));
    if (unlikely(gh == NULL))
        return NULL;
    memset(gh, 0, sizeof(DetectAddressHead));

#ifdef DEBUG
    detect_address_group_head_init_cnt++;
    detect_address_group_head_memory += sizeof(DetectAddressHead);
#endif

    return gh;
}

/**
 * \brief Cleans a DetectAddressHead.  The functions frees the 3 address
 *        group heads(any, ipv4 and ipv6) inside the DetectAddressHead
 *        instance.
 *
 * \param gh Pointer to the DetectAddressHead instance that has to be
 *           cleaned.
 */
void DetectAddressHeadCleanup(DetectAddressHead *gh)
{
    if (gh != NULL) {
        if (gh->any_head != NULL) {
            DetectAddressCleanupList(gh->any_head);
            gh->any_head = NULL;
        }
        if (gh->ipv4_head != NULL) {
            DetectAddressCleanupList(gh->ipv4_head);
            gh->ipv4_head = NULL;
        }
        if (gh->ipv6_head != NULL) {
            DetectAddressCleanupList(gh->ipv6_head);
            gh->ipv6_head = NULL;
        }
    }

    return;
}

/**
 * \brief Frees a DetectAddressHead instance.
 *
 * \param gh Pointer to the DetectAddressHead instance to be freed.
 */
void DetectAddressHeadFree(DetectAddressHead *gh)
{
    if (gh != NULL) {
        DetectAddressHeadCleanup(gh);
        SCFree(gh);
#ifdef DEBUG
        detect_address_group_head_free_cnt++;
        detect_address_group_head_memory -= sizeof(DetectAddressHead);
#endif
    }

    return;
}

/**
 * \brief Dispatcher function that calls the ipv4 and ipv6 address cut functions.
 *        Have a look at DetectAddressCutIPv4() and DetectAddressCutIPv6() for
 *        explanations on what these functions do.
 *
 * \param de_ctx Pointer to the DetectEngineCtx.
 * \param a      Pointer the the first address to be cut.
 * \param b      Pointer to the second address to be cut.
 * \param c      Pointer to a pointer to a third DetectAddressData, in case the
 *               ranges from a and b, demand a third address range.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int DetectAddressCut(DetectEngineCtx *de_ctx, DetectAddress *a,
                     DetectAddress *b, DetectAddress **c)
{
    if (a->ip.family == AF_INET)
        return DetectAddressCutIPv4(de_ctx, a, b, c);
    else if (a->ip.family == AF_INET6)
        return DetectAddressCutIPv6(de_ctx, a, b, c);

    return -1;
}

/**
 * \brief Cuts a negated address range with respect to the entire ip range, and
 *        supplies with the address range that doesn't belong to the negated
 *        address range.
 *
 *        There are 2 cases here -
 *
 *        The first case includes the address being located at the extreme ends
 *        of the ip space, in which we get a single range.
 *        For example: !0.0.0.0, in which case we get 0.0.0.1 to 255.255.255.255.
 *
 *        The second case includes the address not present at either of the
 *        ip space extremes, in which case we get 2 ranges.  The second range
 *        would be supplied back with the argument "b" supplied to this function.
 *        For example: !10.20.30.40, in which case we the 2 ranges, 0.0.0.0 -
 *        10.20.30.39 and 10.20.30.41 - 255.255.255.255.
 *
 *        The above negation cases can similarly be extended to ranges, i.e.
 *        ![0.0.0.0 - 10.20.30.40], ![255.255.240.240 - 255.255.255.255] and
 *        ![10.20.30.40 - 10.20.30.50].
 *
 *
 * \param a Pointer to the DetectAddressData instance, that contains the negated
 *          address range that has to be cut.
 * \param b Pointer to a pointer to a DetectAddressData instance, that should be
 *          filled with the address range, if the argument "a", doesn't fall at
 *          the extreme ends of the ip address space.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int DetectAddressCutNot(DetectAddress *a, DetectAddress **b)
{
    if (a->ip.family == AF_INET)
        return DetectAddressCutNotIPv4(a, b);
    else if (a->ip.family == AF_INET6)
        return DetectAddressCutNotIPv6(a, b);

    return -1;
}

/**
 * \brief Used to compare 2 address ranges.
 *
 * \param a Pointer to the first DetectAddressData to be compared.
 * \param b Pointer to the second DetectAddressData to be compared.
 */
int DetectAddressCmp(DetectAddress *a, DetectAddress *b)
{
    if (a->ip.family != b->ip.family)
        return ADDRESS_ER;

    /* check any */
    if ((a->flags & ADDRESS_FLAG_ANY) && (b->flags & ADDRESS_FLAG_ANY))
        return ADDRESS_EQ;
    else if (a->ip.family == AF_INET)
        return DetectAddressCmpIPv4(a, b);
    else if (a->ip.family == AF_INET6)
        return DetectAddressCmpIPv6(a, b);

    return ADDRESS_ER;
}

/**
 *  \brief Match a packets address against a signatures addrs array
 *
 *  \param addrs array of DetectMatchAddressIPv4's
 *  \param addrs_cnt array size in members
 *  \param a packets address
 *
 *  \retval 0 no match
 *  \retval 1 match
 *
 *  \note addresses in addrs are in host order
 *
 *  \todo array should be ordered, so we can break out of the loop
 */
int DetectAddressMatchIPv4(DetectMatchAddressIPv4 *addrs, uint16_t addrs_cnt, Address *a)
{
    SCEnter();

    if (addrs == NULL || addrs_cnt == 0) {
        SCReturnInt(0);
    }

    uint16_t idx;
    for (idx = 0; idx < addrs_cnt; idx++) {
        if (ntohl(a->addr_data32[0]) >= addrs[idx].ip &&
            ntohl(a->addr_data32[0]) <= addrs[idx].ip2)
        {
            SCReturnInt(1);
        }
    }

    SCReturnInt(0);
}

/**
 *  \brief Match a packets address against a signatures addrs array
 *
 *  \param addrs array of DetectMatchAddressIPv6's
 *  \param addrs_cnt array size in members
 *  \param a packets address
 *
 *  \retval 0 no match
 *  \retval 1 match
 *
 *  \note addresses in addrs are in host order
 *
 *  \todo array should be ordered, so we can break out of the loop
 */
int DetectAddressMatchIPv6(DetectMatchAddressIPv6 *addrs, uint16_t addrs_cnt, Address *a)
{
    SCEnter();

    if (addrs == NULL || addrs_cnt == 0) {
        SCReturnInt(0);
    }

    uint16_t idx;
    int i = 0;
    uint16_t result1, result2;

    /* See if the packet address is within the range of any entry in the
     * signature's address match array.
     */
    for (idx = 0; idx < addrs_cnt; idx++) {
        result1 = result2 = 0;

        /* See if packet address equals either limit. Return 1 if true. */
        if (ntohl(a->addr_data32[0]) == addrs[idx].ip[0] &&
            ntohl(a->addr_data32[1]) == addrs[idx].ip[1] &&
            ntohl(a->addr_data32[2]) == addrs[idx].ip[2] &&
            ntohl(a->addr_data32[3]) == addrs[idx].ip[3])
        {
            SCReturnInt(1);
        }
        if (ntohl(a->addr_data32[0]) == addrs[idx].ip2[0] &&
            ntohl(a->addr_data32[1]) == addrs[idx].ip2[1] &&
            ntohl(a->addr_data32[2]) == addrs[idx].ip2[2] &&
            ntohl(a->addr_data32[3]) == addrs[idx].ip2[3])
        {
            SCReturnInt(1);
        }

        /* See if packet address is greater than lower limit
         * of the current signature address match pair.
         */
        for (i = 0; i < 4; i++) {
            if (ntohl(a->addr_data32[i]) > addrs[idx].ip[i]) {
                result1 = 1;
                break;
            }
            if (ntohl(a->addr_data32[i]) < addrs[idx].ip[i]) {
                result1 = 0;
                break;
            }
        }

        /* If not greater than lower limit, try next address match entry */
        if (result1 == 0)
            continue;

        /* See if packet address is less than upper limit
         * of the current signature address match pair.
         */
        for (i = 0; i < 4; i++) {
            if (ntohl(a->addr_data32[i]) < addrs[idx].ip2[i]) {
                result2 = 1;
                break;
            }
            if (ntohl(a->addr_data32[i]) > addrs[idx].ip2[i]) {
                result2 = 0;
                break;
            }
        }

        /* Return a match if packet address is between the two
         * signature address match limits.
         */
        if (result1 == 1 && result2 == 1)
            SCReturnInt(1);
    }

    SCReturnInt(0);
}

/**
 * \brief Check if a particular address(ipv4 or ipv6) matches the address
 *        range in the DetectAddress instance.
 *
 *        We basically check that the address falls inbetween the address
 *        range in DetectAddress.
 *
 * \param dd Pointer to the DetectAddress instance.
 * \param a  Pointer to an Address instance.
 *
 * \param 1 On a match.
 * \param 0 On no match.
 */
int DetectAddressMatch(DetectAddress *dd, Address *a)
{
    SCEnter();

    if (dd->ip.family != a->family) {
        SCReturnInt(0);
    }

    //DetectAddressPrint(dd);
    //AddressDebugPrint(a);

    switch (a->family) {
        case AF_INET:

            /* XXX figure out a way to not need to do this ntohl if we switch to
             * Address inside DetectAddressData we can do uint8_t checks */
            if (ntohl(a->addr_data32[0]) >= ntohl(dd->ip.addr_data32[0]) &&
                ntohl(a->addr_data32[0]) <= ntohl(dd->ip2.addr_data32[0]))
            {
                SCReturnInt(1);
            } else {
                SCReturnInt(0);
            }

            break;
        case AF_INET6:
            if (AddressIPv6Ge(a, &dd->ip) == 1 &&
                AddressIPv6Le(a, &dd->ip2) == 1)
            {
                SCReturnInt(1);
            } else {
                SCReturnInt(0);
            }

            break;
        default:
            SCLogDebug("What other address type can we have :-/");
            break;
    }

    SCReturnInt(0);
}

/**
 * \brief Prints the address data held by the DetectAddress.  If the
 *        address data family is any, we print "ANY".  If the address data
 *        family is IPv4, we print the the ipv4 address and mask, and if the
 *        address data family is IPv6, we print the ipv6 address and mask.
 *
 * \param ad Pointer to the DetectAddress instance to be printed.
 */
void DetectAddressPrint(DetectAddress *gr)
{
    if (gr == NULL)
        return;

    if (gr->flags & ADDRESS_FLAG_ANY) {
        SCLogDebug("ANY");
    } else if (gr->ip.family == AF_INET) {
        struct in_addr in;
        char ip[16], mask[16];

        memcpy(&in, &gr->ip.addr_data32[0], sizeof(in));
        PrintInet(AF_INET, &in, ip, sizeof(ip));
        memcpy(&in, &gr->ip2.addr_data32[0], sizeof(in));
        PrintInet(AF_INET, &in, mask, sizeof(mask));

        SCLogDebug("%s/%s", ip, mask);
//        printf("%s/%s", ip, mask);
    } else if (gr->ip.family == AF_INET6) {
        struct in6_addr in6;
        char ip[66], mask[66];

        memcpy(&in6, &gr->ip.addr_data32, sizeof(in6));
        PrintInet(AF_INET6, &in6, ip, sizeof(ip));
        memcpy(&in6, &gr->ip2.addr_data32, sizeof(in6));
        PrintInet(AF_INET6, &in6, mask, sizeof(mask));

        SCLogDebug("%s/%s", ip, mask);
//        printf("%s/%s", ip, mask);
    }

    return;
}

/**
 * \brief Find the group matching address in a group head.
 *
 * \param gh Pointer to the address group head(DetectAddressHead instance).
 * \param a  Pointer to an Address instance.
 *
 * \retval g On success pointer to an DetectAddress if we find a match
 *           for the Address "a", in the DetectAddressHead "gh".
 */
DetectAddress *DetectAddressLookupInHead(DetectAddressHead *gh, Address *a)
{
    SCEnter();

    DetectAddress *g;

    if (gh == NULL) {
        SCReturnPtr(NULL, "DetectAddress");
    }

    /* XXX should we really do this check every time we run this function? */
    if (a->family == AF_INET) {
        SCLogDebug("IPv4");
        g = gh->ipv4_head;
    } else if (a->family == AF_INET6) {
        SCLogDebug("IPv6");
        g = gh->ipv6_head;
    } else {
        SCLogDebug("ANY");
        g = gh->any_head;
    }

    for ( ; g != NULL; g = g->next) {
        if (DetectAddressMatch(g,a) == 1) {
            SCReturnPtr(g, "DetectAddress");
        }
    }

    SCReturnPtr(NULL, "DetectAddress");
}

/********************************Unittests*************************************/

#ifdef UNITTESTS

static int UTHValidateDetectAddress(DetectAddress *ad, const char *one, const char *two)
{
    char str1[46] = "", str2[46] = "";

    if (ad == NULL)
        return FALSE;

    switch(ad->ip.family) {
        case AF_INET:
            PrintInet(AF_INET, (const void *)&ad->ip.addr_data32[0], str1, sizeof(str1));
            SCLogDebug("%s", str1);
            PrintInet(AF_INET, (const void *)&ad->ip2.addr_data32[0], str2, sizeof(str2));
            SCLogDebug("%s", str2);

            if (strcmp(str1, one) != 0) {
                SCLogInfo("%s != %s", str1, one);
                return FALSE;
            }

            if (strcmp(str2, two) != 0) {
                SCLogInfo("%s != %s", str2, two);
                return FALSE;
            }

            return TRUE;
            break;

        case AF_INET6:
            PrintInet(AF_INET6, (const void *)&ad->ip.addr_data32[0], str1, sizeof(str1));
            SCLogDebug("%s", str1);
            PrintInet(AF_INET6, (const void *)&ad->ip2.addr_data32[0], str2, sizeof(str2));
            SCLogDebug("%s", str2);

            if (strcmp(str1, one) != 0) {
                SCLogInfo("%s != %s", str1, one);
                return FALSE;
            }

            if (strcmp(str2, two) != 0) {
                SCLogInfo("%s != %s", str2, two);
                return FALSE;
            }

            return TRUE;
            break;
    }

    return FALSE;
}

typedef struct UTHValidateDetectAddressHeadRange_ {
    const char *one;
    const char *two;
} UTHValidateDetectAddressHeadRange;

int UTHValidateDetectAddressHead(DetectAddressHead *gh, int nranges, UTHValidateDetectAddressHeadRange *expectations)
{
    int expect = nranges;
    int have = 0;

    if (gh == NULL)
        return FALSE;

    DetectAddress *ad = NULL;
    ad = gh->ipv4_head;
    if (ad == NULL)
        ad = gh->ipv6_head;
    while (have < expect) {
        if (ad == NULL) {
            printf("bad head: have %d ranges, expected %d: ", have, expect);
            return FALSE;
        }

        if (UTHValidateDetectAddress(ad, expectations[have].one, expectations[have].two) == FALSE)
            return FALSE;

        ad = ad->next;
        have++;
    }

    return TRUE;
}

int AddressTestParse01(void)
{
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse02(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4");

    if (dd) {
        if (dd->ip2.addr_data32[0] != ntohl(16909060) ||
            dd->ip.addr_data32[0] != ntohl(16909060)) {
            result = 0;
        }

        printf("ip %"PRIu32", ip2 %"PRIu32"\n", dd->ip.addr_data32[0], dd->ip2.addr_data32[0]);
        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse03(void)
{
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4/255.255.255.0");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse04(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4/255.255.255.0");

    if (dd) {
        if (dd->ip.addr_data32[0] != ntohl(16909056)||
            dd->ip2.addr_data32[0] != ntohl(16909311)) {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse05(void)
{
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4/24");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse06(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4/24");

    if (dd) {
        if (dd->ip2.addr_data32[0] != ntohl(16909311) ||
            dd->ip.addr_data32[0] != ntohl(16909056)) {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse07(void)
{
    DetectAddress *dd = DetectAddressParseSingle("2001::/3");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse08(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("2001::/3");

    if (dd) {
        if (dd->ip.addr_data32[0] != ntohl(536870912) || dd->ip.addr_data32[1] != 0x00000000 ||
            dd->ip.addr_data32[2] != 0x00000000 || dd->ip.addr_data32[3] != 0x00000000 ||

            dd->ip2.addr_data32[0] != ntohl(1073741823) || dd->ip2.addr_data32[1] != 0xFFFFFFFF ||
            dd->ip2.addr_data32[2] != 0xFFFFFFFF || dd->ip2.addr_data32[3] != 0xFFFFFFFF) {
            DetectAddressPrint(dd);
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse09(void)
{
    DetectAddress *dd = DetectAddressParseSingle("2001::1/128");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse10(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("2001::/128");

   if (dd) {
        if (dd->ip.addr_data32[0] != ntohl(536936448) || dd->ip.addr_data32[1] != 0x00000000 ||
            dd->ip.addr_data32[2] != 0x00000000 || dd->ip.addr_data32[3] != 0x00000000 ||

            dd->ip2.addr_data32[0] != ntohl(536936448) || dd->ip2.addr_data32[1] != 0x00000000 ||
            dd->ip2.addr_data32[2] != 0x00000000 || dd->ip2.addr_data32[3] != 0x00000000) {
            DetectAddressPrint(dd);
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse11(void)
{
    DetectAddress *dd = DetectAddressParseSingle("2001::/48");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse12(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("2001::/48");

    if (dd) {
        if (dd->ip.addr_data32[0] != ntohl(536936448) || dd->ip.addr_data32[1] != 0x00000000 ||
            dd->ip.addr_data32[2] != 0x00000000 || dd->ip.addr_data32[3] != 0x00000000 ||

            dd->ip2.addr_data32[0] != ntohl(536936448) || dd->ip2.addr_data32[1] != ntohl(65535) ||
            dd->ip2.addr_data32[2] != 0xFFFFFFFF || dd->ip2.addr_data32[3] != 0xFFFFFFFF) {
            DetectAddressPrint(dd);
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}
int AddressTestParse13(void)
{
    DetectAddress *dd = DetectAddressParseSingle("2001::/16");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse14(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("2001::/16");

    if (dd) {
        if (dd->ip.addr_data32[0] != ntohl(536936448) || dd->ip.addr_data32[1] != 0x00000000 ||
            dd->ip.addr_data32[2] != 0x00000000 || dd->ip.addr_data32[3] != 0x00000000 ||

            dd->ip2.addr_data32[0] != ntohl(537001983) || dd->ip2.addr_data32[1] != 0xFFFFFFFF ||
            dd->ip2.addr_data32[2] != 0xFFFFFFFF || dd->ip2.addr_data32[3] != 0xFFFFFFFF) {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse15(void)
{
    DetectAddress *dd = DetectAddressParseSingle("2001::/0");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse16(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("2001::/0");

    if (dd) {
        if (dd->ip.addr_data32[0] != 0x00000000 || dd->ip.addr_data32[1] != 0x00000000 ||
            dd->ip.addr_data32[2] != 0x00000000 || dd->ip.addr_data32[3] != 0x00000000 ||

            dd->ip2.addr_data32[0] != 0xFFFFFFFF || dd->ip2.addr_data32[1] != 0xFFFFFFFF ||
            dd->ip2.addr_data32[2] != 0xFFFFFFFF || dd->ip2.addr_data32[3] != 0xFFFFFFFF) {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse17(void)
{
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4-1.2.3.6");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse18(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4-1.2.3.6");

    if (dd) {
        if (dd->ip2.addr_data32[0] != ntohl(16909062) ||
            dd->ip.addr_data32[0] != ntohl(16909060)) {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse19(void)
{
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.6-1.2.3.4");

    if (dd) {
        DetectAddressFree(dd);
        return 0;
    }

    return 1;
}

int AddressTestParse20(void)
{
    DetectAddress *dd = DetectAddressParseSingle("2001::1-2001::4");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse21(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("2001::1-2001::4");

    if (dd) {
        if (dd->ip.addr_data32[0] != ntohl(536936448) || dd->ip.addr_data32[1] != 0x00000000 ||
            dd->ip.addr_data32[2] != 0x00000000 || dd->ip.addr_data32[3] != ntohl(1) ||

            dd->ip2.addr_data32[0] != ntohl(536936448) || dd->ip2.addr_data32[1] != 0x00000000 ||
            dd->ip2.addr_data32[2] != 0x00000000 || dd->ip2.addr_data32[3] != ntohl(4)) {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse22(void)
{
    DetectAddress *dd = DetectAddressParseSingle("2001::4-2001::1");

    if (dd) {
        DetectAddressFree(dd);
        return 0;
    }

    return 1;
}

int AddressTestParse23(void)
{
    DetectAddress *dd = DetectAddressParseSingle("any");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse24(void)
{
    DetectAddress *dd = DetectAddressParseSingle("Any");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse25(void)
{
    DetectAddress *dd = DetectAddressParseSingle("ANY");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse26(void)
{
    int result = 0;
    DetectAddress *dd = DetectAddressParseSingle("any");

    if (dd) {
        if (dd->flags & ADDRESS_FLAG_ANY)
            result = 1;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse27(void)
{
    DetectAddress *dd = DetectAddressParseSingle("!192.168.0.1");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse28(void)
{
    int result = 0;
    DetectAddress *dd = DetectAddressParseSingle("!1.2.3.4");

    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip.addr_data32[0] == ntohl(16909060)) {
            result = 1;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse29(void)
{
    DetectAddress *dd = DetectAddressParseSingle("!1.2.3.0/24");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse30(void)
{
    int result = 0;
    DetectAddress *dd = DetectAddressParseSingle("!1.2.3.4/24");

    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip.addr_data32[0] == ntohl(16909056) &&
            dd->ip2.addr_data32[0] == ntohl(16909311)) {
            result = 1;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

/**
 * \test make sure !any is rejected
 */
int AddressTestParse31(void)
{
    DetectAddress *dd = DetectAddressParseSingle("!any");

    if (dd) {
        DetectAddressFree(dd);
        return 0;
    }

    return 1;
}

int AddressTestParse32(void)
{
    DetectAddress *dd = DetectAddressParseSingle("!2001::1");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse33(void)
{
    int result = 0;
    DetectAddress *dd = DetectAddressParseSingle("!2001::1");

    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip.addr_data32[0] == ntohl(536936448) && dd->ip.addr_data32[1] == 0x00000000 &&
            dd->ip.addr_data32[2] == 0x00000000 && dd->ip.addr_data32[3] == ntohl(1)) {
            result = 1;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse34(void)
{
    DetectAddress *dd = DetectAddressParseSingle("!2001::/16");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

int AddressTestParse35(void)
{
    int result = 0;
    DetectAddress *dd = DetectAddressParseSingle("!2001::/16");

    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip.addr_data32[0] == ntohl(536936448) && dd->ip.addr_data32[1] == 0x00000000 &&
            dd->ip.addr_data32[2] == 0x00000000 && dd->ip.addr_data32[3] == 0x00000000 &&

            dd->ip2.addr_data32[0] == ntohl(537001983) && dd->ip2.addr_data32[1] == 0xFFFFFFFF &&
            dd->ip2.addr_data32[2] == 0xFFFFFFFF && dd->ip2.addr_data32[3] == 0xFFFFFFFF) {
            result = 1;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse36(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("ffff::/16");

    if (dd) {
        if (dd->ip.addr_data32[0] != ntohl(0xFFFF0000) || dd->ip.addr_data32[1] != 0x00000000 ||
            dd->ip.addr_data32[2] != 0x00000000 || dd->ip.addr_data32[3] != 0x00000000 ||

            dd->ip2.addr_data32[0] != 0xFFFFFFFF || dd->ip2.addr_data32[1] != 0xFFFFFFFF ||
            dd->ip2.addr_data32[2] != 0xFFFFFFFF || dd->ip2.addr_data32[3] != 0xFFFFFFFF) {

            DetectAddressPrint(dd);
            result = 0;
        }
        DetectAddressPrint(dd);

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestParse37(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("::/0");

    if (dd) {
        if (dd->ip.addr_data32[0] != 0x00000000 || dd->ip.addr_data32[1] != 0x00000000 ||
            dd->ip.addr_data32[2] != 0x00000000 || dd->ip.addr_data32[3] != 0x00000000 ||

            dd->ip2.addr_data32[0] != 0xFFFFFFFF || dd->ip2.addr_data32[1] != 0xFFFFFFFF ||
            dd->ip2.addr_data32[2] != 0xFFFFFFFF || dd->ip2.addr_data32[3] != 0xFFFFFFFF) {
            DetectAddressPrint(dd);
            result = 0;
        }
        DetectAddressPrint(dd);

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch01(void)
{
    DetectAddress *dd = NULL;
    int result = 1;
    struct in_addr in;
    Address a;

    if (inet_pton(AF_INET, "1.2.3.4", &in) != 1)
        return 0;
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    dd = DetectAddressParseSingle("1.2.3.4/24");
    if (dd) {
        if (DetectAddressMatch(dd, &a) == 0)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch02(void)
{
    DetectAddress *dd = NULL;
    int result = 1;
    struct in_addr in;
    Address a;

    if (inet_pton(AF_INET, "1.2.3.127", &in) != 1)
        return 0;
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    dd = DetectAddressParseSingle("1.2.3.4/25");
    if (dd) {
        if (DetectAddressMatch(dd, &a) == 0)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch03(void)
{
    DetectAddress *dd = NULL;
    int result = 1;
    struct in_addr in;
    Address a;

    if (inet_pton(AF_INET, "1.2.3.128", &in) != 1)
        return 0;
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    dd = DetectAddressParseSingle("1.2.3.4/25");
    if (dd) {
        if (DetectAddressMatch(dd, &a) == 1)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch04(void)
{
    DetectAddress *dd = NULL;
    int result = 1;
    struct in_addr in;
    Address a;

    if (inet_pton(AF_INET, "1.2.2.255", &in) != 1)
        return 0;
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    dd = DetectAddressParseSingle("1.2.3.4/25");
    if (dd) {
        if (DetectAddressMatch(dd, &a) == 1)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch05(void)
{
    DetectAddress *dd = NULL;
    int result = 1;
    struct in_addr in;
    Address a;

    if (inet_pton(AF_INET, "1.2.3.4", &in) != 1)
        return 0;
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    dd = DetectAddressParseSingle("1.2.3.4/32");
    if (dd) {
        if (DetectAddressMatch(dd, &a) == 0)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch06(void)
{
    DetectAddress *dd = NULL;
    int result = 1;
    struct in_addr in;
    Address a;

    if (inet_pton(AF_INET, "1.2.3.4", &in) != 1)
        return 0;
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET;
    a.addr_data32[0] = in.s_addr;

    dd = DetectAddressParseSingle("0.0.0.0/0.0.0.0");
    if (dd) {
        if (DetectAddressMatch(dd, &a) == 0)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch07(void)
{
    DetectAddress *dd = NULL;
    int result = 1;
    struct in6_addr in6;
    Address a;

    if (inet_pton(AF_INET6, "2001::1", &in6) != 1)
        return 0;
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    dd = DetectAddressParseSingle("2001::/3");
    if (dd) {
        if (DetectAddressMatch(dd, &a) == 0)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch08(void)
{
    DetectAddress *dd = NULL;
    int result = 1;
    struct in6_addr in6;
    Address a;

    if (inet_pton(AF_INET6, "1999:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &in6) != 1)
        return 0;
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    dd = DetectAddressParseSingle("2001::/3");
    if (dd) {
        if (DetectAddressMatch(dd, &a) == 1)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch09(void)
{
    DetectAddress *dd = NULL;
    int result = 1;
    struct in6_addr in6;
    Address a;

    if (inet_pton(AF_INET6, "2001::2", &in6) != 1)
        return 0;
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    dd = DetectAddressParseSingle("2001::1/128");
    if (dd) {
        if (DetectAddressMatch(dd, &a) == 1)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch10(void)
{
    DetectAddress *dd = NULL;
    int result = 1;
    struct in6_addr in6;
    Address a;

    if (inet_pton(AF_INET6, "2001::2", &in6) != 1)
        return 0;
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    dd = DetectAddressParseSingle("2001::1/126");
    if (dd) {
        if (DetectAddressMatch(dd, &a) == 0)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestMatch11(void)
{
    DetectAddress *dd = NULL;
    int result = 1;
    struct in6_addr in6;
    Address a;

    if (inet_pton(AF_INET6, "2001::3", &in6) != 1)
        return 0;
    memset(&a, 0, sizeof(Address));
    a.family = AF_INET6;
    memcpy(&a.addr_data32, &in6.s6_addr, sizeof(in6.s6_addr));

    dd = DetectAddressParseSingle("2001::1/127");
    if (dd) {
        if (DetectAddressMatch(dd, &a) == 1)
            result = 0;

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

int AddressTestCmp01(void)
{
    DetectAddress *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.0.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.0.0/255.255.255.0");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da, db) != ADDRESS_EQ)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp02(void)
{
    DetectAddress *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.0.0/255.255.0.0");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.0.0/255.255.255.0");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da, db) != ADDRESS_EB)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp03(void)
{
    DetectAddress *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.0.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.0.0/255.255.0.0");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da, db) != ADDRESS_ES)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp04(void)
{
    DetectAddress *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.0.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.1.0/255.255.255.0");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da, db) != ADDRESS_LT)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp05(void)
{
    DetectAddress *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.1.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.0.0/255.255.255.0");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da, db) != ADDRESS_GT)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp06(void)
{
    DetectAddress *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.1.0/255.255.0.0");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.0.0/255.255.0.0");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da, db) != ADDRESS_EQ)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmpIPv407(void)
{
    DetectAddress *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.1.0/255.255.255.0");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.1.128-192.168.2.128");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da, db) != ADDRESS_LE)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmpIPv408(void)
{
    DetectAddress *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("192.168.1.128-192.168.2.128");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("192.168.1.0/255.255.255.0");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da, db) != ADDRESS_GE)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp07(void)
{
    DetectAddress *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("2001::/3");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("2001::1/3");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da, db) != ADDRESS_EQ)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp08(void)
{
    DetectAddress *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("2001::/3");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("2001::/8");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da, db) != ADDRESS_EB)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp09(void)
{
    DetectAddress *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("2001::/8");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("2001::/3");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da, db) != ADDRESS_ES)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp10(void)
{
    DetectAddress *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("2001:1:2:3:0:0:0:0/64");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("2001:1:2:4:0:0:0:0/64");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da, db) != ADDRESS_LT)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp11(void)
{
    DetectAddress *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("2001:1:2:4:0:0:0:0/64");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("2001:1:2:3:0:0:0:0/64");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da, db) != ADDRESS_GT)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestCmp12(void)
{
    DetectAddress *da = NULL, *db = NULL;
    int result = 1;

    da = DetectAddressParseSingle("2001:1:2:3:1:0:0:0/64");
    if (da == NULL) goto error;
    db = DetectAddressParseSingle("2001:1:2:3:2:0:0:0/64");
    if (db == NULL) goto error;

    if (DetectAddressCmp(da, db) != ADDRESS_EQ)
        result = 0;

    DetectAddressFree(da);
    DetectAddressFree(db);
    return result;

error:
    if (da) DetectAddressFree(da);
    if (db) DetectAddressFree(db);
    return 0;
}

int AddressTestAddressGroupSetup01(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "1.2.3.4");
        if (r == 0)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup02(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "1.2.3.4");
        if (r == 0 && gh->ipv4_head != NULL)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup03(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "1.2.3.4");
        if (r == 0 && gh->ipv4_head != NULL) {
            DetectAddress *prev_head = gh->ipv4_head;

            r = DetectAddressParse(NULL, gh, "1.2.3.3");
            if (r == 0 && gh->ipv4_head != prev_head &&
                gh->ipv4_head != NULL && gh->ipv4_head->next == prev_head) {
                result = 1;
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup04(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "1.2.3.4");
        if (r == 0 && gh->ipv4_head != NULL) {
            DetectAddress *prev_head = gh->ipv4_head;

            r = DetectAddressParse(NULL, gh, "1.2.3.3");
            if (r == 0 && gh->ipv4_head != prev_head &&
                gh->ipv4_head != NULL && gh->ipv4_head->next == prev_head) {
                DetectAddress *prev_head = gh->ipv4_head;

                r = DetectAddressParse(NULL, gh, "1.2.3.2");
                if (r == 0 && gh->ipv4_head != prev_head &&
                    gh->ipv4_head != NULL && gh->ipv4_head->next == prev_head) {
                    result = 1;
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup05(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "1.2.3.2");
        if (r == 0 && gh->ipv4_head != NULL) {
            DetectAddress *prev_head = gh->ipv4_head;

            r = DetectAddressParse(NULL, gh, "1.2.3.3");
            if (r == 0 && gh->ipv4_head == prev_head &&
                gh->ipv4_head != NULL && gh->ipv4_head->next != prev_head) {
                DetectAddress *prev_head = gh->ipv4_head;

                r = DetectAddressParse(NULL, gh, "1.2.3.4");
                if (r == 0 && gh->ipv4_head == prev_head &&
                    gh->ipv4_head != NULL && gh->ipv4_head->next != prev_head) {
                    result = 1;
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup06(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "1.2.3.2");
        if (r == 0 && gh->ipv4_head != NULL) {
            DetectAddress *prev_head = gh->ipv4_head;

            r = DetectAddressParse(NULL, gh, "1.2.3.2");
            if (r == 0 && gh->ipv4_head == prev_head &&
                gh->ipv4_head != NULL && gh->ipv4_head->next == NULL) {
                result = 1;
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup07(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "10.0.0.0/8");
        if (r == 0 && gh->ipv4_head != NULL) {
            r = DetectAddressParse(NULL, gh, "10.10.10.10");
            if (r == 0 && gh->ipv4_head != NULL &&
                gh->ipv4_head->next != NULL &&
                gh->ipv4_head->next->next != NULL) {
                result = 1;
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup08(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "10.10.10.10");
        if (r == 0 && gh->ipv4_head != NULL) {
            r = DetectAddressParse(NULL, gh, "10.0.0.0/8");
            if (r == 0 && gh->ipv4_head != NULL &&
                gh->ipv4_head->next != NULL &&
                gh->ipv4_head->next->next != NULL) {
                result = 1;
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup09(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "10.10.10.0/24");
        if (r == 0 && gh->ipv4_head != NULL) {
            r = DetectAddressParse(NULL, gh, "10.10.10.10-10.10.11.1");
            if (r == 0 && gh->ipv4_head != NULL &&
                gh->ipv4_head->next != NULL &&
                gh->ipv4_head->next->next != NULL) {
                result = 1;
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup10(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "10.10.10.10-10.10.11.1");
        if (r == 0 && gh->ipv4_head != NULL) {
            r = DetectAddressParse(NULL, gh, "10.10.10.0/24");
            if (r == 0 && gh->ipv4_head != NULL &&
                gh->ipv4_head->next != NULL &&
                gh->ipv4_head->next->next != NULL) {
                result = 1;
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup11(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "10.10.10.10-10.10.11.1");
        if (r == 0) {
            r = DetectAddressParse(NULL, gh, "10.10.10.0/24");
            if (r == 0) {
                r = DetectAddressParse(NULL, gh, "0.0.0.0/0");
                if (r == 0) {
                    DetectAddress *one = gh->ipv4_head, *two = one->next,
                        *three = two->next, *four = three->next,
                        *five = four->next;

                    /* result should be:
                     * 0.0.0.0/10.10.9.255
                     * 10.10.10.0/10.10.10.9
                     * 10.10.10.10/10.10.10.255
                     * 10.10.11.0/10.10.11.1
                     * 10.10.11.2/255.255.255.255
                     */
                    if (one->ip.addr_data32[0] == 0x00000000 && one->ip2.addr_data32[0] == ntohl(168430079) &&
                        two->ip.addr_data32[0] == ntohl(168430080) && two->ip2.addr_data32[0] == ntohl(168430089) &&
                        three->ip.addr_data32[0] == ntohl(168430090) && three->ip2.addr_data32[0] == ntohl(168430335) &&
                        four->ip.addr_data32[0] == ntohl(168430336) && four->ip2.addr_data32[0] == ntohl(168430337) &&
                        five->ip.addr_data32[0] == ntohl(168430338) && five->ip2.addr_data32[0]  == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup12 (void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "10.10.10.10-10.10.11.1");
        if (r == 0) {
            r = DetectAddressParse(NULL, gh, "0.0.0.0/0");
            if (r == 0) {
                r = DetectAddressParse(NULL, gh, "10.10.10.0/24");
                if (r == 0) {
                    DetectAddress *one = gh->ipv4_head, *two = one->next,
                        *three = two->next, *four = three->next,
                        *five = four->next;

                    /* result should be:
                     * 0.0.0.0/10.10.9.255
                     * 10.10.10.0/10.10.10.9
                     * 10.10.10.10/10.10.10.255
                     * 10.10.11.0/10.10.11.1
                     * 10.10.11.2/255.255.255.255
                     */
                    if (one->ip.addr_data32[0] == 0x00000000 && one->ip2.addr_data32[0] == ntohl(168430079) &&
                        two->ip.addr_data32[0] == ntohl(168430080) && two->ip2.addr_data32[0] == ntohl(168430089) &&
                        three->ip.addr_data32[0] == ntohl(168430090) && three->ip2.addr_data32[0] == ntohl(168430335) &&
                        four->ip.addr_data32[0] == ntohl(168430336) && four->ip2.addr_data32[0] == ntohl(168430337) &&
                        five->ip.addr_data32[0] == ntohl(168430338) && five->ip2.addr_data32[0]  == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup13(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "0.0.0.0/0");
        if (r == 0) {
            r = DetectAddressParse(NULL, gh, "10.10.10.10-10.10.11.1");
            if (r == 0) {
                r = DetectAddressParse(NULL, gh, "10.10.10.0/24");
                if (r == 0) {
                    DetectAddress *one = gh->ipv4_head, *two = one->next,
                        *three = two->next, *four = three->next,
                        *five = four->next;

                    /* result should be:
                     * 0.0.0.0/10.10.9.255
                     * 10.10.10.0/10.10.10.9
                     * 10.10.10.10/10.10.10.255
                     * 10.10.11.0/10.10.11.1
                     * 10.10.11.2/255.255.255.255
                     */
                    if (one->ip.addr_data32[0] == 0x00000000 && one->ip2.addr_data32[0] == ntohl(168430079) &&
                        two->ip.addr_data32[0] == ntohl(168430080) && two->ip2.addr_data32[0] == ntohl(168430089) &&
                        three->ip.addr_data32[0] == ntohl(168430090) && three->ip2.addr_data32[0] == ntohl(168430335) &&
                        four->ip.addr_data32[0] == ntohl(168430336) && four->ip2.addr_data32[0] == ntohl(168430337) &&
                        five->ip.addr_data32[0] == ntohl(168430338) && five->ip2.addr_data32[0]  == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetupIPv414(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "!1.2.3.4");
        if (r == 0) {
            DetectAddress *one = gh->ipv4_head;
            DetectAddress *two = one ? one->next : NULL;

            if (one && two) {
                /* result should be:
                 * 0.0.0.0/1.2.3.3
                 * 1.2.3.5/255.255.255.255
                 */
                if (one->ip.addr_data32[0] == 0x00000000 && one->ip2.addr_data32[0] == ntohl(16909059) &&
                    two->ip.addr_data32[0] == ntohl(16909061) && two->ip2.addr_data32[0] == 0xFFFFFFFF) {
                    result = 1;
                } else {
                    printf("unexpected addresses: ");
                }
            } else {
                printf("one %p two %p: ", one, two);
            }
        } else {
            printf("DetectAddressParse returned %d, expected 0: ", r);
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetupIPv415(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "!0.0.0.0");
        if (r == 0) {
            DetectAddress *one = gh->ipv4_head;

            if (one && one->next == NULL) {
                /* result should be:
                 * 0.0.0.1/255.255.255.255
                 */
                if (one->ip.addr_data32[0] == ntohl(1) && one->ip2.addr_data32[0] == 0xFFFFFFFF)
                    result = 1;
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetupIPv416(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "!255.255.255.255");
        if (r == 0) {
            DetectAddress *one = gh->ipv4_head;

            if (one && one->next == NULL) {
                /* result should be:
                 * 0.0.0.0/255.255.255.254
                 */
                if (one->ip.addr_data32[0] == 0x00000000 && one->ip2.addr_data32[0] == ntohl(4294967294))
                    result = 1;
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup14(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "2001::1");
        if (r == 0)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup15(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "2001::1");
        if (r == 0 && gh->ipv6_head != NULL)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup16(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "2001::4");
        if (r == 0 && gh->ipv6_head != NULL) {
            DetectAddress *prev_head = gh->ipv6_head;

            r = DetectAddressParse(NULL, gh, "2001::3");
            if (r == 0 && gh->ipv6_head != prev_head &&
                gh->ipv6_head != NULL && gh->ipv6_head->next == prev_head) {
                result = 1;
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup17(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "2001::4");
        if (r == 0 && gh->ipv6_head != NULL) {
            DetectAddress *prev_head = gh->ipv6_head;

            r = DetectAddressParse(NULL, gh, "2001::3");
            if (r == 0 && gh->ipv6_head != prev_head &&
                gh->ipv6_head != NULL && gh->ipv6_head->next == prev_head) {
                DetectAddress *prev_head = gh->ipv6_head;

                r = DetectAddressParse(NULL, gh, "2001::2");
                if (r == 0 && gh->ipv6_head != prev_head &&
                    gh->ipv6_head != NULL && gh->ipv6_head->next == prev_head) {
                    result = 1;
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup18(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "2001::2");
        if (r == 0 && gh->ipv6_head != NULL) {
            DetectAddress *prev_head = gh->ipv6_head;

            r = DetectAddressParse(NULL, gh, "2001::3");
            if (r == 0 && gh->ipv6_head == prev_head &&
                gh->ipv6_head != NULL && gh->ipv6_head->next != prev_head) {
                DetectAddress *prev_head = gh->ipv6_head;

                r = DetectAddressParse(NULL, gh, "2001::4");
                if (r == 0 && gh->ipv6_head == prev_head &&
                    gh->ipv6_head != NULL && gh->ipv6_head->next != prev_head) {
                    result = 1;
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup19(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "2001::2");
        if (r == 0 && gh->ipv6_head != NULL) {
            DetectAddress *prev_head = gh->ipv6_head;

            r = DetectAddressParse(NULL, gh, "2001::2");
            if (r == 0 && gh->ipv6_head == prev_head &&
                gh->ipv6_head != NULL && gh->ipv6_head->next == NULL) {
                result = 1;
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup20(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "2000::/3");
        if (r == 0 && gh->ipv6_head != NULL) {
            r = DetectAddressParse(NULL, gh, "2001::4");
            if (r == 0 && gh->ipv6_head != NULL &&
                gh->ipv6_head->next != NULL &&
                gh->ipv6_head->next->next != NULL) {
                result = 1;
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup21(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "2001::4");
        if (r == 0 && gh->ipv6_head != NULL) {
            r = DetectAddressParse(NULL, gh, "2000::/3");
            if (r == 0 && gh->ipv6_head != NULL &&
                gh->ipv6_head->next != NULL &&
                gh->ipv6_head->next->next != NULL) {
                result = 1;
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup22(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "2000::/3");
        if (r == 0 && gh->ipv6_head != NULL) {
            r = DetectAddressParse(NULL, gh, "2001::4-2001::6");
            if (r == 0 && gh->ipv6_head != NULL &&
                gh->ipv6_head->next != NULL &&
                gh->ipv6_head->next->next != NULL) {
                result = 1;
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup23(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "2001::4-2001::6");
        if (r == 0 && gh->ipv6_head != NULL) {
            r = DetectAddressParse(NULL, gh, "2000::/3");
            if (r == 0 && gh->ipv6_head != NULL &&
                gh->ipv6_head->next != NULL &&
                gh->ipv6_head->next->next != NULL) {
                result = 1;
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup24(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "2001::4-2001::6");
        if (r == 0) {
            r = DetectAddressParse(NULL, gh, "2001::/3");
            if (r == 0) {
                r = DetectAddressParse(NULL, gh, "::/0");
                if (r == 0) {
                    DetectAddress *one = gh->ipv6_head, *two = one->next,
                        *three = two->next, *four = three->next,
                        *five = four->next;
                    if (one->ip.addr_data32[0] == 0x00000000 &&
                        one->ip.addr_data32[1] == 0x00000000 &&
                        one->ip.addr_data32[2] == 0x00000000 &&
                        one->ip.addr_data32[3] == 0x00000000 &&
                        one->ip2.addr_data32[0] == ntohl(536870911) &&
                        one->ip2.addr_data32[1] == 0xFFFFFFFF &&
                        one->ip2.addr_data32[2] == 0xFFFFFFFF &&
                        one->ip2.addr_data32[3] == 0xFFFFFFFF &&

                        two->ip.addr_data32[0] == ntohl(536870912) &&
                        two->ip.addr_data32[1] == 0x00000000 &&
                        two->ip.addr_data32[2] == 0x00000000 &&
                        two->ip.addr_data32[3] == 0x00000000 &&
                        two->ip2.addr_data32[0] == ntohl(536936448) &&
                        two->ip2.addr_data32[1] == 0x00000000 &&
                        two->ip2.addr_data32[2] == 0x00000000 &&
                        two->ip2.addr_data32[3] == ntohl(3) &&

                        three->ip.addr_data32[0] == ntohl(536936448) &&
                        three->ip.addr_data32[1] == 0x00000000 &&
                        three->ip.addr_data32[2] == 0x00000000 &&
                        three->ip.addr_data32[3] == ntohl(4) &&
                        three->ip2.addr_data32[0] == ntohl(536936448) &&
                        three->ip2.addr_data32[1] == 0x00000000 &&
                        three->ip2.addr_data32[2] == 0x00000000 &&
                        three->ip2.addr_data32[3] == ntohl(6) &&

                        four->ip.addr_data32[0] == ntohl(536936448) &&
                        four->ip.addr_data32[1] == 0x00000000 &&
                        four->ip.addr_data32[2] == 0x00000000 &&
                        four->ip.addr_data32[3] == ntohl(7) &&
                        four->ip2.addr_data32[0] == ntohl(1073741823) &&
                        four->ip2.addr_data32[1] == 0xFFFFFFFF &&
                        four->ip2.addr_data32[2] == 0xFFFFFFFF &&
                        four->ip2.addr_data32[3] == 0xFFFFFFFF &&

                        five->ip.addr_data32[0] == ntohl(1073741824) &&
                        five->ip.addr_data32[1] == 0x00000000 &&
                        five->ip.addr_data32[2] == 0x00000000 &&
                        five->ip.addr_data32[3] == 0x00000000 &&
                        five->ip2.addr_data32[0] == 0xFFFFFFFF &&
                        five->ip2.addr_data32[1] == 0xFFFFFFFF &&
                        five->ip2.addr_data32[2] == 0xFFFFFFFF &&
                        five->ip2.addr_data32[3] == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup25(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "2001::4-2001::6");
        if (r == 0) {
            r = DetectAddressParse(NULL, gh, "::/0");
            if (r == 0) {
                r = DetectAddressParse(NULL, gh, "2001::/3");
                if (r == 0) {
                    DetectAddress *one = gh->ipv6_head, *two = one->next,
                        *three = two->next, *four = three->next,
                        *five = four->next;
                    if (one->ip.addr_data32[0] == 0x00000000 &&
                        one->ip.addr_data32[1] == 0x00000000 &&
                        one->ip.addr_data32[2] == 0x00000000 &&
                        one->ip.addr_data32[3] == 0x00000000 &&
                        one->ip2.addr_data32[0]  == ntohl(536870911) &&
                        one->ip2.addr_data32[1]  == 0xFFFFFFFF &&
                        one->ip2.addr_data32[2]  == 0xFFFFFFFF &&
                        one->ip2.addr_data32[3]  == 0xFFFFFFFF &&

                        two->ip.addr_data32[0] == ntohl(536870912) &&
                        two->ip.addr_data32[1] == 0x00000000 &&
                        two->ip.addr_data32[2] == 0x00000000 &&
                        two->ip.addr_data32[3] == 0x00000000 &&
                        two->ip2.addr_data32[0] == ntohl(536936448) &&
                        two->ip2.addr_data32[1] == 0x00000000 &&
                        two->ip2.addr_data32[2] == 0x00000000 &&
                        two->ip2.addr_data32[3] == ntohl(3) &&

                        three->ip.addr_data32[0] == ntohl(536936448) &&
                        three->ip.addr_data32[1] == 0x00000000 &&
                        three->ip.addr_data32[2] == 0x00000000 &&
                        three->ip.addr_data32[3] == ntohl(4) &&
                        three->ip2.addr_data32[0] == ntohl(536936448) &&
                        three->ip2.addr_data32[1] == 0x00000000 &&
                        three->ip2.addr_data32[2] == 0x00000000 &&
                        three->ip2.addr_data32[3] == ntohl(6) &&

                        four->ip.addr_data32[0] == ntohl(536936448) &&
                        four->ip.addr_data32[1] == 0x00000000 &&
                        four->ip.addr_data32[2] == 0x00000000 &&
                        four->ip.addr_data32[3] == ntohl(7) &&
                        four->ip2.addr_data32[0] == ntohl(1073741823) &&
                        four->ip2.addr_data32[1] == 0xFFFFFFFF &&
                        four->ip2.addr_data32[2] == 0xFFFFFFFF &&
                        four->ip2.addr_data32[3] == 0xFFFFFFFF &&

                        five->ip.addr_data32[0] == ntohl(1073741824) &&
                        five->ip.addr_data32[1] == 0x00000000 &&
                        five->ip.addr_data32[2] == 0x00000000 &&
                        five->ip.addr_data32[3] == 0x00000000 &&
                        five->ip2.addr_data32[0] == 0xFFFFFFFF &&
                        five->ip2.addr_data32[1] == 0xFFFFFFFF &&
                        five->ip2.addr_data32[2] == 0xFFFFFFFF &&
                        five->ip2.addr_data32[3] == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup26(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "::/0");
        if (r == 0) {
            r = DetectAddressParse(NULL, gh, "2001::4-2001::6");
            if (r == 0) {
                r = DetectAddressParse(NULL, gh, "2001::/3");
                if (r == 0) {
                    DetectAddress *one = gh->ipv6_head, *two = one->next,
                        *three = two->next, *four = three->next,
                        *five = four->next;
                    if (one->ip.addr_data32[0] == 0x00000000 &&
                        one->ip.addr_data32[1] == 0x00000000 &&
                        one->ip.addr_data32[2] == 0x00000000 &&
                        one->ip.addr_data32[3] == 0x00000000 &&
                        one->ip2.addr_data32[0] == ntohl(536870911) &&
                        one->ip2.addr_data32[1] == 0xFFFFFFFF &&
                        one->ip2.addr_data32[2] == 0xFFFFFFFF &&
                        one->ip2.addr_data32[3] == 0xFFFFFFFF &&

                        two->ip.addr_data32[0] == ntohl(536870912) &&
                        two->ip.addr_data32[1] == 0x00000000 &&
                        two->ip.addr_data32[2] == 0x00000000 &&
                        two->ip.addr_data32[3] == 0x00000000 &&
                        two->ip2.addr_data32[0] == ntohl(536936448) &&
                        two->ip2.addr_data32[1] == 0x00000000 &&
                        two->ip2.addr_data32[2] == 0x00000000 &&
                        two->ip2.addr_data32[3] == ntohl(3) &&

                        three->ip.addr_data32[0] == ntohl(536936448) &&
                        three->ip.addr_data32[1] == 0x00000000 &&
                        three->ip.addr_data32[2] == 0x00000000 &&
                        three->ip.addr_data32[3] == ntohl(4) &&
                        three->ip2.addr_data32[0] == ntohl(536936448) &&
                        three->ip2.addr_data32[1] == 0x00000000 &&
                        three->ip2.addr_data32[2] == 0x00000000 &&
                        three->ip2.addr_data32[3] == ntohl(6) &&

                        four->ip.addr_data32[0] == ntohl(536936448) &&
                        four->ip.addr_data32[1] == 0x00000000 &&
                        four->ip.addr_data32[2] == 0x00000000 &&
                        four->ip.addr_data32[3] == ntohl(7) &&
                        four->ip2.addr_data32[0] == ntohl(1073741823) &&
                        four->ip2.addr_data32[1] == 0xFFFFFFFF &&
                        four->ip2.addr_data32[2] == 0xFFFFFFFF &&
                        four->ip2.addr_data32[3] == 0xFFFFFFFF &&

                        five->ip.addr_data32[0] == ntohl(1073741824) &&
                        five->ip.addr_data32[1] == 0x00000000 &&
                        five->ip.addr_data32[2] == 0x00000000 &&
                        five->ip.addr_data32[3] == 0x00000000 &&
                        five->ip2.addr_data32[0] == 0xFFFFFFFF &&
                        five->ip2.addr_data32[1] == 0xFFFFFFFF &&
                        five->ip2.addr_data32[2] == 0xFFFFFFFF &&
                        five->ip2.addr_data32[3] == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup27(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[1.2.3.4]");
        if (r == 0)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup28(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[1.2.3.4,4.3.2.1]");
        if (r == 0)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup29(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[1.2.3.4,4.3.2.1,10.10.10.10]");
        if (r == 0)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup30(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[[1.2.3.4,2.3.4.5],4.3.2.1,[10.10.10.10,11.11.11.11]]");
        if (r == 0)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup31(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[[1.2.3.4,[2.3.4.5,3.4.5.6]],4.3.2.1,[10.10.10.10,[11.11.11.11,12.12.12.12]]]");
        if (r == 0)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup32(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[[1.2.3.4,[2.3.4.5,[3.4.5.6,4.5.6.7]]],4.3.2.1,[10.10.10.10,[11.11.11.11,[12.12.12.12,13.13.13.13]]]]");
        if (r == 0)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup33(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "![1.1.1.1,[2.2.2.2,[3.3.3.3,4.4.4.4]]]");
        if (r == 0)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup34(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[1.0.0.0/8,![1.1.1.1,[1.2.1.1,1.3.1.1]]]");
        if (r == 0)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup35(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[1.0.0.0/8,[2.0.0.0/8,![1.1.1.1,2.2.2.2]]]");
        if (r == 0)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup36 (void)
{
    int result = 0;

    DetectAddressHead *gh = DetectAddressHeadInit();
    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[1.0.0.0/8,[2.0.0.0/8,[3.0.0.0/8,!1.1.1.1]]]");
        if (r == 0)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestAddressGroupSetup37(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[0.0.0.0/0,::/0]");
        if (r == 0)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup38(void)
{
    UTHValidateDetectAddressHeadRange expectations[3] = {
        { "0.0.0.0", "192.167.255.255" },
        { "192.168.14.0", "192.168.14.255" },
        { "192.169.0.0", "255.255.255.255" } };
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "![192.168.0.0/16,!192.168.14.0/24]");
        if (r == 0) {
            if (UTHValidateDetectAddressHead(gh, 3, expectations) == TRUE)
                result = 1;
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup39(void)
{
    UTHValidateDetectAddressHeadRange expectations[3] = {
        { "0.0.0.0", "192.167.255.255" },
        { "192.168.14.0", "192.168.14.255" },
        { "192.169.0.0", "255.255.255.255" } };
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[![192.168.0.0/16,!192.168.14.0/24]]");
        if (r == 0) {
            if (UTHValidateDetectAddressHead(gh, 3, expectations) == TRUE)
                result = 1;
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup40(void)
{
    UTHValidateDetectAddressHeadRange expectations[3] = {
        { "0.0.0.0", "192.167.255.255" },
        { "192.168.14.0", "192.168.14.255" },
        { "192.169.0.0", "255.255.255.255" } };
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();
    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[![192.168.0.0/16,[!192.168.14.0/24]]]");
        if (r == 0) {
            if (UTHValidateDetectAddressHead(gh, 3, expectations) == TRUE)
                result = 1;
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup41(void)
{
    UTHValidateDetectAddressHeadRange expectations[3] = {
        { "0.0.0.0", "192.167.255.255" },
        { "192.168.14.0", "192.168.14.255" },
        { "192.169.0.0", "255.255.255.255" } };
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();
    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[![192.168.0.0/16,![192.168.14.0/24]]]");
        if (r == 0) {
            if (UTHValidateDetectAddressHead(gh, 3, expectations) == TRUE)
                result = 1;
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup42(void)
{
    UTHValidateDetectAddressHeadRange expectations[1] = {
        { "2000:0000:0000:0000:0000:0000:0000:0000", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" } };
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();
    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[2001::/3]");
        if (r == 0) {
            if (UTHValidateDetectAddressHead(gh, 1, expectations) == TRUE)
                result = 1;
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup43(void)
{
    UTHValidateDetectAddressHeadRange expectations[2] = {
        { "2000:0000:0000:0000:0000:0000:0000:0000", "2fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" },
        { "3800:0000:0000:0000:0000:0000:0000:0000", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" } };
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();
    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[2001::/3,!3000::/5]");
        if (r == 0) {
            if (UTHValidateDetectAddressHead(gh, 2, expectations) == TRUE)
                result = 1;
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup44(void)
{
    UTHValidateDetectAddressHeadRange expectations[2] = {
        { "3ffe:ffff:7654:feda:1245:ba98:0000:0000", "3ffe:ffff:7654:feda:1245:ba98:ffff:ffff" }};
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();
    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "3ffe:ffff:7654:feda:1245:ba98:3210:4562/96");
        if (r == 0) {
            if (UTHValidateDetectAddressHead(gh, 1, expectations) == TRUE)
                result = 1;
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup45(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();
    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[192.168.1.3,!192.168.0.0/16]");
        if (r != 0) {
            result = 1;
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup46(void)
{
    UTHValidateDetectAddressHeadRange expectations[4] = {
        { "0.0.0.0", "192.167.255.255" },
        { "192.168.1.0", "192.168.1.255" },
        { "192.168.3.0", "192.168.3.255" },
        { "192.169.0.0", "255.255.255.255" } };
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();
    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[![192.168.0.0/16,![192.168.1.0/24,192.168.3.0/24]]]");
        if (r == 0) {
            if (UTHValidateDetectAddressHead(gh, 4, expectations) == TRUE)
                result = 1;
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

/** \test net with some negations, then all negated */
static int AddressTestAddressGroupSetup47(void)
{
    UTHValidateDetectAddressHeadRange expectations[5] = {
        { "0.0.0.0", "192.167.255.255" },
        { "192.168.1.0", "192.168.1.255" },
        { "192.168.3.0", "192.168.3.255" },
        { "192.168.5.0", "192.168.5.255" },
        { "192.169.0.0", "255.255.255.255" } };
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();
    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[![192.168.0.0/16,![192.168.1.0/24,192.168.3.0/24],!192.168.5.0/24]]");
        if (r == 0) {
            if (UTHValidateDetectAddressHead(gh, 5, expectations) == TRUE)
                result = 1;
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

/** \test same as AddressTestAddressGroupSetup47, but not negated */
static int AddressTestAddressGroupSetup48(void)
{
    UTHValidateDetectAddressHeadRange expectations[4] = {
        { "192.168.0.0", "192.168.0.255" },
        { "192.168.2.0", "192.168.2.255" },
        { "192.168.4.0", "192.168.4.255" },
        { "192.168.6.0", "192.168.255.255" } };
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();
    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[192.168.0.0/16,![192.168.1.0/24,192.168.3.0/24],!192.168.5.0/24]");
        if (r == 0) {
            if (UTHValidateDetectAddressHead(gh, 4, expectations) == TRUE)
                result = 1;
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

int AddressTestCutIPv401(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0/255.255.255.0");
    b = DetectAddressParseSingle("1.2.2.0-1.2.3.4");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 1;

error:
    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 0;
}

int AddressTestCutIPv402(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0/255.255.255.0");
    b = DetectAddressParseSingle("1.2.2.0-1.2.3.4");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c == NULL)
        goto error;

    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 1;

error:
    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 0;
}

int AddressTestCutIPv403(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0/255.255.255.0");
    b = DetectAddressParseSingle("1.2.2.0-1.2.3.4");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c == NULL)
        goto error;

    if (a->ip.addr_data32[0] != ntohl(16908800) || a->ip2.addr_data32[0] != ntohl(16909055))
        goto error;
    if (b->ip.addr_data32[0] != ntohl(16909056) || b->ip2.addr_data32[0] != ntohl(16909060))
        goto error;
    if (c->ip.addr_data32[0] != ntohl(16909061) || c->ip2.addr_data32[0] != ntohl(16909311))
        goto error;

    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 1;

error:
    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 0;
}

int AddressTestCutIPv404(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.3-1.2.3.6");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.5");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c == NULL)
        goto error;

    if (a->ip.addr_data32[0] != ntohl(16909056) || a->ip2.addr_data32[0] != ntohl(16909058))
        goto error;
    if (b->ip.addr_data32[0] != ntohl(16909059) || b->ip2.addr_data32[0] != ntohl(16909061))
        goto error;
    if (c->ip.addr_data32[0] != ntohl(16909062) || c->ip2.addr_data32[0] != ntohl(16909062))
        goto error;


    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 1;

error:
    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 0;
}

int AddressTestCutIPv405(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.3-1.2.3.6");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.9");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c == NULL)
        goto error;

    if (a->ip.addr_data32[0] != ntohl(16909056) || a->ip2.addr_data32[0] != ntohl(16909058))
        goto error;
    if (b->ip.addr_data32[0] != ntohl(16909059) || b->ip2.addr_data32[0] != ntohl(16909062))
        goto error;
    if (c->ip.addr_data32[0] != ntohl(16909063) || c->ip2.addr_data32[0] != ntohl(16909065))
        goto error;

    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 1;

error:
    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 0;
}

int AddressTestCutIPv406(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0-1.2.3.9");
    b = DetectAddressParseSingle("1.2.3.3-1.2.3.6");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c == NULL)
        goto error;

    if (a->ip.addr_data32[0] != ntohl(16909056) || a->ip2.addr_data32[0] != ntohl(16909058))
        goto error;
    if (b->ip.addr_data32[0] != ntohl(16909059) || b->ip2.addr_data32[0] != ntohl(16909062))
        goto error;
    if (c->ip.addr_data32[0] != ntohl(16909063) || c->ip2.addr_data32[0] != ntohl(16909065))
        goto error;

    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 1;

error:
    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 0;
}

int AddressTestCutIPv407(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0-1.2.3.6");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.9");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c != NULL)
        goto error;

    if (a->ip.addr_data32[0] != ntohl(16909056) || a->ip2.addr_data32[0] != ntohl(16909062))
        goto error;
    if (b->ip.addr_data32[0] != ntohl(16909063) || b->ip2.addr_data32[0] != ntohl(16909065))
        goto error;

    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 1;

error:
    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 0;
}

int AddressTestCutIPv408(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.3-1.2.3.9");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.9");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c != NULL)
        goto error;

    if (a->ip.addr_data32[0] != ntohl(16909056) || a->ip2.addr_data32[0] != ntohl(16909058))
        goto error;
    if (b->ip.addr_data32[0] != ntohl(16909059) || b->ip2.addr_data32[0] != ntohl(16909065))
        goto error;

    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 1;

error:
    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 0;
}

int AddressTestCutIPv409(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0-1.2.3.9");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.6");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c != NULL)
        goto error;

    if (a->ip.addr_data32[0] != ntohl(16909056) || a->ip2.addr_data32[0] != ntohl(16909062))
        goto error;
    if (b->ip.addr_data32[0] != ntohl(16909063) || b->ip2.addr_data32[0] != ntohl(16909065))
        goto error;

    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 1;

error:
    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 0;
}

int AddressTestCutIPv410(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0-1.2.3.9");
    b = DetectAddressParseSingle("1.2.3.3-1.2.3.9");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c != NULL)
        goto error;

    if (a->ip.addr_data32[0] != ntohl(16909056) || a->ip2.addr_data32[0] != ntohl(16909058))
        goto error;
    if (b->ip.addr_data32[0] != ntohl(16909059) || b->ip2.addr_data32[0] != ntohl(16909065))
        goto error;

    printf("ip %u ip2 %u ", htonl(a->ip.addr_data32[0]), htonl(a->ip2.addr_data32[0]));

    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 1;

error:
    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    return 0;
}

int AddressTestParseInvalidMask01(void)
{
    int result = 1;
    DetectAddress *dd = NULL;

    dd = DetectAddressParseSingle("192.168.2.0/33");
    if (dd != NULL) {
        DetectAddressFree(dd);
        result = 0;
    }
    return result;
}

int AddressTestParseInvalidMask02(void)
{
    int result = 1;
    DetectAddress *dd = NULL;

    dd = DetectAddressParseSingle("192.168.2.0/255.255.257.0");
    if (dd != NULL) {
        DetectAddressFree(dd);
        result = 0;
    }
    return result;
}

int AddressTestParseInvalidMask03(void)
{
    int result = 1;
    DetectAddress *dd = NULL;

    dd = DetectAddressParseSingle("192.168.2.0/blue");
    if (dd != NULL) {
        DetectAddressFree(dd);
        result = 0;
    }
    return result;
}

int AddressConfVarsTest01(void)
{
    static const char *dummy_conf_string =
        "%YAML 1.1\n"
        "---\n"
        "\n"
        "vars:\n"
        "\n"
        "  address-groups:\n"
        "\n"
        "    HOME_NET: \"any\"\n"
        "\n"
        "    EXTERNAL_NET: \"!any\"\n"
        "\n"
        "  port-groups:\n"
        "\n"
        "    HTTP_PORTS: \"any\"\n"
        "\n"
        "    SHELLCODE_PORTS: \"!any\"\n"
        "\n";

    int result = 0;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    if (DetectAddressTestConfVars() < 0 && DetectPortTestConfVars() < 0)
        result = 1;

    ConfDeInit();
    ConfRestoreContextBackup();

    return result;
}

int AddressConfVarsTest02(void)
{
    static const char *dummy_conf_string =
        "%YAML 1.1\n"
        "---\n"
        "\n"
        "vars:\n"
        "\n"
        "  address-groups:\n"
        "\n"
        "    HOME_NET: \"any\"\n"
        "\n"
        "    EXTERNAL_NET: \"any\"\n"
        "\n"
        "  port-groups:\n"
        "\n"
        "    HTTP_PORTS: \"any\"\n"
        "\n"
        "    SHELLCODE_PORTS: \"!any\"\n"
        "\n";

    int result = 0;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    if (DetectAddressTestConfVars() == 0 && DetectPortTestConfVars() < 0)
        result = 1;

    ConfDeInit();
    ConfRestoreContextBackup();

    return result;
}

int AddressConfVarsTest03(void)
{
    static const char *dummy_conf_string =
        "%YAML 1.1\n"
        "---\n"
        "\n"
        "vars:\n"
        "\n"
        "  address-groups:\n"
        "\n"
        "    HOME_NET: \"any\"\n"
        "\n"
        "    EXTERNAL_NET: \"!$HOME_NET\"\n"
        "\n"
        "  port-groups:\n"
        "\n"
        "    HTTP_PORTS: \"any\"\n"
        "\n"
        "    SHELLCODE_PORTS: \"!$HTTP_PORTS\"\n"
        "\n";

    int result = 0;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    if (DetectAddressTestConfVars() < 0 && DetectPortTestConfVars() < 0)
        result = 1;

    ConfDeInit();
    ConfRestoreContextBackup();

    return result;
}

int AddressConfVarsTest04(void)
{
    static const char *dummy_conf_string =
        "%YAML 1.1\n"
        "---\n"
        "\n"
        "vars:\n"
        "\n"
        "  address-groups:\n"
        "\n"
        "    HOME_NET: \"any\"\n"
        "\n"
        "    EXTERNAL_NET: \"$HOME_NET\"\n"
        "\n"
        "  port-groups:\n"
        "\n"
        "    HTTP_PORTS: \"any\"\n"
        "\n"
        "    SHELLCODE_PORTS: \"$HTTP_PORTS\"\n"
        "\n";

    int result = 0;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    if (DetectAddressTestConfVars() == 0 && DetectPortTestConfVars() == 0)
        result = 1;

    ConfDeInit();
    ConfRestoreContextBackup();

    return result;
}

int AddressConfVarsTest05(void)
{
    static const char *dummy_conf_string =
        "%YAML 1.1\n"
        "---\n"
        "\n"
        "vars:\n"
        "\n"
        "  address-groups:\n"
        "\n"
        "    HOME_NET: \"any\"\n"
        "\n"
        "    EXTERNAL_NET: [192.168.0.1]\n"
        "\n"
        "  port-groups:\n"
        "\n"
        "    HTTP_PORTS: \"any\"\n"
        "\n"
        "    SHELLCODE_PORTS: [80]\n"
        "\n";

    int result = 0;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    if (DetectAddressTestConfVars() != -1 && DetectPortTestConfVars() != -1)
        goto end;

    result = 1;

 end:
    ConfDeInit();
    ConfRestoreContextBackup();

    return result;
}

#include "detect-engine.h"

/**
 * \test Test sig distribution over address groups
 */
static int AddressTestFunctions01(void)
{
    DetectAddress *a1 = NULL;
    DetectAddress *a2 = NULL;
    DetectAddressHead *h = NULL;
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    Signature s[2];
    memset(s,0x00,sizeof(s));

    s[0].num = 0;
    s[1].num = 1;

    a1 = DetectAddressParseSingle("255.0.0.0/8");
    if (a1 == NULL) {
        printf("a1 == NULL: ");
        goto end;
    }
    SigGroupHeadAppendSig(de_ctx, &a1->sh, &s[0]);

    a2 = DetectAddressParseSingle("0.0.0.0/0");
    if (a2 == NULL) {
        printf("a2 == NULL: ");
        goto end;
    }
    SigGroupHeadAppendSig(de_ctx, &a2->sh, &s[1]);

    SCLogDebug("a1");
    DetectAddressPrint(a1);
    SCLogDebug("a2");
    DetectAddressPrint(a2);

    h = DetectAddressHeadInit();
    if (h == NULL)
        goto end;
    DetectAddressInsert(de_ctx, h, a1);
    DetectAddressInsert(de_ctx, h, a2);

    if (h == NULL)
        goto end;

    DetectAddress *x = h->ipv4_head;
    for ( ; x != NULL; x = x->next) {
        SCLogDebug("x %p next %p", x, x->next);
        DetectAddressPrint(x);
        //SigGroupHeadPrintSigs(de_ctx, x->sh);
    }

    DetectAddress *one = h->ipv4_head;
    DetectAddress *two = one->next;

    int sig = 0;
    if ((one->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'one', but it shouldn't: ", sig);
        goto end;
    }
    sig = 1;
    if (!(one->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'one', but it shouldn't: ", sig);
        goto end;
    }
    sig = 1;
    if (!(two->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'two', but it shouldn't: ", sig);
        goto end;
    }

    result = 1;
end:
    if (h != NULL)
        DetectAddressHeadFree(h);
    return result;
}

/**
 * \test Test sig distribution over address groups
 */
static int AddressTestFunctions02(void)
{
    DetectAddress *a1 = NULL;
    DetectAddress *a2 = NULL;
    DetectAddressHead *h = NULL;
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    Signature s[2];
    memset(s,0x00,sizeof(s));

    s[0].num = 0;
    s[1].num = 1;

    a1 = DetectAddressParseSingle("255.0.0.0/8");
    if (a1 == NULL) {
        printf("a1 == NULL: ");
        goto end;
    }
    SigGroupHeadAppendSig(de_ctx, &a1->sh, &s[0]);

    a2 = DetectAddressParseSingle("0.0.0.0/0");
    if (a2 == NULL) {
        printf("a2 == NULL: ");
        goto end;
    }
    SigGroupHeadAppendSig(de_ctx, &a2->sh, &s[1]);

    SCLogDebug("a1");
    DetectAddressPrint(a1);
    SCLogDebug("a2");
    DetectAddressPrint(a2);

    h = DetectAddressHeadInit();
    if (h == NULL)
        goto end;
    DetectAddressInsert(de_ctx, h, a2);
    DetectAddressInsert(de_ctx, h, a1);

    BUG_ON(h == NULL);

    SCLogDebug("dp3");

    DetectAddress *x = h->ipv4_head;
    for ( ; x != NULL; x = x->next) {
        DetectAddressPrint(x);
        //SigGroupHeadPrintSigs(de_ctx, x->sh);
    }

    DetectAddress *one = h->ipv4_head;
    DetectAddress *two = one->next;

    int sig = 0;
    if ((one->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'one', but it shouldn't: ", sig);
        goto end;
    }
    sig = 1;
    if (!(one->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'one', but it shouldn't: ", sig);
        goto end;
    }
    sig = 1;
    if (!(two->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'two', but it shouldn't: ", sig);
        goto end;
    }

    result = 1;
end:
    if (h != NULL)
        DetectAddressHeadFree(h);
    return result;
}

/**
 * \test Test sig distribution over address groups
 */
static int AddressTestFunctions03(void)
{
    DetectAddress *a1 = NULL;
    DetectAddress *a2 = NULL;
    DetectAddressHead *h = NULL;
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    Signature s[2];
    memset(s,0x00,sizeof(s));

    s[0].num = 0;
    s[1].num = 1;

    a1 = DetectAddressParseSingle("ffff::/16");
    if (a1 == NULL) {
        printf("a1 == NULL: ");
        goto end;
    }
    SigGroupHeadAppendSig(de_ctx, &a1->sh, &s[0]);

    a2 = DetectAddressParseSingle("::/0");
    if (a2 == NULL) {
        printf("a2 == NULL: ");
        goto end;
    }
    SigGroupHeadAppendSig(de_ctx, &a2->sh, &s[1]);

    SCLogDebug("a1");
    DetectAddressPrint(a1);
    SCLogDebug("a2");
    DetectAddressPrint(a2);

    h = DetectAddressHeadInit();
    if (h == NULL)
        goto end;
    DetectAddressInsert(de_ctx, h, a1);
    DetectAddressInsert(de_ctx, h, a2);

    if (h == NULL)
        goto end;

    DetectAddress *x = h->ipv6_head;
    for ( ; x != NULL; x = x->next) {
        SCLogDebug("x %p next %p", x, x->next);
        DetectAddressPrint(x);
        //SigGroupHeadPrintSigs(de_ctx, x->sh);
    }

    DetectAddress *one = h->ipv6_head;
    DetectAddress *two = one->next;

    int sig = 0;
    if ((one->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'one', but it shouldn't: ", sig);
        goto end;
    }
    sig = 1;
    if (!(one->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'one', but it shouldn't: ", sig);
        goto end;
    }
    sig = 1;
    if (!(two->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'two', but it shouldn't: ", sig);
        goto end;
    }

    result = 1;
end:
    if (h != NULL)
        DetectAddressHeadFree(h);
    return result;
}

/**
 * \test Test sig distribution over address groups
 */
static int AddressTestFunctions04(void)
{
    DetectAddress *a1 = NULL;
    DetectAddress *a2 = NULL;
    DetectAddressHead *h = NULL;
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    Signature s[2];
    memset(s,0x00,sizeof(s));

    s[0].num = 0;
    s[1].num = 1;

    a1 = DetectAddressParseSingle("ffff::/16");
    if (a1 == NULL) {
        printf("a1 == NULL: ");
        goto end;
    }
    SigGroupHeadAppendSig(de_ctx, &a1->sh, &s[0]);

    a2 = DetectAddressParseSingle("::/0");
    if (a2 == NULL) {
        printf("a2 == NULL: ");
        goto end;
    }
    SigGroupHeadAppendSig(de_ctx, &a2->sh, &s[1]);

    SCLogDebug("a1");
    DetectAddressPrint(a1);
    SCLogDebug("a2");
    DetectAddressPrint(a2);

    h = DetectAddressHeadInit();
    if (h == NULL)
        goto end;
    DetectAddressInsert(de_ctx, h, a2);
    DetectAddressInsert(de_ctx, h, a1);

    BUG_ON(h == NULL);

    SCLogDebug("dp3");

    DetectAddress *x = h->ipv6_head;
    for ( ; x != NULL; x = x->next) {
        DetectAddressPrint(x);
        //SigGroupHeadPrintSigs(de_ctx, x->sh);
    }

    DetectAddress *one = h->ipv6_head;
    DetectAddress *two = one->next;

    int sig = 0;
    if ((one->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'one', but it shouldn't: ", sig);
        goto end;
    }
    sig = 1;
    if (!(one->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'one', but it shouldn't: ", sig);
        goto end;
    }
    sig = 1;
    if (!(two->sh->init->sig_array[sig / 8] & (1 << (sig % 8)))) {
        printf("sig %d part of 'two', but it shouldn't: ", sig);
        goto end;
    }

    result = 1;
end:
    if (h != NULL)
        DetectAddressHeadFree(h);
    return result;
}

#endif /* UNITTESTS */

void DetectAddressTests(void)
{
#ifdef UNITTESTS
    DetectAddressIPv4Tests();
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
    UtRegisterTest("AddressTestParse36", AddressTestParse36, 1);
    UtRegisterTest("AddressTestParse37", AddressTestParse37, 1);

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

    UtRegisterTest("AddressTestAddressGroupSetup01",
                   AddressTestAddressGroupSetup01, 1);
    UtRegisterTest("AddressTestAddressGroupSetup02",
                   AddressTestAddressGroupSetup02, 1);
    UtRegisterTest("AddressTestAddressGroupSetup03",
                   AddressTestAddressGroupSetup03, 1);
    UtRegisterTest("AddressTestAddressGroupSetup04",
                   AddressTestAddressGroupSetup04, 1);
    UtRegisterTest("AddressTestAddressGroupSetup05",
                   AddressTestAddressGroupSetup05, 1);
    UtRegisterTest("AddressTestAddressGroupSetup06",
                   AddressTestAddressGroupSetup06, 1);
    UtRegisterTest("AddressTestAddressGroupSetup07",
                   AddressTestAddressGroupSetup07, 1);
    UtRegisterTest("AddressTestAddressGroupSetup08",
                   AddressTestAddressGroupSetup08, 1);
    UtRegisterTest("AddressTestAddressGroupSetup09",
                   AddressTestAddressGroupSetup09, 1);
    UtRegisterTest("AddressTestAddressGroupSetup10",
                   AddressTestAddressGroupSetup10, 1);
    UtRegisterTest("AddressTestAddressGroupSetup11",
                   AddressTestAddressGroupSetup11, 1);
    UtRegisterTest("AddressTestAddressGroupSetup12",
                   AddressTestAddressGroupSetup12, 1);
    UtRegisterTest("AddressTestAddressGroupSetup13",
                   AddressTestAddressGroupSetup13, 1);
    UtRegisterTest("AddressTestAddressGroupSetupIPv414",
                   AddressTestAddressGroupSetupIPv414, 1);
    UtRegisterTest("AddressTestAddressGroupSetupIPv415",
                   AddressTestAddressGroupSetupIPv415, 1);
    UtRegisterTest("AddressTestAddressGroupSetupIPv416",
                   AddressTestAddressGroupSetupIPv416, 1);

    UtRegisterTest("AddressTestAddressGroupSetup14",
                   AddressTestAddressGroupSetup14, 1);
    UtRegisterTest("AddressTestAddressGroupSetup15",
                   AddressTestAddressGroupSetup15, 1);
    UtRegisterTest("AddressTestAddressGroupSetup16",
                   AddressTestAddressGroupSetup16, 1);
    UtRegisterTest("AddressTestAddressGroupSetup17",
                   AddressTestAddressGroupSetup17, 1);
    UtRegisterTest("AddressTestAddressGroupSetup18",
                   AddressTestAddressGroupSetup18, 1);
    UtRegisterTest("AddressTestAddressGroupSetup19",
                   AddressTestAddressGroupSetup19, 1);
    UtRegisterTest("AddressTestAddressGroupSetup20",
                   AddressTestAddressGroupSetup20, 1);
    UtRegisterTest("AddressTestAddressGroupSetup21",
                   AddressTestAddressGroupSetup21, 1);
    UtRegisterTest("AddressTestAddressGroupSetup22",
                   AddressTestAddressGroupSetup22, 1);
    UtRegisterTest("AddressTestAddressGroupSetup23",
                   AddressTestAddressGroupSetup23, 1);
    UtRegisterTest("AddressTestAddressGroupSetup24",
                   AddressTestAddressGroupSetup24, 1);
    UtRegisterTest("AddressTestAddressGroupSetup25",
                   AddressTestAddressGroupSetup25, 1);
    UtRegisterTest("AddressTestAddressGroupSetup26",
                   AddressTestAddressGroupSetup26, 1);

    UtRegisterTest("AddressTestAddressGroupSetup27",
                   AddressTestAddressGroupSetup27, 1);
    UtRegisterTest("AddressTestAddressGroupSetup28",
                   AddressTestAddressGroupSetup28, 1);
    UtRegisterTest("AddressTestAddressGroupSetup29",
                   AddressTestAddressGroupSetup29, 1);
    UtRegisterTest("AddressTestAddressGroupSetup30",
                   AddressTestAddressGroupSetup30, 1);
    UtRegisterTest("AddressTestAddressGroupSetup31",
                   AddressTestAddressGroupSetup31, 1);
    UtRegisterTest("AddressTestAddressGroupSetup32",
                   AddressTestAddressGroupSetup32, 1);
    UtRegisterTest("AddressTestAddressGroupSetup33",
                   AddressTestAddressGroupSetup33, 1);
    UtRegisterTest("AddressTestAddressGroupSetup34",
                   AddressTestAddressGroupSetup34, 1);
    UtRegisterTest("AddressTestAddressGroupSetup35",
                   AddressTestAddressGroupSetup35, 1);
    UtRegisterTest("AddressTestAddressGroupSetup36",
                   AddressTestAddressGroupSetup36, 1);
    UtRegisterTest("AddressTestAddressGroupSetup37",
                   AddressTestAddressGroupSetup37, 1);
    UtRegisterTest("AddressTestAddressGroupSetup38",
                   AddressTestAddressGroupSetup38, 1);
    UtRegisterTest("AddressTestAddressGroupSetup39",
                   AddressTestAddressGroupSetup39, 1);
    UtRegisterTest("AddressTestAddressGroupSetup40",
                   AddressTestAddressGroupSetup40, 1);
    UtRegisterTest("AddressTestAddressGroupSetup41",
                   AddressTestAddressGroupSetup41, 1);
    UtRegisterTest("AddressTestAddressGroupSetup42",
                   AddressTestAddressGroupSetup42, 1);
    UtRegisterTest("AddressTestAddressGroupSetup43",
                   AddressTestAddressGroupSetup43, 1);
    UtRegisterTest("AddressTestAddressGroupSetup44",
                   AddressTestAddressGroupSetup44, 1);
    UtRegisterTest("AddressTestAddressGroupSetup45",
                   AddressTestAddressGroupSetup45, 1);
    UtRegisterTest("AddressTestAddressGroupSetup46",
                   AddressTestAddressGroupSetup46, 1);
    UtRegisterTest("AddressTestAddressGroupSetup47",
                   AddressTestAddressGroupSetup47, 1);
    UtRegisterTest("AddressTestAddressGroupSetup48",
                   AddressTestAddressGroupSetup48, 1);

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

    UtRegisterTest("AddressTestParseInvalidMask01",
                   AddressTestParseInvalidMask01, 1);
    UtRegisterTest("AddressTestParseInvalidMask02",
                   AddressTestParseInvalidMask02, 1);
    UtRegisterTest("AddressTestParseInvalidMask03",
                   AddressTestParseInvalidMask03, 1);

    UtRegisterTest("AddressConfVarsTest01 ", AddressConfVarsTest01, 1);
    UtRegisterTest("AddressConfVarsTest02 ", AddressConfVarsTest02, 1);
    UtRegisterTest("AddressConfVarsTest03 ", AddressConfVarsTest03, 1);
    UtRegisterTest("AddressConfVarsTest04 ", AddressConfVarsTest04, 1);
    UtRegisterTest("AddressConfVarsTest05 ", AddressConfVarsTest05, 1);

    UtRegisterTest("AddressTestFunctions01", AddressTestFunctions01, 1);
    UtRegisterTest("AddressTestFunctions02", AddressTestFunctions02, 1);
    UtRegisterTest("AddressTestFunctions03", AddressTestFunctions03, 1);
    UtRegisterTest("AddressTestFunctions04", AddressTestFunctions04, 1);
#endif /* UNITTESTS */
}
