/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#include "util-byte.h"
#include "util-print.h"
#include "util-var.h"

/* prototypes */
#ifdef DEBUG
static void DetectAddressPrint(DetectAddress *);
#else
#define DetectAddressPrint(...)
#endif
static int DetectAddressCutNot(DetectAddress *, DetectAddress **);
static int DetectAddressCut(DetectEngineCtx *, DetectAddress *, DetectAddress *,
                            DetectAddress **);
static int DetectAddressParse2(const DetectEngineCtx *de_ctx, DetectAddressHead *gh,
        DetectAddressHead *ghn, const char *s, int negate, ResolvedVariablesList *var_list,
        int recur);

int DetectAddressMergeNot(DetectAddressHead *gh, DetectAddressHead *ghn);

/**
 * \brief Creates and returns a new instance of a DetectAddress.
 *
 * \retval ag Pointer to the newly created DetectAddress on success;
 *            NULL on failure.
 */
DetectAddress *DetectAddressInit(void)
{
    DetectAddress *ag = SCCalloc(1, sizeof(DetectAddress));
    if (unlikely(ag == NULL))
        return NULL;
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

    SCFree(ag);
    return;
}

/**
 * \internal
 * \brief Returns a new instance of DetectAddressHead.
 *
 * \retval gh Pointer to the new instance of DetectAddressHead.
 */
static DetectAddressHead *DetectAddressHeadInit(void)
{
    DetectAddressHead *gh = SCCalloc(1, sizeof(DetectAddressHead));
    if (unlikely(gh == NULL))
        return NULL;
    return gh;
}

/**
 * \internal
 * \brief Frees a DetectAddressHead instance.
 *
 * \param gh Pointer to the DetectAddressHead instance to be freed.
 */
static void DetectAddressHeadFree(DetectAddressHead *gh)
{
    if (gh != NULL) {
        DetectAddressHeadCleanup(gh);
        SCFree(gh);
    }
}

/**
 * \brief copy a DetectAddress
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
    return ag;
}

#ifdef DEBUG
/**
 * \brief Prints the address data information for all the DetectAddress
 *        instances in the DetectAddress list sent as the argument.
 *
 * \param head Pointer to a list of DetectAddress instances.
 */
void DetectAddressPrintList(DetectAddress *head)
{
    SCLogInfo("list:");
    for (DetectAddress *cur = head; cur != NULL; cur = cur->next) {
        DetectAddressPrint(cur);
    }
    SCLogInfo("endlist");
}
#endif

/**
 * \internal
 * \brief Frees a list of DetectAddress instances.
 *
 * \param head Pointer to a list of DetectAddress instances to be freed.
 */
static void DetectAddressCleanupList(DetectAddress *head)
{
    for (DetectAddress *cur = head; cur != NULL; ) {
        DetectAddress *next = cur->next;
        cur->next = NULL;
        DetectAddressFree(cur);
        cur = next;
    }
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
    if (newhead->ip.family == AF_INET) {
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

    if (new->ip.family == AF_INET)
        head = gh->ipv4_head;
    else if (new->ip.family == AF_INET6)
        head = gh->ipv6_head;

    return head;
}

/**
 * \internal
 * \brief insert DetectAddress into a DetectAddressHead
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
static int DetectAddressInsert(DetectEngineCtx *de_ctx, DetectAddressHead *gh,
                        DetectAddress *new)
{
    DetectAddress *head = NULL;
    DetectAddress *cur = NULL;
    DetectAddress *c = NULL;
    int r = 0;

    if (new == NULL)
        return 0;

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
 * \brief Checks if two address group lists are equal.
 *
 * \param list1 Pointer to the first address group list.
 * \param list2 Pointer to the second address group list.
 *
 * \retval true On success.
 * \retval false On failure.
 */
bool DetectAddressListsAreEqual(DetectAddress *list1, DetectAddress *list2)
{
    DetectAddress *item = list1;
    DetectAddress *it = list2;

    // First, compare items one by one.
    while (item != NULL && it != NULL) {
        if (DetectAddressCmp(item, it) != ADDRESS_EQ) {
            return false;
        }

        item = item->next;
        it = it->next;
    }

    // Are the lists of the same size?
    if (!(item == NULL && it == NULL)) {
        return false;
    }

    return true;
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
static int DetectAddressParseString(DetectAddress *dd, const char *str)
{
    char *ip = NULL;
    char *ip2 = NULL;
    char *mask = NULL;
    int r = 0;
    char ipstr[256];

    /* shouldn't see 'any' here */
    BUG_ON(strcasecmp(str, "any") == 0);

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

            if ((strchr (mask, '.')) == NULL) {
                /* 1.2.3.4/24 format */

                for (size_t u = 0; u < strlen(mask); u++) {
                    if(!isdigit((unsigned char)mask[u]))
                        goto error;
                }

                int cidr;
                if (StringParseI32RangeCheck(&cidr, 10, 0, (const char *)mask, 0, 32) < 0)
                    goto error;
                netmask = CIDRGet(cidr);
            } else {
                /* 1.2.3.4/255.255.255.0 format */
                r = inet_pton(AF_INET, mask, &in);
                if (r <= 0)
                    goto error;

                netmask = in.s_addr;

                /* validate netmask */
                int cidr = CIDRFromMask(netmask);
                if (cidr < 0) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE,
                            "netmask \"%s\" is not usable. Only netmasks that are compatible with "
                            "CIDR notation are supported. See #5168.",
                            mask);
                    goto error;
                }
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
            if (SCNtohl(dd->ip.addr_data32[0]) > SCNtohl(dd->ip2.addr_data32[0]))
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

            int cidr;
            if (StringParseI32RangeCheck(&cidr, 10, 0, (const char *)mask, 0, 128) < 0)
                goto error;

            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0)
                goto error;
            memcpy(&ip6addr, &in6.s6_addr, sizeof(ip6addr));

            CIDRGetIPv6(cidr, &mask6);
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
static DetectAddress *DetectAddressParseSingle(const char *str)
{
    SCLogDebug("str %s", str);

    DetectAddress *dd = DetectAddressInit();
    if (dd == NULL)
        return NULL;

    if (DetectAddressParseString(dd, str) < 0) {
        SCLogDebug("AddressParse failed");
        DetectAddressFree(dd);
        return NULL;
    }

    return dd;
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
static int DetectAddressSetup(DetectAddressHead *gh, const char *s)
{
    SCLogDebug("gh %p, s %s", gh, s);

    while (*s != '\0' && isspace(*s))
        s++;

    if (strcasecmp(s, "any") == 0) {
        SCLogDebug("adding 0.0.0.0/0 and ::/0 as we\'re handling \'any\'");

        DetectAddress *ad = DetectAddressParseSingle("0.0.0.0/0");
        if (ad == NULL)
            return -1;

        BUG_ON(ad->ip.family == 0);

        if (DetectAddressInsert(NULL, gh, ad) < 0) {
            SCLogDebug("DetectAddressInsert failed");
            DetectAddressFree(ad);
            return -1;
        }

        ad = DetectAddressParseSingle("::/0");
        if (ad == NULL)
            return -1;

        BUG_ON(ad->ip.family == 0);

        if (DetectAddressInsert(NULL, gh, ad) < 0) {
            SCLogDebug("DetectAddressInsert failed");
            DetectAddressFree(ad);
            return -1;
        }
        return 0;
    }

    /* parse the address */
    DetectAddress *ad = DetectAddressParseSingle(s);
    if (ad == NULL) {
        SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC,
                "failed to parse address \"%s\"", s);
        return -1;
    }

    /* handle the not case, we apply the negation then insert the part(s) */
    if (ad->flags & ADDRESS_FLAG_NOT) {
        DetectAddress *ad2 = NULL;

        if (DetectAddressCutNot(ad, &ad2) < 0) {
            SCLogDebug("DetectAddressCutNot failed");
            DetectAddressFree(ad);
            return -1;
        }

        /* normally a 'not' will result in two ad's unless the 'not' is on the start or end
         * of the address space (e.g. 0.0.0.0 or 255.255.255.255). */
        if (ad2 != NULL) {
            if (DetectAddressInsert(NULL, gh, ad2) < 0) {
                SCLogDebug("DetectAddressInsert failed");
                DetectAddressFree(ad);
                DetectAddressFree(ad2);
                return -1;
            }
        }
    }

    int r = DetectAddressInsert(NULL, gh, ad);
    if (r < 0) {
        SCLogDebug("DetectAddressInsert failed");
        DetectAddressFree(ad);
        return -1;
    }
    SCLogDebug("r %d",r);
    return 0;
}

/**
 * \brief Parses an address string and updates the 2 address heads with the
 *        address data.
 *
 * Note that this function should only be called by the wrapping function
 * DetectAddressParse2. The wrapping function provides long address handling
 * when the address size exceeds a threshold value.
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
 * \param negate Flag that indicates if the received address string is negated
 *               or not.  0 if it is not, 1 it it is.
 *
 * \retval  0 On successfully parsing.
 * \retval -1 On failure.
 */
static int DetectAddressParseInternal(const DetectEngineCtx *de_ctx, DetectAddressHead *gh,
        DetectAddressHead *ghn, const char *s, int negate, ResolvedVariablesList *var_list,
        int recur, char *address, size_t address_length)
{
    size_t x = 0;
    size_t u = 0;
    int o_set = 0, n_set = 0, d_set = 0;
    int depth = 0;
    const char *rule_var_address = NULL;
    char *temp_rule_var_address = NULL;

    if (++recur > 64) {
        SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC, "address block recursion "
                "limit reached (max 64)");
        goto error;
    }

    SCLogDebug("s %s negate %s", s, negate ? "true" : "false");

    size_t size = strlen(s);
    for (u = 0, x = 0; u < size && x < address_length; u++) {
        if (x == (address_length - 1)) {
            SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC,
                    "Hit the address buffer"
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

                    if (DetectAddressParse2(de_ctx, gh, ghn, address, (negate + n_set) % 2, var_list, recur) < 0)
                        goto error;
                } else {
                    /* negated block
                     *
                     * Extra steps are necessary. First consider it as a normal
                     * (non-negated) range. Merge the + and - ranges if
                     * applicable. Then insert the result into the ghn list. */
                    SCLogDebug("negated block");

                    DetectAddressHead tmp_gh = { NULL, NULL };
                    DetectAddressHead tmp_ghn = { NULL, NULL };

                    if (DetectAddressParse2(de_ctx, &tmp_gh, &tmp_ghn, address, 0, var_list, recur) < 0) {
                        DetectAddressHeadCleanup(&tmp_gh);
                        DetectAddressHeadCleanup(&tmp_ghn);
                        goto error;
                    }

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
                    if (DetectAddressMergeNot(&tmp_gh, &tmp_ghn) < 0) {
                        DetectAddressHeadCleanup(&tmp_ghn);
                        DetectAddressHeadCleanup(&tmp_gh);
                        goto error;
                    }
                    DetectAddressHeadCleanup(&tmp_ghn);

                    SCLogDebug("merged successfully");

                    /* insert the IPv4 addresses into the negated list */
                    for (tmp_ad = tmp_gh.ipv4_head; tmp_ad; tmp_ad = tmp_ad->next) {
                        /* work with a copy of the address group */
                        tmp_ad2 = DetectAddressCopy(tmp_ad);
                        if (tmp_ad2 == NULL) {
                            SCLogDebug("DetectAddressCopy failed");
                            DetectAddressHeadCleanup(&tmp_gh);
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
                            DetectAddressHeadCleanup(&tmp_gh);
                            goto error;
                        }
                        DetectAddressPrint(tmp_ad2);
                        DetectAddressInsert(NULL, ghn, tmp_ad2);
                    }

                    DetectAddressHeadCleanup(&tmp_gh);
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
                if ((negate + n_set) % 2) {
                    temp_rule_var_address = SCMalloc(strlen(rule_var_address) + 3);
                    if (unlikely(temp_rule_var_address == NULL))
                        goto error;
                    snprintf(temp_rule_var_address, strlen(rule_var_address) + 3,
                             "[%s]", rule_var_address);
                } else {
                    temp_rule_var_address = SCStrdup(rule_var_address);
                    if (unlikely(temp_rule_var_address == NULL))
                        goto error;
                }

                if (DetectAddressParse2(de_ctx, gh, ghn, temp_rule_var_address,
                            (negate + n_set) % 2, var_list, recur) < 0) {
                    if (temp_rule_var_address != rule_var_address)
                        SCFree(temp_rule_var_address);
                    goto error;
                }
                d_set = 0;
                n_set = 0;
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
            if (x == address_length) {
                address[x - 1] = '\0';
            } else {
                address[x] = '\0';
            }
            x = 0;

            if (AddVariableToResolveList(var_list, address) == -1) {
                SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Found a loop in a address "
                    "groups declaration. This is likely a misconfiguration.");
                goto error;
            }

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
                if ((negate + n_set) % 2) {
                    temp_rule_var_address = SCMalloc(strlen(rule_var_address) + 3);
                    if (unlikely(temp_rule_var_address == NULL))
                        goto error;
                    snprintf(temp_rule_var_address, strlen(rule_var_address) + 3,
                            "[%s]", rule_var_address);
                } else {
                    temp_rule_var_address = SCStrdup(rule_var_address);
                    if (unlikely(temp_rule_var_address == NULL))
                        goto error;
                }

                if (DetectAddressParse2(de_ctx, gh, ghn, temp_rule_var_address,
                            (negate + n_set) % 2, var_list, recur) < 0) {
                    SCLogDebug("DetectAddressParse2 hates us");
                    if (temp_rule_var_address != rule_var_address)
                        SCFree(temp_rule_var_address);
                    goto error;
                }
                d_set = 0;
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
 * \brief Wrapper function for address parsing to minimize heap allocs during address parsing.
 *
 * \retval Return value from DetectAddressParseInternal
 */
static int DetectAddressParse2(const DetectEngineCtx *de_ctx, DetectAddressHead *gh,
        DetectAddressHead *ghn, const char *s, int negate, ResolvedVariablesList *var_list,
        int recur)
{
    int rc;
#define MAX_ADDRESS_LENGTH 8192

    size_t address_length = strlen(s);
    if (address_length > (MAX_ADDRESS_LENGTH - 1)) {
        char *address = SCCalloc(1, address_length);
        if (address == NULL) {
            SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC, "Unable to allocate"
                                                      " memory for address parsing.");
            return -1;
        }
        rc = DetectAddressParseInternal(
                de_ctx, gh, ghn, s, negate, var_list, recur, address, address_length);
        SCFree(address);
    } else {
        char address[MAX_ADDRESS_LENGTH] = "";
        rc = DetectAddressParseInternal(
                de_ctx, gh, ghn, s, negate, var_list, recur, address, MAX_ADDRESS_LENGTH);
    }
    return rc;
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

    ResolvedVariablesList var_list = TAILQ_HEAD_INITIALIZER(var_list);

    ConfNode *address_vars_node = ConfGetNode("vars.address-groups");
    if (address_vars_node == NULL) {
        return 0;
    }

    DetectAddressHead *gh = NULL;
    DetectAddressHead *ghn = NULL;

    ConfNode *seq_node;
    TAILQ_FOREACH(seq_node, &address_vars_node->head, next) {
        SCLogDebug("Testing %s - %s", seq_node->name, seq_node->val);

        gh = DetectAddressHeadInit();
        if (gh == NULL) {
            goto error;
        }
        ghn = DetectAddressHeadInit();
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

        int r = DetectAddressParse2(
                NULL, gh, ghn, seq_node->val, /* start with negate no */ 0, &var_list, 0);

        CleanVariableResolveList(&var_list);

        if (r < 0) {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                    "failed to parse address var \"%s\" with value \"%s\". "
                    "Please check its syntax",
                    seq_node->name, seq_node->val);
            goto error;
        }

        if (DetectAddressIsCompleteIPSpace(ghn)) {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                    "address var - \"%s\" has the complete IP space negated "
                    "with its value \"%s\".  Rule address range is NIL. "
                    "Probably have a !any or an address range that supplies "
                    "a NULL address range",
                    seq_node->name, seq_node->val);
            goto error;
        }

        DetectAddressHeadFree(gh);
        gh = NULL;
        DetectAddressHeadFree(ghn);
        ghn = NULL;
    }

    return 0;
 error:
    if (gh != NULL)
        DetectAddressHeadFree(gh);
    if (ghn != NULL)
        DetectAddressHeadFree(ghn);
    return -1;
}

#include "util-hash-lookup3.h"

typedef struct DetectAddressMap_ {
    char *string;
    DetectAddressHead *address;
    bool contains_negation;
} DetectAddressMap;

static uint32_t DetectAddressMapHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    const DetectAddressMap *map = (DetectAddressMap *)data;
    uint32_t hash = 0;

    hash = hashlittle_safe(map->string, strlen(map->string), 0);
    hash %= ht->array_size;

    return hash;
}

static char DetectAddressMapCompareFunc(void *data1, uint16_t len1, void *data2,
                                        uint16_t len2)
{
    DetectAddressMap *map1 = (DetectAddressMap *)data1;
    DetectAddressMap *map2 = (DetectAddressMap *)data2;

    char r = (strcmp(map1->string, map2->string) == 0);
    return r;
}

static void DetectAddressMapFreeFunc(void *data)
{
    DetectAddressMap *map = (DetectAddressMap *)data;
    if (map != NULL) {
        DetectAddressHeadFree(map->address);
        SCFree(map->string);
    }
    SCFree(map);
}

int DetectAddressMapInit(DetectEngineCtx *de_ctx)
{
    de_ctx->address_table = HashListTableInit(4096, DetectAddressMapHashFunc,
                                                    DetectAddressMapCompareFunc,
                                                    DetectAddressMapFreeFunc);
    if (de_ctx->address_table == NULL)
        return -1;

    return 0;
}

void DetectAddressMapFree(DetectEngineCtx *de_ctx)
{
    if (de_ctx->address_table == NULL)
        return;

    HashListTableFree(de_ctx->address_table);
    de_ctx->address_table = NULL;
    return;
}

static int DetectAddressMapAdd(DetectEngineCtx *de_ctx, const char *string,
                        DetectAddressHead *address, bool contains_negation)
{
    DetectAddressMap *map = SCCalloc(1, sizeof(*map));
    if (map == NULL)
        return -1;

    map->string = SCStrdup(string);
    if (map->string == NULL) {
        SCFree(map);
        return -1;
    }
    map->address = address;
    map->contains_negation = contains_negation;

    BUG_ON(HashListTableAdd(de_ctx->address_table, (void *)map, 0) != 0);
    return 0;
}

static const DetectAddressMap *DetectAddressMapLookup(DetectEngineCtx *de_ctx,
                                                const char *string)
{
    DetectAddressMap map = { (char *)string, NULL, false };

    const DetectAddressMap *res = HashListTableLookup(de_ctx->address_table,
            &map, 0);
    return res;
}

/**
 * \brief Parses an address group sent as a character string and updates the
 *        DetectAddressHead sent as the argument with the relevant address
 *        ranges from the parsed string.
 *
 * \param de_ctx Pointer to the detection engine context
 * \param gh  Pointer to the DetectAddressHead.
 * \param str Pointer to the character string containing the address group
 *            that has to be parsed.
 *
 * \retval  1 On success. Contained negation.
 * \retval  0 On success. Did not contain negation.
 * \retval -1 On failure.
 */
int DetectAddressParse(const DetectEngineCtx *de_ctx,
                       DetectAddressHead *gh, const char *str)
{
    SCLogDebug("gh %p, str %s", gh, str);

    if (str == NULL) {
        SCLogDebug("DetectAddressParse can not be run with NULL address");
        return -1;
    }

    DetectAddressHead *ghn = DetectAddressHeadInit();
    if (ghn == NULL) {
        SCLogDebug("DetectAddressHeadInit for ghn failed");
        return -1;
    }

    int r = DetectAddressParse2(de_ctx, gh, ghn, str, /* start with negate no */ 0, NULL, 0);
    if (r < 0) {
        SCLogDebug("DetectAddressParse2 returned %d", r);
        DetectAddressHeadFree(ghn);
        return -1;
    }

    SCLogDebug("gh->ipv4_head %p, ghn->ipv4_head %p", gh->ipv4_head,
               ghn->ipv4_head);

    bool contains_negation = (ghn->ipv4_head != NULL || ghn->ipv6_head != NULL);

    /* merge the 'not' address groups */
    if (DetectAddressMergeNot(gh, ghn) < 0) {
        SCLogDebug("DetectAddressMergeNot failed");
        DetectAddressHeadFree(ghn);
        return -1;
    }

    /* free the temp negate head */
    DetectAddressHeadFree(ghn);
    return contains_negation ? 1 : 0;
}

const DetectAddressHead *DetectParseAddress(DetectEngineCtx *de_ctx,
        const char *string, bool *contains_negation)
{
    const DetectAddressMap *res = DetectAddressMapLookup(de_ctx, string);
    if (res != NULL) {
        SCLogDebug("found: %s :: %p", string, res);
        *contains_negation = res->contains_negation;
        return res->address;
    }

    SCLogDebug("%s not found", string);

    DetectAddressHead *head = DetectAddressHeadInit();
    if (head == NULL)
        return NULL;

    const int r = DetectAddressParse(de_ctx, head, string);
    if (r < 0) {
        DetectAddressHeadFree(head);
        return NULL;
    } else if (r == 1) {
        *contains_negation = true;
    } else {
        *contains_negation = false;
    }

    DetectAddressMapAdd((DetectEngineCtx *)de_ctx, string, head,
            *contains_negation);
    return head;
}

/**
 * \brief Cleans a DetectAddressHead.  The functions frees the address
 *        group heads(ipv4 and ipv6) inside the DetectAddressHead
 *        instance.
 *
 * \param gh Pointer to the DetectAddressHead instance that has to be
 *           cleaned.
 */
void DetectAddressHeadCleanup(DetectAddressHead *gh)
{
    if (gh != NULL) {
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
 * \brief Dispatcher function that calls the ipv4 and ipv6 address cut functions.
 *        Have a look at DetectAddressCutIPv4() and DetectAddressCutIPv6() for
 *        explanations on what these functions do.
 *
 * \param de_ctx Pointer to the DetectEngineCtx.
 * \param a      Pointer to the first address to be cut.
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

    if (a->ip.family == AF_INET)
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
int DetectAddressMatchIPv4(const DetectMatchAddressIPv4 *addrs,
        uint16_t addrs_cnt, const Address *a)
{
    SCEnter();

    if (addrs == NULL || addrs_cnt == 0) {
        SCReturnInt(0);
    }

    uint32_t match_addr = SCNtohl(a->addr_data32[0]);
    for (uint16_t idx = 0; idx < addrs_cnt; idx++) {
        if (match_addr >= addrs[idx].ip && match_addr <= addrs[idx].ip2) {
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
int DetectAddressMatchIPv6(const DetectMatchAddressIPv6 *addrs,
        uint16_t addrs_cnt, const Address *a)
{
    SCEnter();

    if (addrs == NULL || addrs_cnt == 0) {
        SCReturnInt(0);
    }

    uint32_t match_addr[4];
    match_addr[0] = SCNtohl(a->addr_data32[0]);
    match_addr[1] = SCNtohl(a->addr_data32[1]);
    match_addr[2] = SCNtohl(a->addr_data32[2]);
    match_addr[3] = SCNtohl(a->addr_data32[3]);

    /* See if the packet address is within the range of any entry in the
     * signature's address match array.
     */
    for (uint16_t idx = 0; idx < addrs_cnt; idx++) {
        uint16_t result1 = 0, result2 = 0;

        /* See if packet address equals either limit. Return 1 if true. */
        if (0 == memcmp(match_addr, addrs[idx].ip, sizeof(match_addr))) {
            SCReturnInt(1);
        }
        if (0 == memcmp(match_addr, addrs[idx].ip2, sizeof(match_addr))) {
            SCReturnInt(1);
        }

        /* See if packet address is greater than lower limit
         * of the current signature address match pair.
         */
        for (int i = 0; i < 4; i++) {
            if (match_addr[i] > addrs[idx].ip[i]) {
                result1 = 1;
                break;
            }
            if (match_addr[i] < addrs[idx].ip[i]) {
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
        for (int i = 0; i < 4; i++) {
            if (match_addr[i] < addrs[idx].ip2[i]) {
                result2 = 1;
                break;
            }
            if (match_addr[i] > addrs[idx].ip2[i]) {
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
 *        We basically check that the address falls in between the address
 *        range in DetectAddress.
 *
 * \param dd Pointer to the DetectAddress instance.
 * \param a  Pointer to an Address instance.
 *
 * \param 1 On a match.
 * \param 0 On no match.
 */
static int DetectAddressMatch(DetectAddress *dd, Address *a)
{
    SCEnter();

    if (dd->ip.family != a->family) {
        SCReturnInt(0);
    }

    //DetectAddressPrint(dd);
    //AddressDebugPrint(a);

    switch (a->family) {
        case AF_INET:

            /* XXX figure out a way to not need to do this SCNtohl if we switch to
             * Address inside DetectAddressData we can do uint8_t checks */
            if (SCNtohl(a->addr_data32[0]) >= SCNtohl(dd->ip.addr_data32[0]) &&
                SCNtohl(a->addr_data32[0]) <= SCNtohl(dd->ip2.addr_data32[0]))
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

#ifdef DEBUG
/**
 * \brief Prints the address data held by the DetectAddress. If the address
 *        data family is IPv4, we print the the ipv4 address and mask, and
 *        if the address data family is IPv6, we print the ipv6 address and
 *        mask.
 *
 * \param ad Pointer to the DetectAddress instance to be printed.
 */
static void DetectAddressPrint(DetectAddress *gr)
{
    if (gr == NULL)
        return;

    if (gr->ip.family == AF_INET) {
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
#endif

/**
 * \brief Find the group matching address in a group head.
 *
 * \param gh Pointer to the address group head(DetectAddressHead instance).
 * \param a  Pointer to an Address instance.
 *
 * \retval g On success pointer to an DetectAddress if we find a match
 *           for the Address "a", in the DetectAddressHead "gh".
 */
DetectAddress *DetectAddressLookupInHead(const DetectAddressHead *gh, Address *a)
{
    SCEnter();

    DetectAddress *g = NULL;

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

static int UTHValidateDetectAddressHead(DetectAddressHead *gh, int nranges, UTHValidateDetectAddressHeadRange *expectations)
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

static int AddressTestParse01(void)
{
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

static int AddressTestParse02(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4");

    if (dd) {
        if (dd->ip2.addr_data32[0] != SCNtohl(16909060) ||
            dd->ip.addr_data32[0] != SCNtohl(16909060)) {
            result = 0;
        }

        printf("ip %"PRIu32", ip2 %"PRIu32"\n", dd->ip.addr_data32[0], dd->ip2.addr_data32[0]);
        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

static int AddressTestParse03(void)
{
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4/255.255.255.0");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

static int AddressTestParse04(void)
{
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4/255.255.255.0");
    FAIL_IF_NULL(dd);

    char left[16], right[16];
    PrintInet(AF_INET, (const void *)&dd->ip.addr_data32[0], left, sizeof(left));
    PrintInet(AF_INET, (const void *)&dd->ip2.addr_data32[0], right, sizeof(right));
    SCLogDebug("left %s right %s", left, right);
    FAIL_IF_NOT(dd->ip.addr_data32[0] == SCNtohl(16909056));
    FAIL_IF_NOT(dd->ip2.addr_data32[0] == SCNtohl(16909311));
    FAIL_IF_NOT(strcmp(left, "1.2.3.0") == 0);
    FAIL_IF_NOT(strcmp(right, "1.2.3.255") == 0);

    DetectAddressFree(dd);
    PASS;
}

/** \test that address range sets proper start address */
static int AddressTestParse04bug5081(void)
{
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.64/26");
    FAIL_IF_NULL(dd);

    char left[16], right[16];
    PrintInet(AF_INET, (const void *)&dd->ip.addr_data32[0], left, sizeof(left));
    PrintInet(AF_INET, (const void *)&dd->ip2.addr_data32[0], right, sizeof(right));
    SCLogDebug("left %s right %s", left, right);
    FAIL_IF_NOT(strcmp(left, "1.2.3.64") == 0);
    FAIL_IF_NOT(strcmp(right, "1.2.3.127") == 0);

    DetectAddressFree(dd);
    PASS;
}

static int AddressTestParse05(void)
{
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4/24");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

static int AddressTestParse06(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4/24");

    if (dd) {
        if (dd->ip2.addr_data32[0] != SCNtohl(16909311) ||
            dd->ip.addr_data32[0] != SCNtohl(16909056)) {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

static int AddressTestParse07(void)
{
    DetectAddress *dd = DetectAddressParseSingle("2001::/3");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

static int AddressTestParse08(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("2001::/3");

    if (dd) {
        if (dd->ip.addr_data32[0] != SCNtohl(536870912) || dd->ip.addr_data32[1] != 0x00000000 ||
            dd->ip.addr_data32[2] != 0x00000000 || dd->ip.addr_data32[3] != 0x00000000 ||

            dd->ip2.addr_data32[0] != SCNtohl(1073741823) || dd->ip2.addr_data32[1] != 0xFFFFFFFF ||
            dd->ip2.addr_data32[2] != 0xFFFFFFFF || dd->ip2.addr_data32[3] != 0xFFFFFFFF) {
            DetectAddressPrint(dd);
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

static int AddressTestParse09(void)
{
    DetectAddress *dd = DetectAddressParseSingle("2001::1/128");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

static int AddressTestParse10(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("2001::/128");

   if (dd) {
        if (dd->ip.addr_data32[0] != SCNtohl(536936448) || dd->ip.addr_data32[1] != 0x00000000 ||
            dd->ip.addr_data32[2] != 0x00000000 || dd->ip.addr_data32[3] != 0x00000000 ||

            dd->ip2.addr_data32[0] != SCNtohl(536936448) || dd->ip2.addr_data32[1] != 0x00000000 ||
            dd->ip2.addr_data32[2] != 0x00000000 || dd->ip2.addr_data32[3] != 0x00000000) {
            DetectAddressPrint(dd);
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

static int AddressTestParse11(void)
{
    DetectAddress *dd = DetectAddressParseSingle("2001::/48");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

static int AddressTestParse12(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("2001::/48");

    if (dd) {
        if (dd->ip.addr_data32[0] != SCNtohl(536936448) || dd->ip.addr_data32[1] != 0x00000000 ||
            dd->ip.addr_data32[2] != 0x00000000 || dd->ip.addr_data32[3] != 0x00000000 ||

            dd->ip2.addr_data32[0] != SCNtohl(536936448) || dd->ip2.addr_data32[1] != SCNtohl(65535) ||
            dd->ip2.addr_data32[2] != 0xFFFFFFFF || dd->ip2.addr_data32[3] != 0xFFFFFFFF) {
            DetectAddressPrint(dd);
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}
static int AddressTestParse13(void)
{
    DetectAddress *dd = DetectAddressParseSingle("2001::/16");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

static int AddressTestParse14(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("2001::/16");

    if (dd) {
        if (dd->ip.addr_data32[0] != SCNtohl(536936448) || dd->ip.addr_data32[1] != 0x00000000 ||
            dd->ip.addr_data32[2] != 0x00000000 || dd->ip.addr_data32[3] != 0x00000000 ||

            dd->ip2.addr_data32[0] != SCNtohl(537001983) || dd->ip2.addr_data32[1] != 0xFFFFFFFF ||
            dd->ip2.addr_data32[2] != 0xFFFFFFFF || dd->ip2.addr_data32[3] != 0xFFFFFFFF) {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

static int AddressTestParse15(void)
{
    DetectAddress *dd = DetectAddressParseSingle("2001::/0");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

static int AddressTestParse16(void)
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

static int AddressTestParse17(void)
{
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4-1.2.3.6");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

static int AddressTestParse18(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.4-1.2.3.6");

    if (dd) {
        if (dd->ip2.addr_data32[0] != SCNtohl(16909062) ||
            dd->ip.addr_data32[0] != SCNtohl(16909060)) {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

static int AddressTestParse19(void)
{
    DetectAddress *dd = DetectAddressParseSingle("1.2.3.6-1.2.3.4");

    if (dd) {
        DetectAddressFree(dd);
        return 0;
    }

    return 1;
}

static int AddressTestParse20(void)
{
    DetectAddress *dd = DetectAddressParseSingle("2001::1-2001::4");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

static int AddressTestParse21(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("2001::1-2001::4");

    if (dd) {
        if (dd->ip.addr_data32[0] != SCNtohl(536936448) || dd->ip.addr_data32[1] != 0x00000000 ||
            dd->ip.addr_data32[2] != 0x00000000 || dd->ip.addr_data32[3] != SCNtohl(1) ||

            dd->ip2.addr_data32[0] != SCNtohl(536936448) || dd->ip2.addr_data32[1] != 0x00000000 ||
            dd->ip2.addr_data32[2] != 0x00000000 || dd->ip2.addr_data32[3] != SCNtohl(4)) {
            result = 0;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

static int AddressTestParse22(void)
{
    DetectAddress *dd = DetectAddressParseSingle("2001::4-2001::1");

    if (dd) {
        DetectAddressFree(dd);
        return 0;
    }

    return 1;
}

static int AddressTestParse23(void)
{
    DetectAddressHead *gh = DetectAddressHeadInit();
    FAIL_IF_NULL(gh);
    int r = DetectAddressParse(NULL, gh, "any");
    FAIL_IF_NOT(r == 0);
    DetectAddressHeadFree(gh);
    PASS;
}

static int AddressTestParse24(void)
{
    DetectAddressHead *gh = DetectAddressHeadInit();
    FAIL_IF_NULL(gh);
    int r = DetectAddressParse(NULL, gh, "Any");
    FAIL_IF_NOT(r == 0);
    DetectAddressHeadFree(gh);
    PASS;
}

static int AddressTestParse25(void)
{
    DetectAddressHead *gh = DetectAddressHeadInit();
    FAIL_IF_NULL(gh);
    int r = DetectAddressParse(NULL, gh, "ANY");
    FAIL_IF_NOT(r == 0);
    DetectAddressHeadFree(gh);
    PASS;
}

/** \test recursion limit */
static int AddressTestParse26(void)
{
    DetectAddressHead *gh = DetectAddressHeadInit();
    FAIL_IF_NULL(gh);
    /* exactly 64: should pass */
    int r = DetectAddressParse(NULL, gh,
            "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
            "1.2.3.4"
            "]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
            );
    FAIL_IF_NOT(r == 0);
    DetectAddressHeadFree(gh);
    gh = DetectAddressHeadInit();
    FAIL_IF_NULL(gh);
    /* exactly 65: should fail */
    r = DetectAddressParse(NULL, gh,
            "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
            "1.2.3.4"
            "]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
            );
    FAIL_IF(r == 0);
    DetectAddressHeadFree(gh);
    PASS;
}

static int AddressTestParse27(void)
{
    DetectAddress *dd = DetectAddressParseSingle("!192.168.0.1");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

static int AddressTestParse28(void)
{
    int result = 0;
    DetectAddress *dd = DetectAddressParseSingle("!1.2.3.4");

    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip.addr_data32[0] == SCNtohl(16909060)) {
            result = 1;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

static int AddressTestParse29(void)
{
    DetectAddress *dd = DetectAddressParseSingle("!1.2.3.0/24");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

static int AddressTestParse30(void)
{
    int result = 0;
    DetectAddress *dd = DetectAddressParseSingle("!1.2.3.4/24");

    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip.addr_data32[0] == SCNtohl(16909056) &&
            dd->ip2.addr_data32[0] == SCNtohl(16909311)) {
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
static int AddressTestParse31(void)
{
    DetectAddress *dd = DetectAddressParseSingle("!any");

    if (dd) {
        DetectAddressFree(dd);
        return 0;
    }

    return 1;
}

static int AddressTestParse32(void)
{
    DetectAddress *dd = DetectAddressParseSingle("!2001::1");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

static int AddressTestParse33(void)
{
    int result = 0;
    DetectAddress *dd = DetectAddressParseSingle("!2001::1");

    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip.addr_data32[0] == SCNtohl(536936448) && dd->ip.addr_data32[1] == 0x00000000 &&
            dd->ip.addr_data32[2] == 0x00000000 && dd->ip.addr_data32[3] == SCNtohl(1)) {
            result = 1;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

static int AddressTestParse34(void)
{
    DetectAddress *dd = DetectAddressParseSingle("!2001::/16");

    if (dd) {
        DetectAddressFree(dd);
        return 1;
    }

    return 0;
}

static int AddressTestParse35(void)
{
    int result = 0;
    DetectAddress *dd = DetectAddressParseSingle("!2001::/16");

    if (dd) {
        if (dd->flags & ADDRESS_FLAG_NOT &&
            dd->ip.addr_data32[0] == SCNtohl(536936448) && dd->ip.addr_data32[1] == 0x00000000 &&
            dd->ip.addr_data32[2] == 0x00000000 && dd->ip.addr_data32[3] == 0x00000000 &&

            dd->ip2.addr_data32[0] == SCNtohl(537001983) && dd->ip2.addr_data32[1] == 0xFFFFFFFF &&
            dd->ip2.addr_data32[2] == 0xFFFFFFFF && dd->ip2.addr_data32[3] == 0xFFFFFFFF) {
            result = 1;
        }

        DetectAddressFree(dd);
        return result;
    }

    return 0;
}

static int AddressTestParse36(void)
{
    int result = 1;
    DetectAddress *dd = DetectAddressParseSingle("ffff::/16");

    if (dd) {
        if (dd->ip.addr_data32[0] != SCNtohl(0xFFFF0000) || dd->ip.addr_data32[1] != 0x00000000 ||
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

static int AddressTestParse37(void)
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

static int AddressTestMatch01(void)
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

static int AddressTestMatch02(void)
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

static int AddressTestMatch03(void)
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

static int AddressTestMatch04(void)
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

static int AddressTestMatch05(void)
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

static int AddressTestMatch06(void)
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

static int AddressTestMatch07(void)
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

static int AddressTestMatch08(void)
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

static int AddressTestMatch09(void)
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

static int AddressTestMatch10(void)
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

static int AddressTestMatch11(void)
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

static int AddressTestCmp01(void)
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

static int AddressTestCmp02(void)
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

static int AddressTestCmp03(void)
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

static int AddressTestCmp04(void)
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

static int AddressTestCmp05(void)
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

static int AddressTestCmp06(void)
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

static int AddressTestCmpIPv407(void)
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

static int AddressTestCmpIPv408(void)
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

static int AddressTestCmp07(void)
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

static int AddressTestCmp08(void)
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

static int AddressTestCmp09(void)
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

static int AddressTestCmp10(void)
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

static int AddressTestCmp11(void)
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

static int AddressTestCmp12(void)
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

static int AddressTestAddressGroupSetup01(void)
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

static int AddressTestAddressGroupSetup02(void)
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

static int AddressTestAddressGroupSetup03(void)
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

static int AddressTestAddressGroupSetup04(void)
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
                DetectAddress *ph = gh->ipv4_head;

                r = DetectAddressParse(NULL, gh, "1.2.3.2");
                if (r == 0 && gh->ipv4_head != ph &&
                    gh->ipv4_head != NULL && gh->ipv4_head->next == ph) {
                    result = 1;
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup05(void)
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
                DetectAddress *ph = gh->ipv4_head;

                r = DetectAddressParse(NULL, gh, "1.2.3.4");
                if (r == 0 && gh->ipv4_head == ph &&
                    gh->ipv4_head != NULL && gh->ipv4_head->next != ph) {
                    result = 1;
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup06(void)
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

static int AddressTestAddressGroupSetup07(void)
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

static int AddressTestAddressGroupSetup08(void)
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

static int AddressTestAddressGroupSetup09(void)
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

static int AddressTestAddressGroupSetup10(void)
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

static int AddressTestAddressGroupSetup11(void)
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
                    if (one->ip.addr_data32[0] == 0x00000000 && one->ip2.addr_data32[0] == SCNtohl(168430079) &&
                        two->ip.addr_data32[0] == SCNtohl(168430080) && two->ip2.addr_data32[0] == SCNtohl(168430089) &&
                        three->ip.addr_data32[0] == SCNtohl(168430090) && three->ip2.addr_data32[0] == SCNtohl(168430335) &&
                        four->ip.addr_data32[0] == SCNtohl(168430336) && four->ip2.addr_data32[0] == SCNtohl(168430337) &&
                        five->ip.addr_data32[0] == SCNtohl(168430338) && five->ip2.addr_data32[0]  == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup12 (void)
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
                    if (one->ip.addr_data32[0] == 0x00000000 && one->ip2.addr_data32[0] == SCNtohl(168430079) &&
                        two->ip.addr_data32[0] == SCNtohl(168430080) && two->ip2.addr_data32[0] == SCNtohl(168430089) &&
                        three->ip.addr_data32[0] == SCNtohl(168430090) && three->ip2.addr_data32[0] == SCNtohl(168430335) &&
                        four->ip.addr_data32[0] == SCNtohl(168430336) && four->ip2.addr_data32[0] == SCNtohl(168430337) &&
                        five->ip.addr_data32[0] == SCNtohl(168430338) && five->ip2.addr_data32[0]  == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup13(void)
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
                    if (one->ip.addr_data32[0] == 0x00000000 && one->ip2.addr_data32[0] == SCNtohl(168430079) &&
                        two->ip.addr_data32[0] == SCNtohl(168430080) && two->ip2.addr_data32[0] == SCNtohl(168430089) &&
                        three->ip.addr_data32[0] == SCNtohl(168430090) && three->ip2.addr_data32[0] == SCNtohl(168430335) &&
                        four->ip.addr_data32[0] == SCNtohl(168430336) && four->ip2.addr_data32[0] == SCNtohl(168430337) &&
                        five->ip.addr_data32[0] == SCNtohl(168430338) && five->ip2.addr_data32[0]  == 0xFFFFFFFF) {
                        result = 1;
                    }
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetupIPv414(void)
{
    DetectAddressHead *gh = DetectAddressHeadInit();
    FAIL_IF_NULL(gh);

    int r = DetectAddressParse(NULL, gh, "!1.2.3.4");
    FAIL_IF_NOT(r == 1);

    DetectAddress *one = gh->ipv4_head;
    FAIL_IF_NULL(one);
    DetectAddress *two = one->next;
    FAIL_IF_NULL(two);

    /* result should be:
     * 0.0.0.0/1.2.3.3
     * 1.2.3.5/255.255.255.255
     */
    FAIL_IF_NOT(one->ip.addr_data32[0] == 0x00000000);
    FAIL_IF_NOT(one->ip2.addr_data32[0] == SCNtohl(16909059));
    FAIL_IF_NOT(two->ip.addr_data32[0] == SCNtohl(16909061));
    FAIL_IF_NOT(two->ip2.addr_data32[0] == 0xFFFFFFFF);
    DetectAddressHeadFree(gh);

    PASS;
}

static int AddressTestAddressGroupSetupIPv415(void)
{
    DetectAddressHead *gh = DetectAddressHeadInit();
    FAIL_IF_NULL(gh);

    int r = DetectAddressParse(NULL, gh, "!0.0.0.0");
    FAIL_IF_NOT(r == 1);

    DetectAddress *one = gh->ipv4_head;
    FAIL_IF_NULL(one);
    FAIL_IF_NOT_NULL(one->next);

    /* result should be:
     * 0.0.0.1/255.255.255.255
     */
    FAIL_IF_NOT(one->ip.addr_data32[0] == SCNtohl(1));
    FAIL_IF_NOT(one->ip2.addr_data32[0] == 0xFFFFFFFF);

    DetectAddressHeadFree(gh);
    PASS;
}

static int AddressTestAddressGroupSetupIPv416(void)
{
    DetectAddressHead *gh = DetectAddressHeadInit();
    FAIL_IF_NULL(gh);

    int r = DetectAddressParse(NULL, gh, "!255.255.255.255");
    FAIL_IF_NOT(r == 1);

    DetectAddress *one = gh->ipv4_head;
    FAIL_IF_NULL(one);
    FAIL_IF_NOT_NULL(one->next);

    /* result should be:
     * 0.0.0.0/255.255.255.254
     */
    FAIL_IF_NOT(one->ip.addr_data32[0] == 0x00000000);
    FAIL_IF_NOT(one->ip2.addr_data32[0] == SCNtohl(4294967294));

    DetectAddressHeadFree(gh);
    PASS;
}

static int AddressTestAddressGroupSetup14(void)
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

static int AddressTestAddressGroupSetup15(void)
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

static int AddressTestAddressGroupSetup16(void)
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

static int AddressTestAddressGroupSetup17(void)
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
                DetectAddress *ph = gh->ipv6_head;

                r = DetectAddressParse(NULL, gh, "2001::2");
                if (r == 0 && gh->ipv6_head != ph &&
                    gh->ipv6_head != NULL && gh->ipv6_head->next == ph) {
                    result = 1;
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup18(void)
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
                DetectAddress *ph = gh->ipv6_head;

                r = DetectAddressParse(NULL, gh, "2001::4");
                if (r == 0 && gh->ipv6_head == ph &&
                    gh->ipv6_head != NULL && gh->ipv6_head->next != ph) {
                    result = 1;
                }
            }
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup19(void)
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

static int AddressTestAddressGroupSetup20(void)
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

static int AddressTestAddressGroupSetup21(void)
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

static int AddressTestAddressGroupSetup22(void)
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

static int AddressTestAddressGroupSetup23(void)
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

static int AddressTestAddressGroupSetup24(void)
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
                        one->ip2.addr_data32[0] == SCNtohl(536870911) &&
                        one->ip2.addr_data32[1] == 0xFFFFFFFF &&
                        one->ip2.addr_data32[2] == 0xFFFFFFFF &&
                        one->ip2.addr_data32[3] == 0xFFFFFFFF &&

                        two->ip.addr_data32[0] == SCNtohl(536870912) &&
                        two->ip.addr_data32[1] == 0x00000000 &&
                        two->ip.addr_data32[2] == 0x00000000 &&
                        two->ip.addr_data32[3] == 0x00000000 &&
                        two->ip2.addr_data32[0] == SCNtohl(536936448) &&
                        two->ip2.addr_data32[1] == 0x00000000 &&
                        two->ip2.addr_data32[2] == 0x00000000 &&
                        two->ip2.addr_data32[3] == SCNtohl(3) &&

                        three->ip.addr_data32[0] == SCNtohl(536936448) &&
                        three->ip.addr_data32[1] == 0x00000000 &&
                        three->ip.addr_data32[2] == 0x00000000 &&
                        three->ip.addr_data32[3] == SCNtohl(4) &&
                        three->ip2.addr_data32[0] == SCNtohl(536936448) &&
                        three->ip2.addr_data32[1] == 0x00000000 &&
                        three->ip2.addr_data32[2] == 0x00000000 &&
                        three->ip2.addr_data32[3] == SCNtohl(6) &&

                        four->ip.addr_data32[0] == SCNtohl(536936448) &&
                        four->ip.addr_data32[1] == 0x00000000 &&
                        four->ip.addr_data32[2] == 0x00000000 &&
                        four->ip.addr_data32[3] == SCNtohl(7) &&
                        four->ip2.addr_data32[0] == SCNtohl(1073741823) &&
                        four->ip2.addr_data32[1] == 0xFFFFFFFF &&
                        four->ip2.addr_data32[2] == 0xFFFFFFFF &&
                        four->ip2.addr_data32[3] == 0xFFFFFFFF &&

                        five->ip.addr_data32[0] == SCNtohl(1073741824) &&
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

static int AddressTestAddressGroupSetup25(void)
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
                        one->ip2.addr_data32[0]  == SCNtohl(536870911) &&
                        one->ip2.addr_data32[1]  == 0xFFFFFFFF &&
                        one->ip2.addr_data32[2]  == 0xFFFFFFFF &&
                        one->ip2.addr_data32[3]  == 0xFFFFFFFF &&

                        two->ip.addr_data32[0] == SCNtohl(536870912) &&
                        two->ip.addr_data32[1] == 0x00000000 &&
                        two->ip.addr_data32[2] == 0x00000000 &&
                        two->ip.addr_data32[3] == 0x00000000 &&
                        two->ip2.addr_data32[0] == SCNtohl(536936448) &&
                        two->ip2.addr_data32[1] == 0x00000000 &&
                        two->ip2.addr_data32[2] == 0x00000000 &&
                        two->ip2.addr_data32[3] == SCNtohl(3) &&

                        three->ip.addr_data32[0] == SCNtohl(536936448) &&
                        three->ip.addr_data32[1] == 0x00000000 &&
                        three->ip.addr_data32[2] == 0x00000000 &&
                        three->ip.addr_data32[3] == SCNtohl(4) &&
                        three->ip2.addr_data32[0] == SCNtohl(536936448) &&
                        three->ip2.addr_data32[1] == 0x00000000 &&
                        three->ip2.addr_data32[2] == 0x00000000 &&
                        three->ip2.addr_data32[3] == SCNtohl(6) &&

                        four->ip.addr_data32[0] == SCNtohl(536936448) &&
                        four->ip.addr_data32[1] == 0x00000000 &&
                        four->ip.addr_data32[2] == 0x00000000 &&
                        four->ip.addr_data32[3] == SCNtohl(7) &&
                        four->ip2.addr_data32[0] == SCNtohl(1073741823) &&
                        four->ip2.addr_data32[1] == 0xFFFFFFFF &&
                        four->ip2.addr_data32[2] == 0xFFFFFFFF &&
                        four->ip2.addr_data32[3] == 0xFFFFFFFF &&

                        five->ip.addr_data32[0] == SCNtohl(1073741824) &&
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

static int AddressTestAddressGroupSetup26(void)
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
                        one->ip2.addr_data32[0] == SCNtohl(536870911) &&
                        one->ip2.addr_data32[1] == 0xFFFFFFFF &&
                        one->ip2.addr_data32[2] == 0xFFFFFFFF &&
                        one->ip2.addr_data32[3] == 0xFFFFFFFF &&

                        two->ip.addr_data32[0] == SCNtohl(536870912) &&
                        two->ip.addr_data32[1] == 0x00000000 &&
                        two->ip.addr_data32[2] == 0x00000000 &&
                        two->ip.addr_data32[3] == 0x00000000 &&
                        two->ip2.addr_data32[0] == SCNtohl(536936448) &&
                        two->ip2.addr_data32[1] == 0x00000000 &&
                        two->ip2.addr_data32[2] == 0x00000000 &&
                        two->ip2.addr_data32[3] == SCNtohl(3) &&

                        three->ip.addr_data32[0] == SCNtohl(536936448) &&
                        three->ip.addr_data32[1] == 0x00000000 &&
                        three->ip.addr_data32[2] == 0x00000000 &&
                        three->ip.addr_data32[3] == SCNtohl(4) &&
                        three->ip2.addr_data32[0] == SCNtohl(536936448) &&
                        three->ip2.addr_data32[1] == 0x00000000 &&
                        three->ip2.addr_data32[2] == 0x00000000 &&
                        three->ip2.addr_data32[3] == SCNtohl(6) &&

                        four->ip.addr_data32[0] == SCNtohl(536936448) &&
                        four->ip.addr_data32[1] == 0x00000000 &&
                        four->ip.addr_data32[2] == 0x00000000 &&
                        four->ip.addr_data32[3] == SCNtohl(7) &&
                        four->ip2.addr_data32[0] == SCNtohl(1073741823) &&
                        four->ip2.addr_data32[1] == 0xFFFFFFFF &&
                        four->ip2.addr_data32[2] == 0xFFFFFFFF &&
                        four->ip2.addr_data32[3] == 0xFFFFFFFF &&

                        five->ip.addr_data32[0] == SCNtohl(1073741824) &&
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

static int AddressTestAddressGroupSetup27(void)
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

static int AddressTestAddressGroupSetup28(void)
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

static int AddressTestAddressGroupSetup29(void)
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

static int AddressTestAddressGroupSetup30(void)
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

static int AddressTestAddressGroupSetup31(void)
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

static int AddressTestAddressGroupSetup32(void)
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

static int AddressTestAddressGroupSetup33(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "![1.1.1.1,[2.2.2.2,[3.3.3.3,4.4.4.4]]]");
        if (r == 1)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup34(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[1.0.0.0/8,![1.1.1.1,[1.2.1.1,1.3.1.1]]]");
        if (r == 1)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup35(void)
{
    int result = 0;
    DetectAddressHead *gh = DetectAddressHeadInit();

    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[1.0.0.0/8,[2.0.0.0/8,![1.1.1.1,2.2.2.2]]]");
        if (r == 1)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup36 (void)
{
    int result = 0;

    DetectAddressHead *gh = DetectAddressHeadInit();
    if (gh != NULL) {
        int r = DetectAddressParse(NULL, gh, "[1.0.0.0/8,[2.0.0.0/8,[3.0.0.0/8,!1.1.1.1]]]");
        if (r == 1)
            result = 1;

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestAddressGroupSetup37(void)
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
        if (r == 1) {
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
        if (r == 1) {
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
        if (r == 1) {
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
        if (r == 1) {
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
        if (r == 1) {
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
        if (r == 1) {
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
        if (r == 1) {
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
        if (r == 1) {
            if (UTHValidateDetectAddressHead(gh, 4, expectations) == TRUE)
                result = 1;
        }

        DetectAddressHeadFree(gh);
    }
    return result;
}

static int AddressTestCutIPv401(void)
{
    DetectAddress *c;
    DetectAddress *a = DetectAddressParseSingle("1.2.3.0/255.255.255.0");
    FAIL_IF_NULL(a);
    DetectAddress *b = DetectAddressParseSingle("1.2.2.0-1.2.3.4");
    FAIL_IF_NULL(b);

    FAIL_IF(DetectAddressCut(NULL, a, b, &c) == -1);

    DetectAddressFree(a);
    DetectAddressFree(b);
    DetectAddressFree(c);
    PASS;
}

static int AddressTestCutIPv402(void)
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

static int AddressTestCutIPv403(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0/255.255.255.0");
    b = DetectAddressParseSingle("1.2.2.0-1.2.3.4");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c == NULL)
        goto error;

    if (a->ip.addr_data32[0] != SCNtohl(16908800) || a->ip2.addr_data32[0] != SCNtohl(16909055))
        goto error;
    if (b->ip.addr_data32[0] != SCNtohl(16909056) || b->ip2.addr_data32[0] != SCNtohl(16909060))
        goto error;
    if (c->ip.addr_data32[0] != SCNtohl(16909061) || c->ip2.addr_data32[0] != SCNtohl(16909311))
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

static int AddressTestCutIPv404(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.3-1.2.3.6");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.5");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c == NULL)
        goto error;

    if (a->ip.addr_data32[0] != SCNtohl(16909056) || a->ip2.addr_data32[0] != SCNtohl(16909058))
        goto error;
    if (b->ip.addr_data32[0] != SCNtohl(16909059) || b->ip2.addr_data32[0] != SCNtohl(16909061))
        goto error;
    if (c->ip.addr_data32[0] != SCNtohl(16909062) || c->ip2.addr_data32[0] != SCNtohl(16909062))
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

static int AddressTestCutIPv405(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.3-1.2.3.6");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.9");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c == NULL)
        goto error;

    if (a->ip.addr_data32[0] != SCNtohl(16909056) || a->ip2.addr_data32[0] != SCNtohl(16909058))
        goto error;
    if (b->ip.addr_data32[0] != SCNtohl(16909059) || b->ip2.addr_data32[0] != SCNtohl(16909062))
        goto error;
    if (c->ip.addr_data32[0] != SCNtohl(16909063) || c->ip2.addr_data32[0] != SCNtohl(16909065))
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

static int AddressTestCutIPv406(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0-1.2.3.9");
    b = DetectAddressParseSingle("1.2.3.3-1.2.3.6");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c == NULL)
        goto error;

    if (a->ip.addr_data32[0] != SCNtohl(16909056) || a->ip2.addr_data32[0] != SCNtohl(16909058))
        goto error;
    if (b->ip.addr_data32[0] != SCNtohl(16909059) || b->ip2.addr_data32[0] != SCNtohl(16909062))
        goto error;
    if (c->ip.addr_data32[0] != SCNtohl(16909063) || c->ip2.addr_data32[0] != SCNtohl(16909065))
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

static int AddressTestCutIPv407(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0-1.2.3.6");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.9");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c != NULL)
        goto error;

    if (a->ip.addr_data32[0] != SCNtohl(16909056) || a->ip2.addr_data32[0] != SCNtohl(16909062))
        goto error;
    if (b->ip.addr_data32[0] != SCNtohl(16909063) || b->ip2.addr_data32[0] != SCNtohl(16909065))
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

static int AddressTestCutIPv408(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.3-1.2.3.9");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.9");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c != NULL)
        goto error;

    if (a->ip.addr_data32[0] != SCNtohl(16909056) || a->ip2.addr_data32[0] != SCNtohl(16909058))
        goto error;
    if (b->ip.addr_data32[0] != SCNtohl(16909059) || b->ip2.addr_data32[0] != SCNtohl(16909065))
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

static int AddressTestCutIPv409(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0-1.2.3.9");
    b = DetectAddressParseSingle("1.2.3.0-1.2.3.6");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c != NULL)
        goto error;

    if (a->ip.addr_data32[0] != SCNtohl(16909056) || a->ip2.addr_data32[0] != SCNtohl(16909062))
        goto error;
    if (b->ip.addr_data32[0] != SCNtohl(16909063) || b->ip2.addr_data32[0] != SCNtohl(16909065))
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

static int AddressTestCutIPv410(void)
{
    DetectAddress *a, *b, *c;
    a = DetectAddressParseSingle("1.2.3.0-1.2.3.9");
    b = DetectAddressParseSingle("1.2.3.3-1.2.3.9");

    if (DetectAddressCut(NULL, a, b, &c) == -1)
        goto error;

    if (c != NULL)
        goto error;

    if (a->ip.addr_data32[0] != SCNtohl(16909056) || a->ip2.addr_data32[0] != SCNtohl(16909058))
        goto error;
    if (b->ip.addr_data32[0] != SCNtohl(16909059) || b->ip2.addr_data32[0] != SCNtohl(16909065))
        goto error;

    printf("ip %u ip2 %u ", (uint32_t)htonl(a->ip.addr_data32[0]), (uint32_t)htonl(a->ip2.addr_data32[0]));

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

static int AddressTestParseInvalidMask01(void)
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

static int AddressTestParseInvalidMask02(void)
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

static int AddressTestParseInvalidMask03(void)
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

static int AddressConfVarsTest01(void)
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

static int AddressConfVarsTest02(void)
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

static int AddressConfVarsTest03(void)
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

static int AddressConfVarsTest04(void)
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

static int AddressConfVarsTest05(void)
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

static int AddressConfVarsTest06(void)
{
    // HOME_NET value size = 10261 bytes
    static const char *dummy_conf_string =
            "%YAML 1.1\n"
            "---\n"
            "\n"
            "vars:\n"
            "\n"
            "  address-groups:\n"
            "\n"
            "    HOME_NET: "
            "\"[2002:0000:3238:DFE1:63:0000:0000:FEFB,2002:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2004:0000:3238:DFE1:63:0000:0000:FEFB,2005:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2006:0000:3238:DFE1:63:0000:0000:FEFB,2007:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB,"
            "2002:0000:3238:DFE1:63:0000:0000:FEFB,2003:0000:3238:DFE1:63:0000:0000:FEFB]\"\n"
            "\n"
            "    EXTERNAL_NET: \"any\"\n"
            "\n";

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    FAIL_IF(0 != DetectAddressTestConfVars());

    ConfDeInit();
    ConfRestoreContextBackup();

    PASS;
}

#endif /* UNITTESTS */

void DetectAddressTests(void)
{
#ifdef UNITTESTS
    DetectAddressIPv4Tests();
    DetectAddressIPv6Tests();

    UtRegisterTest("AddressTestParse01", AddressTestParse01);
    UtRegisterTest("AddressTestParse02", AddressTestParse02);
    UtRegisterTest("AddressTestParse03", AddressTestParse03);
    UtRegisterTest("AddressTestParse04", AddressTestParse04);
    UtRegisterTest("AddressTestParse04bug5081", AddressTestParse04bug5081);
    UtRegisterTest("AddressTestParse05", AddressTestParse05);
    UtRegisterTest("AddressTestParse06", AddressTestParse06);
    UtRegisterTest("AddressTestParse07", AddressTestParse07);
    UtRegisterTest("AddressTestParse08", AddressTestParse08);
    UtRegisterTest("AddressTestParse09", AddressTestParse09);
    UtRegisterTest("AddressTestParse10", AddressTestParse10);
    UtRegisterTest("AddressTestParse11", AddressTestParse11);
    UtRegisterTest("AddressTestParse12", AddressTestParse12);
    UtRegisterTest("AddressTestParse13", AddressTestParse13);
    UtRegisterTest("AddressTestParse14", AddressTestParse14);
    UtRegisterTest("AddressTestParse15", AddressTestParse15);
    UtRegisterTest("AddressTestParse16", AddressTestParse16);
    UtRegisterTest("AddressTestParse17", AddressTestParse17);
    UtRegisterTest("AddressTestParse18", AddressTestParse18);
    UtRegisterTest("AddressTestParse19", AddressTestParse19);
    UtRegisterTest("AddressTestParse20", AddressTestParse20);
    UtRegisterTest("AddressTestParse21", AddressTestParse21);
    UtRegisterTest("AddressTestParse22", AddressTestParse22);
    UtRegisterTest("AddressTestParse23", AddressTestParse23);
    UtRegisterTest("AddressTestParse24", AddressTestParse24);
    UtRegisterTest("AddressTestParse25", AddressTestParse25);
    UtRegisterTest("AddressTestParse26", AddressTestParse26);
    UtRegisterTest("AddressTestParse27", AddressTestParse27);
    UtRegisterTest("AddressTestParse28", AddressTestParse28);
    UtRegisterTest("AddressTestParse29", AddressTestParse29);
    UtRegisterTest("AddressTestParse30", AddressTestParse30);
    UtRegisterTest("AddressTestParse31", AddressTestParse31);
    UtRegisterTest("AddressTestParse32", AddressTestParse32);
    UtRegisterTest("AddressTestParse33", AddressTestParse33);
    UtRegisterTest("AddressTestParse34", AddressTestParse34);
    UtRegisterTest("AddressTestParse35", AddressTestParse35);
    UtRegisterTest("AddressTestParse36", AddressTestParse36);
    UtRegisterTest("AddressTestParse37", AddressTestParse37);

    UtRegisterTest("AddressTestMatch01", AddressTestMatch01);
    UtRegisterTest("AddressTestMatch02", AddressTestMatch02);
    UtRegisterTest("AddressTestMatch03", AddressTestMatch03);
    UtRegisterTest("AddressTestMatch04", AddressTestMatch04);
    UtRegisterTest("AddressTestMatch05", AddressTestMatch05);
    UtRegisterTest("AddressTestMatch06", AddressTestMatch06);
    UtRegisterTest("AddressTestMatch07", AddressTestMatch07);
    UtRegisterTest("AddressTestMatch08", AddressTestMatch08);
    UtRegisterTest("AddressTestMatch09", AddressTestMatch09);
    UtRegisterTest("AddressTestMatch10", AddressTestMatch10);
    UtRegisterTest("AddressTestMatch11", AddressTestMatch11);

    UtRegisterTest("AddressTestCmp01", AddressTestCmp01);
    UtRegisterTest("AddressTestCmp02", AddressTestCmp02);
    UtRegisterTest("AddressTestCmp03", AddressTestCmp03);
    UtRegisterTest("AddressTestCmp04", AddressTestCmp04);
    UtRegisterTest("AddressTestCmp05", AddressTestCmp05);
    UtRegisterTest("AddressTestCmp06", AddressTestCmp06);
    UtRegisterTest("AddressTestCmpIPv407", AddressTestCmpIPv407);
    UtRegisterTest("AddressTestCmpIPv408", AddressTestCmpIPv408);

    UtRegisterTest("AddressTestCmp07", AddressTestCmp07);
    UtRegisterTest("AddressTestCmp08", AddressTestCmp08);
    UtRegisterTest("AddressTestCmp09", AddressTestCmp09);
    UtRegisterTest("AddressTestCmp10", AddressTestCmp10);
    UtRegisterTest("AddressTestCmp11", AddressTestCmp11);
    UtRegisterTest("AddressTestCmp12", AddressTestCmp12);

    UtRegisterTest("AddressTestAddressGroupSetup01",
                   AddressTestAddressGroupSetup01);
    UtRegisterTest("AddressTestAddressGroupSetup02",
                   AddressTestAddressGroupSetup02);
    UtRegisterTest("AddressTestAddressGroupSetup03",
                   AddressTestAddressGroupSetup03);
    UtRegisterTest("AddressTestAddressGroupSetup04",
                   AddressTestAddressGroupSetup04);
    UtRegisterTest("AddressTestAddressGroupSetup05",
                   AddressTestAddressGroupSetup05);
    UtRegisterTest("AddressTestAddressGroupSetup06",
                   AddressTestAddressGroupSetup06);
    UtRegisterTest("AddressTestAddressGroupSetup07",
                   AddressTestAddressGroupSetup07);
    UtRegisterTest("AddressTestAddressGroupSetup08",
                   AddressTestAddressGroupSetup08);
    UtRegisterTest("AddressTestAddressGroupSetup09",
                   AddressTestAddressGroupSetup09);
    UtRegisterTest("AddressTestAddressGroupSetup10",
                   AddressTestAddressGroupSetup10);
    UtRegisterTest("AddressTestAddressGroupSetup11",
                   AddressTestAddressGroupSetup11);
    UtRegisterTest("AddressTestAddressGroupSetup12",
                   AddressTestAddressGroupSetup12);
    UtRegisterTest("AddressTestAddressGroupSetup13",
                   AddressTestAddressGroupSetup13);
    UtRegisterTest("AddressTestAddressGroupSetupIPv414",
                   AddressTestAddressGroupSetupIPv414);
    UtRegisterTest("AddressTestAddressGroupSetupIPv415",
                   AddressTestAddressGroupSetupIPv415);
    UtRegisterTest("AddressTestAddressGroupSetupIPv416",
                   AddressTestAddressGroupSetupIPv416);

    UtRegisterTest("AddressTestAddressGroupSetup14",
                   AddressTestAddressGroupSetup14);
    UtRegisterTest("AddressTestAddressGroupSetup15",
                   AddressTestAddressGroupSetup15);
    UtRegisterTest("AddressTestAddressGroupSetup16",
                   AddressTestAddressGroupSetup16);
    UtRegisterTest("AddressTestAddressGroupSetup17",
                   AddressTestAddressGroupSetup17);
    UtRegisterTest("AddressTestAddressGroupSetup18",
                   AddressTestAddressGroupSetup18);
    UtRegisterTest("AddressTestAddressGroupSetup19",
                   AddressTestAddressGroupSetup19);
    UtRegisterTest("AddressTestAddressGroupSetup20",
                   AddressTestAddressGroupSetup20);
    UtRegisterTest("AddressTestAddressGroupSetup21",
                   AddressTestAddressGroupSetup21);
    UtRegisterTest("AddressTestAddressGroupSetup22",
                   AddressTestAddressGroupSetup22);
    UtRegisterTest("AddressTestAddressGroupSetup23",
                   AddressTestAddressGroupSetup23);
    UtRegisterTest("AddressTestAddressGroupSetup24",
                   AddressTestAddressGroupSetup24);
    UtRegisterTest("AddressTestAddressGroupSetup25",
                   AddressTestAddressGroupSetup25);
    UtRegisterTest("AddressTestAddressGroupSetup26",
                   AddressTestAddressGroupSetup26);

    UtRegisterTest("AddressTestAddressGroupSetup27",
                   AddressTestAddressGroupSetup27);
    UtRegisterTest("AddressTestAddressGroupSetup28",
                   AddressTestAddressGroupSetup28);
    UtRegisterTest("AddressTestAddressGroupSetup29",
                   AddressTestAddressGroupSetup29);
    UtRegisterTest("AddressTestAddressGroupSetup30",
                   AddressTestAddressGroupSetup30);
    UtRegisterTest("AddressTestAddressGroupSetup31",
                   AddressTestAddressGroupSetup31);
    UtRegisterTest("AddressTestAddressGroupSetup32",
                   AddressTestAddressGroupSetup32);
    UtRegisterTest("AddressTestAddressGroupSetup33",
                   AddressTestAddressGroupSetup33);
    UtRegisterTest("AddressTestAddressGroupSetup34",
                   AddressTestAddressGroupSetup34);
    UtRegisterTest("AddressTestAddressGroupSetup35",
                   AddressTestAddressGroupSetup35);
    UtRegisterTest("AddressTestAddressGroupSetup36",
                   AddressTestAddressGroupSetup36);
    UtRegisterTest("AddressTestAddressGroupSetup37",
                   AddressTestAddressGroupSetup37);
    UtRegisterTest("AddressTestAddressGroupSetup38",
                   AddressTestAddressGroupSetup38);
    UtRegisterTest("AddressTestAddressGroupSetup39",
                   AddressTestAddressGroupSetup39);
    UtRegisterTest("AddressTestAddressGroupSetup40",
                   AddressTestAddressGroupSetup40);
    UtRegisterTest("AddressTestAddressGroupSetup41",
                   AddressTestAddressGroupSetup41);
    UtRegisterTest("AddressTestAddressGroupSetup42",
                   AddressTestAddressGroupSetup42);
    UtRegisterTest("AddressTestAddressGroupSetup43",
                   AddressTestAddressGroupSetup43);
    UtRegisterTest("AddressTestAddressGroupSetup44",
                   AddressTestAddressGroupSetup44);
    UtRegisterTest("AddressTestAddressGroupSetup45",
                   AddressTestAddressGroupSetup45);
    UtRegisterTest("AddressTestAddressGroupSetup46",
                   AddressTestAddressGroupSetup46);
    UtRegisterTest("AddressTestAddressGroupSetup47",
                   AddressTestAddressGroupSetup47);
    UtRegisterTest("AddressTestAddressGroupSetup48",
                   AddressTestAddressGroupSetup48);

    UtRegisterTest("AddressTestCutIPv401", AddressTestCutIPv401);
    UtRegisterTest("AddressTestCutIPv402", AddressTestCutIPv402);
    UtRegisterTest("AddressTestCutIPv403", AddressTestCutIPv403);
    UtRegisterTest("AddressTestCutIPv404", AddressTestCutIPv404);
    UtRegisterTest("AddressTestCutIPv405", AddressTestCutIPv405);
    UtRegisterTest("AddressTestCutIPv406", AddressTestCutIPv406);
    UtRegisterTest("AddressTestCutIPv407", AddressTestCutIPv407);
    UtRegisterTest("AddressTestCutIPv408", AddressTestCutIPv408);
    UtRegisterTest("AddressTestCutIPv409", AddressTestCutIPv409);
    UtRegisterTest("AddressTestCutIPv410", AddressTestCutIPv410);

    UtRegisterTest("AddressTestParseInvalidMask01",
                   AddressTestParseInvalidMask01);
    UtRegisterTest("AddressTestParseInvalidMask02",
                   AddressTestParseInvalidMask02);
    UtRegisterTest("AddressTestParseInvalidMask03",
                   AddressTestParseInvalidMask03);

    UtRegisterTest("AddressConfVarsTest01 ", AddressConfVarsTest01);
    UtRegisterTest("AddressConfVarsTest02 ", AddressConfVarsTest02);
    UtRegisterTest("AddressConfVarsTest03 ", AddressConfVarsTest03);
    UtRegisterTest("AddressConfVarsTest04 ", AddressConfVarsTest04);
    UtRegisterTest("AddressConfVarsTest05 ", AddressConfVarsTest05);
    UtRegisterTest("AddressConfVarsTest06 ", AddressConfVarsTest06);
#endif /* UNITTESTS */
}
