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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Signatures that only inspect IP addresses are processed here
 * We use radix trees for src dst ipv4 and ipv6 addresses
 * This radix trees hold information for subnets and hosts in a
 * hierarchical distribution
 */

#include "suricata-common.h"
#include "detect.h"
#include "decode.h"
#include "flow.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-proto.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-build.h"

#include "detect-engine-threshold.h"
#include "detect-engine-iponly.h"
#include "detect-threshold.h"
#include "util-classification-config.h"
#include "util-rule-vars.h"
#include "detect-engine-alert.h"

#include "flow-util.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-print.h"
#include "util-byte.h"
#include "util-profiling.h"
#include "util-validate.h"
#include "util-cidr.h"

#ifdef OS_WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#endif /* OS_WIN32 */

/**
 * \brief This function creates a new IPOnlyCIDRItem
 *
 * \retval IPOnlyCIDRItem address of the new instance
 */
static IPOnlyCIDRItem *IPOnlyCIDRItemNew(void)
{
    SCEnter();
    IPOnlyCIDRItem *item = NULL;

    item = SCCalloc(1, sizeof(IPOnlyCIDRItem));
    if (unlikely(item == NULL))
        SCReturnPtr(NULL, "IPOnlyCIDRItem");

    SCReturnPtr(item, "IPOnlyCIDRItem");
}

/**
 * \brief Compares two list items
 *
 * \retval An integer less than, equal to, or greater than zero if lhs is
 *         considered to be respectively less than, equal to, or greater than
 *         rhs.
 */
static int IPOnlyCIDRItemCompareReal(const IPOnlyCIDRItem *lhs, const IPOnlyCIDRItem *rhs)
{
    if (lhs->netmask == rhs->netmask) {
        uint8_t i = 0;
        for (; i < lhs->netmask / 32 || i < 1; i++) {
            if (lhs->ip[i] < rhs->ip[i])
                return -1;
            if (lhs->ip[i] > rhs->ip[i])
                return 1;
        }
        return 0;
    }

    return lhs->netmask < rhs->netmask ? -1 : 1;
}

static int IPOnlyCIDRItemCompare(const void *lhsv, const void *rhsv)
{
    const IPOnlyCIDRItem *lhs = *(const IPOnlyCIDRItem **)lhsv;
    const IPOnlyCIDRItem *rhs = *(const IPOnlyCIDRItem **)rhsv;

    return IPOnlyCIDRItemCompareReal(lhs, rhs);
}

static void IPOnlyCIDRListQSort(IPOnlyCIDRItem **head)
{
    if (unlikely(head == NULL || *head == NULL))
        return;

    // First count the number of elements in the list
    size_t len = 0;
    IPOnlyCIDRItem *curr = *head;

    while (curr) {
        curr = curr->next;
        len++;
    }

    // Place a pointer to the list item in an array for sorting
    IPOnlyCIDRItem **tmp = SCMalloc(len * sizeof(IPOnlyCIDRItem *));

    if (unlikely(tmp == NULL)) {
        SCLogError("Failed to allocate enough memory to sort IP-only CIDR items.");
        return;
    }

    curr = *head;
    for (size_t i = 0; i < len; i++) {
        tmp[i] = curr;
        curr = curr->next;
    }

    // Perform the sort using the qsort algorithm
    qsort(tmp, len, sizeof(IPOnlyCIDRItem *), IPOnlyCIDRItemCompare);

    // Update the links to the next element
    *head = tmp[0];

    for (size_t i = 0; i + 1 < len; i++) {
        tmp[i]->next = tmp[i + 1];
    }

    tmp[len - 1]->next = NULL;

    SCFree(tmp);
}

//declaration for using it already
static IPOnlyCIDRItem *IPOnlyCIDRItemInsert(IPOnlyCIDRItem *head,
                                            IPOnlyCIDRItem *item);

static int InsertRange(
        IPOnlyCIDRItem **pdd, IPOnlyCIDRItem *dd, const uint32_t first_in, const uint32_t last_in)
{
    DEBUG_VALIDATE_BUG_ON(dd == NULL);
    DEBUG_VALIDATE_BUG_ON(pdd == NULL);

    uint32_t first = first_in;
    uint32_t last = last_in;

    dd->netmask = 32;
    /* Find the maximum netmask starting from current address first
     * and not crossing last.
     * To extend the mask, we need to start from a power of 2.
     * And we need to pay attention to unsigned overflow back to 0.0.0.0
     */
    while (dd->netmask > 0 && (first & (1UL << (32 - dd->netmask))) == 0 &&
            first + (1UL << (32 - (dd->netmask - 1))) - 1 <= last) {
        dd->netmask--;
    }
    dd->ip[0] = htonl(first);
    first += 1UL << (32 - dd->netmask);
    // case whatever-255.255.255.255 looping to 0.0.0.0/0
    while (first <= last && first != 0) {
        IPOnlyCIDRItem *new = IPOnlyCIDRItemNew();
        if (new == NULL)
            goto error;
        new->negated = dd->negated;
        new->family = dd->family;
        new->netmask = 32;
        while (new->netmask > 0 && (first & (1UL << (32 - new->netmask))) == 0 &&
                first + (1UL << (32 - (new->netmask - 1))) - 1 <= last) {
            new->netmask--;
        }
        new->ip[0] = htonl(first);
        first += 1UL << (32 - new->netmask);
        dd = IPOnlyCIDRItemInsert(dd, new);
    }
    // update head of list
    *pdd = dd;
    return 0;
error:
    return -1;
}

/**
 * \internal
 * \brief Parses an ipv4/ipv6 address string and updates the result into the
 *        IPOnlyCIDRItem instance sent as the argument.
 *
 * \param pdd Double pointer to the IPOnlyCIDRItem instance which should be updated
 *            with the address (in cidr) details from the parsed ip string.
 * \param str Pointer to address string that has to be parsed.
 *
 * \retval  0 On successfully parsing the address string.
 * \retval -1 On failure.
 */
static int IPOnlyCIDRItemParseSingle(IPOnlyCIDRItem **pdd, const char *str)
{
    char buf[256] = "";
    char *ip = NULL, *ip2 = NULL;
    char *mask = NULL;
    int r = 0;
    IPOnlyCIDRItem *dd = *pdd;

    while (*str != '\0' && *str == ' ')
        str++;

    SCLogDebug("str %s", str);
    strlcpy(buf, str, sizeof(buf));
    ip = buf;

    /* first handle 'any' */
    if (strcasecmp(str, "any") == 0) {
        /* if any, insert 0.0.0.0/0 and ::/0 as well */
        SCLogDebug("adding 0.0.0.0/0 and ::/0 as we\'re handling \'any\'");

        IPOnlyCIDRItemParseSingle(&dd, "0.0.0.0/0");
        BUG_ON(dd->family == 0);

        dd->next = IPOnlyCIDRItemNew();
        if (dd->next == NULL)
            goto error;

        IPOnlyCIDRItemParseSingle(&dd->next, "::/0");
        BUG_ON(dd->family == 0);

        SCLogDebug("address is \'any\'");
        return 0;
    }

    /* handle the negation case */
    if (ip[0] == '!') {
        dd->negated = (dd->negated)? 0 : 1;
        ip++;
    }

    /* see if the address is an ipv4 or ipv6 address */
    if ((strchr(str, ':')) == NULL) {
        /* IPv4 Address */
        struct in_addr in;

        dd->family = AF_INET;

        if ((mask = strchr(ip, '/')) != NULL) {
            /* 1.2.3.4/xxx format (either dotted or cidr notation */
            ip[mask - ip] = '\0';
            mask++;
            uint32_t netmask = 0;
            size_t u = 0;

            if ((strchr (mask, '.')) == NULL) {
                /* 1.2.3.4/24 format */

                for (u = 0; u < strlen(mask); u++) {
                    if(!isdigit((unsigned char)mask[u]))
                        goto error;
                }

                uint8_t cidr;
                if (StringParseU8RangeCheck(&cidr, 10, 0, (const char *)mask, 0, 32) < 0)
                    goto error;

                dd->netmask = cidr;
                netmask = CIDRGet(cidr);
            } else {
                /* 1.2.3.4/255.255.255.0 format */
                r = inet_pton(AF_INET, mask, &in);
                if (r <= 0)
                    goto error;

                int cidr = CIDRFromMask(in.s_addr);
                if (cidr < 0)
                    goto error;

                dd->netmask = (uint8_t)cidr;
            }

            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0)
                goto error;

            dd->ip[0] = in.s_addr & netmask;

        } else if ((ip2 = strchr(ip, '-')) != NULL) {
            /* 1.2.3.4-1.2.3.6 range format */
            ip[ip2 - ip] = '\0';
            ip2++;

            uint32_t first, last;

            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0)
                goto error;
            first = SCNtohl(in.s_addr);

            r = inet_pton(AF_INET, ip2, &in);
            if (r <= 0)
                goto error;
            last = SCNtohl(in.s_addr);

            /* a > b is illegal, a = b is ok */
            if (first > last)
                goto error;

            SCLogDebug("Creating CIDR range for [%s - %s]", ip, ip2);
            return InsertRange(pdd, dd, first, last);
        } else {
            /* 1.2.3.4 format */
            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0)
                goto error;

            /* single host */
            dd->ip[0] = in.s_addr;
            dd->netmask = 32;
        }
    } else {
        /* IPv6 Address */
        struct in6_addr in6, mask6;
        uint32_t ip6addr[4], netmask[4];

        dd->family = AF_INET6;

        if ((mask = strchr(ip, '/')) != NULL)  {
            mask[0] = '\0';
            mask++;

            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0)
                goto error;

            /* Format is cidr val */
            if (StringParseU8RangeCheck(&dd->netmask, 10, 0,
                                        (const char *)mask, 0, 128) < 0) {
                goto error;
            }

            memcpy(&ip6addr, &in6.s6_addr, sizeof(ip6addr));
            CIDRGetIPv6(dd->netmask, &mask6);
            memcpy(&netmask, &mask6.s6_addr, sizeof(netmask));

            dd->ip[0] = ip6addr[0] & netmask[0];
            dd->ip[1] = ip6addr[1] & netmask[1];
            dd->ip[2] = ip6addr[2] & netmask[2];
            dd->ip[3] = ip6addr[3] & netmask[3];
        } else {
            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0)
                goto error;

            memcpy(dd->ip, &in6.s6_addr, sizeof(dd->ip));
            dd->netmask = 128;
        }

    }

    BUG_ON(dd->family == 0);
    return 0;

error:
    return -1;
}

/**
 * \brief Setup a single address string, parse it and add the resulting
 *        Address items in cidr format to the list of gh
 *
 * \param gh Pointer to the IPOnlyCIDRItem list Head to which the
 *           resulting Address-Range(s) from the parsed ip string has to
 *           be added.
 * \param s  Pointer to the ip address string to be parsed.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int IPOnlyCIDRItemSetup(IPOnlyCIDRItem **gh, char *s)
{
    SCLogDebug("gh %p, s %s", *gh, s);

    /* parse the address */
    if (IPOnlyCIDRItemParseSingle(gh, s) == -1) {
        SCLogError("address parsing error \"%s\"", s);
        goto error;
    }

    return 0;

error:
    return -1;
}

/**
 * \brief This function insert a IPOnlyCIDRItem
 *        to a list of IPOnlyCIDRItems
 * \param head Pointer to the head of IPOnlyCIDRItems list
 * \param item Pointer to the item to insert in the list
 *
 * \retval IPOnlyCIDRItem address of the new head if apply
 */
static IPOnlyCIDRItem *IPOnlyCIDRItemInsertReal(IPOnlyCIDRItem *head,
                                         IPOnlyCIDRItem *item)
{
    if (item == NULL)
        return head;

    /* Always insert item as head */
    item->next = head;
    return item;
}

/**
 * \brief This function insert a IPOnlyCIDRItem list
 *        to a list of IPOnlyCIDRItems sorted by netmask
 *        ascending
 * \param head Pointer to the head of IPOnlyCIDRItems list
 * \param item Pointer to the list of items to insert in the list
 *
 * \retval IPOnlyCIDRItem address of the new head if apply
 */
static IPOnlyCIDRItem *IPOnlyCIDRItemInsert(IPOnlyCIDRItem *head,
                                     IPOnlyCIDRItem *item)
{
    IPOnlyCIDRItem *it, *prev = NULL;

    /* The first element */
    if (head == NULL) {
        SCLogDebug("Head is NULL to insert item (%p)",item);
        return item;
    }

    if (item == NULL) {
        SCLogDebug("Item is NULL");
        return head;
    }

    SCLogDebug("Inserting item(%p)->netmask %u head %p", item, item->netmask, head);

    prev = item;
    while (prev != NULL) {
        it = prev->next;

        /* Separate from the item list */
        prev->next = NULL;

        //SCLogDebug("Before:");
        //IPOnlyCIDRListPrint(head);
        head = IPOnlyCIDRItemInsertReal(head, prev);
        //SCLogDebug("After:");
        //IPOnlyCIDRListPrint(head);
        prev = it;
    }

    return head;
}

/**
 * \brief This function free a IPOnlyCIDRItem list
 * \param tmphead Pointer to the list
 */
void IPOnlyCIDRListFree(IPOnlyCIDRItem *tmphead)
{
    SCEnter();
#ifdef DEBUG
    uint32_t i = 0;
#endif
    IPOnlyCIDRItem *it, *next = NULL;

    if (tmphead == NULL) {
        SCLogDebug("temphead is NULL");
        return;
    }

    it = tmphead;
    next = it->next;

    while (it != NULL) {
#ifdef DEBUG
        i++;
        SCLogDebug("Item(%p) %"PRIu32" removed", it, i);
#endif
        SCFree(it);
        it = next;

        if (next != NULL)
            next = next->next;
    }
    SCReturn;
}

/**
 * \brief This function update a list of IPOnlyCIDRItems
 *        setting the signature internal id (signum) to "i"
 *
 * \param tmphead Pointer to the list
 * \param i number of signature internal id
 */
static void IPOnlyCIDRListSetSigNum(IPOnlyCIDRItem *tmphead, SigIntId i)
{
    while (tmphead != NULL) {
        tmphead->signum = i;
        tmphead = tmphead->next;
    }
}

#ifdef UNITTESTS
/**
 * \brief This function print a IPOnlyCIDRItem list
 * \param tmphead Pointer to the head of IPOnlyCIDRItems list
 */
static void IPOnlyCIDRListPrint(IPOnlyCIDRItem *tmphead)
{
#ifdef DEBUG
    uint32_t i = 0;

    while (tmphead != NULL) {
        i++;
        SCLogDebug("Item %"PRIu32" has netmask %"PRIu8" negated:"
                   " %s; IP: %s; signum: %"PRIu32, i, tmphead->netmask,
                   (tmphead->negated) ? "yes":"no",
                   inet_ntoa(*(struct in_addr*)&tmphead->ip[0]),
                   tmphead->signum);
        tmphead = tmphead->next;
    }
#endif
}
#endif

/** \brief user data for storing signature id's in the radix tree
 *
 *  Bit array representing signature internal id's (Signature::num).
 */
typedef struct SigNumArray_ {
    uint8_t *array; /* bit array of sig nums */
    uint32_t size;  /* size in bytes of the array */
} SigNumArray;

/**
 * \brief This function print a SigNumArray, it's used with the
 *        radix tree print function to help debugging
 * \param tmp Pointer to the head of SigNumArray
 */
static void SigNumArrayPrint(void *tmp)
{
    SigNumArray *sna = (SigNumArray *)tmp;
    for (uint32_t u = 0; u < sna->size; u++) {
        uint8_t bitarray = sna->array[u];
        for (uint8_t i = 0; i < 8; i++) {
            if (bitarray & 0x01)
                printf("%" PRIu32 " ", u * 8 + i);
            bitarray = bitarray >> 1;
        }
    }
}

/**
 * \brief This function creates a new SigNumArray with the
 *        size fixed to the io_ctx->max_idx
 * \param de_ctx Pointer to the current detection context
 * \param io_ctx Pointer to the current ip only context
 *
 * \retval SigNumArray address of the new instance
 */
static SigNumArray *SigNumArrayNew(DetectEngineCtx *de_ctx,
                            DetectEngineIPOnlyCtx *io_ctx)
{
    SigNumArray *new = SCCalloc(1, sizeof(SigNumArray));

    if (unlikely(new == NULL)) {
        FatalError("Fatal error encountered in SigNumArrayNew. Exiting...");
    }

    new->array = SCCalloc(1, io_ctx->max_idx / 8 + 1);
    if (new->array == NULL) {
       exit(EXIT_FAILURE);
    }

    new->size = io_ctx->max_idx / 8 + 1;

    SCLogDebug("max idx= %u", io_ctx->max_idx);

    return new;
}

/**
 * \brief This function creates a new SigNumArray with the
 *        same data as the argument
 *
 * \param orig Pointer to the original SigNumArray to copy
 *
 * \retval SigNumArray address of the new instance
 */
static SigNumArray *SigNumArrayCopy(SigNumArray *orig)
{
    SigNumArray *new = SCCalloc(1, sizeof(SigNumArray));

    if (unlikely(new == NULL)) {
        FatalError("Fatal error encountered in SigNumArrayCopy. Exiting...");
    }

    new->size = orig->size;

    new->array = SCMalloc(orig->size);
    if (new->array == NULL) {
        exit(EXIT_FAILURE);
    }

    memcpy(new->array, orig->array, orig->size);
    return new;
}

/**
 * \brief This function free() a SigNumArray
 * \param orig Pointer to the original SigNumArray to copy
 */
static void SigNumArrayFree(void *tmp)
{
    SigNumArray *sna = (SigNumArray *)tmp;

    if (sna == NULL)
        return;

    if (sna->array != NULL)
        SCFree(sna->array);

    SCFree(sna);
}

/**
 * \brief This function parses and return a list of IPOnlyCIDRItem
 *
 * \param s Pointer to the string of the addresses
 *          (in the format of signatures)
 * \param negate flag to indicate if all this string is negated or not
 *
 * \retval 0 if success
 * \retval -1 if fails
 */
static IPOnlyCIDRItem *IPOnlyCIDRListParse2(
        const DetectEngineCtx *de_ctx, const char *s, int negate)
{
    size_t x = 0;
    size_t u = 0;
    int o_set = 0, n_set = 0, d_set = 0;
    int depth = 0;
    size_t size = strlen(s);
    char address[8196] = "";
    const char *rule_var_address = NULL;
    char *temp_rule_var_address = NULL;
    IPOnlyCIDRItem *head;
    IPOnlyCIDRItem *subhead;
    head = subhead = NULL;

    SCLogDebug("s %s negate %s", s, negate ? "true" : "false");

    for (u = 0, x = 0; u < size && x < sizeof(address); u++) {
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

                if ( (subhead = IPOnlyCIDRListParse2(de_ctx, address,
                                                (negate + n_set) % 2)) == NULL)
                    goto error;

                head = IPOnlyCIDRItemInsert(head, subhead);
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

                if ((negate + n_set) % 2) {
                    temp_rule_var_address = SCMalloc(strlen(rule_var_address) + 3);
                    if (unlikely(temp_rule_var_address == NULL)) {
                        goto error;
                    }

                    snprintf(temp_rule_var_address, strlen(rule_var_address) + 3,
                             "[%s]", rule_var_address);
                } else {
                    temp_rule_var_address = SCStrdup(rule_var_address);
                    if (unlikely(temp_rule_var_address == NULL)) {
                        goto error;
                    }
                }

                subhead = IPOnlyCIDRListParse2(de_ctx, temp_rule_var_address,
                                               (negate + n_set) % 2);
                head = IPOnlyCIDRItemInsert(head, subhead);

                d_set = 0;
                n_set = 0;

                SCFree(temp_rule_var_address);

            } else {
                address[x - 1] = '\0';

                subhead = IPOnlyCIDRItemNew();
                if (subhead == NULL)
                    goto error;

                if (!((negate + n_set) % 2))
                    subhead->negated = 0;
                else
                    subhead->negated = 1;

                if (IPOnlyCIDRItemSetup(&subhead, address) < 0) {
                    IPOnlyCIDRListFree(subhead);
                    subhead = NULL;
                    goto error;
                }
                head = IPOnlyCIDRItemInsert(head, subhead);

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

                if ((negate + n_set) % 2) {
                    temp_rule_var_address = SCMalloc(strlen(rule_var_address) + 3);
                    if (unlikely(temp_rule_var_address == NULL)) {
                        goto error;
                    }
                    snprintf(temp_rule_var_address, strlen(rule_var_address) + 3,
                            "[%s]", rule_var_address);
                } else {
                    temp_rule_var_address = SCStrdup(rule_var_address);
                    if (unlikely(temp_rule_var_address == NULL)) {
                        goto error;
                    }
                }
                subhead = IPOnlyCIDRListParse2(de_ctx, temp_rule_var_address,
                                               (negate + n_set) % 2);
                head = IPOnlyCIDRItemInsert(head, subhead);

                d_set = 0;

                SCFree(temp_rule_var_address);
            } else {
                subhead = IPOnlyCIDRItemNew();
                if (subhead == NULL)
                    goto error;

                if (!((negate + n_set) % 2))
                    subhead->negated = 0;
                else
                    subhead->negated = 1;

                if (IPOnlyCIDRItemSetup(&subhead, address) < 0) {
                    IPOnlyCIDRListFree(subhead);
                    subhead = NULL;
                    goto error;
                }
                head = IPOnlyCIDRItemInsert(head, subhead);
            }
            n_set = 0;
        }
    }

    return head;

error:
    SCLogError("Error parsing addresses");
    return head;
}


/**
 * \brief Parses an address group sent as a character string and updates the
 *        IPOnlyCIDRItem list
 *
 * \param gh  Pointer to the IPOnlyCIDRItem list
 * \param str Pointer to the character string containing the address group
 *            that has to be parsed.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int IPOnlyCIDRListParse(const DetectEngineCtx *de_ctx, IPOnlyCIDRItem **gh, const char *str)
{
    SCLogDebug("gh %p, str %s", gh, str);

    if (gh == NULL)
        goto error;

    *gh = IPOnlyCIDRListParse2(de_ctx, str, 0);
    if (*gh == NULL) {
        SCLogDebug("IPOnlyCIDRListParse2 returned null");
        goto error;
    }

    return 0;

error:
    return -1;
}

/**
 * \brief Parses an address group sent as a character string and updates the
 *        IPOnlyCIDRItem lists src and dst of the Signature *s
 *
 * \param s Pointer to the signature structure
 * \param addrstr Pointer to the character string containing the address group
 *            that has to be parsed.
 * \param flag to indicate if we are parsing the src string or the dst string
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int IPOnlySigParseAddress(const DetectEngineCtx *de_ctx,
                          Signature *s, const char *addrstr, char flag)
{
    SCLogDebug("Address Group \"%s\" to be parsed now", addrstr);

    /* pass on to the address(list) parser */
    if (flag == 0) {
        if (strcasecmp(addrstr, "any") == 0) {
            s->flags |= SIG_FLAG_SRC_ANY;
            if (IPOnlyCIDRListParse(de_ctx, &s->init_data->cidr_src, "[0.0.0.0/0,::/0]") < 0)
                goto error;

        } else if (IPOnlyCIDRListParse(de_ctx, &s->init_data->cidr_src, (char *)addrstr) < 0) {
            goto error;
        }

        /* IPOnlyCIDRListPrint(s->CidrSrc); */
    } else {
        if (strcasecmp(addrstr, "any") == 0) {
            s->flags |= SIG_FLAG_DST_ANY;
            if (IPOnlyCIDRListParse(de_ctx, &s->init_data->cidr_dst, "[0.0.0.0/0,::/0]") < 0)
                goto error;

        } else if (IPOnlyCIDRListParse(de_ctx, &s->init_data->cidr_dst, (char *)addrstr) < 0) {
            goto error;
        }

        /* IPOnlyCIDRListPrint(s->CidrDst); */
    }

    return 0;

error:
    SCLogError("failed to parse addresses");
    return -1;
}

/**
 * \brief Setup the IP Only detection engine context
 *
 * \param de_ctx Pointer to the current detection engine
 * \param io_ctx Pointer to the current ip only detection engine
 */
void IPOnlyInit(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx)
{
    io_ctx->tree_ipv4src = SCRadixCreateRadixTree(SigNumArrayFree, SigNumArrayPrint);
    io_ctx->tree_ipv4dst = SCRadixCreateRadixTree(SigNumArrayFree, SigNumArrayPrint);
    io_ctx->tree_ipv6src = SCRadixCreateRadixTree(SigNumArrayFree, SigNumArrayPrint);
    io_ctx->tree_ipv6dst = SCRadixCreateRadixTree(SigNumArrayFree, SigNumArrayPrint);

    io_ctx->sig_mapping = SCCalloc(1, de_ctx->sig_array_len * sizeof(uint32_t));
    if (io_ctx->sig_mapping == NULL) {
        FatalError("Unable to allocate iponly signature tracking area");
    }
    io_ctx->sig_mapping_size = 0;
}

SigIntId IPOnlyTrackSigNum(DetectEngineIPOnlyCtx *io_ctx, SigIntId signum)
{
    SigIntId loc = io_ctx->sig_mapping_size;
    io_ctx->sig_mapping[loc] = signum;
    io_ctx->sig_mapping_size++;
    return loc;
}

/**
 * \brief Print stats of the IP Only engine
 *
 * \param de_ctx Pointer to the current detection engine
 * \param io_ctx Pointer to the current ip only detection engine
 */
void IPOnlyPrint(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx)
{
    /* XXX: how are we going to print the stats now? */
}

/**
 * \brief Deinitialize the IP Only detection engine context
 *
 * \param de_ctx Pointer to the current detection engine
 * \param io_ctx Pointer to the current ip only detection engine
 */
void IPOnlyDeinit(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx)
{

    if (io_ctx == NULL)
        return;

    if (io_ctx->tree_ipv4src != NULL)
        SCRadixReleaseRadixTree(io_ctx->tree_ipv4src);
    io_ctx->tree_ipv4src = NULL;

    if (io_ctx->tree_ipv4dst != NULL)
        SCRadixReleaseRadixTree(io_ctx->tree_ipv4dst);
    io_ctx->tree_ipv4dst = NULL;

    if (io_ctx->tree_ipv6src != NULL)
        SCRadixReleaseRadixTree(io_ctx->tree_ipv6src);
    io_ctx->tree_ipv6src = NULL;

    if (io_ctx->tree_ipv6dst != NULL)
        SCRadixReleaseRadixTree(io_ctx->tree_ipv6dst);
    io_ctx->tree_ipv6dst = NULL;

    if (io_ctx->sig_mapping != NULL)
        SCFree(io_ctx->sig_mapping);
    io_ctx->sig_mapping = NULL;
}

static inline int IPOnlyMatchCompatSMs(
        ThreadVars *tv, DetectEngineThreadCtx *det_ctx, const Signature *s, Packet *p)
{
    KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_MATCH);
    const SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_MATCH];
    while (smd) {
        DEBUG_VALIDATE_BUG_ON(!(sigmatch_table[smd->type].flags & SIGMATCH_IPONLY_COMPAT));
        KEYWORD_PROFILING_START;
        if (sigmatch_table[smd->type].Match(det_ctx, p, s, smd->ctx) > 0) {
            KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
            if (smd->is_last)
                break;
            smd++;
            continue;
        }
        KEYWORD_PROFILING_END(det_ctx, smd->type, 0);
        return 0;
    }
    return 1;
}

/**
 * \brief Match a packet against the IP Only detection engine contexts
 *
 * \param de_ctx Pointer to the current detection engine
 * \param io_ctx Pointer to the current ip only detection engine
 * \param io_ctx Pointer to the current ip only thread detection engine
 * \param p Pointer to the Packet to match against
 */
void IPOnlyMatchPacket(ThreadVars *tv, const DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineIPOnlyCtx *io_ctx, Packet *p)
{
    SigNumArray *src = NULL;
    SigNumArray *dst = NULL;
    void *user_data_src = NULL, *user_data_dst = NULL;

    SCEnter();

    if (p->src.family == AF_INET) {
        (void)SCRadixFindKeyIPV4BestMatch((uint8_t *)&GET_IPV4_SRC_ADDR_U32(p),
                                              io_ctx->tree_ipv4src, &user_data_src);
    } else if (p->src.family == AF_INET6) {
        (void)SCRadixFindKeyIPV6BestMatch((uint8_t *)&GET_IPV6_SRC_ADDR(p),
                                              io_ctx->tree_ipv6src, &user_data_src);
    }

    if (p->dst.family == AF_INET) {
        (void)SCRadixFindKeyIPV4BestMatch((uint8_t *)&GET_IPV4_DST_ADDR_U32(p),
                                              io_ctx->tree_ipv4dst, &user_data_dst);
    } else if (p->dst.family == AF_INET6) {
        (void)SCRadixFindKeyIPV6BestMatch((uint8_t *)&GET_IPV6_DST_ADDR(p),
                                              io_ctx->tree_ipv6dst, &user_data_dst);
    }

    src = user_data_src;
    dst = user_data_dst;

    if (src == NULL || dst == NULL)
        SCReturn;

    for (uint32_t u = 0; u < src->size; u++) {
        SCLogDebug("And %"PRIu8" & %"PRIu8, src->array[u], dst->array[u]);

        uint8_t bitarray = dst->array[u] & src->array[u];

        /* We have to move the logic of the signature checking
         * to the main detect loop, in order to apply the
         * priority of actions (pass, drop, reject, alert) */
        if (!bitarray)
            continue;

        /* We have a match :) Let's see from which signum's */

        for (uint8_t i = 0; i < 8; i++, bitarray = bitarray >> 1) {
            if (bitarray & 0x01) {
                const Signature *s = de_ctx->sig_array[io_ctx->sig_mapping[u * 8 + i]];

                if ((s->proto.flags & DETECT_PROTO_IPV4) && !PacketIsIPv4(p)) {
                    SCLogDebug("ip version didn't match");
                    continue;
                }
                if ((s->proto.flags & DETECT_PROTO_IPV6) && !PacketIsIPv6(p)) {
                    SCLogDebug("ip version didn't match");
                    continue;
                }
                if (DetectProtoContainsProto(&s->proto, PacketGetIPProto(p)) == 0) {
                    SCLogDebug("proto didn't match");
                    continue;
                }

                /* check the source & dst port in the sig */
                if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP ||
                        p->proto == IPPROTO_SCTP) {
                    if (!(s->flags & SIG_FLAG_DP_ANY)) {
                        if (p->flags & PKT_IS_FRAGMENT)
                            continue;

                        const DetectPort *dport = DetectPortLookupGroup(s->dp, p->dp);
                        if (dport == NULL) {
                            SCLogDebug("dport didn't match.");
                            continue;
                        }
                    }
                    if (!(s->flags & SIG_FLAG_SP_ANY)) {
                        if (p->flags & PKT_IS_FRAGMENT)
                            continue;

                        const DetectPort *sport = DetectPortLookupGroup(s->sp, p->sp);
                        if (sport == NULL) {
                            SCLogDebug("sport didn't match.");
                            continue;
                        }
                    }
                } else if ((s->flags & (SIG_FLAG_DP_ANY | SIG_FLAG_SP_ANY)) !=
                           (SIG_FLAG_DP_ANY | SIG_FLAG_SP_ANY)) {
                    SCLogDebug("port-less protocol and sig needs ports");
                    continue;
                }

                if (!IPOnlyMatchCompatSMs(tv, det_ctx, s, p)) {
                    continue;
                }

                SCLogDebug("Signum %" PRIu32 " match (sid: %" PRIu32 ", msg: %s)", u * 8 + i, s->id,
                        s->msg);

                if (s->sm_arrays[DETECT_SM_LIST_POSTMATCH] != NULL) {
                    KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_POSTMATCH);
                    const SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_POSTMATCH];

                    SCLogDebug("running match functions, sm %p", smd);

                    if (smd != NULL) {
                        while (1) {
                            KEYWORD_PROFILING_START;
                            (void)sigmatch_table[smd->type].Match(det_ctx, p, s, smd->ctx);
                            KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
                            if (smd->is_last)
                                break;
                            smd++;
                        }
                    }
                }
                AlertQueueAppend(det_ctx, s, p, 0, 0);
            }
        }
    }
    SCReturn;
}

/**
 * \brief Build the radix trees from the lists of parsed addresses in CIDR format
 *        the result should be 4 radix trees: src/dst ipv4 and src/dst ipv6
 *        holding SigNumArrays, each of them with a hierarchical relation
 *        of subnets and hosts
 *
 * \param de_ctx Pointer to the current detection engine
 */
void IPOnlyPrepare(DetectEngineCtx *de_ctx)
{
    SCLogDebug("Preparing Final Lists");

    /*
       IPOnlyCIDRListPrint((de_ctx->io_ctx).ip_src);
       IPOnlyCIDRListPrint((de_ctx->io_ctx).ip_dst);
     */

    IPOnlyCIDRListQSort(&(de_ctx->io_ctx).ip_src);
    IPOnlyCIDRListQSort(&(de_ctx->io_ctx).ip_dst);

    IPOnlyCIDRItem *src, *dst;
    SCRadixNode *node = NULL;

    /* Prepare Src radix trees */
    for (src = (de_ctx->io_ctx).ip_src; src != NULL; ) {
        if (src->family == AF_INET) {
        /*
            SCLogDebug("To IPv4");
            SCLogDebug("Item has netmask %"PRIu16" negated: %s; IP: %s; "
                       "signum: %"PRIu16, src->netmask,
                        (src->negated) ? "yes":"no",
                        inet_ntoa( *(struct in_addr*)&src->ip[0]),
                        src->signum);
        */

            void *user_data = NULL;
            if (src->netmask == 32)
                (void)SCRadixFindKeyIPV4ExactMatch((uint8_t *)&src->ip[0],
                                                    (de_ctx->io_ctx).tree_ipv4src,
                                                    &user_data);
            else
                (void)SCRadixFindKeyIPV4Netblock((uint8_t *)&src->ip[0],
                                                  (de_ctx->io_ctx).tree_ipv4src,
                                                  src->netmask, &user_data);
            if (user_data == NULL) {
                SCLogDebug("Exact match not found");

                /** Not found, look if there's a subnet of this range with
                 * bigger netmask */
                (void)SCRadixFindKeyIPV4BestMatch((uint8_t *)&src->ip[0],
                                                   (de_ctx->io_ctx).tree_ipv4src,
                                                   &user_data);
                if (user_data == NULL) {
                    SCLogDebug("best match not found");

                    /* Not found, insert a new one */
                    SigNumArray *sna = SigNumArrayNew(de_ctx, &de_ctx->io_ctx);

                    /* Update the sig */
                    uint8_t tmp = (uint8_t)(1 << (src->signum % 8));

                    if (src->negated > 0)
                        /* Unset it */
                        sna->array[src->signum / 8] &= ~tmp;
                    else
                        /* Set it */
                        sna->array[src->signum / 8] |= tmp;

                    if (src->netmask == 32)
                        node = SCRadixAddKeyIPV4((uint8_t *)&src->ip[0],
                                                 (de_ctx->io_ctx).tree_ipv4src, sna);
                    else
                        node = SCRadixAddKeyIPV4Netblock((uint8_t *)&src->ip[0],
                                                         (de_ctx->io_ctx).tree_ipv4src,
                                                         sna, src->netmask);

                    if (node == NULL)
                        SCLogError("Error inserting in the "
                                   "src ipv4 radix tree");
                } else {
                    SCLogDebug("Best match found");

                    /* Found, copy the sig num table, add this signum and insert */
                    SigNumArray *sna = NULL;
                    sna = SigNumArrayCopy((SigNumArray *) user_data);

                    /* Update the sig */
                    uint8_t tmp = (uint8_t)(1 << (src->signum % 8));

                    if (src->negated > 0)
                        /* Unset it */
                        sna->array[src->signum / 8] &= ~tmp;
                    else
                        /* Set it */
                        sna->array[src->signum / 8] |= tmp;

                    if (src->netmask == 32)
                        node = SCRadixAddKeyIPV4((uint8_t *)&src->ip[0],
                                                 (de_ctx->io_ctx).tree_ipv4src, sna);
                    else
                        node = SCRadixAddKeyIPV4Netblock((uint8_t *)&src->ip[0],
                                                         (de_ctx->io_ctx).tree_ipv4src, sna,
                                                         src->netmask);

                    if (node == NULL) {
                        char tmpstr[64];
                        PrintInet(src->family, &src->ip[0], tmpstr, sizeof(tmpstr));
                        SCLogError("Error inserting in the"
                                   " src ipv4 radix tree ip %s netmask %" PRIu8,
                                tmpstr, src->netmask);
                        //SCRadixPrintTree((de_ctx->io_ctx).tree_ipv4src);
                        exit(-1);
                    }
                }
            } else {
                SCLogDebug("Exact match found");

                /* it's already inserted. Update it */
                SigNumArray *sna = (SigNumArray *)user_data;

                /* Update the sig */
                uint8_t tmp = (uint8_t)(1 << (src->signum % 8));

                if (src->negated > 0)
                    /* Unset it */
                    sna->array[src->signum / 8] &= ~tmp;
                else
                    /* Set it */
                    sna->array[src->signum / 8] |= tmp;
            }
        } else if (src->family == AF_INET6) {
            SCLogDebug("To IPv6");

            void *user_data = NULL;
            if (src->netmask == 128)
                (void)SCRadixFindKeyIPV6ExactMatch((uint8_t *)&src->ip[0],
                                                    (de_ctx->io_ctx).tree_ipv6src,
                                                    &user_data);
            else
                (void)SCRadixFindKeyIPV6Netblock((uint8_t *)&src->ip[0],
                                                  (de_ctx->io_ctx).tree_ipv6src,
                                                  src->netmask, &user_data);

            if (user_data == NULL) {
                /* Not found, look if there's a subnet of this range with bigger netmask */
                (void)SCRadixFindKeyIPV6BestMatch((uint8_t *)&src->ip[0],
                                                   (de_ctx->io_ctx).tree_ipv6src,
                                                   &user_data);

                if (user_data == NULL) {
                    /* Not found, insert a new one */
                    SigNumArray *sna = SigNumArrayNew(de_ctx, &de_ctx->io_ctx);

                    /* Update the sig */
                    uint8_t tmp = (uint8_t)(1 << (src->signum % 8));

                    if (src->negated > 0)
                        /* Unset it */
                        sna->array[src->signum / 8] &= ~tmp;
                    else
                        /* Set it */
                        sna->array[src->signum / 8] |= tmp;

                    if (src->netmask == 128)
                        node = SCRadixAddKeyIPV6((uint8_t *)&src->ip[0],
                                                 (de_ctx->io_ctx).tree_ipv6src, sna);
                    else
                        node = SCRadixAddKeyIPV6Netblock((uint8_t *)&src->ip[0],
                                                         (de_ctx->io_ctx).tree_ipv6src,
                                                         sna, src->netmask);
                    if (node == NULL)
                        SCLogError("Error inserting in the src "
                                   "ipv6 radix tree");
                } else {
                    /* Found, copy the sig num table, add this signum and insert */
                    SigNumArray *sna = NULL;
                    sna = SigNumArrayCopy((SigNumArray *)user_data);

                    /* Update the sig */
                    uint8_t tmp = (uint8_t)(1 << (src->signum % 8));
                    if (src->negated > 0)
                        /* Unset it */
                        sna->array[src->signum / 8] &= ~tmp;
                    else
                        /* Set it */
                        sna->array[src->signum / 8] |= tmp;

                    if (src->netmask == 128)
                        node = SCRadixAddKeyIPV6((uint8_t *)&src->ip[0],
                                                 (de_ctx->io_ctx).tree_ipv6src, sna);
                    else
                        node = SCRadixAddKeyIPV6Netblock((uint8_t *)&src->ip[0],
                                                         (de_ctx->io_ctx).tree_ipv6src,
                                                         sna, src->netmask);
                    if (node == NULL)
                        SCLogError("Error inserting in the src "
                                   "ipv6 radix tree");
                }
            } else {
                /* it's already inserted. Update it */
                SigNumArray *sna = (SigNumArray *)user_data;

                /* Update the sig */
                uint8_t tmp = (uint8_t)(1 << (src->signum % 8));
                if (src->negated > 0)
                    /* Unset it */
                    sna->array[src->signum / 8] &= ~tmp;
                else
                    /* Set it */
                    sna->array[src->signum / 8] |= tmp;
            }
        }
        IPOnlyCIDRItem *tmpaux = src;
        src = src->next;
        SCFree(tmpaux);
    }

    SCLogDebug("dsts:");

    /* Prepare Dst radix trees */
    for (dst = (de_ctx->io_ctx).ip_dst; dst != NULL; ) {
        if (dst->family == AF_INET) {

            SCLogDebug("To IPv4");
            SCLogDebug("Item has netmask %"PRIu8" negated: %s; IP: %s; signum:"
                       " %"PRIu32"", dst->netmask, (dst->negated)?"yes":"no",
                       inet_ntoa(*(struct in_addr*)&dst->ip[0]), dst->signum);

            void *user_data = NULL;
            if (dst->netmask == 32)
                (void) SCRadixFindKeyIPV4ExactMatch((uint8_t *) &dst->ip[0],
                                                    (de_ctx->io_ctx).tree_ipv4dst,
                                                    &user_data);
            else
                (void) SCRadixFindKeyIPV4Netblock((uint8_t *) &dst->ip[0],
                                                  (de_ctx->io_ctx).tree_ipv4dst,
                                                  dst->netmask,
                                                  &user_data);

            if (user_data == NULL) {
                SCLogDebug("Exact match not found");

                /**
                 * Not found, look if there's a subnet of this range
                 * with bigger netmask
                 */
                (void) SCRadixFindKeyIPV4BestMatch((uint8_t *)&dst->ip[0],
                                                   (de_ctx->io_ctx).tree_ipv4dst,
                                                   &user_data);
                if (user_data == NULL) {
                    SCLogDebug("Best match not found");

                    /** Not found, insert a new one */
                    SigNumArray *sna = SigNumArrayNew(de_ctx, &de_ctx->io_ctx);

                    /** Update the sig */
                    uint8_t tmp = (uint8_t)(1 << (dst->signum % 8));
                    if (dst->negated > 0)
                        /** Unset it */
                        sna->array[dst->signum / 8] &= ~tmp;
                    else
                        /** Set it */
                        sna->array[dst->signum / 8] |= tmp;

                    if (dst->netmask == 32)
                        node = SCRadixAddKeyIPV4((uint8_t *)&dst->ip[0],
                                                 (de_ctx->io_ctx).tree_ipv4dst, sna);
                    else
                        node = SCRadixAddKeyIPV4Netblock((uint8_t *)&dst->ip[0],
                                                         (de_ctx->io_ctx).tree_ipv4dst,
                                                         sna, dst->netmask);

                    if (node == NULL)
                        SCLogError("Error inserting in the dst "
                                   "ipv4 radix tree");
                } else {
                    SCLogDebug("Best match found");

                    /* Found, copy the sig num table, add this signum and insert */
                    SigNumArray *sna = NULL;
                    sna = SigNumArrayCopy((SigNumArray *) user_data);

                    /* Update the sig */
                    uint8_t tmp = (uint8_t)(1 << (dst->signum % 8));
                    if (dst->negated > 0)
                        /* Unset it */
                        sna->array[dst->signum / 8] &= ~tmp;
                    else
                        /* Set it */
                        sna->array[dst->signum / 8] |= tmp;

                    if (dst->netmask == 32)
                        node = SCRadixAddKeyIPV4((uint8_t *)&dst->ip[0],
                                                 (de_ctx->io_ctx).tree_ipv4dst, sna);
                    else
                        node = SCRadixAddKeyIPV4Netblock((uint8_t *)&dst->ip[0],
                                                         (de_ctx->io_ctx).tree_ipv4dst,
                                                          sna, dst->netmask);

                    if (node == NULL)
                        SCLogError("Error inserting in the dst "
                                   "ipv4 radix tree");
                }
            } else {
                SCLogDebug("Exact match found");

                /* it's already inserted. Update it */
                SigNumArray *sna = (SigNumArray *)user_data;

                /* Update the sig */
                uint8_t tmp = (uint8_t)(1 << (dst->signum % 8));
                if (dst->negated > 0)
                    /* Unset it */
                    sna->array[dst->signum / 8] &= ~tmp;
                else
                    /* Set it */
                    sna->array[dst->signum / 8] |= tmp;
            }
        } else if (dst->family == AF_INET6) {
            SCLogDebug("To IPv6");

            void *user_data = NULL;
            if (dst->netmask == 128)
                (void) SCRadixFindKeyIPV6ExactMatch((uint8_t *)&dst->ip[0],
                                                    (de_ctx->io_ctx).tree_ipv6dst,
                                                    &user_data);
            else
                (void) SCRadixFindKeyIPV6Netblock((uint8_t *)&dst->ip[0],
                                                  (de_ctx->io_ctx).tree_ipv6dst,
                                                  dst->netmask, &user_data);

            if (user_data == NULL) {
                /** Not found, look if there's a subnet of this range with
                 * bigger netmask
                 */
                (void) SCRadixFindKeyIPV6BestMatch((uint8_t *)&dst->ip[0],
                                                   (de_ctx->io_ctx).tree_ipv6dst,
                                                   &user_data);

                if (user_data == NULL) {
                    /* Not found, insert a new one */
                    SigNumArray *sna = SigNumArrayNew(de_ctx, &de_ctx->io_ctx);

                    /* Update the sig */
                    uint8_t tmp = (uint8_t)(1 << (dst->signum % 8));
                    if (dst->negated > 0)
                        /* Unset it */
                        sna->array[dst->signum / 8] &= ~tmp;
                    else
                        /* Set it */
                        sna->array[dst->signum / 8] |= tmp;

                    if (dst->netmask == 128)
                        node = SCRadixAddKeyIPV6((uint8_t *)&dst->ip[0],
                                                 (de_ctx->io_ctx).tree_ipv6dst, sna);
                    else
                        node = SCRadixAddKeyIPV6Netblock((uint8_t *)&dst->ip[0],
                                                         (de_ctx->io_ctx).tree_ipv6dst,
                                                          sna, dst->netmask);

                    if (node == NULL)
                        SCLogError("Error inserting in the dst "
                                   "ipv6 radix tree");
                } else {
                    /* Found, copy the sig num table, add this signum and insert */
                    SigNumArray *sna = NULL;
                    sna = SigNumArrayCopy((SigNumArray *)user_data);

                    /* Update the sig */
                    uint8_t tmp = (uint8_t)(1 << (dst->signum % 8));
                    if (dst->negated > 0)
                        /* Unset it */
                        sna->array[dst->signum / 8] &= ~tmp;
                    else
                        /* Set it */
                        sna->array[dst->signum / 8] |= tmp;

                    if (dst->netmask == 128)
                        node = SCRadixAddKeyIPV6((uint8_t *)&dst->ip[0],
                                                 (de_ctx->io_ctx).tree_ipv6dst, sna);
                    else
                        node = SCRadixAddKeyIPV6Netblock((uint8_t *)&dst->ip[0],
                                                         (de_ctx->io_ctx).tree_ipv6dst,
                                                         sna, dst->netmask);

                    if (node == NULL)
                        SCLogError("Error inserting in the dst "
                                   "ipv6 radix tree");
                }
            } else {
                /* it's already inserted. Update it */
                SigNumArray *sna = (SigNumArray *)user_data;

                /* Update the sig */
                uint8_t tmp = (uint8_t)(1 << (dst->signum % 8));
                if (dst->negated > 0)
                    /* Unset it */
                    sna->array[dst->signum / 8] &= ~tmp;
                else
                    /* Set it */
                    sna->array[dst->signum / 8] |= tmp;
            }
        }
        IPOnlyCIDRItem *tmpaux = dst;
        dst = dst->next;
        SCFree(tmpaux);
    }

    /* print all the trees: for debugging it might print too much info
    SCLogDebug("Radix tree src ipv4:");
    SCRadixPrintTree((de_ctx->io_ctx).tree_ipv4src);
    SCLogDebug("Radix tree src ipv6:");
    SCRadixPrintTree((de_ctx->io_ctx).tree_ipv6src);
    SCLogDebug("__________________");

    SCLogDebug("Radix tree dst ipv4:");
    SCRadixPrintTree((de_ctx->io_ctx).tree_ipv4dst);
    SCLogDebug("Radix tree dst ipv6:");
    SCRadixPrintTree((de_ctx->io_ctx).tree_ipv6dst);
    SCLogDebug("__________________");
    */
}

/**
 * \brief Add a signature to the lists of Addresses in CIDR format (sorted)
 *        this step is necessary to build the radix tree with a hierarchical
 *        relation between nodes
 * \param de_ctx Pointer to the current detection engine context
 * \param de_ctx Pointer to the current ip only detection engine contest
 * \param s Pointer to the current signature
 */
void IPOnlyAddSignature(DetectEngineCtx *de_ctx, DetectEngineIPOnlyCtx *io_ctx,
                        Signature *s)
{
    if (!(s->type == SIG_TYPE_IPONLY))
        return;

    SigIntId mapped_signum = IPOnlyTrackSigNum(io_ctx, s->num);
    SCLogDebug("Adding IPs from rule: %" PRIu32 " (%s) as %" PRIu32 " mapped to %" PRIu32 "\n",
            s->id, s->msg, s->num, mapped_signum);
    /* Set the internal signum to the list before merging */
    IPOnlyCIDRListSetSigNum(s->init_data->cidr_src, mapped_signum);

    IPOnlyCIDRListSetSigNum(s->init_data->cidr_dst, mapped_signum);

    /**
     * ipv4 and ipv6 are mixed, but later we will separate them into
     * different trees
     */
    io_ctx->ip_src = IPOnlyCIDRItemInsert(io_ctx->ip_src, s->init_data->cidr_src);
    io_ctx->ip_dst = IPOnlyCIDRItemInsert(io_ctx->ip_dst, s->init_data->cidr_dst);

    if (mapped_signum > io_ctx->max_idx)
        io_ctx->max_idx = mapped_signum;

    /** no longer ref to this, it's in the table now */
    s->init_data->cidr_src = NULL;
    s->init_data->cidr_dst = NULL;
}

#ifdef UNITTESTS
/**
 * \test check that we set a Signature as IPOnly because it has no rule
 *       option appending a SigMatch and no port is fixed
 */

static int IPOnlyTestSig01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);
    de_ctx->flags |= DE_QUIET;

    Signature *s = SigInit(de_ctx,"alert tcp any any -> any any (sid:400001; rev:1;)");
    FAIL_IF(s == NULL);

    FAIL_IF(SignatureIsIPOnly(de_ctx, s) == 0);
    SigFree(de_ctx, s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test check that we don't set a Signature as IPOnly because it has no rule
 *       option appending a SigMatch but a port is fixed
 */

static int IPOnlyTestSig02 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);
    de_ctx->flags |= DE_QUIET;

    Signature *s = SigInit(de_ctx,"alert tcp any any -> any 80 (sid:400001; rev:1;)");
    FAIL_IF(s == NULL);

    FAIL_IF(SignatureIsIPOnly(de_ctx, s) == 0);
    SigFree(de_ctx, s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test check that we set don't set a Signature as IPOnly
 *  because it has rule options appending a SigMatch like content, and pcre
 */

static int IPOnlyTestSig03 (void)
{
    int result = 1;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    /* combination of pcre and content */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (pcre and content) \"; content:\"php\"; pcre:\"/require(_once)?/i\"; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (content): ");
        result=0;
    }
    SigFree(de_ctx, s);

    /* content */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (content) \"; content:\"match something\"; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (content): ");
        result=0;
    }
    SigFree(de_ctx, s);

    /* uricontent */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (uricontent) \"; uricontent:\"match something\"; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (uricontent): ");
        result=0;
    }
    SigFree(de_ctx, s);

    /* pcre */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (pcre) \"; pcre:\"/e?idps rule[sz]/i\"; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (pcre): ");
        result=0;
    }
    SigFree(de_ctx, s);

    /* flow */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (flow) \"; flow:to_server; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (flow): ");
        result=0;
    }
    SigFree(de_ctx, s);

    /* dsize */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (dsize) \"; dsize:100; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (dsize): ");
        result=0;
    }
    SigFree(de_ctx, s);

    /* flowbits */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (flowbits) \"; flowbits:unset; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (flowbits): ");
        result=0;
    }
    SigFree(de_ctx, s);

    /* flowvar */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (flowvar) \"; pcre:\"/(?<flow_var>.*)/i\"; flowvar:var,\"str\"; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (flowvar): ");
        result=0;
    }
    SigFree(de_ctx, s);

    /* pktvar */
    s = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest40-03 sig is not IPOnly (pktvar) \"; pcre:\"/(?<pkt_var>.*)/i\"; pktvar:var,\"str\"; classtype:misc-activity; sid:400001; rev:1;)");
    if (s == NULL) {
        goto end;
    }
    if(SignatureIsIPOnly(de_ctx, s))
    {
        printf("got a IPOnly signature (pktvar): ");
        result=0;
    }
    SigFree(de_ctx, s);

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test
 */
static int IPOnlyTestSig04 (void)
{
    int result = 1;
    IPOnlyCIDRItem *head = NULL;

    // Test a linked list of size 0, 1, 2, ..., 5
    for (int size = 0; size < 6; size++) {
        IPOnlyCIDRItem *new = NULL;

        if (size > 0) {
            new = IPOnlyCIDRItemNew();
            new->netmask = 10;
            new->ip[0] = 3;

            head = IPOnlyCIDRItemInsert(head, new);
        }

        if (size > 1) {
            new = IPOnlyCIDRItemNew();
            new->netmask = 11;

            head = IPOnlyCIDRItemInsert(head, new);
        }

        if (size > 2) {
            new = IPOnlyCIDRItemNew();
            new->netmask = 9;

            head = IPOnlyCIDRItemInsert(head, new);
        }

        if (size > 3) {
            new = IPOnlyCIDRItemNew();
            new->netmask = 10;
            new->ip[0] = 1;

            head = IPOnlyCIDRItemInsert(head, new);
        }

        if (size > 4) {
            new = IPOnlyCIDRItemNew();
            new->netmask = 10;
            new->ip[0] = 2;

            head = IPOnlyCIDRItemInsert(head, new);
        }

        IPOnlyCIDRListPrint(head);

        IPOnlyCIDRListQSort(&head);

        if (size == 0) {
            if (head != NULL) {
                result = 0;
                goto end;
            }
        }

        /**
         * Validate the following list entries for each size
         * 1 - 10
         * 2 - 10<3> 11
         * 3 - 9     10<3> 11
         * 4 - 9     10<1> 10<3> 11
         * 5 - 9     10<1> 10<2> 10<3> 11
         */
        new = head;
        if (size >= 3) {
            if (new->netmask != 9) {
                result = 0;
                goto end;
            }
            new = new->next;
        }

        if (size >= 4) {
            if (new->netmask != 10 || new->ip[0] != 1) {
                result = 0;
                goto end;
            }
            new = new->next;
        }

        if (size >= 5) {
            if (new->netmask != 10 || new->ip[0] != 2) {
                result = 0;
                goto end;
            }
            new = new->next;
        }

        if (size >= 1) {
            if (new->netmask != 10 || new->ip[0] != 3) {
                result = 0;
                goto end;
            }
            new = new->next;
        }

        if (size >= 2) {
            if (new->netmask != 11) {
                result = 0;
                goto end;
            }
            new = new->next;
        }

        if (new != NULL) {
            result = 0;
            goto end;
        }

        IPOnlyCIDRListFree(head);
        head = NULL;
    }

end:
    if (head) {
        IPOnlyCIDRListFree(head);
        head = NULL;
    }
    return result;
}

/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (all should match)
 */
static int IPOnlyTestSig05(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 7;

    Packet *p[1];

    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    const char *sigs[numsigs];
    sigs[0]= "alert tcp 192.168.1.5 any -> any any (msg:\"Testing src ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp any any -> 192.168.1.1 any (msg:\"Testing dst ip (sid 2)\"; sid:2;)";
    sigs[2]= "alert tcp 192.168.1.5 any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 3)\"; sid:3;)";
    sigs[3]= "alert tcp 192.168.1.5 any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 4)\"; sid:4;)";
    sigs[4]= "alert tcp 192.168.1.0/24 any -> any any (msg:\"Testing src/dst ip (sid 5)\"; sid:5;)";
    sigs[5]= "alert tcp any any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 6)\"; sid:6;)";
    sigs[6]= "alert tcp 192.168.1.0/24 any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 7)\"; content:\"Hi all\";sid:7;)";

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[7] = { 1, 1, 1, 1, 1, 1, 1};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (none should match)
 */
static int IPOnlyTestSig06(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 7;

    Packet *p[1];

    p[0] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "80.58.0.33", "195.235.113.3");

    const char *sigs[numsigs];
    sigs[0]= "alert tcp 192.168.1.5 any -> any any (msg:\"Testing src ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp any any -> 192.168.1.1 any (msg:\"Testing dst ip (sid 2)\"; sid:2;)";
    sigs[2]= "alert tcp 192.168.1.5 any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 3)\"; sid:3;)";
    sigs[3]= "alert tcp 192.168.1.5 any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 4)\"; sid:4;)";
    sigs[4]= "alert tcp 192.168.1.0/24 any -> any any (msg:\"Testing src/dst ip (sid 5)\"; sid:5;)";
    sigs[5]= "alert tcp any any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 6)\"; sid:6;)";
    sigs[6]= "alert tcp 192.168.1.0/24 any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 7)\"; content:\"Hi all\";sid:7;)";

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[7] = { 0, 0, 0, 0, 0, 0, 0};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

/* \todo fix it.  We have disabled this unittest because 599 exposes 608,
 * which is why these unittests fail.  When we fix 608, we need to renable
 * these sigs */
#if 0
/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (all should match)
 */
static int IPOnlyTestSig07(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 7;

    Packet *p[1];

    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    char *sigs[numsigs];
    sigs[0]= "alert tcp 192.168.1.5 any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp [192.168.1.2,192.168.1.5,192.168.1.4] any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 2)\"; sid:2;)";
    sigs[2]= "alert tcp [192.168.1.0/24,!192.168.1.1] any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 3)\"; sid:3;)";
    sigs[3]= "alert tcp [192.0.0.0/8,!192.168.0.0/16,192.168.1.0/24,!192.168.1.1] any -> [192.168.1.0/24,!192.168.1.5] any (msg:\"Testing src/dst ip (sid 4)\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing src/dst ip (sid 5)\"; sid:5;)";
    sigs[5]= "alert tcp any any -> [192.168.0.0/16,!192.168.1.0/24,192.168.1.1] any (msg:\"Testing src/dst ip (sid 6)\"; sid:6;)";
    sigs[6]= "alert tcp [78.129.202.0/24,192.168.1.5,78.129.205.64,78.129.214.103,78.129.223.19,78.129.233.17,78.137.168.33,78.140.132.11,78.140.133.15,78.140.138.105,78.140.139.105,78.140.141.107,78.140.141.114,78.140.143.103,78.140.143.13,78.140.145.144,78.140.170.164,78.140.23.18,78.143.16.7,78.143.46.124,78.157.129.71] any -> 192.168.1.1 any (msg:\"ET RBN Known Russian Business Network IP TCP - BLOCKING (246)\"; sid:7;)"; /* real sid:"2407490" */

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[7] = { 1, 1, 1, 1, 1, 1, 1};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}
#endif

/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (none should match)
 */
static int IPOnlyTestSig08(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 7;

    Packet *p[1];

    p[0] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP,"192.168.1.1","192.168.1.5");

    const char *sigs[numsigs];
    sigs[0]= "alert tcp 192.168.1.5 any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp [192.168.1.2,192.168.1.5,192.168.1.4] any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 2)\"; sid:2;)";
    sigs[2]= "alert tcp [192.168.1.0/24,!192.168.1.1] any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 3)\"; sid:3;)";
    sigs[3]= "alert tcp [192.0.0.0/8,!192.168.0.0/16,192.168.1.0/24,!192.168.1.1] any -> [192.168.1.0/24,!192.168.1.5] any (msg:\"Testing src/dst ip (sid 4)\"; sid:4;)";
    sigs[4]= "alert tcp any any -> !192.168.1.5 any (msg:\"Testing src/dst ip (sid 5)\"; sid:5;)";
    sigs[5]= "alert tcp any any -> [192.168.0.0/16,!192.168.1.0/24,192.168.1.1] any (msg:\"Testing src/dst ip (sid 6)\"; sid:6;)";
    sigs[6]= "alert tcp [78.129.202.0/24,192.168.1.5,78.129.205.64,78.129.214.103,78.129.223.19,78.129.233.17,78.137.168.33,78.140.132.11,78.140.133.15,78.140.138.105,78.140.139.105,78.140.141.107,78.140.141.114,78.140.143.103,78.140.143.13,78.140.145.144,78.140.170.164,78.140.23.18,78.143.16.7,78.143.46.124,78.157.129.71] any -> 192.168.1.1 any (msg:\"ET RBN Known Russian Business Network IP TCP - BLOCKING (246)\"; sid:7;)"; /* real sid:"2407490" */

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[7] = { 0, 0, 0, 0, 0, 0, 0};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (all should match)
 */
static int IPOnlyTestSig09(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 7;

    Packet *p[1];

    p[0] = UTHBuildPacketIPV6SrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565", "3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562");

    const char *sigs[numsigs];
    sigs[0]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565 any -> any any (msg:\"Testing src ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp any any -> 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562 any (msg:\"Testing dst ip (sid 2)\"; sid:2;)";
    sigs[2]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565 any -> 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562 any (msg:\"Testing src/dst ip (sid 3)\"; sid:3;)";
    sigs[3]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565 any -> 3FFE:FFFF:7654:FEDA:1245:BA98:3210:0/96 any (msg:\"Testing src/dst ip (sid 4)\"; sid:4;)";
    sigs[4]= "alert tcp 3FFE:FFFF:7654:FEDA:0:0:0:0/64 any -> any any (msg:\"Testing src/dst ip (sid 5)\"; sid:5;)";
    sigs[5]= "alert tcp any any -> 3FFE:FFFF:7654:FEDA:0:0:0:0/64 any (msg:\"Testing src/dst ip (sid 6)\"; sid:6;)";
    sigs[6]= "alert tcp 3FFE:FFFF:7654:FEDA:0:0:0:0/64 any -> 3FFE:FFFF:7654:FEDA:0:0:0:0/64 any (msg:\"Testing src/dst ip (sid 7)\"; content:\"Hi all\";sid:7;)";

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[7] = { 1, 1, 1, 1, 1, 1, 1};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (none should match)
 */
static int IPOnlyTestSig10(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 7;

    Packet *p[1];

    p[0] = UTHBuildPacketIPV6SrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562", "3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565");

    const char *sigs[numsigs];
    sigs[0]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565 any -> any any (msg:\"Testing src ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp any any -> 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562 any (msg:\"Testing dst ip (sid 2)\"; sid:2;)";
    sigs[2]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565 any -> 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562 any (msg:\"Testing src/dst ip (sid 3)\"; sid:3;)";
    sigs[3]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565 any -> !3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562/96 any (msg:\"Testing src/dst ip (sid 4)\"; sid:4;)";
    sigs[4]= "alert tcp !3FFE:FFFF:7654:FEDA:0:0:0:0/64 any -> any any (msg:\"Testing src/dst ip (sid 5)\"; sid:5;)";
    sigs[5]= "alert tcp any any -> !3FFE:FFFF:7654:FEDA:0:0:0:0/64 any (msg:\"Testing src/dst ip (sid 6)\"; sid:6;)";
    sigs[6]= "alert tcp 3FFE:FFFF:7654:FEDA:0:0:0:0/64 any -> 3FFE:FFFF:7654:FEDB:0:0:0:0/64 any (msg:\"Testing src/dst ip (sid 7)\"; content:\"Hi all\";sid:7;)";

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[7] = { 0, 0, 0, 0, 0, 0, 0};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

/* \todo fix it.  We have disabled this unittest because 599 exposes 608,
 * which is why these unittests fail.  When we fix 608, we need to renable
 * these sigs */
#if 0
/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (all should match) with ipv4 and ipv6 mixed
 */
static int IPOnlyTestSig11(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 2;
    uint8_t numsigs = 7;

    Packet *p[2];

    p[0] = UTHBuildPacketIPV6SrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565", "3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562");
    p[1] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP,"192.168.1.1","192.168.1.5");

    char *sigs[numsigs];
    sigs[0]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565,192.168.1.1 any -> 3FFE:FFFF:7654:FEDA:0:0:0:0/64,192.168.1.5 any (msg:\"Testing src/dst ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp [192.168.1.1,3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565,192.168.1.4,192.168.1.5,!192.168.1.0/24] any -> [3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.0/24] any (msg:\"Testing src/dst ip (sid 2)\"; sid:2;)";
    sigs[2]= "alert tcp [3FFE:FFFF:7654:FEDA:0:0:0:0/64,!3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.1] any -> [3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.5] any (msg:\"Testing src/dst ip (sid 3)\"; sid:3;)";
    sigs[3]= "alert tcp [3FFE:FFFF:0:0:0:0:0:0/32,!3FFE:FFFF:7654:FEDA:0:0:0:0/64,3FFE:FFFF:7654:FEDA:0:0:0:0/64,!3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.1] any -> [3FFE:FFFF:7654:FEDA:0:0:0:0/64,192.168.1.0/24,!3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565] any (msg:\"Testing src/dst ip (sid 4)\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing src/dst ip (sid 5)\"; sid:5;)";
    sigs[5]= "alert tcp any any -> [3FFE:FFFF:7654:FEDA:0:0:0:0/64,!3FFE:FFFF:7654:FEDA:0:0:0:0/64,3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.5] any (msg:\"Testing src/dst ip (sid 6)\"; sid:6;)";
    sigs[6]= "alert tcp [78.129.202.0/24,3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565,192.168.1.1,78.129.205.64,78.129.214.103,78.129.223.19,78.129.233.17,78.137.168.33,78.140.132.11,78.140.133.15,78.140.138.105,78.140.139.105,78.140.141.107,78.140.141.114,78.140.143.103,78.140.143.13,78.140.145.144,78.140.170.164,78.140.23.18,78.143.16.7,78.143.46.124,78.157.129.71] any -> [3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.0.0.0/8] any (msg:\"ET RBN Known Russian Business Network IP TCP - BLOCKING (246)\"; sid:7;)"; /* real sid:"2407490" */

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[2][7] = {{ 1, 1, 1, 1, 1, 1, 1}, { 1, 1, 1, 1, 1, 1, 1}};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}
#endif

/**
 * \test Test a set of ip only signatures making use a lot of
 * addresses for src and dst (none should match) with ipv4 and ipv6 mixed
 */
static int IPOnlyTestSig12(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 2;
    uint8_t numsigs = 7;

    Packet *p[2];

    p[0] = UTHBuildPacketIPV6SrcDst((uint8_t *)buf, buflen, IPPROTO_TCP,"3FBE:FFFF:7654:FEDA:1245:BA98:3210:4562","3FBE:FFFF:7654:FEDA:1245:BA98:3210:4565");
    p[1] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP,"195.85.1.1","80.198.1.5");

    const char *sigs[numsigs];
    sigs[0]= "alert tcp 3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565,192.168.1.1 any -> 3FFE:FFFF:7654:FEDA:0:0:0:0/64,192.168.1.5 any (msg:\"Testing src/dst ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp [192.168.1.1,3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565,192.168.1.4,192.168.1.5,!192.168.1.0/24] any -> [3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.0/24] any (msg:\"Testing src/dst ip (sid 2)\"; sid:2;)";
    sigs[2]= "alert tcp [3FFE:FFFF:7654:FEDA:0:0:0:0/64,!3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.1] any -> [3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.5] any (msg:\"Testing src/dst ip (sid 3)\"; sid:3;)";
    sigs[3]= "alert tcp [3FFE:FFFF:0:0:0:0:0:0/32,!3FFE:FFFF:7654:FEDA:0:0:0:0/64,3FFE:FFFF:7654:FEDA:0:0:0:0/64,!3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.1] any -> [3FFE:FFFF:7654:FEDA:0:0:0:0/64,192.168.1.0/24,!3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565] any (msg:\"Testing src/dst ip (sid 4)\"; sid:4;)";
    sigs[4]= "alert tcp any any -> [!3FBE:FFFF:7654:FEDA:1245:BA98:3210:4565,!80.198.1.5] any (msg:\"Testing src/dst ip (sid 5)\"; sid:5;)";
    sigs[5]= "alert tcp any any -> [3FFE:FFFF:7654:FEDA:0:0:0:0/64,!3FFE:FFFF:7654:FEDA:0:0:0:0/64,3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.5] any (msg:\"Testing src/dst ip (sid 6)\"; sid:6;)";
    sigs[6]= "alert tcp [78.129.202.0/24,3FFE:FFFF:7654:FEDA:1245:BA98:3210:4565,192.168.1.1,78.129.205.64,78.129.214.103,78.129.223.19,78.129.233.17,78.137.168.33,78.140.132.11,78.140.133.15,78.140.138.105,78.140.139.105,78.140.141.107,78.140.141.114,78.140.143.103,78.140.143.13,78.140.145.144,78.140.170.164,78.140.23.18,78.143.16.7,78.143.46.124,78.157.129.71] any -> [3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.0.0.0/8] any (msg:\"ET RBN Known Russian Business Network IP TCP - BLOCKING (246)\"; sid:7;)"; /* real sid:"2407490" */

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[2][7] = {{ 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0}};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

static int IPOnlyTestSig13(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);
    de_ctx->flags |= DE_QUIET;

    Signature *s = SigInit(de_ctx,
                           "alert tcp any any -> any any (msg:\"Test flowbits ip only\"; "
                           "flowbits:set,myflow1; sid:1; rev:1;)");
    FAIL_IF(s == NULL);

    FAIL_IF(SignatureIsIPOnly(de_ctx, s) == 0);
    SigFree(de_ctx, s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int IPOnlyTestSig14(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);
    de_ctx->flags |= DE_QUIET;

    Signature *s = SigInit(de_ctx,
                           "alert tcp any any -> any any (msg:\"Test flowbits ip only\"; "
                           "flowbits:set,myflow1; flowbits:isset,myflow2; sid:1; rev:1;)");
    FAIL_IF(s == NULL);

    FAIL_IF(SignatureIsIPOnly(de_ctx, s) == 1);
    SigFree(de_ctx, s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int IPOnlyTestSig15(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 7;

    Packet *p[1];
    Flow f;
    GenericVar flowvar;
    memset(&f, 0, sizeof(Flow));
    memset(&flowvar, 0, sizeof(GenericVar));
    FLOW_INITIALIZE(&f);

    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    p[0]->flow = &f;
    p[0]->flow->flowvar = &flowvar;
    p[0]->flags |= PKT_HAS_FLOW;
    p[0]->flowflags |= FLOW_PKT_TOSERVER;

    const char *sigs[numsigs];
    sigs[0]= "alert tcp 192.168.1.5 any -> any any (msg:\"Testing src ip (sid 1)\"; "
        "flowbits:set,one; sid:1;)";
    sigs[1]= "alert tcp any any -> 192.168.1.1 any (msg:\"Testing dst ip (sid 2)\"; "
        "flowbits:set,two; sid:2;)";
    sigs[2]= "alert tcp 192.168.1.5 any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 3)\"; "
        "flowbits:set,three; sid:3;)";
    sigs[3]= "alert tcp 192.168.1.5 any -> 192.168.1.1 any (msg:\"Testing src/dst ip (sid 4)\"; "
        "flowbits:set,four; sid:4;)";
    sigs[4]= "alert tcp 192.168.1.0/24 any -> any any (msg:\"Testing src/dst ip (sid 5)\"; "
        "flowbits:set,five; sid:5;)";
    sigs[5]= "alert tcp any any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 6)\"; "
        "flowbits:set,six; sid:6;)";
    sigs[6]= "alert tcp 192.168.1.0/24 any -> 192.168.0.0/16 any (msg:\"Testing src/dst ip (sid 7)\"; "
        "flowbits:set,seven; content:\"Hi all\"; sid:7;)";

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[7] = { 1, 2, 3, 4, 5, 6, 7};
    uint32_t results[7] = { 1, 1, 1, 1, 1, 1, 1};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    FLOW_DESTROY(&f);
    return result;
}

/**
 * \brief Unittest to show #599.  We fail to match if we have negated addresses.
 */
static int IPOnlyTestSig16(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 2;

    Packet *p[1];

    p[0] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "100.100.0.0", "50.0.0.0");

    const char *sigs[numsigs];
    sigs[0]= "alert tcp !100.100.0.1 any -> any any (msg:\"Testing src ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert tcp any any -> !50.0.0.1 any (msg:\"Testing dst ip (sid 2)\"; sid:2;)";

    /* Sid numbers (we could extract them from the sig) */
    uint32_t sid[2] = { 1, 2};
    uint32_t results[2] = { 1, 1};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

/**
 * \brief Unittest to show #611. Ports on portless protocols.
 */
static int IPOnlyTestSig17(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 1;
    uint8_t numsigs = 2;

    Packet *p[1];

    p[0] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_ICMP, "100.100.0.0", "50.0.0.0");

    const char *sigs[numsigs];
    sigs[0]= "alert ip 100.100.0.0 80 -> any any (msg:\"Testing src ip (sid 1)\"; sid:1;)";
    sigs[1]= "alert ip any any -> 50.0.0.0 123 (msg:\"Testing dst ip (sid 2)\"; sid:2;)";

    uint32_t sid[2] = { 1, 2};
    uint32_t results[2] = { 0, 0}; /* neither should match */

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    return result;
}

/**
 * \brief Unittest to show #3568 -- IP address range handling
 */
static int IPOnlyTestSig18(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);

    uint8_t numpkts = 4;
    uint8_t numsigs = 4;

    Packet *p[4];

    p[0] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "10.10.10.1", "50.0.0.1");
    p[1] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "220.10.10.1", "5.0.0.1");
    p[2] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "0.0.0.1", "50.0.0.1");
    p[3] = UTHBuildPacketSrcDst((uint8_t *)buf, buflen, IPPROTO_TCP, "255.255.255.254", "5.0.0.1");

    const char *sigs[numsigs];
    // really many IP addresses
    sigs[0]= "alert ip 1.2.3.4-219.6.7.8 any -> any any (sid:1;)";
    sigs[1]= "alert ip 51.2.3.4-253.1.2.3 any -> any any (sid:2;)";
    sigs[2]= "alert ip 0.0.0.0-50.0.0.2 any -> any any (sid:3;)";
    sigs[3]= "alert ip 50.0.0.0-255.255.255.255 any -> any any (sid:4;)";

    uint32_t sid[4] = { 1, 2, 3, 4, };
    uint32_t results[4][4] = {
        { 1, 0, 1, 0, }, { 0, 1, 0, 1}, { 0, 0, 1, 0 }, { 0, 0, 0, 1}};

    result = UTHGenericTest(p, numpkts, sigs, sid, (uint32_t *) results, numsigs);

    UTHFreePackets(p, numpkts);

    FAIL_IF(result != 1);

    PASS;
}

/** \test build IP-only tree */
static int IPOnlyTestBug5066v1(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(
            de_ctx, "alert ip [1.2.3.4/24,1.2.3.64/27] any -> any any (sid:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert ip [1.2.3.4/24] any -> any any (sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int IPOnlyTestBug5066v2(void)
{
    IPOnlyCIDRItem *x = IPOnlyCIDRItemNew();
    FAIL_IF_NULL(x);

    FAIL_IF(IPOnlyCIDRItemParseSingle(&x, "1.2.3.4/24") != 0);

    char ip[16];
    PrintInet(AF_INET, (const void *)&x->ip[0], ip, sizeof(ip));
    SCLogDebug("ip %s netmask %d", ip, x->netmask);

    FAIL_IF_NOT(strcmp(ip, "1.2.3.0") == 0);
    FAIL_IF_NOT(x->netmask == 24);

    IPOnlyCIDRListFree(x);
    PASS;
}

static int IPOnlyTestBug5066v3(void)
{
    IPOnlyCIDRItem *x = IPOnlyCIDRItemNew();
    FAIL_IF_NULL(x);

    FAIL_IF(IPOnlyCIDRItemParseSingle(&x, "1.2.3.64/26") != 0);

    char ip[16];
    PrintInet(AF_INET, (const void *)&x->ip[0], ip, sizeof(ip));
    SCLogDebug("ip %s netmask %d", ip, x->netmask);

    FAIL_IF_NOT(strcmp(ip, "1.2.3.64") == 0);
    FAIL_IF_NOT(x->netmask == 26);

    IPOnlyCIDRListFree(x);
    PASS;
}

static int IPOnlyTestBug5066v4(void)
{
    IPOnlyCIDRItem *x = IPOnlyCIDRItemNew();
    FAIL_IF_NULL(x);

    FAIL_IF(IPOnlyCIDRItemParseSingle(&x, "2000::1:1/122") != 0);

    char ip[64];
    PrintInet(AF_INET6, (const void *)&x->ip, ip, sizeof(ip));
    SCLogDebug("ip %s netmask %d", ip, x->netmask);

    FAIL_IF_NOT(strcmp(ip, "2000:0000:0000:0000:0000:0000:0001:0000") == 0);
    FAIL_IF_NOT(x->netmask == 122);

    IPOnlyCIDRListFree(x);
    PASS;
}

static int IPOnlyTestBug5066v5(void)
{
    IPOnlyCIDRItem *x = IPOnlyCIDRItemNew();
    FAIL_IF_NULL(x);

    FAIL_IF(IPOnlyCIDRItemParseSingle(&x, "2000::1:40/122") != 0);

    char ip[64];
    PrintInet(AF_INET6, (const void *)&x->ip, ip, sizeof(ip));
    SCLogDebug("ip %s netmask %d", ip, x->netmask);

    FAIL_IF_NOT(strcmp(ip, "2000:0000:0000:0000:0000:0000:0001:0040") == 0);
    FAIL_IF_NOT(x->netmask == 122);

    IPOnlyCIDRListFree(x);
    PASS;
}

static int IPOnlyTestBug5168v1(void)
{
    IPOnlyCIDRItem *x = IPOnlyCIDRItemNew();
    FAIL_IF_NULL(x);

    FAIL_IF(IPOnlyCIDRItemParseSingle(&x, "1.2.3.64/0.0.0.0") != 0);

    char ip[16];
    PrintInet(AF_INET, (const void *)&x->ip[0], ip, sizeof(ip));
    SCLogDebug("ip %s netmask %d", ip, x->netmask);

    FAIL_IF_NOT(strcmp(ip, "0.0.0.0") == 0);
    FAIL_IF_NOT(x->netmask == 0);

    IPOnlyCIDRListFree(x);
    PASS;
}

static int IPOnlyTestBug5168v2(void)
{
    IPOnlyCIDRItem *x = IPOnlyCIDRItemNew();
    FAIL_IF_NULL(x);
    FAIL_IF(IPOnlyCIDRItemParseSingle(&x, "0.0.0.5/0.0.0.5") != -1);
    IPOnlyCIDRListFree(x);
    PASS;
}

#endif /* UNITTESTS */

void IPOnlyRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("IPOnlyTestSig01", IPOnlyTestSig01);
    UtRegisterTest("IPOnlyTestSig02", IPOnlyTestSig02);
    UtRegisterTest("IPOnlyTestSig03", IPOnlyTestSig03);
    UtRegisterTest("IPOnlyTestSig04", IPOnlyTestSig04);

    UtRegisterTest("IPOnlyTestSig05", IPOnlyTestSig05);
    UtRegisterTest("IPOnlyTestSig06", IPOnlyTestSig06);
/* \todo fix it.  We have disabled this unittest because 599 exposes 608,
 * which is why these unittests fail.  When we fix 608, we need to renable
 * these sigs */
#if 0
    UtRegisterTest("IPOnlyTestSig07", IPOnlyTestSig07, 1);
#endif
    UtRegisterTest("IPOnlyTestSig08", IPOnlyTestSig08);

    UtRegisterTest("IPOnlyTestSig09", IPOnlyTestSig09);
    UtRegisterTest("IPOnlyTestSig10", IPOnlyTestSig10);
/* \todo fix it.  We have disabled this unittest because 599 exposes 608,
 * which is why these unittests fail.  When we fix 608, we need to renable
 * these sigs */
#if 0
    UtRegisterTest("IPOnlyTestSig11", IPOnlyTestSig11, 1);
#endif
    UtRegisterTest("IPOnlyTestSig12", IPOnlyTestSig12);
    UtRegisterTest("IPOnlyTestSig13", IPOnlyTestSig13);
    UtRegisterTest("IPOnlyTestSig14", IPOnlyTestSig14);
    UtRegisterTest("IPOnlyTestSig15", IPOnlyTestSig15);
    UtRegisterTest("IPOnlyTestSig16", IPOnlyTestSig16);

    UtRegisterTest("IPOnlyTestSig17", IPOnlyTestSig17);
    UtRegisterTest("IPOnlyTestSig18", IPOnlyTestSig18);

    UtRegisterTest("IPOnlyTestBug5066v1", IPOnlyTestBug5066v1);
    UtRegisterTest("IPOnlyTestBug5066v2", IPOnlyTestBug5066v2);
    UtRegisterTest("IPOnlyTestBug5066v3", IPOnlyTestBug5066v3);
    UtRegisterTest("IPOnlyTestBug5066v4", IPOnlyTestBug5066v4);
    UtRegisterTest("IPOnlyTestBug5066v5", IPOnlyTestBug5066v5);

    UtRegisterTest("IPOnlyTestBug5168v1", IPOnlyTestBug5168v1);
    UtRegisterTest("IPOnlyTestBug5168v2", IPOnlyTestBug5168v2);
#endif
}
