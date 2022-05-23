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

#include "detect.h"
#include "detect-engine-iponly.h"
#include "detect-engine-ip.h"
#include "detect-engine-ipcache.h"

#include "util-byte.h"
#include "util-cidr.h"
#include "util-ip.h"
#include "util-rule-vars.h"

static void AddrStateFree(void *p)
{
    SCFree(p);
}

static void AddrStatePrint(void *p)
{
    struct AddrState *as = p;
    if (as->state == 0)
        printf("negated\n");
    else
        printf("positive\n");
}

static const SCRadix4Config ip_radix4_config = { AddrStateFree, AddrStatePrint };
static const SCRadix6Config ip_radix6_config = { AddrStateFree, AddrStatePrint };

struct ParserScratch {
    SCRadix4Tree *ip4_tree;
    SCRadix6Tree *ip6_tree;
    uint32_t sid;

    IPOnlyCIDRItem *pos_v4[33];
    IPOnlyCIDRItem *neg_v4[33];
    IPOnlyCIDRItem *pos_v6[129];
    IPOnlyCIDRItem *neg_v6[129];
    uint32_t pos_v4_cnt;
    uint32_t neg_v4_cnt;
    uint32_t pos_v6_cnt;
    uint32_t neg_v6_cnt;

    int recur;

    bool validate_vars;
    ResolvedVariablesList var_list;
};

static int BuildTree(struct ParserScratch *ps, IPOnlyCIDRItem *subhead, const char *address);

static int InsertRange(struct ParserScratch *ps, const uint32_t first_in, const uint32_t last_in,
        const bool negated, const char *address)
{
    uint32_t first = first_in;
    uint32_t last = last_in;

    IPOnlyCIDRItem a;
    memset(&a, 0, sizeof(a));
    a.family = AF_INET;
    a.netmask = 32;
    a.negated = negated;

    /* Find the maximum netmask starting from current address first
     * and not crossing last.
     * To extend the mask, we need to start from a power of 2.
     * And we need to pay attention to unsigned overflow back to 0.0.0.0
     */
    while (a.netmask > 0 && (first & (1UL << (32 - a.netmask))) == 0 &&
            first + (1UL << (32 - (a.netmask - 1))) - 1 <= last) {
        a.netmask--;
    }
    a.ip[0] = htonl(first);

    if (BuildTree(ps, &a, address) < 0)
        return -1;

    first += 1UL << (32 - a.netmask);

    // case whatever-255.255.255.255 looping to 0.0.0.0/0
    while (first <= last && first != 0) {
        memset(&a, 0, sizeof(a));
        a.family = AF_INET;
        a.negated = negated;
        a.netmask = 32;
        while (a.netmask > 0 && (first & (1UL << (32 - a.netmask))) == 0 &&
                first + (1UL << (32 - (a.netmask - 1))) - 1 <= last) {
            a.netmask--;
        }
        a.ip[0] = htonl(first);
        first += 1UL << (32 - a.netmask);

        if (BuildTree(ps, &a, address) < 0)
            return -1;
    }
    return 0;
}

/**
 * \internal
 *
 * \param str Pointer to address string that has to be parsed.
 *
 * \retval  0 On successfully parsing the address string.
 * \retval -1 On failure.
 */
static int IPOnlyCIDRItemParseSingle(struct ParserScratch *ps, const char *str, const bool negated)
{
    char buf[256] = "";
    char *ip = NULL, *ip2 = NULL;
    char *mask = NULL;
    int r = 0;
    IPOnlyCIDRItem a;
    memset(&a, 0, sizeof(a));
    a.negated = negated;

    while (*str != '\0' && *str == ' ')
        str++;

    SCLogDebug("str %s", str);
    strlcpy(buf, str, sizeof(buf));
    ip = buf;

    /* first handle 'any' */
    if (strcasecmp(str, "any") == 0) {
        /* if any, insert 0.0.0.0/0 and ::/0 as well */
        SCLogDebug("adding 0.0.0.0/0 and ::/0 as we\'re handling \'any\'");

        if (IPOnlyCIDRItemParseSingle(ps, "0.0.0.0/0", negated) < 0)
            return -1;
        if (IPOnlyCIDRItemParseSingle(ps, "::/0", negated) < 0)
            return -1;

        SCLogDebug("address is \'any\'");
        return 0;
    }

    /* handle the negation case */
    if (ip[0] == '!') {
        a.negated = negated ? 0 : 1;
        ip++;
    }

    /* see if the address is an ipv4 or ipv6 address */
    if ((strchr(str, ':')) == NULL) {
        /* IPv4 Address */
        struct in_addr in;
        a.family = AF_INET;

        if ((mask = strchr(ip, '/')) != NULL) {
            /* 1.2.3.4/xxx format (either dotted or cidr notation */
            ip[mask - ip] = '\0';
            mask++;
            uint32_t netmask = 0;

            if ((strchr(mask, '.')) == NULL) {
                /* 1.2.3.4/24 format */

                for (size_t u = 0; u < strlen(mask); u++) {
                    if (!isdigit((unsigned char)mask[u])) {
                        SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC,
                                "CIDR %s contains invalid characters", mask);
                        return -1;
                    }
                }
                int cidr;
                if (StringParseI32RangeCheck(&cidr, 10, 0, (const char *)mask, 0, 32) < 0) {
                    SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC,
                            "CIDR %s is out of the acceptable range of 0-32", mask);
                    return -1;
                }
                a.netmask = cidr;
                netmask = CIDRGet(cidr);
            } else {
                /* 1.2.3.4/255.255.255.0 format */
                r = inet_pton(AF_INET, mask, &in);
                if (r <= 0) {
                    SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC, "netmask %s format error", mask);
                    return -1;
                }

                int cidr = CIDRFromMask(in.s_addr);
                if (cidr < 0) {
                    SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC,
                            "netmask %s can't be expressed in CIDR notation", mask);
                    return -1;
                }
                a.netmask = (uint8_t)cidr;
            }

            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0) {
                SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC, "ipv4 address %s format error", ip);
                return -1;
            }
            a.ip[0] = in.s_addr & netmask;

            if (BuildTree(ps, &a, str) < 0)
                return -1;

        } else if ((ip2 = strchr(ip, '-')) != NULL) {
            /* 1.2.3.4-1.2.3.6 range format */
            ip[ip2 - ip] = '\0';
            ip2++;

            uint32_t first, last;

            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0) {
                SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC, "ipv4 address %s format error", ip);
                return -1;
            }
            first = SCNtohl(in.s_addr);

            r = inet_pton(AF_INET, ip2, &in);
            if (r <= 0) {
                SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC, "ipv4 address %s format error", ip);
                return -1;
            }
            last = SCNtohl(in.s_addr);

            /* a > b is illegal, a = b is ok */
            if (first > last) {
                SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC,
                        "range start %s is greater than range end %s", ip, ip2);
                return -1;
            }
            SCLogDebug("Creating CIDR range for [%s - %s]", ip, ip2);
            return InsertRange(ps, first, last, a.negated, str);
        } else {
            /* 1.2.3.4 format */
            r = inet_pton(AF_INET, ip, &in);
            if (r <= 0) {
                SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC, "ipv4 address %s format error", ip);
                return -1;
            }
            /* single host */
            a.ip[0] = in.s_addr;
            a.netmask = 32;

            if (BuildTree(ps, &a, str) < 0)
                return -1;
        }
    } else {
        /* IPv6 Address */
        struct in6_addr in6, mask6;
        uint32_t ip6addr[4], netmask[4];

        a.family = AF_INET6;

        if ((mask = strchr(ip, '/')) != NULL) {
            mask[0] = '\0';
            mask++;

            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0) {
                SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC, "ipv6 address %s format error", ip);
                return -1;
            }
            /* Format is cidr val */
            if (StringParseU8RangeCheck(&a.netmask, 10, 0, (const char *)mask, 0, 128) < 0) {
                SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC,
                        "CIDR %s is out of the acceptable range of 0-128", mask);
                return -1;
            }

            memcpy(&ip6addr, &in6.s6_addr, sizeof(ip6addr));
            CIDRGetIPv6(a.netmask, &mask6);
            memcpy(&netmask, &mask6.s6_addr, sizeof(netmask));

            a.ip[0] = ip6addr[0] & netmask[0];
            a.ip[1] = ip6addr[1] & netmask[1];
            a.ip[2] = ip6addr[2] & netmask[2];
            a.ip[3] = ip6addr[3] & netmask[3];
        } else {
            r = inet_pton(AF_INET6, ip, &in6);
            if (r <= 0) {
                SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC, "ipv6 address %s format error", ip);
                return -1;
            }
            memcpy(a.ip, &in6.s6_addr, sizeof(a.ip));
            a.netmask = 128;
        }

        if (BuildTree(ps, &a, str) < 0)
            return -1;
    }
    return 0;
}

static IPOnlyCIDRItem *Copy(IPOnlyCIDRItem *r)
{
    IPOnlyCIDRItem *n = SCCalloc(1, sizeof(*n));
    BUG_ON(n == NULL);
    *n = *r;
    return n;
}

/* Helper for building the per signature radix */
static int BuildTree(struct ParserScratch *ps, IPOnlyCIDRItem *subhead, const char *address)
{
    if (subhead->netmask == 0 && subhead->negated) {
        SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC, "address %s negates complete IP space", address);
        return -1;
    }

    IPOnlyCIDRItem *copy = Copy(subhead);
    if (subhead->family == AF_INET) {
        BUG_ON(subhead->netmask > 32);
        if (subhead->negated) {
            copy->next = ps->neg_v4[subhead->netmask];
            ps->neg_v4[subhead->netmask] = copy;
            ps->neg_v4_cnt++;
            /* copy into pos list as well */
            copy = Copy(subhead);
            copy->next = ps->pos_v4[subhead->netmask];
            ps->pos_v4[subhead->netmask] = copy;
        } else {
            copy->next = ps->pos_v4[subhead->netmask];
            ps->pos_v4[subhead->netmask] = copy;
            ps->pos_v4_cnt++;
        }
    } else {
        BUG_ON(subhead->family != AF_INET6);
        BUG_ON(subhead->netmask > 128);

        if (subhead->negated) {
            copy->next = ps->neg_v6[subhead->netmask];
            ps->neg_v6[subhead->netmask] = copy;
            ps->neg_v6_cnt++;
            /* copy into pos list as well */
            copy = Copy(subhead);
            copy->next = ps->pos_v6[subhead->netmask];
            ps->pos_v6[subhead->netmask] = copy;
        } else {
            copy->next = ps->pos_v6[subhead->netmask];
            ps->pos_v6[subhead->netmask] = copy;
            ps->pos_v6_cnt++;
        }
    }
    return 0;
}

static int DetectAddressParse(
        const DetectEngineCtx *de_ctx, struct ParserScratch *ps, const char *s, int negate);

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
static int DetectAddressParseInternal(const DetectEngineCtx *de_ctx, struct ParserScratch *ps,
        const char *s, int negate, char *address, size_t address_length)
{
    int o_set = 0, n_set = 0, d_set = 0;
    int depth = 0;
    const size_t size = strlen(s);
    const char *rule_var_address = NULL;
    char *temp_rule_var_address = NULL;

    SCLogDebug("s %s negate %s", s, negate ? "true" : "false");

    for (size_t u = 0, x = 0; u < size && x < address_length; u++) {
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

                if (DetectAddressParse(de_ctx, ps, address, (negate + n_set) % 2) < 0) {
                    return -1;
                }
                n_set = 0;
            }
            depth--;
        } else if (depth == 0 && s[u] == ',') {
            if (o_set == 1) {
                o_set = 0;
            } else if (d_set == 1) {
                address[x - 1] = '\0';

                rule_var_address =
                        SCRuleVarsGetConfVar(de_ctx, address, SC_RULE_VARS_ADDRESS_GROUPS);
                if (rule_var_address == NULL) {
                    return -1;
                }
                if ((negate + n_set) % 2) {
                    temp_rule_var_address = SCMalloc(strlen(rule_var_address) + 3);
                    if (unlikely(temp_rule_var_address == NULL)) {
                        return -1;
                    }

                    snprintf(temp_rule_var_address, strlen(rule_var_address) + 3, "[%s]",
                            rule_var_address);
                } else {
                    temp_rule_var_address = SCStrdup(rule_var_address);
                    if (unlikely(temp_rule_var_address == NULL)) {
                        return -1;
                    }
                }

                if (DetectAddressParse(de_ctx, ps, temp_rule_var_address, (negate + n_set) % 2) <
                        0) {
                    SCFree(temp_rule_var_address);
                    return -1;
                }
                d_set = 0;
                n_set = 0;

                SCFree(temp_rule_var_address);

            } else {
                address[x - 1] = '\0';

                bool neg;
                if (!((negate + n_set) % 2))
                    neg = false;
                else
                    neg = true;

                if (IPOnlyCIDRItemParseSingle(ps, address, neg) < 0) {
                    return -1;
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

            if (ps->validate_vars) {
                if (AddVariableToResolveList(&ps->var_list, address) == -1) {
                    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                            "Found a loop in a address "
                            "groups declaration. This is likely a misconfiguration.");
                    return -1;
                }
            }

            if (d_set == 1) {
                rule_var_address =
                        SCRuleVarsGetConfVar(de_ctx, address, SC_RULE_VARS_ADDRESS_GROUPS);
                if (rule_var_address == NULL) {
                    return -1;
                }
                if ((negate + n_set) % 2) {
                    temp_rule_var_address = SCMalloc(strlen(rule_var_address) + 3);
                    if (unlikely(temp_rule_var_address == NULL)) {
                        return -1;
                    }
                    snprintf(temp_rule_var_address, strlen(rule_var_address) + 3, "[%s]",
                            rule_var_address);
                } else {
                    temp_rule_var_address = SCStrdup(rule_var_address);
                    if (unlikely(temp_rule_var_address == NULL)) {
                        return -1;
                    }
                }
                if (DetectAddressParse(de_ctx, ps, temp_rule_var_address, (negate + n_set) % 2) <
                        0) {
                    SCFree(temp_rule_var_address);
                    return -1;
                }
                d_set = 0;
                SCFree(temp_rule_var_address);
            } else {
                bool neg;
                if (!((negate + n_set) % 2))
                    neg = false;
                else
                    neg = true;

                if (IPOnlyCIDRItemParseSingle(ps, address, neg) < 0) {
                    return -1;
                }
            }
            n_set = 0;
        }
    }
    if (depth > 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                "not every address block was "
                "properly closed in \"%s\", %d missing closing brackets (]). "
                "Note: problem might be in a variable.",
                s, depth);
        return -1;
    } else if (depth < 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                "not every address block was "
                "properly opened in \"%s\", %d missing opening brackets ([). "
                "Note: problem might be in a variable.",
                s, depth * -1);
        return -1;
    }

    return 0;
}

static int DetectAddressParse(
        const DetectEngineCtx *de_ctx, struct ParserScratch *ps, const char *s, int negate)
{
    // TODO test from master
    if (++ps->recur > 64) {
        SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC, "address block recursion "
                                                  "limit reached (max 64)");
        return -1;
    }

#define MAX_ADDRESS_LENGTH 8192
    const size_t address_length = strlen(s);
    if (address_length > (MAX_ADDRESS_LENGTH - 1)) {
        char *address = SCCalloc(1, address_length);
        if (address == NULL) {
            SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC, "Unable to allocate"
                                                      " memory for address parsing.");
            return -1;
        }

        int rc = DetectAddressParseInternal(de_ctx, ps, s, negate, address, address_length);
        SCFree(address);
        if (rc < 0) {
            return -1;
        }
    } else {
        char address[MAX_ADDRESS_LENGTH] = "";
        int rc = DetectAddressParseInternal(de_ctx, ps, s, negate, address, sizeof(address));
        if (rc < 0) {
            return -1;
        }
    }
    return 0;
}

/**
 * \brief Parses an address group sent as a character string and updates the
 *        IPOnlyCIDRItem list
 *
 * \param str Pointer to the character string containing the address group
 *            that has to be parsed.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int IPOnlyCIDRListParse(
        const DetectEngineCtx *de_ctx, struct ParserScratch *ps, const char *str)
{
    if (DetectAddressParse(de_ctx, ps, str, 0) < 0)
        return -1;

    int pos_v4_added = 0;
    int neg_v4_added = 0;
    int pos_v6_added = 0;
    int neg_v6_added = 0;
    SCRadix4Tree *tree = ps->ip4_tree;
    BUG_ON(tree == NULL);

    SCLogDebug("ranges: v4 %u+ %u-, v6 %u+ %u-", ps->pos_v4_cnt, ps->neg_v4_cnt, ps->pos_v6_cnt,
            ps->neg_v4_cnt);

    if (ps->pos_v4_cnt == 0 && ps->neg_v4_cnt != 0) {
        struct AddrState *as = SCCalloc(1, sizeof(*as));
        BUG_ON(as == NULL);
        as->state = 1;
        void *u = as;
        uint32_t all = 0;
        SCRadix4AddKeyIPV4Netblock(tree, &ip_radix4_config, (uint8_t *)&all, 0, u);
        SCLogDebug("no positive ranges, inserting 0.0.0.0/0");
        pos_v4_added++;
    }
    /* build a tree of all the positive values first, going from broad to narrow.
       Then loop the negations and AND them. We build and negate from large range
       to small range to get the cleanest tree. TODO does this make sense?

        addrs = (pos1|pos2|posN) &= ~(neg1|neg2|negN);

        Start with positive addresses/ranges:
    */
    for (int x = 0; x <= 32; x++) {
        for (IPOnlyCIDRItem *i = ps->pos_v4[x]; i != NULL;) {
            SCRadix4Node *node;
            void *user_data = NULL;
            SCLogDebug("sid %u: %s %s/%u", ps->sid, i->negated ? "negated" : "positive",
                    inet_ntoa(*(struct in_addr *)&i->ip[0]), i->netmask);
            if (i->netmask == 32) {
                node = SCRadix4TreeFindExactMatch(tree, (uint8_t *)&i->ip[0], &user_data);
            } else {
                node = SCRadix4TreeFindNetblock(tree, (uint8_t *)&i->ip[0], i->netmask, &user_data);
            }
            if (node != NULL) {
                SCLogDebug("exact match");
                if (i->negated) {
                    struct AddrState *as = (struct AddrState *)user_data;
                    as->state = 0;
                    SCLogDebug("flipped negated due to negation");
                }
            } else {
                uint8_t netmask = 0;
                SCLogDebug("no match, try best match");
                node = SCRadix4TreeFindBestMatch2(tree, (uint8_t *)&i->ip[0], &user_data, &netmask);
                if (node != NULL) {
                    SCLogDebug("sid %u: parent %s/%u for %s/%u", ps->sid,
                            inet_ntoa(*(struct in_addr *)node->prefix_stream), netmask,
                            inet_ntoa(*(struct in_addr *)&i->ip[0]), i->netmask);
                } else {
                    SCLogDebug("no match, adding %s/%u", inet_ntoa(*(struct in_addr *)&i->ip[0]),
                            i->netmask);
                    struct AddrState *as = SCCalloc(1, sizeof(*as));
                    BUG_ON(as == NULL);
                    as->state = i->negated == 0;
                    void *u = as;
                    if (i->netmask == 32)
                        node = SCRadix4AddKeyIPV4(tree, &ip_radix4_config, (uint8_t *)&i->ip[0], u);
                    else
                        node = SCRadix4AddKeyIPV4Netblock(
                                tree, &ip_radix4_config, (uint8_t *)&i->ip[0], i->netmask, u);
                    if (node == NULL)
                        return -1;
                    if (as->state)
                        pos_v4_added++;
                    else
                        neg_v4_added++;
                }
            }
            IPOnlyCIDRItem *next = i->next;
            SCFree(i);
            i = next;
        }
        ps->pos_v4[x] = NULL;
    }
    for (int x = 0; x <= 32; x++) {
        // neg
        for (IPOnlyCIDRItem *i = ps->neg_v4[x]; i != NULL;) {
            SCRadix4Node *node;
            void *user_data = NULL;
            SCLogDebug("sid %u: negative %s/%u", ps->sid, inet_ntoa(*(struct in_addr *)&i->ip[0]),
                    i->netmask);
            if (i->netmask == 32) {
                node = SCRadix4TreeFindExactMatch(tree, (uint8_t *)&i->ip[0], &user_data);
            } else {
                node = SCRadix4TreeFindNetblock(tree, (uint8_t *)&i->ip[0], i->netmask, &user_data);
            }
            if (node != NULL) {
                SCLogDebug("exact match");
                struct AddrState *as = user_data;
                BUG_ON(as->state);
                as->state = 0;
            } else {
                bool add = true;
                // TODO check best match and see if it is negated. Can happen ...
                node = SCRadix4TreeFindBestMatch(tree, (uint8_t *)&i->ip[0], &user_data);
                if (node != NULL) {
                    struct AddrState *as = user_data;
                    if (as->state == 0) {
                        add = false;
                    }
                }

                if (add) {
                    SCLogDebug("no match, adding %s/%u", inet_ntoa(*(struct in_addr *)&i->ip[0]),
                            i->netmask);
                    struct AddrState *as = SCCalloc(1, sizeof(*as));
                    BUG_ON(as == NULL);
                    as->state = 0;
                    void *u = as;
                    if (i->netmask == 32)
                        node = SCRadix4AddKeyIPV4(tree, &ip_radix4_config, (uint8_t *)&i->ip[0], u);
                    else
                        node = SCRadix4AddKeyIPV4Netblock(
                                tree, &ip_radix4_config, (uint8_t *)&i->ip[0], i->netmask, u);
                    if (node == NULL)
                        return -1;
                    neg_v4_added++;
                }
            }
            IPOnlyCIDRItem *next = i->next;
            SCFree(i);
            i = next;
        }
        ps->neg_v4[x] = NULL;
    }
    if (neg_v4_added && !pos_v4_added) {
        SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC,
                "no IPv4 ranges left after applying negation for '%s'", str);
        return -1;
    }

    SCRadix6Tree *tree_v6 = ps->ip6_tree;
    BUG_ON(tree_v6 == NULL);

    if (ps->pos_v6_cnt == 0 && ps->neg_v6_cnt != 0) {
        struct AddrState *as = SCCalloc(1, sizeof(*as));
        BUG_ON(as == NULL);
        as->state = 1;
        void *u = as;
        uint32_t all[4] = { 0, 0, 0, 0 };
        SCRadix6AddKeyIPV6Netblock(tree_v6, &ip_radix6_config, (uint8_t *)&all, 0, u);
        SCLogDebug("no positive ranges, inserting ::/0");
        pos_v6_added++;
    }
    for (int x = 0; x <= 128; x++) {
        for (IPOnlyCIDRItem *i = ps->pos_v6[x]; i != NULL;) {
            SCRadix6Node *node;
            void *user_data = NULL;
            SCLogDebug("sid %u: positive %s/%u", ps->sid, inet_ntoa(*(struct in_addr *)&i->ip[0]),
                    i->netmask);
            if (i->netmask == 128) {
                node = SCRadix6TreeFindExactMatch(tree_v6, (uint8_t *)&i->ip[0], &user_data);
            } else {
                node = SCRadix6TreeFindNetblock(
                        tree_v6, (uint8_t *)&i->ip[0], i->netmask, &user_data);
            }
            if (node != NULL) {
                SCLogDebug("exact match");
                if (i->negated) {
                    struct AddrState *as = (struct AddrState *)user_data;
                    as->state = 0;
                    SCLogDebug("flipped negated due to negation");
                }
            } else {
                SCLogDebug("no match, try best match");
                node = SCRadix6TreeFindBestMatch(tree_v6, (uint8_t *)&i->ip[0], &user_data);
                if (node == NULL) {
                    SCLogDebug("no match, adding %s/%u", inet_ntoa(*(struct in_addr *)&i->ip[0]),
                            i->netmask);
                    struct AddrState *as = SCCalloc(1, sizeof(*as));
                    BUG_ON(as == NULL);
                    as->state = i->negated == 0;
                    if (i->netmask == 128)
                        node = SCRadix6AddKeyIPV6(
                                tree_v6, &ip_radix6_config, (uint8_t *)&i->ip[0], as);
                    else
                        node = SCRadix6AddKeyIPV6Netblock(
                                tree_v6, &ip_radix6_config, (uint8_t *)&i->ip[0], i->netmask, as);
                    if (node == NULL) {
                        abort();
                        return -1;
                    }
                    if (as->state)
                        pos_v6_added++;
                    else
                        neg_v6_added++;
                }
            }
            IPOnlyCIDRItem *next = i->next;
            SCFree(i);
            i = next;
        }
        ps->pos_v6[x] = NULL;
    }
    for (int x = 0; x <= 128; x++) {
        // neg
        for (IPOnlyCIDRItem *i = ps->neg_v6[x]; i != NULL;) {
            SCRadix6Node *node;
            void *user_data = NULL;
            SCLogDebug("sid %u: negative %s/%u", ps->sid, inet_ntoa(*(struct in_addr *)&i->ip[0]),
                    i->netmask);
            if (i->netmask == 128) {
                node = SCRadix6TreeFindExactMatch(tree_v6, (uint8_t *)&i->ip[0], &user_data);
            } else {
                node = SCRadix6TreeFindNetblock(
                        tree_v6, (uint8_t *)&i->ip[0], i->netmask, &user_data);
            }
            if (node != NULL) {
                SCLogDebug("exact match");
                struct AddrState *as = user_data;
                as->state = 0;
            } else {
                SCLogDebug("no match, adding %s/%u", inet_ntoa(*(struct in_addr *)&i->ip[0]),
                        i->netmask);
                struct AddrState *as = SCCalloc(1, sizeof(*as));
                BUG_ON(as == NULL);
                as->state = 0;
                if (i->netmask == 128)
                    node = SCRadix6AddKeyIPV6(tree_v6, &ip_radix6_config, (uint8_t *)&i->ip[0], as);
                else
                    node = SCRadix6AddKeyIPV6Netblock(
                            tree_v6, &ip_radix6_config, (uint8_t *)&i->ip[0], i->netmask, as);
                if (node == NULL)
                    return -1;
                neg_v6_added++;
            }
            IPOnlyCIDRItem *next = i->next;
            SCFree(i);
            i = next;
        }
        ps->neg_v6[x] = NULL;
    }

    if (neg_v6_added && !pos_v6_added) {
        SCLogError(SC_ERR_ADDRESS_ENGINE_GENERIC,
                "no IPv6 ranges left after applying negation for '%s'", str);
        return -1;
    }
    return 0;
}

bool CheckAddress(const Address *a, const struct DetectAddresses *addrs)
{
    void *user_data = NULL;
    if (a->family == AF_INET) {
        (void)SCRadix4TreeFindBestMatch(&addrs->ipv4, (uint8_t *)&a->addr_data32[0], &user_data);
    } else if (a->family == AF_INET6) {
        (void)SCRadix6TreeFindBestMatch(&addrs->ipv6, (uint8_t *)&a->addr_data32[0], &user_data);
    }
    struct AddrState *as = user_data;
    if (as == NULL || !as->state) {
        return false;
    }
    return true;
}

bool CheckAddresses(const Packet *p, const Signature *s)
{
    void *user_data_src = NULL;
    if (p->src.family == AF_INET) {
        (void)SCRadix4TreeFindBestMatch(
                &s->ip_src.ipv4, (uint8_t *)&GET_IPV4_SRC_ADDR_U32(p), &user_data_src);
    } else if (p->src.family == AF_INET6) {
        (void)SCRadix6TreeFindBestMatch(
                &s->ip_src.ipv6, (uint8_t *)&GET_IPV6_SRC_ADDR(p), &user_data_src);
    }
    struct AddrState *asrc = user_data_src;
    if (asrc == NULL || !asrc->state)
        return false;

    void *user_data_dst = NULL;
    if (p->dst.family == AF_INET) {
        (void)SCRadix4TreeFindBestMatch(
                &s->ip_dst.ipv4, (uint8_t *)&GET_IPV4_DST_ADDR_U32(p), &user_data_dst);
    } else if (p->dst.family == AF_INET6) {
        (void)SCRadix6TreeFindBestMatch(
                &s->ip_dst.ipv6, (uint8_t *)&GET_IPV6_DST_ADDR(p), &user_data_dst);
    }
    struct AddrState *adst = user_data_dst;
    if (adst == NULL || !adst->state)
        return false;

    return true;
}

static void ParserScratchCleanup(struct ParserScratch *ps)
{
    for (int x = 0; x <= 32; x++) {
        for (IPOnlyCIDRItem *i = ps->pos_v4[x]; i != NULL;) {
            IPOnlyCIDRItem *next = i->next;
            SCFree(i);
            i = next;
        }
        ps->pos_v4[x] = NULL;
    }
    for (int x = 0; x <= 32; x++) {
        for (IPOnlyCIDRItem *i = ps->neg_v4[x]; i != NULL;) {
            IPOnlyCIDRItem *next = i->next;
            SCFree(i);
            i = next;
        }
        ps->neg_v4[x] = NULL;
    }
    for (int x = 0; x <= 128; x++) {
        for (IPOnlyCIDRItem *i = ps->pos_v6[x]; i != NULL;) {
            IPOnlyCIDRItem *next = i->next;
            SCFree(i);
            i = next;
        }
        ps->pos_v6[x] = NULL;
    }
    for (int x = 0; x <= 128; x++) {
        for (IPOnlyCIDRItem *i = ps->neg_v6[x]; i != NULL;) {
            IPOnlyCIDRItem *next = i->next;
            SCFree(i);
            i = next;
        }
        ps->neg_v6[x] = NULL;
    }
}

static int DetectParseAddressesDo(const DetectEngineCtx *de_ctx, struct DetectAddresses *addrs,
        const char *str, bool validate_vars)
{
    struct ParserScratch ps = { .ip4_tree = &addrs->ipv4,
        .ip6_tree = &addrs->ipv6,
        .var_list = TAILQ_HEAD_INITIALIZER(ps.var_list),
        .validate_vars = validate_vars };

    if (strcasecmp(str, "any") == 0) {
        if (IPOnlyCIDRListParse(de_ctx, &ps, "[0.0.0.0/0,::/0]") < 0) {
            CleanVariableResolveList(&ps.var_list);
            goto error;
        }
    } else if (IPOnlyCIDRListParse(de_ctx, &ps, (char *)str) < 0) {
        CleanVariableResolveList(&ps.var_list);
        goto error;
    }
    CleanVariableResolveList(&ps.var_list);
    return 0;
error:
    ParserScratchCleanup(&ps);
    return -1;
}

int DetectParseAddressesValidate(struct DetectAddresses *addrs, const char *str)
{
    return DetectParseAddressesDo(NULL, addrs, str, true);
}

int DetectParseAddresses(
        const DetectEngineCtx *de_ctx, struct DetectAddresses *addrs, const char *str)
{
    return DetectParseAddressesDo(de_ctx, addrs, str, false);
}

static int CopyV4(const SCRadix4Node *node, void *user_data, const uint8_t cidr, void *data)
{
    struct AddrState *as_in = (struct AddrState *)user_data;
    struct AddrState *as = SCCalloc(1, sizeof(*as));
    if (as == NULL)
        return -1;
    as->state = as_in->state;
    void *u = as;
    SCRadix4Tree *tree = (SCRadix4Tree *)data;
    SCRadix4Node *copy;
    if (cidr == 32)
        copy = SCRadix4AddKeyIPV4(tree, &ip_radix4_config, (uint8_t *)&node->prefix_stream, u);
    else
        copy = SCRadix4AddKeyIPV4Netblock(
                tree, &ip_radix4_config, (uint8_t *)&node->prefix_stream, cidr, u);
    if (copy == NULL) {
        SCFree(as);
        return -1;
    }
    return 0;
}

static int CopyV6(const SCRadix6Node *node, void *user_data, const uint8_t cidr, void *data)
{
    struct AddrState *as_in = (struct AddrState *)user_data;
    struct AddrState *as = SCCalloc(1, sizeof(*as));
    if (as == NULL)
        return -1;
    as->state = as_in->state;
    void *u = as;
    SCRadix6Tree *tree = (SCRadix6Tree *)data;
    SCRadix6Node *copy;
    if (cidr == 128)
        copy = SCRadix6AddKeyIPV6(tree, &ip_radix6_config, (uint8_t *)&node->prefix_stream, u);
    else
        copy = SCRadix6AddKeyIPV6Netblock(
                tree, &ip_radix6_config, (uint8_t *)&node->prefix_stream, cidr, u);
    if (copy == NULL) {
        SCFree(as);
        return -1;
    }
    return 0;
}

struct DetectAddresses DetectAddressesCopy(struct DetectAddresses *in_addrs)
{
    struct DetectAddresses addrs = { .ipv4 = SC_RADIX4_TREE_INITIALIZER,
        .ipv6 = SC_RADIX6_TREE_INITIALIZER };

    if (SCRadix4ForEachNode(&in_addrs->ipv4, CopyV4, (void *)&addrs.ipv4) < 0)
        goto error;
    if (SCRadix6ForEachNode(&in_addrs->ipv6, CopyV6, (void *)&addrs.ipv6) < 0)
        goto error;

    return addrs;
error:
    DetectAddressesClear(&addrs);
    return addrs;
}

struct DetectAddresses DetectParseAddress(DetectEngineCtx *de_ctx, const char *string)
{
    const DetectAddressCache *res = DetectAddressCacheLookup(de_ctx, string);
    if (res != NULL) {
        SCLogDebug("found: %s :: %p", string, res);
        return res->a;
    }

    struct DetectAddresses addrs = { .ipv4 = SC_RADIX4_TREE_INITIALIZER,
        .ipv6 = SC_RADIX6_TREE_INITIALIZER };
    if (DetectParseAddresses(de_ctx, &addrs, string) < 0) {
        struct DetectAddresses error = { .ipv4 = SC_RADIX4_TREE_INITIALIZER,
            .ipv6 = SC_RADIX6_TREE_INITIALIZER };
        return error;
    }
    DetectAddressCacheAdd(de_ctx, string, addrs);
    return addrs;
}

void DetectAddressesClear(struct DetectAddresses *a)
{
    SCRadix4TreeRelease(&a->ipv4, &ip_radix4_config);
    SCRadix6TreeRelease(&a->ipv6, &ip_radix6_config);
}

static bool Compare(const void *ud1, const void *ud2)
{
    if (ud1 == NULL && ud2 == NULL) {
        return true;
    } else if (ud1 == NULL) {
        return false;
    } else if (ud2 == NULL) {
        return false;
    } else {
        const struct AddrState *as1 = ud1;
        const struct AddrState *as2 = ud2;
        return (as1->state == as2->state);
    }
}

bool DetectAddressesCompare(const struct DetectAddresses *a, const struct DetectAddresses *b)
{
    return SCRadix4CompareTrees(&a->ipv4, &b->ipv4, Compare) &&
           SCRadix6CompareTrees(&a->ipv6, &b->ipv6, Compare);
}

#ifdef UNITTESTS
#include "detect-engine.h"
#include "detect-parse.h"
#include "util-unittest.h"

static int IPOnlyTestSig20(void)
{
    struct DetectAddresses a = DETECT_ADDRESSES_INITIALIZER;
    FAIL_IF_NOT(
            DetectParseAddressesValidate(&a, "[!192.168.0.0/16,192.168.0.0/16,192.168.2.5]") == 0);
    DetectAddressesClear(&a);
    PASS;
}

static int IPOnlyTestSig21(void)
{
    struct DetectAddresses a = DETECT_ADDRESSES_INITIALIZER;
    FAIL_IF_NOT(
            DetectParseAddressesValidate(&a, "[1.2.3.4,10.0.0.0/8,22.0.0.0/24,!0.0.0.0/1]") == -1);
    DetectAddressesClear(&a);
    PASS;
}

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
    struct DetectAddresses a = DETECT_ADDRESSES_INITIALIZER;
    FAIL_IF_NOT(DetectParseAddressesValidate(&a, "[1.2.3.4/24]") == 0);
    struct in_addr in;
    FAIL_IF(inet_pton(AF_INET, "1.2.3.1", &in) <= 0);
    void *user_data;
    uint8_t cidr;
    SCRadix4Node *node =
            SCRadix4TreeFindBestMatch2(&a.ipv4, (uint8_t *)&in.s_addr, &user_data, &cidr);
    FAIL_IF(user_data == NULL);
    FAIL_IF(node == NULL);
    FAIL_IF(cidr != 24);
    DetectAddressesClear(&a);
    PASS;
}

static int IPOnlyTestBug5066v3(void)
{
    struct DetectAddresses a = DETECT_ADDRESSES_INITIALIZER;
    FAIL_IF_NOT(DetectParseAddressesValidate(&a, "[1.2.3.64/26]") == 0);
    struct in_addr in;
    FAIL_IF(inet_pton(AF_INET, "1.2.3.67", &in) <= 0);
    void *user_data;
    uint8_t cidr;
    SCRadix4Node *node =
            SCRadix4TreeFindBestMatch2(&a.ipv4, (uint8_t *)&in.s_addr, &user_data, &cidr);
    FAIL_IF(user_data == NULL);
    FAIL_IF(node == NULL);
    FAIL_IF(cidr != 26);
    DetectAddressesClear(&a);
    PASS;
}

static int IPOnlyTestBug5066v4(void)
{
    struct DetectAddresses a = DETECT_ADDRESSES_INITIALIZER;
    FAIL_IF_NOT(DetectParseAddressesValidate(&a, "[2000::1:1/122]") == 0);
    struct in6_addr in;
    FAIL_IF(inet_pton(AF_INET6, "2000:0000:0000:0000:0000:0000:0001:0001", &in) <= 0);
    void *user_data;
    uint8_t cidr;
    SCRadix6Node *node =
            SCRadix6TreeFindBestMatch2(&a.ipv6, (uint8_t *)&in.s6_addr, &user_data, &cidr);
    FAIL_IF(user_data == NULL);
    FAIL_IF(node == NULL);
    FAIL_IF(cidr != 122);
    DetectAddressesClear(&a);
    PASS;
}

static int IPOnlyTestBug5066v5(void)
{
    struct DetectAddresses a = DETECT_ADDRESSES_INITIALIZER;
    FAIL_IF_NOT(DetectParseAddressesValidate(&a, "[2000::1:40/122]") == 0);
    struct in6_addr in;
    FAIL_IF(inet_pton(AF_INET6, "2000:0000:0000:0000:0000:0000:0001:0041", &in) <= 0);
    void *user_data;
    uint8_t cidr;
    SCRadix6Node *node =
            SCRadix6TreeFindBestMatch2(&a.ipv6, (uint8_t *)&in.s6_addr, &user_data, &cidr);
    FAIL_IF(user_data == NULL);
    FAIL_IF(node == NULL);
    FAIL_IF(cidr != 122);
    DetectAddressesClear(&a);
    PASS;
}

static int IPOnlyTestBug5168v1(void)
{
    struct DetectAddresses a = DETECT_ADDRESSES_INITIALIZER;
    FAIL_IF_NOT(DetectParseAddressesValidate(&a, "[1.2.3.64/0.0.0.0]") == 0);
    struct in_addr in;
    FAIL_IF(inet_pton(AF_INET, "1.1.1.1", &in) <= 0);
    void *user_data;
    uint8_t cidr;
    SCRadix4Node *node =
            SCRadix4TreeFindBestMatch2(&a.ipv4, (uint8_t *)&in.s_addr, &user_data, &cidr);
    FAIL_IF(user_data == NULL);
    FAIL_IF(node == NULL);
    FAIL_IF(cidr != 0);
    DetectAddressesClear(&a);
    PASS;
}

static int IPOnlyTestBug5168v2(void)
{
    struct DetectAddresses a = DETECT_ADDRESSES_INITIALIZER;
    FAIL_IF_NOT(DetectParseAddressesValidate(&a, "[0.0.0.5/0.0.0.5]") == -1);
    DetectAddressesClear(&a);
    PASS;
}

static int IPTestNegation01(void)
{
    struct DetectAddresses a = DETECT_ADDRESSES_INITIALIZER;
    FAIL_IF_NOT(DetectParseAddressesValidate(&a,
                        "3FFE:FFFF:7654:FEDA:0:0:0:0/64,!3FFE:FFFF:7654:FEDA:0:0:0:0/"
                        "64,3FFE:FFFF:7654:FEDA:1245:BA98:3210:4562,192.168.1.5") == -1);
    DetectAddressesClear(&a);
    PASS;
}

/** \test recursion limit */
static int IPTestRecursion01(void)
{
    struct DetectAddresses a = DETECT_ADDRESSES_INITIALIZER;
    /* exactly 64: should pass */
    FAIL_IF_NOT(DetectParseAddressesValidate(&a,
                        "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
                        "1.2.3.4"
                        "]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]") == 0);
    DetectAddressesClear(&a);

    /* exactly 65: should fail */
    FAIL_IF_NOT(DetectParseAddressesValidate(&a,
                        "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
                        "1.2.3.4"
                        "]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]") == -1);
    DetectAddressesClear(&a);
    PASS;
}

void DetectEngineIPRegisterTests(void)
{
    UtRegisterTest("IPOnlyTestSig20", IPOnlyTestSig20);
    UtRegisterTest("IPOnlyTestSig21", IPOnlyTestSig21);

    UtRegisterTest("IPOnlyTestBug5066v1", IPOnlyTestBug5066v1);
    UtRegisterTest("IPOnlyTestBug5066v2", IPOnlyTestBug5066v2);
    UtRegisterTest("IPOnlyTestBug5066v3", IPOnlyTestBug5066v3);
    UtRegisterTest("IPOnlyTestBug5066v4", IPOnlyTestBug5066v4);
    UtRegisterTest("IPOnlyTestBug5066v5", IPOnlyTestBug5066v5);

    UtRegisterTest("IPOnlyTestBug5168v1", IPOnlyTestBug5168v1);
    UtRegisterTest("IPOnlyTestBug5168v2", IPOnlyTestBug5168v2);

    UtRegisterTest("IPTestNegation01", IPTestNegation01);
    UtRegisterTest("IPTestRecursion01", IPTestRecursion01);
}
#endif
