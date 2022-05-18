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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implementation of radix trees
 */

#include "suricata-common.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-ip.h"
#include "util-cidr.h"
#include "util-unittest.h"
#include "util-memcmp.h"
#include "util-print.h"
#include "util-byte.h"
#include "util-radix6-tree.h"

#define ADDRESS_BYTES               16
#define NETMASK_MAX                 128
#define RADIX_TREE_TYPE             SCRadix6Tree
#define RADIX_NODE_TYPE             SCRadix6Node
#define RADIX_TREE_COMPARE_CALLBACK SCRadix6TreeCompareFunc
#define RADIX_CONFIG_TYPE           SCRadix6Config

static void PrintUserdata(SCRadix6Node *node, void (*PrintData)(void *));

static inline void AddNetmaskToMasks(SCRadix6Node *node, int netmask)
{
    uint8_t *masks = node->masks;
    masks[netmask / 8] |= 1 << (netmask % 8);
}

static inline void RemoveNetmaskFromMasks(SCRadix6Node *node, int netmask)
{
    uint8_t *masks = node->masks;
    masks[netmask / 8] &= ~(1 << (netmask % 8));
}

static inline void AddNetmasksFromNode(SCRadix6Node *dst, SCRadix6Node *src)
{
    for (size_t i = 0; i < sizeof(src->masks); i++) {
        dst->masks[i] |= src->masks[i];
    }
}

static inline bool NetmasksEmpty(const SCRadix6Node *node)
{
    for (size_t i = 0; i < sizeof(node->masks); i++) {
        if (node->masks[i] != 0) {
            return false;
        }
    }
    return true;
}

static inline bool NetmaskEqualsMask(const SCRadix6Node *node, int netmask)
{
    size_t b = netmask / 8;

    for (size_t i = 0; i < sizeof(node->masks); i++) {
        if (i != b && node->masks[i] != 0)
            return false;
        else if (node->masks[i] != (1 << (netmask % 8)))
            return false;
    }
    return true;
}

static inline bool NetmaskIssetInMasks(const SCRadix6Node *node, int netmask)
{
    return ((node->masks[netmask / 8] & 1 << (netmask % 8)) != 0);
}

static inline void ProcessInternode(SCRadix6Node *node, SCRadix6Node *inter_node)
{
    const int differ_bit = inter_node->bit;
    uint8_t rem[sizeof(node->masks)];
    memset(rem, 0, sizeof(rem));

    for (int x = 0; x <= NETMASK_MAX; x++) {
        int m = NETMASK_MAX - x;
        if (m == differ_bit)
            break;
        else {
            if (NetmaskIssetInMasks(node, m))
                rem[m / 8] |= 1 << (m % 8);
        }
    }

    AddNetmasksFromNode(inter_node, node);

    for (size_t i = 0; i < sizeof(inter_node->masks); i++) {
        inter_node->masks[i] &= ~rem[i];
    }

    memcpy(node->masks, rem, sizeof(node->masks));
}

/**
 * \brief Prints the node information from a Radix6 tree
 *
 * \param node  Pointer to the Radix6 node whose information has to be printed
 * \param level Used for indentation purposes
 */
static void PrintNodeInfo(SCRadix6Node *node, int level, void (*PrintData)(void *))
{
    if (node == NULL)
        return;
    for (int i = 0; i < level; i++)
        printf("   ");

    printf("%d [", node->bit);

    if (NetmasksEmpty(node)) {
        printf(" - ");
    } else {
        for (int i = 0, x = 0; i <= NETMASK_MAX; i++) {
            if (NetmaskIssetInMasks(node, i)) {
                printf("%s%d", x ? ", " : "", i);
                x++;
            }
        }
    }
    printf("] (");

    if (node->has_prefix) {
        char addr[46] = "";
        PrintInet(AF_INET6, &node->prefix_stream, addr, sizeof(addr));
        printf("%s)\t%p", addr, node);
        PrintUserdata(node, PrintData);
        printf("\n");
    } else {
        printf("no prefix) %p\n", node);
    }
    return;
}

#include "util-radix-tree-common.h"

SCRadix6Node *SCRadix6TreeFindExactMatch(
        const SCRadix6Tree *tree, const uint8_t *key, void **user_data)
{
    return FindExactMatch(tree, key, user_data);
}

SCRadix6Node *SCRadix6TreeFindNetblock(
        const SCRadix6Tree *tree, const uint8_t *key, const uint8_t netmask, void **user_data)
{
    return FindNetblock(tree, key, netmask, user_data);
}

SCRadix6Node *SCRadix6TreeFindBestMatch(
        const SCRadix6Tree *tree, const uint8_t *key, void **user_data)
{
    return FindBestMatch(tree, key, user_data);
}

SCRadix6Node *SCRadix6TreeFindBestMatch2(
        const SCRadix6Tree *tree, const uint8_t *key, void **user_data, uint8_t *out_netmask)
{
    return FindBestMatch2(tree, key, user_data, out_netmask);
}

/**
 * \brief Adds a new IPV6 address to the Radix6 tree
 *
 * \param key_stream Data that has to be added to the Radix6 tree.  In this case
 *                   a pointer to an IPV6 address
 * \param tree       Pointer to the Radix6 tree
 * \param user       Pointer to the user data that has to be associated with the
 *                   key
 *
 * \retval node Pointer to the newly created node
 */
SCRadix6Node *SCRadix6AddKeyIPV6(
        SCRadix6Tree *tree, const SCRadix6Config *config, const uint8_t *key_stream, void *user)
{
    return AddKey(tree, config, key_stream, 128, user);
}

/**
 * \brief Adds a new IPV6 netblock to the Radix6 tree
 *
 * \param key_stream Data that has to be added to the Radix6 tree.  In this case
 *                   a pointer to an IPV6 netblock
 * \param tree       Pointer to the Radix6 tree
 * \param user       Pointer to the user data that has to be associated with the
 *                   key
 * \param netmask    The netmask (cidr) if we are adding a netblock
 *
 * \retval node Pointer to the newly created node
 */
SCRadix6Node *SCRadix6AddKeyIPV6Netblock(SCRadix6Tree *tree, const SCRadix6Config *config,
        const uint8_t *key_stream, uint8_t netmask, void *user)
{
    return AddKey(tree, config, key_stream, netmask, user);
}

#if defined(DEBUG_VALIDATION) || defined(UNITTESTS)
static void SCRadix6ValidateIPv6Key(uint8_t *key, const uint8_t netmask)
{
    uint32_t address[4];
    memcpy(&address, key, sizeof(address));

    uint32_t mask[4];
    memset(&mask, 0, sizeof(mask));
    struct in6_addr mask6;
    CIDRGetIPv6(netmask, &mask6);
    memcpy(&mask, &mask6.s6_addr, sizeof(mask));

    uint32_t masked[4];
    masked[0] = address[0] & mask[0];
    masked[1] = address[1] & mask[1];
    masked[2] = address[2] & mask[2];
    masked[3] = address[3] & mask[3];

    if (memcmp(masked, address, sizeof(masked)) != 0) {
        char ostr[64], nstr[64];
        PrintInet(AF_INET6, (void *)&address, ostr, sizeof(ostr));
        PrintInet(AF_INET6, (void *)&masked, nstr, sizeof(nstr));
        SCLogNotice("input %s/%u != expected %s/%u", ostr, netmask, nstr, netmask);
        abort();
    }
}
#endif
/**
 * \brief Adds a new IPV6/netblock to the Radix6 tree from a string
 *
 * \param str        IPV6 string with optional /cidr netmask
 * \param tree       Pointer to the Radix6 tree
 * \param user       Pointer to the user data that has to be associated with
 *                   the key
 *
 * \retval node Pointer to the newly created node
 */
SCRadix6Node *SCRadix6AddKeyIPV6String(
        SCRadix6Tree *tree, const SCRadix6Config *config, const char *str, void *user)
{
    uint8_t netmask = 128;
    char ip_str[80] = ""; /* Max length for full ipv6/cidr string with NUL */
    char *mask_str = NULL;
    struct in6_addr addr;

    /* Make a copy of the string so it can be modified */
    strlcpy(ip_str, str, sizeof(ip_str));

    /* Does it have a mask? */
    if (NULL != (mask_str = strchr(ip_str, '/'))) {
        *(mask_str++) = '\0';

        /* Dotted type netmask not valid for ipv6 */
        if (strchr(mask_str, '.') != NULL) {
            return NULL;
        }

        uint8_t cidr;
        if (StringParseU8RangeCheck(&cidr, 10, 0, (const char *)mask_str, 0, 128) < 0) {
            return NULL;
        }
        netmask = (uint8_t)cidr;
    }

    /* Validate the IP */
    if (inet_pton(AF_INET6, ip_str, &addr) <= 0) {
        return NULL;
    }

    if (netmask != 128) {
        struct in6_addr maddr;
        struct in6_addr mask6;
        CIDRGetIPv6(netmask, &mask6);
        for (int i = 0; i < 16; i++) {
            maddr.s6_addr[i] = addr.s6_addr[i] & mask6.s6_addr[i];
        }
        if (SCMemcmp(maddr.s6_addr, addr.s6_addr, 16) != 0) {
            char nstr[64];
            PrintInet(AF_INET6, (void *)&maddr.s6_addr, nstr, sizeof(nstr));
            SCLogWarning(SC_ERR_INVALID_IP_NETBLOCK, "adding '%s' as '%s/%u'", str, nstr, netmask);
            memcpy(addr.s6_addr, maddr.s6_addr, 16);
#if defined(DEBUG_VALIDATION) || defined(UNITTESTS)
            SCRadix6ValidateIPv6Key((uint8_t *)&addr.s6_addr, netmask);
#endif
        }
    }

    return AddKey(tree, config, (uint8_t *)&addr.s6_addr, netmask, user);
}

/**
 * \brief Removes an IPV6 address key(not a netblock) from the Radix6 tree.
 *        Instead of using this function, we can also used
 *        SCRadix6RemoveKeyIPV6Netblock(), by supplying a netmask value of 32.
 *
 * \param key_stream Data that has to be removed from the Radix6 tree.  In this
 *                   case an IPV6 address
 * \param tree       Pointer to the Radix6 tree from which the key has to be
 *                   removed
 */
void SCRadix6RemoveKeyIPV6(
        SCRadix6Tree *tree, const SCRadix6Config *config, const uint8_t *key_stream)
{
    RemoveKey(tree, config, key_stream, 128);
}

/**
 * \brief Removes an IPV6 address netblock key from the tree.
 *
 * \param key_stream Data that has to be removed from the tree. In this
 *                   case an IPV6 address with netmask.
 * \param tree       Pointer to the tree from which the key has to be
 *                   removed
 */
void SCRadix6RemoveKeyIPV6Netblock(SCRadix6Tree *tree, const SCRadix6Config *config,
        const uint8_t *key_stream, uint8_t netmask)
{
    RemoveKey(tree, config, key_stream, netmask);
}

void SCRadix6PrintTree(SCRadix6Tree *tree, const SCRadix6Config *config)
{
    PrintTree(tree, config);
}

SCRadix6Tree SCRadix6TreeInitialize()
{
    SCRadix6Tree t = SC_RADIX6_TREE_INITIALIZER;
    return t;
}

void SCRadix6TreeRelease(SCRadix6Tree *tree, const SCRadix6Config *config)
{
    TreeRelease(tree, config);
}

static void PrintUserdata(SCRadix6Node *node, void (*PrintData)(void *))
{
    if (PrintData != NULL) {
        RadixUserData *ud = node->user_data;
        while (ud != NULL) {
            printf("[%d], ", ud->netmask);
            PrintData(ud->user);
            ud = ud->next;
        }
    } else {
        RadixUserData *ud = node->user_data;
        while (ud != NULL) {
            printf(" [%d], ", ud->netmask);
            ud = ud->next;
        }
    }
}

static int SCRadix6ForEachNodeSub(SCRadix6Node *node, SCRadix6ForEachNodeFunc Callback, void *data)
{
    BUG_ON(!node);

    /* invoke callback for each stored user data */
    for (RadixUserData *ud = node->user_data; ud != NULL; ud = ud->next) {
        if (Callback(node, ud->user, ud->netmask, data) < 0)
            return -1;
    }

    if (node->left) {
        if (SCRadix6ForEachNodeSub(node->left, Callback, data) < 0)
            return -1;
    }
    if (node->right) {
        if (SCRadix6ForEachNodeSub(node->right, Callback, data) < 0)
            return -1;
    }
    return 0;
}

int SCRadix6ForEachNode(SCRadix6Tree *tree, SCRadix6ForEachNodeFunc Callback, void *data)
{
    if (tree->head == NULL)
        return 0;
    return SCRadix6ForEachNodeSub(tree->head, Callback, data);
}

bool SCRadix6CompareTrees(
        const SCRadix6Tree *t1, const SCRadix6Tree *t2, SCRadix6TreeCompareFunc Callback)
{
    return CompareTrees(t1, t2, Callback);
}

/*------------------------------------Unit_Tests------------------------------*/

#ifdef UNITTESTS

static const SCRadix6Config ut_ip_radix6_config = { NULL, NULL };

#define GET_IPV6(str)                                                                              \
    SCLogDebug("setting up %s", (str));                                                            \
    memset(&(sa), 0, sizeof((sa)));                                                                \
    FAIL_IF(inet_pton(AF_INET6, (str), &(sa).sin6_addr) <= 0);

#define ADD_IPV6(str)                                                                              \
    GET_IPV6((str));                                                                               \
    SCRadix6AddKeyIPV6(&tree, &ut_ip_radix6_config, (uint8_t *)&(sa).sin6_addr, NULL);

#define REM_IPV6(str)                                                                              \
    GET_IPV6((str));                                                                               \
    SCRadix6RemoveKeyIPV6(&tree, &ut_ip_radix6_config, (uint8_t *)&(sa).sin6_addr);

#define ADD_IPV6_MASK(str, cidr)                                                                   \
    GET_IPV6((str));                                                                               \
    SCRadix6AddKeyIPV6Netblock(                                                                    \
            &tree, &ut_ip_radix6_config, (uint8_t *)&(sa).sin6_addr, (cidr), NULL);

#define REM_IPV6_MASK(str, cidr)                                                                   \
    GET_IPV6((str));                                                                               \
    SCRadix6RemoveKeyIPV6Netblock(&tree, &ut_ip_radix6_config, (uint8_t *)&(sa).sin6_addr, (cidr));

static int SCRadix6TestIPV6Insertion03(void)
{
    struct sockaddr_in6 sa;
    SCRadix6Tree tree = SCRadix6TreeInitialize();

    ADD_IPV6("2000:1::1");
    ADD_IPV6("2000:1::2");
    ADD_IPV6("2000:0::3");
    ADD_IPV6("2000:0::4");
    ADD_IPV6("2000:0::4");

    /* test for the existance of a key */
    GET_IPV6("2000:1::6");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);

    /* test for the existance of a key */
    GET_IPV6("2000:0::4");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);

    /* continue adding keys */
    ADD_IPV6("2000:0::2");
    ADD_IPV6("2000:1::5");
    ADD_IPV6("2000:1::18");

    /* test the existence of keys */
    GET_IPV6("2000:1::3");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);
    GET_IPV6("2001:1:2:3::62");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);

    GET_IPV6("2000:1::1");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);
    GET_IPV6("2000:1::5");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);
    GET_IPV6("2000:1::2");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);

    GET_IPV6("2000:0::3");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);
    GET_IPV6("2000:0::4");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);
    GET_IPV6("2000:0::2");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);
    GET_IPV6("2000:1::18");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);

    SCRadix6TreeRelease(&tree, &ut_ip_radix6_config);

    PASS;
}

static int SCRadix6TestIPV6Removal04(void)
{
    struct sockaddr_in6 sa;
    SCRadix6Tree tree = SCRadix6TreeInitialize();

    /* add the keys */
    ADD_IPV6("2000:1::1");
    ADD_IPV6("2000:1::2");
    ADD_IPV6("2000:0::3");
    ADD_IPV6("2000:0::4");
    ADD_IPV6("1000:1::2");
    ADD_IPV6("2000:1::5");
    ADD_IPV6("2000:1::18");

    /* remove the keys from the tree */
    REM_IPV6("2000:1::1");
    REM_IPV6("2000:0::3");
    REM_IPV6("2000:0::4");
    REM_IPV6("2000:1::18");

    GET_IPV6("2000:0::1");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);
    GET_IPV6("2000:1::2");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);

    REM_IPV6("2000:0::3");
    REM_IPV6("1000:1::2");

    GET_IPV6("2000:1::5");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);
    GET_IPV6("2000:1::2");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);

    REM_IPV6("2000:1::2");
    REM_IPV6("2000:1::5");

    FAIL_IF_NOT_NULL(tree.head);

    SCRadix6TreeRelease(&tree, &ut_ip_radix6_config);

    PASS;
}

static int SCRadix6TestIPV6NetblockInsertion09(void)
{
    struct sockaddr_in6 sa;
    SCRadix6Tree tree = SCRadix6TreeInitialize();

    /* add the keys */
    ADD_IPV6("2000::1:1");
    ADD_IPV6("2000::1:2");
    ADD_IPV6("2000::0:3");
    ADD_IPV6("2000::0:4");
    ADD_IPV6("1000::1:2");
    ADD_IPV6("2000::1:5");
    ADD_IPV6("2000::1:18");

    ADD_IPV6_MASK("2000::", 16);
    ADD_IPV6_MASK("2000::192:171:128:0", 128 - 8);
    ADD_IPV6_MASK("2000::192:171:192:0", 128 - 14);
    ADD_IPV6_MASK("2000::192:175:0:0", 128 - 16);

    /* test for the existance of a key */
    GET_IPV6("2000:1::6");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);
    GET_IPV6("2000::192:170:1:6");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);
    GET_IPV6("2000::192:171:128:145");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);
    GET_IPV6("2000::192:171:64:6");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);
    GET_IPV6("2000::192:171:191:6");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);
    GET_IPV6("2000::192:171:224:6");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);
    GET_IPV6("2000::192:171:224:6");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);
    GET_IPV6("2000::192:175:224:6");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);

    SCRadix6TreeRelease(&tree, &ut_ip_radix6_config);

    PASS;
}

static int SCRadix6TestIPV6NetblockInsertion10(void)
{
    SCRadix6Node *node[2];
    struct sockaddr_in6 sa;
    SCRadix6Tree tree = SCRadix6TreeInitialize();

    /* add the keys */
    ADD_IPV6_MASK("2000::253:192:0:0", 112);
    ADD_IPV6_MASK("2000::253:192:235:0", 112);
    ADD_IPV6_MASK("2000::192:167:0:0", 112);
    ADD_IPV6("2000:0::4");
    ADD_IPV6_MASK("2000::220:168:0:0", 112);
    ADD_IPV6("2000::253:224:1:5");
    ADD_IPV6_MASK("2000::192:168:0:0", 112);

    GET_IPV6("2000::192:171:128:0");
    node[0] = SCRadix6AddKeyIPV6Netblock(
            &tree, &ut_ip_radix6_config, (uint8_t *)&sa.sin6_addr, 112, NULL);

    GET_IPV6("2000::192:171:128:45");
    node[1] = SCRadix6AddKeyIPV6(&tree, &ut_ip_radix6_config, (uint8_t *)&sa.sin6_addr, NULL);

    ADD_IPV6_MASK("2000::192:171:0:0", 110);
    ADD_IPV6_MASK("2000::192:175:0:0", 112);

    /* test for the existance of a key */
    GET_IPV6("2000::192:171:128:53");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node[0]);

    GET_IPV6("2000::192:171:128:45");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node[1]);

    GET_IPV6("2000::192:171:128:45");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node[1]);

    GET_IPV6("2000::192:171:128:78");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node[0]);

    REM_IPV6_MASK("2000::192:171:128:0", 112);

    GET_IPV6("2000::192:171:128:78");
    SCRadix6Node *n = SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL);
    SCLogNotice("n %p", n);
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);
    GET_IPV6("2000::192:171:127:78");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);

    SCRadix6TreeRelease(&tree, &ut_ip_radix6_config);

    PASS;
}

static int SCRadix6TestIPV6NetblockInsertion11(void)
{
    struct sockaddr_in6 sa;
    SCRadix6Tree tree = SCRadix6TreeInitialize();

    /* add the keys */
    ADD_IPV6_MASK("2000::253:192:0:0", 96);
    ADD_IPV6_MASK("2000::253:192:235:0", 112);
    ADD_IPV6_MASK("2000::192:167:0:0", 96);
    ADD_IPV6("2000:0::4");
    ADD_IPV6_MASK("2000::220:168:0:0", 96);
    ADD_IPV6("2000::253:224:1:5");
    ADD_IPV6_MASK("2000::192:168:0:0", 96);
    ADD_IPV6_MASK("2000::192:171:128:0", 112);
    ADD_IPV6("2000::192:171:128:45");
    ADD_IPV6_MASK("2000::192:171:0:0", 112);
    ADD_IPV6_MASK("2000::192:175:0:0", 96);

    GET_IPV6("::");
    SCRadix6Node *node = SCRadix6AddKeyIPV6Netblock(
            &tree, &ut_ip_radix6_config, (uint8_t *)&sa.sin6_addr, 0, NULL);
    FAIL_IF_NULL(node);

    /* test for the existance of a key */
    GET_IPV6("2000::192:171:128:53");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);

    GET_IPV6("2000::192:171:128:45");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);

    GET_IPV6("2000::192:171:128:78");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);

    GET_IPV6("2000::192:171:127:78");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node);

    GET_IPV6("2000::1:1:1:1");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node);

    GET_IPV6("2000::192:255:254:25");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node);

    GET_IPV6("2000::169:255:254:25");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node);

    GET_IPV6("::");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node);

    GET_IPV6("2000::253:224:1:5");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != node);

    GET_IPV6("2000::245:63:62:121");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node);

    GET_IPV6("2000::253:224:1:6");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node);

    /* remove node 0.0.0.0 */
    REM_IPV6_MASK("::", 0);

    GET_IPV6("2000::253:224:1:6");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);
    GET_IPV6("2000::192:171:127:78");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);
    GET_IPV6("2000::1:1:1:1");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);

    GET_IPV6("2000::192:255:254:25");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);
    GET_IPV6("2000::169:255:254:25");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);

    GET_IPV6("::");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);

    SCRadix6TreeRelease(&tree, &ut_ip_radix6_config);

    PASS;
}

static int SCRadix6TestIPV6NetblockInsertion12(void)
{
    struct sockaddr_in6 sa;
    SCRadix6Node *node[2];
    SCRadix6Tree tree = SCRadix6TreeInitialize();

    /* add the keys */
    ADD_IPV6_MASK("2000::253:192:0:0", 96);
    ADD_IPV6_MASK("2000::253:192:235:0", 112);
    ADD_IPV6_MASK("2000::192:167:0:0", 96);
    ADD_IPV6("2000:0::4");
    ADD_IPV6_MASK("2000::220:168:0:0", 96);
    ADD_IPV6("2000::253:224:1:5");
    ADD_IPV6_MASK("2000::192:168:0:0", 96);

    GET_IPV6("2000::192:171:128:0");
    node[0] = SCRadix6AddKeyIPV6Netblock(
            &tree, &ut_ip_radix6_config, (uint8_t *)&sa.sin6_addr, 96, NULL);
    FAIL_IF_NULL(node[0]);

    GET_IPV6("2000::192:171:128:45");
    node[1] = SCRadix6AddKeyIPV6(&tree, &ut_ip_radix6_config, (uint8_t *)&sa.sin6_addr, NULL);
    FAIL_IF_NULL(node[1]);

    ADD_IPV6_MASK("2000::192:171:0:0", 96);
    ADD_IPV6_MASK("2000::225:175:21:228", 128);

    /* test for the existance of a key */
    GET_IPV6("2000::192:171:128:53");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node[0]);
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);

    GET_IPV6("2000::192:171:128:45");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node[1]);
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node[1]);

    GET_IPV6("2000::192:171:128:78");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == node[0]);
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);

    GET_IPV6("2000::225:175:21:228");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);

    GET_IPV6("2000::225:175:21:224");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);

    GET_IPV6("2000::225:175:21:229");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);

    GET_IPV6("2000::225:175:21:230");
    FAIL_IF_NOT(SCRadix6TreeFindExactMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) == NULL);

    SCRadix6TreeRelease(&tree, &ut_ip_radix6_config);
    PASS;
}

/**
 * \test Check that the best match search works for all the
 *       possible netblocks of a fixed address
 */
static int SCRadix6TestIPV6NetBlocksAndBestSearch16(void)
{
    struct sockaddr_in6 sa;
    SCRadix6Tree tree = SCRadix6TreeInitialize();

    GET_IPV6("2000:1::1");
    for (uint32_t i = 0; i <= 128; i++) {
        uint32_t *user = SCMalloc(sizeof(uint32_t));
        FAIL_IF_NULL(user);
        *user = i;
        SCRadix6AddKeyIPV6Netblock(&tree, &ut_ip_radix6_config, (uint8_t *)&sa.sin6_addr, i, user);
        void *user_data = NULL;
        SCRadix6Node *node = SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, &user_data);
        FAIL_IF_NULL(node);
        FAIL_IF_NULL(user_data);
        FAIL_IF(*((uint32_t *)user_data) != i);
    }

    SCRadix6TreeRelease(&tree, &ut_ip_radix6_config);
    PASS;
}

/**
 * \test Check special combinations of netblocks and addresses
 *       on best search checking the returned userdata
 */
static int SCRadix6TestIPV6NetBlocksAndBestSearch19(void)
{
    struct sockaddr_in6 sa;
    void *user_data = NULL;
    SCRadix6Tree tree = SCRadix6TreeInitialize();

    GET_IPV6("::");
    uint32_t *user = SCMalloc(sizeof(uint32_t));
    FAIL_IF_NULL(user);
    *user = 100;
    SCRadix6AddKeyIPV6Netblock(&tree, &ut_ip_radix6_config, (uint8_t *)&sa.sin6_addr, 0, user);

    GET_IPV6("2000:1::15");
    SCRadix6Node *node = SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, &user_data);
    FAIL_IF_NULL(node);
    FAIL_IF_NULL(user_data);
    FAIL_IF(*((uint32_t *)user_data) != 100);
    user_data = NULL;

    GET_IPV6("2000:177::0:0:0");
    user = SCMalloc(sizeof(uint32_t));
    FAIL_IF_NULL(user);
    *user = 200;
    SCRadix6AddKeyIPV6Netblock(&tree, &ut_ip_radix6_config, (uint8_t *)&sa.sin6_addr, 64, user);

    GET_IPV6("2000:177::168:1:15");
    node = SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, &user_data);
    FAIL_IF_NULL(node);
    FAIL_IF_NULL(user_data);
    FAIL_IF(*((uint32_t *)user_data) != 200);
    user_data = NULL;

    GET_IPV6("2000:178::168:1:15");
    node = SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, &user_data);
    FAIL_IF_NULL(node);
    FAIL_IF_NULL(user_data);
    FAIL_IF(*((uint32_t *)user_data) != 100);
    user_data = NULL;

    GET_IPV6("2000:177::168:0:0");
    user = SCMalloc(sizeof(uint32_t));
    FAIL_IF_NULL(user);
    *user = 300;
    SCRadix6AddKeyIPV6Netblock(&tree, &ut_ip_radix6_config, (uint8_t *)&sa.sin6_addr, 92, user);

    GET_IPV6("2000:177::168:1:15");
    node = SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, &user_data);
    FAIL_IF_NULL(node);
    FAIL_IF_NULL(user_data);
    FAIL_IF(*((uint32_t *)user_data) != 300);
    user_data = NULL;

    GET_IPV6("2000:177::167:1:15");
    node = SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, &user_data);
    FAIL_IF_NULL(node);
    FAIL_IF_NULL(user_data);
    FAIL_IF(*((uint32_t *)user_data) != 300);
    user_data = NULL;

    GET_IPV6("2000:177::178:1:15");
    node = SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, &user_data);
    FAIL_IF_NULL(node);
    FAIL_IF_NULL(user_data);
    FAIL_IF(*((uint32_t *)user_data) != 200);
    user_data = NULL;

    GET_IPV6("2000:197::178:1:15");
    node = SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, &user_data);
    FAIL_IF_NULL(node);
    FAIL_IF_NULL(user_data);
    FAIL_IF(*((uint32_t *)user_data) != 100);
    user_data = NULL;

    SCRadix6TreeRelease(&tree, &ut_ip_radix6_config);
    PASS;
}

/**
 * \test SCRadix6TestIPV6NetblockInsertion15 insert a node searching on it.
 *       Should always return true but the purposse of the test is to monitor
 *       the memory usage to detect memleaks (there was one on searching)
 */
static int SCRadix6TestIPV6NetblockInsertion25(void)
{
    struct sockaddr_in6 sa;
    SCRadix6Tree tree = SCRadix6TreeInitialize();
    ADD_IPV6_MASK("2000::192:168:0:0", 16);
    GET_IPV6("2000::192:168:128:53");
    FAIL_IF_NOT(SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, NULL) != NULL);
    SCRadix6TreeRelease(&tree, &ut_ip_radix6_config);
    PASS;
}

/**
 * \test SCRadix6TestIPV6NetblockInsertion26 insert a node searching on it.
 *       Should always return true but the purposse of the test is to monitor
 *       the memory usage to detect memleaks (there was one on searching)
 */
static int SCRadix6TestIPV6NetblockInsertion26(void)
{
    SCRadix6Node *tmp = NULL;
    struct sockaddr_in6 sa;
    const SCRadix6Config ut_ip_radix6_config_26 = { free, NULL };

    char *str = SCStrdup("Hello1");
    FAIL_IF_NULL(str);

    SCRadix6Tree tree = SCRadix6TreeInitialize();

    GET_IPV6("::");
    SCRadix6AddKeyIPV6Netblock(&tree, &ut_ip_radix6_config_26, (uint8_t *)&sa.sin6_addr, 0, str);

    str = SCStrdup("Hello2");
    FAIL_IF_NULL(str);

    GET_IPV6("2000::176:0:0:1");
    SCRadix6AddKeyIPV6Netblock(&tree, &ut_ip_radix6_config_26, (uint8_t *)&sa.sin6_addr, 5, str);

    str = SCStrdup("Hello3");
    FAIL_IF_NULL(str);

    GET_IPV6("::");
    SCRadix6AddKeyIPV6Netblock(&tree, &ut_ip_radix6_config_26, (uint8_t *)&sa.sin6_addr, 7, str);

    /* test for the existance of a key */
    void *retptr = NULL;
    tmp = SCRadix6TreeFindBestMatch(&tree, (uint8_t *)&sa.sin6_addr, &retptr);
    FAIL_IF_NULL(tmp);
    FAIL_IF_NULL(retptr);
    FAIL_IF_NOT(strcmp((char *)retptr, "Hello3") == 0);

    SCRadix6TreeRelease(&tree, &ut_ip_radix6_config_26);

    PASS;
}
#endif

void SCRadix6RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SCRadix6TestIPV6Insertion03", SCRadix6TestIPV6Insertion03);
    UtRegisterTest("SCRadix6TestIPV6Removal04", SCRadix6TestIPV6Removal04);
    UtRegisterTest("SCRadix6TestIPV6NetblockInsertion09", SCRadix6TestIPV6NetblockInsertion09);
    UtRegisterTest("SCRadix6TestIPV6NetblockInsertion10", SCRadix6TestIPV6NetblockInsertion10);
    UtRegisterTest("SCRadix6TestIPV6NetblockInsertion11", SCRadix6TestIPV6NetblockInsertion11);
    UtRegisterTest("SCRadix6TestIPV6NetblockInsertion12", SCRadix6TestIPV6NetblockInsertion12);
    UtRegisterTest(
            "SCRadix6TestIPV6NetBlocksAndBestSearch16", SCRadix6TestIPV6NetBlocksAndBestSearch16);
    UtRegisterTest(
            "SCRadix6TestIPV6NetBlocksAndBestSearch19", SCRadix6TestIPV6NetBlocksAndBestSearch19);
    UtRegisterTest("SCRadix6TestIPV6NetblockInsertion25", SCRadix6TestIPV6NetblockInsertion25);
    UtRegisterTest("SCRadix6TestIPV6NetblockInsertion26", SCRadix6TestIPV6NetblockInsertion26);
#endif
    return;
}
