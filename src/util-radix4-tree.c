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
 * Implementation of radix tree for IPv4
 */

#include "suricata-common.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-ip.h"
#include "util-unittest.h"
#include "util-memcmp.h"
#include "util-print.h"
#include "util-byte.h"
#include "util-radix4-tree.h"

#define ADDRESS_BYTES 4
#define NETMASK_MAX   32

#define RADIX_TREE_TYPE             SCRadix4Tree
#define RADIX_NODE_TYPE             SCRadix4Node
#define RADIX_CONFIG_TYPE           SCRadix4Config
#define RADIX_TREE_COMPARE_CALLBACK SCRadix4TreeCompareFunc

static void PrintUserdata(SCRadix4Node *node, int level, void (*PrintData)(void *));

static inline void AddNetmaskToMasks(SCRadix4Node *node, int netmask)
{
    SCLogDebug("masks %" PRIX64 ", adding %d/%" PRIX64, node->masks, netmask,
            (uint64_t)BIT_U64(netmask));
    node->masks |= BIT_U64(netmask);
    SCLogDebug("masks %" PRIX64, node->masks);
}

static inline void RemoveNetmaskFromMasks(SCRadix4Node *node, int netmask)
{
    SCLogDebug("masks %" PRIX64 ", removing %d/%" PRIX64, node->masks, netmask,
            (uint64_t)BIT_U64(netmask));
    node->masks &= ~BIT_U64(netmask);
    SCLogDebug("masks %" PRIX64, node->masks);
}

static inline void AddNetmasksFromNode(SCRadix4Node *dst, SCRadix4Node *src)
{
    dst->masks |= src->masks;
}

static inline bool NetmasksEmpty(const SCRadix4Node *node)
{
    return (node->masks == 0);
}

static inline bool NetmaskEqualsMask(const SCRadix4Node *node, int netmask)
{
    return (node->masks == BIT_U64(netmask));
}

static inline bool NetmaskIssetInMasks(const SCRadix4Node *node, int netmask)
{
    return ((node->masks & BIT_U64(netmask)) != 0);
}

static inline void ProcessInternode(SCRadix4Node *node, SCRadix4Node *inter_node)
{
    const int differ_bit = inter_node->bit;
    uint64_t rem = 0;
    for (int x = 0; x <= NETMASK_MAX; x++) {
        int m = NETMASK_MAX - x;
        if (m == differ_bit)
            break;
        else {
            rem |= (node->masks & BIT_U64(m));
        }
    }

    inter_node->masks |= node->masks;
    inter_node->masks &= ~rem;
    node->masks = rem;
}

/**
 * \brief Prints the node information from a Radix4 tree
 *
 * \param node  Pointer to the Radix4 node whose information has to be printed
 * \param level Used for indentation purposes
 */
static void PrintNodeInfo(SCRadix4Node *node, int level, void (*PrintData)(void *))
{
    if (node == NULL)
        return;

    for (int i = 0; i < level; i++)
        printf("   ");

    printf("%d [", node->bit);

    if (node->masks == 0) {
        printf(" - ");
    } else {
        for (int i = 0, x = 0; i <= 32; i++) {
            if (node->masks & BIT_U64(i)) {
                printf("%s%d", (x && x < 32) ? ", " : "", i);
                x++;
            }
        }
    }
    printf("] (");

    if (node->has_prefix) {
        char addr[16] = "";
        PrintInet(AF_INET, &node->prefix_stream, addr, sizeof(addr));
        printf("%s - user_data %p)\n", addr, node->user_data);
        PrintUserdata(node, level + 1, PrintData);
    } else {
        printf("no prefix)\n");
    }
    return;
}

#include "util-radix-tree-common.h"

SCRadix4Node *SCRadix4TreeFindExactMatch(
        const SCRadix4Tree *tree, const uint8_t *key, void **user_data)
{
    return FindExactMatch(tree, key, user_data);
}

SCRadix4Node *SCRadix4TreeFindNetblock(
        const SCRadix4Tree *tree, const uint8_t *key, const uint8_t netmask, void **user_data)
{
    return FindNetblock(tree, key, netmask, user_data);
}

SCRadix4Node *SCRadix4TreeFindBestMatch(
        const SCRadix4Tree *tree, const uint8_t *key, void **user_data)
{
    return FindBestMatch(tree, key, user_data);
}

SCRadix4Node *SCRadix4TreeFindBestMatch2(
        const SCRadix4Tree *tree, const uint8_t *key, void **user_data, uint8_t *out_netmask)
{
    return FindBestMatch2(tree, key, user_data, out_netmask);
}

SCRadix4Tree SCRadix4TreeInitialize(void)
{
    SCRadix4Tree t = SC_RADIX4_TREE_INITIALIZER;
    return t;
}

void SCRadix4TreeRelease(SCRadix4Tree *tree, const SCRadix4Config *config)
{
    TreeRelease(tree, config);
}

/**
 * \brief Adds a new IPV4 address to the Radix4 tree
 *
 * \param key_stream Data that has to be added to the Radix4 tree.  In this case
 *                   a pointer to an IPV4 address
 * \param tree       Pointer to the Radix4 tree
 * \param user       Pointer to the user data that has to be associated with the
 *                   key
 *
 * \retval node Pointer to the newly created node
 */
SCRadix4Node *SCRadix4AddKeyIPV4(
        SCRadix4Tree *tree, const SCRadix4Config *config, const uint8_t *key_stream, void *user)
{
    return AddKey(tree, config, key_stream, 32, user);
}

/**
 * \brief Adds a new IPV4 netblock to the Radix4 tree
 *
 * \param key_stream Data that has to be added to the Radix4 tree.  In this case
 *                   a pointer to an IPV4 netblock
 * \param tree       Pointer to the Radix4 tree
 * \param user       Pointer to the user data that has to be associated with the
 *                   key
 * \param netmask    The netmask (cidr) if we are adding a netblock
 *
 * \retval node Pointer to the newly created node
 */
SCRadix4Node *SCRadix4AddKeyIPV4Netblock(SCRadix4Tree *tree, const SCRadix4Config *config,
        const uint8_t *key_stream, uint8_t netmask, void *user)
{
    return AddKey(tree, config, key_stream, netmask, user);
}

/**
 * \brief Adds a new IPV4/netblock to the Radix4 tree from a string
 *
 * \param str        IPV4 string with optional /cidr netmask
 * \param tree       Pointer to the Radix4 tree
 * \param user       Pointer to the user data that has to be associated with
 *                   the key
 *
 * \retval node Pointer to the newly created node
 */
SCRadix4Node *SCRadix4AddKeyIPV4String(
        SCRadix4Tree *tree, const SCRadix4Config *config, const char *str, void *user)
{
    uint32_t ip;
    uint8_t netmask = 32;
    char ip_str[32]; /* Max length for full ipv4/mask string with NUL */
    char *mask_str = NULL;
    struct in_addr addr;

    /* Make a copy of the string so it can be modified */
    strlcpy(ip_str, str, sizeof(ip_str) - 2);
    *(ip_str + (sizeof(ip_str) - 1)) = '\0';

    /* Does it have a mask? */
    if (NULL != (mask_str = strchr(ip_str, '/'))) {
        *(mask_str++) = '\0';

        /* Dotted type netmask not supported */
        if (strchr(mask_str, '.') != NULL) {
            return NULL;
        }

        uint8_t cidr;
        if (StringParseU8RangeCheck(&cidr, 10, 0, (const char *)mask_str, 0, 32) < 0) {
            return NULL;
        }
        netmask = (uint8_t)cidr;
    }

    /* Validate the IP */
    if (inet_pton(AF_INET, ip_str, &addr) <= 0) {
        return NULL;
    }
    ip = addr.s_addr;

    return AddKey(tree, config, (uint8_t *)&ip, netmask, user);
}

/**
 * \brief Removes an IPV4 address key(not a netblock) from the Radix4 tree.
 *        Instead of using this function, we can also used
 *        SCRadix4RemoveKeyIPV4Netblock(), by supplying a netmask value of 32.
 *
 * \param key_stream Data that has to be removed from the Radix4 tree.  In this
 *                   case an IPV4 address
 * \param tree       Pointer to the Radix4 tree from which the key has to be
 *                   removed
 */
void SCRadix4RemoveKeyIPV4(
        SCRadix4Tree *tree, const SCRadix4Config *config, const uint8_t *key_stream)
{
    RemoveKey(tree, config, key_stream, 32);
}

/**
 * \brief Removes an IPV4 address netblock key from the Radix4 tree.
 *
 * \param key_stream Data that has to be removed from the Radix4 tree.  In this
 *                   case an IPV4 address
 * \param tree       Pointer to the Radix4 tree from which the key has to be
 *                   removed
 */
void SCRadix4RemoveKeyIPV4Netblock(SCRadix4Tree *tree, const SCRadix4Config *config,
        const uint8_t *key_stream, uint8_t netmask)
{
    SCLogNotice("removing with netmask %u", netmask);
    RemoveKey(tree, config, key_stream, netmask);
}

void SCRadix4PrintTree(SCRadix4Tree *tree, const SCRadix4Config *config)
{
    PrintTree(tree, config);
}

static void PrintUserdata(SCRadix4Node *node, int level, void (*PrintData)(void *))
{
    if (PrintData != NULL) {
        RadixUserData *ud = node->user_data;
        while (ud != NULL) {
            for (int i = 0; i < level; i++)
                printf("   ");
            printf("[%d], ", ud->netmask);
            PrintData(ud->user);
            ud = ud->next;
        }
    } else {
        RadixUserData *ud = node->user_data;
        while (ud != NULL) {
            for (int i = 0; i < level; i++)
                printf("   ");
            printf(" [%d], ", ud->netmask);
            ud = ud->next;
        }
    }
}

static int SCRadix4ForEachNodeSub(SCRadix4Node *node, SCRadix4ForEachNodeFunc Callback, void *data)
{
    BUG_ON(!node);

    /* invoke callback for each stored user data */
    for (RadixUserData *ud = node->user_data; ud != NULL; ud = ud->next) {
        if (Callback(node, ud->user, ud->netmask, data) < 0)
            return -1;
    }

    if (node->left) {
        if (SCRadix4ForEachNodeSub(node->left, Callback, data) < 0)
            return -1;
    }
    if (node->right) {
        if (SCRadix4ForEachNodeSub(node->right, Callback, data) < 0)
            return -1;
    }
    return 0;
}

int SCRadix4ForEachNode(SCRadix4Tree *tree, SCRadix4ForEachNodeFunc Callback, void *data)
{
    if (tree->head == NULL)
        return 0;
    return SCRadix4ForEachNodeSub(tree->head, Callback, data);
}

bool SCRadix4CompareTrees(
        const SCRadix4Tree *t1, const SCRadix4Tree *t2, SCRadix4TreeCompareFunc Callback)
{
    return CompareTrees(t1, t2, Callback);
}

/*------------------------------------Unit_Tests------------------------------*/

#ifdef UNITTESTS

static const SCRadix4Config ut_ip_radix4_config = { NULL, NULL };

#define GET_IPV4(str)                                                                              \
    SCLogDebug("setting up %s", (str));                                                            \
    memset(&(sa), 0, sizeof((sa)));                                                                \
    FAIL_IF(inet_pton(AF_INET, (str), &(sa).sin_addr) <= 0);

#define ADD_IPV4(str)                                                                              \
    GET_IPV4((str));                                                                               \
    SCRadix4AddKeyIPV4(&tree, &ut_ip_radix4_config, (uint8_t *)&(sa).sin_addr, NULL);

#define REM_IPV4(str)                                                                              \
    GET_IPV4((str));                                                                               \
    SCRadix4RemoveKeyIPV4(&tree, &ut_ip_radix4_config, (uint8_t *)&(sa).sin_addr);

#define ADD_IPV4_MASK(str, cidr)                                                                   \
    GET_IPV4((str));                                                                               \
    SCRadix4AddKeyIPV4Netblock(                                                                    \
            &tree, &ut_ip_radix4_config, (uint8_t *)&(sa).sin_addr, (cidr), NULL);

#define REM_IPV4_MASK(str, cidr)                                                                   \
    GET_IPV4((str));                                                                               \
    SCRadix4RemoveKeyIPV4Netblock(&tree, &ut_ip_radix4_config, (uint8_t *)&(sa).sin_addr, (cidr));

static int SCRadix4TestIPV4Insertion03(void)
{
    struct sockaddr_in sa;
    SCRadix4Tree tree = SCRadix4TreeInitialize();

    ADD_IPV4("192.168.1.1");
    ADD_IPV4("192.168.1.2");
    ADD_IPV4("192.167.1.3");
    ADD_IPV4("192.167.1.4");
    ADD_IPV4("192.167.1.4");

    /* test for the existance of a key */
    GET_IPV4("192.168.1.6");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);

    /* test for the existance of a key */
    GET_IPV4("192.167.1.4");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);

    /* continue adding keys */
    ADD_IPV4("220.168.1.2");
    ADD_IPV4("192.168.1.5");
    ADD_IPV4("192.168.1.18");

    /* test the existence of keys */
    GET_IPV4("192.168.1.3");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);
    GET_IPV4("127.234.2.62");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);

    GET_IPV4("192.168.1.1");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);
    GET_IPV4("192.168.1.5");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);
    GET_IPV4("192.168.1.2");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);

    GET_IPV4("192.167.1.3");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);
    GET_IPV4("192.167.1.4");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);
    GET_IPV4("220.168.1.2");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);
    GET_IPV4("192.168.1.18");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);

    SCRadix4TreeRelease(&tree, &ut_ip_radix4_config);

    PASS;
}

static int SCRadix4TestIPV4Removal04(void)
{
    struct sockaddr_in sa;

    SCRadix4Tree tree = SCRadix4TreeInitialize();

    /* add the keys */
    ADD_IPV4("192.168.1.1");
    ADD_IPV4("192.168.1.2");
    ADD_IPV4("192.167.1.3");
    ADD_IPV4("192.167.1.4");
    ADD_IPV4("220.168.1.2");
    ADD_IPV4("192.168.1.5");
    ADD_IPV4("192.168.1.18");

    /* remove the keys from the tree */
    REM_IPV4("192.168.1.1");
    REM_IPV4("192.167.1.3");
    REM_IPV4("192.167.1.4");
    REM_IPV4("192.168.1.18");

    GET_IPV4("192.167.1.1");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);
    GET_IPV4("192.168.1.2");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);

    REM_IPV4("192.167.1.3");
    REM_IPV4("220.168.1.2");

    GET_IPV4("192.168.1.5");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);
    GET_IPV4("192.168.1.2");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);

    REM_IPV4("192.168.1.2");
    REM_IPV4("192.168.1.5");

    FAIL_IF_NOT_NULL(tree.head);

    SCRadix4TreeRelease(&tree, &ut_ip_radix4_config);
    PASS;
}

static int SCRadix4TestIPV4NetblockInsertion09(void)
{
    struct sockaddr_in sa;
    SCRadix4Tree tree = SCRadix4TreeInitialize();

    /* add the keys */
    ADD_IPV4("192.168.1.1");
    ADD_IPV4("192.168.1.2");
    ADD_IPV4("192.167.1.3");
    ADD_IPV4("192.167.1.4");
    ADD_IPV4("220.168.1.2");
    ADD_IPV4("192.168.1.5");
    ADD_IPV4("192.168.1.18");

    ADD_IPV4_MASK("192.168.0.0", 16);
    ADD_IPV4_MASK("192.171.128.0", 24);
    ADD_IPV4_MASK("192.171.192.0", 18);
    ADD_IPV4_MASK("192.175.0.0", 16);

    /* test for the existance of a key */
    GET_IPV4("192.168.1.6");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);
    GET_IPV4("192.170.1.6");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);
    GET_IPV4("192.171.128.145");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);
    GET_IPV4("192.171.64.6");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);
    GET_IPV4("192.171.191.6");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);
    GET_IPV4("192.171.224.6");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);
    GET_IPV4("192.171.224.6");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);
    GET_IPV4("192.175.224.6");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);

    SCRadix4TreeRelease(&tree, &ut_ip_radix4_config);
    PASS;
}

static int SCRadix4TestIPV4NetblockInsertion10(void)
{
    SCRadix4Node *node[2];
    struct sockaddr_in sa;
    SCRadix4Tree tree = SCRadix4TreeInitialize();

    /* add the keys */
    ADD_IPV4_MASK("253.192.0.0", 16);
    ADD_IPV4_MASK("253.192.235.0", 24);
    ADD_IPV4_MASK("192.167.0.0", 16);
    ADD_IPV4("192.167.1.4");
    ADD_IPV4_MASK("220.168.0.0", 16);
    ADD_IPV4("253.224.1.5");
    ADD_IPV4_MASK("192.168.0.0", 16);

    GET_IPV4("192.171.128.0");
    node[0] = SCRadix4AddKeyIPV4Netblock(
            &tree, &ut_ip_radix4_config, (uint8_t *)&sa.sin_addr, 24, NULL);

    GET_IPV4("192.171.128.45");
    node[1] = SCRadix4AddKeyIPV4(&tree, &ut_ip_radix4_config, (uint8_t *)&sa.sin_addr, NULL);

    ADD_IPV4_MASK("192.171.0.0", 18);
    ADD_IPV4_MASK("192.175.0.0", 16);

    /* test for the existance of a key */
    GET_IPV4("192.171.128.53");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node[0]);

    GET_IPV4("192.171.128.45");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node[1]);

    GET_IPV4("192.171.128.45");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node[1]);

    GET_IPV4("192.171.128.78");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node[0]);

    REM_IPV4_MASK("192.171.128.0", 24);

    GET_IPV4("192.171.128.78");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);
    GET_IPV4("192.171.127.78");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);

    SCRadix4TreeRelease(&tree, &ut_ip_radix4_config);

    PASS;
}

static int SCRadix4TestIPV4NetblockInsertion11(void)
{
    struct sockaddr_in sa;
    SCRadix4Tree tree = SCRadix4TreeInitialize();

    /* add the keys */
    ADD_IPV4_MASK("253.192.0.0", 16);
    ADD_IPV4_MASK("253.192.235.0", 24);
    ADD_IPV4_MASK("192.167.0.0", 16);
    ADD_IPV4("192.167.1.4");
    ADD_IPV4_MASK("220.168.0.0", 16);
    ADD_IPV4("253.224.1.5");
    ADD_IPV4_MASK("192.168.0.0", 16);
    ADD_IPV4_MASK("192.171.128.0", 24);
    ADD_IPV4("192.171.128.45");
    ADD_IPV4_MASK("192.171.0.0", 18);
    ADD_IPV4_MASK("192.175.0.0", 16);

    GET_IPV4("0.0.0.0");
    SCRadix4Node *node = SCRadix4AddKeyIPV4Netblock(
            &tree, &ut_ip_radix4_config, (uint8_t *)&sa.sin_addr, 0, NULL);
    FAIL_IF_NULL(node);

    /* test for the existance of a key */
    GET_IPV4("192.171.128.53");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);

    GET_IPV4("192.171.128.45");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);

    GET_IPV4("192.171.128.78");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);

    GET_IPV4("192.171.127.78");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node);

    GET_IPV4("1.1.1.1");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node);

    GET_IPV4("192.255.254.25");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node);

    GET_IPV4("169.255.254.25");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node);

    GET_IPV4("0.0.0.0");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node);

    GET_IPV4("253.224.1.5");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != node);

    GET_IPV4("245.63.62.121");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node);

    GET_IPV4("253.224.1.6");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node);

    /* remove node 0.0.0.0 */
    REM_IPV4_MASK("0.0.0.0", 0);

    GET_IPV4("253.224.1.6");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);
    GET_IPV4("192.171.127.78");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);
    GET_IPV4("1.1.1.1");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);

    GET_IPV4("192.255.254.25");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);
    GET_IPV4("169.255.254.25");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);

    GET_IPV4("0.0.0.0");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);

    SCRadix4TreeRelease(&tree, &ut_ip_radix4_config);
    PASS;
}

static int SCRadix4TestIPV4NetblockInsertion12(void)
{
    struct sockaddr_in sa;
    SCRadix4Tree tree = SCRadix4TreeInitialize();
    SCRadix4Node *node[2];

    /* add the keys */
    ADD_IPV4_MASK("253.192.0.0", 16);
    ADD_IPV4_MASK("253.192.235.0", 24);
    ADD_IPV4_MASK("192.167.0.0", 16);
    ADD_IPV4("192.167.1.4");
    ADD_IPV4_MASK("220.168.0.0", 16);
    ADD_IPV4("253.224.1.5");
    ADD_IPV4_MASK("192.168.0.0", 16);

    GET_IPV4("192.171.128.0");
    node[0] = SCRadix4AddKeyIPV4Netblock(
            &tree, &ut_ip_radix4_config, (uint8_t *)&sa.sin_addr, 24, NULL);
    FAIL_IF_NULL(node[0]);

    GET_IPV4("192.171.128.45");
    node[1] = SCRadix4AddKeyIPV4(&tree, &ut_ip_radix4_config, (uint8_t *)&sa.sin_addr, NULL);
    FAIL_IF_NULL(node[1]);

    ADD_IPV4_MASK("192.171.0.0", 18);
    ADD_IPV4_MASK("225.175.21.228", 32);

    /* test for the existance of a key */
    GET_IPV4("192.171.128.53");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node[0]);
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);

    GET_IPV4("192.171.128.45");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node[1]);
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node[1]);

    GET_IPV4("192.171.128.78");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == node[0]);
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);

    GET_IPV4("225.175.21.228");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);

    GET_IPV4("225.175.21.224");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);

    GET_IPV4("225.175.21.229");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);

    GET_IPV4("225.175.21.230");
    FAIL_IF_NOT(SCRadix4TreeFindExactMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) == NULL);

    SCRadix4TreeRelease(&tree, &ut_ip_radix4_config);

    PASS;
}

/**
 * \test Check that the best match search works for all the
 *       possible netblocks of a fixed address
 */
static int SCRadix4TestIPV4NetBlocksAndBestSearch16(void)
{
    struct sockaddr_in sa;
    SCRadix4Tree tree = SCRadix4TreeInitialize();

    GET_IPV4("192.168.1.1");

    for (uint32_t i = 0; i <= 32; i++) {
        uint32_t *user = SCMalloc(sizeof(uint32_t));
        FAIL_IF_NULL(user);
        *user = i;
        SCRadix4AddKeyIPV4Netblock(&tree, &ut_ip_radix4_config, (uint8_t *)&sa.sin_addr, i, user);
        void *user_data = NULL;
        SCRadix4Node *node = SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, &user_data);
        FAIL_IF_NULL(node);
        FAIL_IF_NULL(user_data);
        FAIL_IF(*((uint32_t *)user_data) != i);
    }

    SCRadix4TreeRelease(&tree, &ut_ip_radix4_config);
    PASS;
}

/**
 * \test Check special combinations of netblocks and addresses
 *       on best search checking the returned userdata
 */
static int SCRadix4TestIPV4NetBlocksAndBestSearch19(void)
{
    struct sockaddr_in sa;
    void *user_data = NULL;
    SCRadix4Tree tree = SCRadix4TreeInitialize();

    GET_IPV4("0.0.0.0");
    uint32_t *user = SCMalloc(sizeof(uint32_t));
    FAIL_IF_NULL(user);
    *user = 100;
    SCRadix4AddKeyIPV4Netblock(&tree, &ut_ip_radix4_config, (uint8_t *)&sa.sin_addr, 0, user);

    GET_IPV4("192.168.1.15");
    SCRadix4Node *node = SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, &user_data);
    FAIL_IF_NULL(node);
    FAIL_IF_NULL(user_data);
    FAIL_IF(*((uint32_t *)user_data) != 100);
    user_data = NULL;

    GET_IPV4("177.0.0.0");
    user = SCMalloc(sizeof(uint32_t));
    FAIL_IF_NULL(user);
    *user = 200;
    SCRadix4AddKeyIPV4Netblock(&tree, &ut_ip_radix4_config, (uint8_t *)&sa.sin_addr, 8, user);

    GET_IPV4("177.168.1.15");
    node = SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, &user_data);
    FAIL_IF_NULL(node);
    FAIL_IF_NULL(user_data);
    FAIL_IF(*((uint32_t *)user_data) != 200);
    user_data = NULL;

    GET_IPV4("178.168.1.15");
    node = SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, &user_data);
    FAIL_IF_NULL(node);
    FAIL_IF_NULL(user_data);
    FAIL_IF(*((uint32_t *)user_data) != 100);
    user_data = NULL;

    GET_IPV4("177.168.0.0");
    user = SCMalloc(sizeof(uint32_t));
    FAIL_IF_NULL(user);
    *user = 300;
    SCRadix4AddKeyIPV4Netblock(&tree, &ut_ip_radix4_config, (uint8_t *)&sa.sin_addr, 12, user);

    GET_IPV4("177.168.1.15");
    node = SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, &user_data);
    FAIL_IF_NULL(node);
    FAIL_IF_NULL(user_data);
    FAIL_IF(*((uint32_t *)user_data) != 300);
    user_data = NULL;

    GET_IPV4("177.167.1.15");
    node = SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, &user_data);
    FAIL_IF_NULL(node);
    FAIL_IF_NULL(user_data);
    FAIL_IF(*((uint32_t *)user_data) != 300);
    user_data = NULL;

    GET_IPV4("177.178.1.15");
    node = SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, &user_data);
    FAIL_IF_NULL(node);
    FAIL_IF_NULL(user_data);
    FAIL_IF(*((uint32_t *)user_data) != 200);
    user_data = NULL;

    GET_IPV4("197.178.1.15");
    node = SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, &user_data);
    FAIL_IF_NULL(node);
    FAIL_IF_NULL(user_data);
    FAIL_IF(*((uint32_t *)user_data) != 100);
    user_data = NULL;

    SCRadix4TreeRelease(&tree, &ut_ip_radix4_config);
    PASS;
}

/**
 * \test SCRadix4TestIPV4NetblockInsertion15 insert a node searching on it.
 *       Should always return true but the purposse of the test is to monitor
 *       the memory usage to detect memleaks (there was one on searching)
 */
static int SCRadix4TestIPV4NetblockInsertion25(void)
{
    struct sockaddr_in sa;
    SCRadix4Tree tree = SCRadix4TreeInitialize();
    ADD_IPV4_MASK("192.168.0.0", 16);
    GET_IPV4("192.168.128.53");
    FAIL_IF_NOT(SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, NULL) != NULL);
    SCRadix4TreeRelease(&tree, &ut_ip_radix4_config);
    PASS;
}

/**
 * \test SCRadix4TestIPV4NetblockInsertion26 insert a node searching on it.
 *       Should always return true but the purposse of the test is to monitor
 *       the memory usage to detect memleaks (there was one on searching)
 */
static int SCRadix4TestIPV4NetblockInsertion26(void)
{
    SCRadix4Node *tmp = NULL;
    struct sockaddr_in sa;
    char *str = SCStrdup("Hello1");
    FAIL_IF_NULL(str);
    SCRadix4Tree tree = SCRadix4TreeInitialize();
    GET_IPV4("0.0.0.0");
    SCRadix4AddKeyIPV4Netblock(&tree, &ut_ip_radix4_config, (uint8_t *)&sa.sin_addr, 0, str);
    str = SCStrdup("Hello2");
    FAIL_IF_NULL(str);
    GET_IPV4("176.0.0.1");
    SCRadix4AddKeyIPV4Netblock(&tree, &ut_ip_radix4_config, (uint8_t *)&sa.sin_addr, 5, str);
    str = SCStrdup("Hello3");
    FAIL_IF_NULL(str);
    GET_IPV4("0.0.0.0");
    SCRadix4AddKeyIPV4Netblock(&tree, &ut_ip_radix4_config, (uint8_t *)&sa.sin_addr, 7, str);
    /* test for the existance of a key */
    void *retptr = NULL;
    tmp = SCRadix4TreeFindBestMatch(&tree, (uint8_t *)&sa.sin_addr, &retptr);
    FAIL_IF_NULL(tmp);
    FAIL_IF_NULL(retptr);
    FAIL_IF_NOT(strcmp((char *)retptr, "Hello3") == 0);
    SCRadix4TreeRelease(&tree, &ut_ip_radix4_config);
    PASS;
}

static int SCRadix4TestIPV4InsertRemove01(void)
{
    struct sockaddr_in sa;

    SCRadix4Tree tree = SCRadix4TreeInitialize();
    ADD_IPV4_MASK("1.0.0.0", 8);
    ADD_IPV4_MASK("1.1.1.0", 24);
    ADD_IPV4("1.1.1.1");
    FAIL_IF(tree.head == NULL);
    FAIL_IF_NOT(tree.head->bit == 15);
    FAIL_IF_NULL(tree.head->left);
    FAIL_IF_NOT(tree.head->left->masks == 0);
    FAIL_IF_NOT(tree.head->left->bit == 32);
    FAIL_IF_NULL(tree.head->right);
    FAIL_IF_NOT(tree.head->right->masks == BIT_U64(24));
    FAIL_IF_NOT(tree.head->right->bit == 31);
    SCRadix4PrintTree(&tree, &ut_ip_radix4_config);
    SCRadix4TreeRelease(&tree, &ut_ip_radix4_config);

    /* tree after adds/removals */
    tree = SCRadix4TreeInitialize();
    ADD_IPV4_MASK("1.0.0.0", 8);
    ADD_IPV4_MASK("1.0.0.0", 10);
    ADD_IPV4_MASK("1.0.0.0", 12);
    ADD_IPV4_MASK("1.1.0.0", 16);
    ADD_IPV4_MASK("1.1.0.0", 18);
    ADD_IPV4_MASK("1.1.0.0", 20);
    ADD_IPV4_MASK("1.1.1.0", 24);
    ADD_IPV4("1.1.1.1");
    REM_IPV4_MASK("1.1.0.0", 20);
    REM_IPV4_MASK("1.1.0.0", 18);
    REM_IPV4_MASK("1.1.0.0", 16);
    REM_IPV4_MASK("1.0.0.0", 12);
    REM_IPV4_MASK("1.0.0.0", 10);
    FAIL_IF(tree.head == NULL);
    FAIL_IF_NOT(tree.head->bit == 15);
    FAIL_IF_NULL(tree.head->left);
    FAIL_IF_NOT(tree.head->left->masks == 0);
    FAIL_IF_NOT(tree.head->left->bit == 32);
    FAIL_IF_NULL(tree.head->right);
    FAIL_IF_NOT(tree.head->right->masks == BIT_U64(24));
    FAIL_IF_NOT(tree.head->right->bit == 31);
    SCRadix4PrintTree(&tree, &ut_ip_radix4_config);
    SCRadix4TreeRelease(&tree, &ut_ip_radix4_config);

    PASS;
}
#endif

void SCRadix4RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SCRadix4TestIPV4Insertion03", SCRadix4TestIPV4Insertion03);
    UtRegisterTest("SCRadix4TestIPV4Removal04", SCRadix4TestIPV4Removal04);
    UtRegisterTest("SCRadix4TestIPV4NetblockInsertion09", SCRadix4TestIPV4NetblockInsertion09);
    UtRegisterTest("SCRadix4TestIPV4NetblockInsertion10", SCRadix4TestIPV4NetblockInsertion10);
    UtRegisterTest("SCRadix4TestIPV4NetblockInsertion11", SCRadix4TestIPV4NetblockInsertion11);
    UtRegisterTest("SCRadix4TestIPV4NetblockInsertion12", SCRadix4TestIPV4NetblockInsertion12);
    UtRegisterTest(
            "SCRadix4TestIPV4NetBlocksAndBestSearch16", SCRadix4TestIPV4NetBlocksAndBestSearch16);
    UtRegisterTest(
            "SCRadix4TestIPV4NetBlocksAndBestSearch19", SCRadix4TestIPV4NetBlocksAndBestSearch19);
    UtRegisterTest("SCRadix4TestIPV4NetblockInsertion25", SCRadix4TestIPV4NetblockInsertion25);
    UtRegisterTest("SCRadix4TestIPV4NetblockInsertion26", SCRadix4TestIPV4NetblockInsertion26);
    UtRegisterTest("SCRadix4TestIPV4InsertRemove01", SCRadix4TestIPV4InsertRemove01);
#endif
    return;
}
