/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "util-radix-tree.h"
#include "util-unittest.h"

/**
 * \brief Creates a new node for the Radix tree
 *
 * \retval node The newly created node for the radix tree
 */
static inline SCRadixNode *SCRadixCreateNode()
{
    SCRadixNode *node = NULL;

    if ( (node = malloc(sizeof(SCRadixNode))) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }
    memset(node, 0, sizeof(SCRadixNode));

    return node;
}

/**
 * \brief Frees a Radix tree node
 *
 * \param node Pointer to a Radix tree node
 */
static inline void SCRadixReleaseNode(SCRadixNode *node)
{
    if (node != NULL) {
        //SCRadixReleaseKeyPrefix(node->prefix);
        free(node);
    }

    return;
}

/**
 * \brief Creates a new Prefix
 *
 * \param stream Data that has to be wrapped in a SCRadixPrefix instance to be
 *               processed for insertion/lookup by the radix tree
 * \param bitlen The bitlen of the the above stream.  For example if the stream
 *               holds the ipv4 address(in 1 byte), bitlen would be 32
 *
 * \retval prefix The newly created prefix instance on success; NULL on failure
 */
SCRadixPrefix *SCRadixCreatePrefix(uint8_t *stream, uint16_t bitlen)
{
    SCRadixPrefix *prefix = NULL;

    if ((bitlen % 8 != 0) || bitlen == 0) {
        printf("Error: SCRadixCreatePrefix: Invalid bitlen: %d", bitlen);
        return NULL;
    }

    if (stream == NULL) {
        printf("Error: SCRadixCreatePrefix: Argument \"stream\" NULL");
        return NULL;
    }

    if ( (prefix = malloc(sizeof(SCRadixPrefix))) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }
    memset(prefix, 0, sizeof(SCRadixPrefix));

    if ( (prefix->stream = malloc(bitlen / 8)) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }
    memset(prefix->stream, 0, bitlen / 8);

    memcpy(prefix->stream, stream, bitlen / 8);
    prefix->bitlen = bitlen;

    return prefix;
}

/**
 * \brief Creates a new Prefix for an IPV4 address
 *
 * \param stream IPV4 address that has to be wrapped in a SCRadixPrefix instance
 *               to be processed for insertion/lookup by the radix tree
 *
 * \retval prefix The newly created prefix instance on success; NULL on failure
 */
SCRadixPrefix *SCRadixCreateIPV4Prefix(uint8_t *stream)
{
    return SCRadixCreatePrefix(stream, 32);
}

/**
 * \brief Creates a new Prefix for an IPV6 address
 *
 * \param stream IPV6 address that has to be wrapped in a SCRadixPrefix instance
 *               to be processed for insertion/lookup by the radix tree
 *
 * \retval prefix The newly created prefix instance on success; NULL on failure
 */
SCRadixPrefix *SCRadixCreateIPV6Prefix(uint8_t *stream)
{
    return SCRadixCreatePrefix(stream, 128);
}

/**
 * \brief Frees a SCRadixPrefix instance
 *
 * \param prefix Pointer to a prefix instance
 */
void SCRadixReleasePrefix(SCRadixPrefix *prefix)
{
    if (prefix != NULL) {
        if (prefix->stream != NULL)
            free(prefix->stream);
        free(prefix);
    }

    return;
}

/**
 * \brief Creates a new Radix tree
 *
 * \retval tree The newly created radix tree on success
 */
SCRadixTree *SCRadixCreateRadixTree()
{
    SCRadixTree *tree = NULL;

    if ( (tree = malloc(sizeof(SCRadixTree))) == NULL) {
        printf("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }
    memset(tree, 0, sizeof(SCRadixTree));

    return tree;
}

/**
 * \brief Internal helper function used by SCRadixReleaseRadixTree to free a subtree
 *
 * \param node Pointer to the root of the subtree that has to be freed
 */
static void SCRadixReleaseRadixSubtree(SCRadixNode *node)
{
    if (node != NULL) {
        SCRadixReleaseRadixSubtree(node->left);
        SCRadixReleaseRadixSubtree(node->right);
        SCRadixReleaseNode(node);
    }

    return;
}

/**
 * \brief Frees a Radix tree and all its nodes
 *
 * \param tree Pointer to the Radix tree that has to be freed
 */
void SCRadixReleaseRadixTree(SCRadixTree *tree)
{
    SCRadixReleaseRadixSubtree(tree->head);

    tree->head = NULL;

    return;
}

/**
 * \brief Adds a prefix to the Radix tree
 *
 * \param tree   Pointer to the Radix tree
 * \param prefix The prefix that has to be added to the Radix tree
 *
 * \retval node Pointer to the newly created node
 */
SCRadixNode *SCRadixAddKey(SCRadixPrefix *prefix, SCRadixTree *tree)
{
    SCRadixNode *node = NULL;
    SCRadixNode *new_node = NULL;
    SCRadixNode *parent = NULL;
    SCRadixNode *inter_node = NULL;
    SCRadixNode *bottom_node = NULL;

    uint8_t *stream = NULL;
    uint8_t bitlen = 0;

    int check_bit = 0;
    int differ_bit = 0;

    int i = 0;
    int j = 0;
    int temp = 0;

    if (tree->head == NULL) {
        node = SCRadixCreateNode();
        node->prefix = prefix;
        node->bit = prefix->bitlen;
        tree->head = node;
        return node;
    }

    node = tree->head;
    stream = prefix->stream;
    bitlen = prefix->bitlen;

    /* we walk down the tree only when we satisfy 2 conditions.  The first one
     * being the incoming prefix is shorter than the differ bit of the current
     * node.  In case we fail in this aspect, we walk down to the tree, till we
     * arrive at a node that ends in a prefix */
    while (node->bit < bitlen || node->prefix == NULL) {
        /* if the bitlen isn't long enough to handle the bit test, we just walk
         * down along one of the paths, since either paths should end up with a
         * node that has a common prefix whose differ bit is greater than the
         * bitlen of the incoming prefix */
        if (bitlen < node->bit) {
            if (node->right == NULL)
                break;

            node = node->right;
        } else {
            if (SC_RADIX_BITTEST(stream[node->bit >> 3],
                                 (0x80 >> (node->bit % 8))) ) {
                if (node->right == NULL)
                    break;

                node = node->right;
            } else {
                if (node->left == NULL)
                    break;

                node = node->left;
            }
        }
    }

    /* we need to keep a reference to the bottom-most node, that actually holds
     * the prefix */
    bottom_node = node;

    check_bit = (node->bit < bitlen)? node->bit: bitlen;
    for (i = 0; (i * 8) < check_bit; i++) {
        if ((temp = (stream[i] ^ bottom_node->prefix->stream[i])) == 0) {
            differ_bit = (i + 1) * 8;
            continue;
        }

        /* find out the position where the first bit differs.  This method is
         * larger and faster, but with larger caches these days we don't have
         * to worry about cache misses */
        temp = temp * 2;
        if (temp >= 256)
            j = 0;
        else if (temp >= 128)
            j = 1;
        else if (temp >= 64)
            j = 2;
        else if (temp >= 32)
            j = 3;
        else if (temp >= 16)
            j = 4;
        else if (temp >= 8)
            j = 5;
        else if (temp >= 4)
            j = 6;
        else if (temp >= 2)
            j = 7;

        differ_bit = i * 8 + j;
        break;
    }
    if (check_bit < differ_bit)
        differ_bit = check_bit;

    /* walk up the tree till we find the position, to fit our new node in */
    parent = node->parent;
    while (parent && differ_bit <= parent->bit) {
        node = parent;
        parent = node->parent;
    }

    /* We already have the node in the tree with the same differing bit pstn */
    if (differ_bit == bitlen && node->bit == bitlen) {
        if (node->prefix)
            return node;

        node->prefix = SCRadixCreatePrefix(prefix->stream, prefix->bitlen);
        return node;
    }

    new_node = SCRadixCreateNode();
    new_node->prefix = prefix;
    new_node->bit = prefix->bitlen;

    /* indicates that we have got a key that has length that is already covered
     * by a prefix of some other key in the tree.  We create a new intermediate
     * node with a single child and stick it in */
    if (differ_bit == bitlen) {
        if (SC_RADIX_BITTEST(bottom_node->prefix->stream[differ_bit >> 3],
                             (0x80 >> (differ_bit % 8))) ) {
            new_node->right = node;
        } else {
            new_node->left = node;
        }
        new_node->parent = node->parent;

        if (node->parent == NULL)
            tree->head = new_node;
        else if (node->parent->right == node)
            node->parent->right = new_node;
        else
            node->parent->left = new_node;

        node->parent = new_node;
    } else {
        inter_node = SCRadixCreateNode();
        inter_node->prefix = NULL;
        inter_node->bit = differ_bit;
        inter_node->parent = node->parent;

        if (SC_RADIX_BITTEST(stream[differ_bit >> 3],
                             (0x80 >> (differ_bit % 8))) ) {
            inter_node->left = node;
            inter_node->right = new_node;
        } else {
            inter_node->left = new_node;
            inter_node->right = node;
        }
        new_node->parent = inter_node;

        if (node->parent == NULL)
            tree->head = inter_node;
        else if (node->parent->right == node)
            node->parent->right = inter_node;
        else
            node->parent->left = inter_node;

        node->parent = inter_node;
    }

    return new_node;
}

/**
 * \brief Removes a key from the Radix tree
 *
 * \param prefix Pointer to the key instance that has to be removed
 * \param tree   Pointer to the Radix tree from which the key has to be removed
 */
void SCRadixRemoveKey(SCRadixPrefix *prefix, SCRadixTree *tree)
{
    SCRadixNode *node = tree->head;
    SCRadixNode *parent = NULL;
    SCRadixNode *temp = NULL;
    int mask = 0;
    int i = 0;

    if (node == NULL)
        return;

    while (node->bit < prefix->bitlen) {
        if (SC_RADIX_BITTEST(prefix->stream[node->bit >> 3],
                             (0x80 >> (node->bit % 8))) ) {
            node = node->right;
        } else {
            node = node->left;
        }

        if (node == NULL)
            return;
    }

    if (node->bit != prefix->bitlen || node->prefix == NULL)
        return;

    i = prefix->bitlen / 8;
    if (memcmp(node->prefix->stream, prefix->stream, i) == 0) {
        mask = -1 << (8 - prefix->bitlen % 8);

        if (prefix->bitlen % 8 == 0 ||
            (node->prefix->stream[i] & mask) == (prefix->stream[i] & mask))
            ;
        else
            return;
    }

    if (tree->head == node) {
        free(node);
        tree->head = NULL;
        return;
    }

    parent = node->parent;
    if (parent->parent != NULL) {
        if (parent->parent->left == parent) {
            if (node->parent->left == node) {
                parent->parent->left = parent->right;
                parent->right->parent = parent->parent;
            } else {
                parent->parent->left = parent->left;
                parent->left->parent = parent->parent;
            }
        } else {
            if (node->parent->left == node) {
                parent->parent->right = parent->right;
                parent->right->parent = parent->parent;
            } else {
                parent->parent->right = parent->left;
                parent->left->parent = parent->parent;
            }
        }
        SCRadixReleaseNode(parent);
        SCRadixReleaseNode(node);
    } else {
        temp = tree->head;
        if (parent->left == node) {
            tree->head->right->parent = NULL;
            tree->head = tree->head->right;
        } else {
            tree->head->left->parent = NULL;
            tree->head = tree->head->left;
        }
        SCRadixReleaseNode(temp);
        SCRadixReleaseNode(node);
    }
    return;
}

/**
 * \brief Checks if a key is present in the tree
 *
 * \param prefix Pointer to a SCRadixPrefix instance that holds the key to be
 *               checked
 * \param tree   Pointer to the Radix tree instance
 */
SCRadixNode *SCRadixFindKey(SCRadixPrefix *prefix, SCRadixTree *tree)
{
    SCRadixNode *node = tree->head;
    int mask = 0;
    int i = 0;

    if (tree->head == NULL)
        return NULL;

    while (node->bit < prefix->bitlen) {
        if (SC_RADIX_BITTEST(prefix->stream[node->bit >> 3],
                             (0x80 >> (node->bit % 8))) ) {
            node = node->right;
        } else {
            node = node->left;
        }

        if (node == NULL)
            return NULL;
    }

    if (node->bit != prefix->bitlen || node->prefix == NULL)
        return NULL;

    i = prefix->bitlen / 8;
    if (memcmp(node->prefix->stream, prefix->stream, i) == 0) {
        mask = -1 << (8 - prefix->bitlen % 8);

        if (prefix->bitlen % 8 == 0 ||
            (node->prefix->stream[i] & mask) == (prefix->stream[i] & mask))
            return node;
    }

    return NULL;
}

/**
 * \brief Prints the node information from a Radix tree
 *
 * \param node  Pointer to the Radix node whose information has to be printed
 * \param level Used for indentation purposes
 */
static void SCRadixPrintNodeInfo(SCRadixNode *node, int level)
{
    int i = 0;

    if (node == NULL)
        return;

    for (i = 0; i < level; i++)
        printf("  ");

    printf("%d (", node->bit);
    if (node->prefix != NULL) {
        for (i = 0; i * 8 < node->prefix->bitlen; i++) {
            if (i != 0)
                printf(".");
            printf("%d", node->prefix->stream[i]);
        }
        printf(")\n");
    } else {
        printf("NULL)\n");
    }

    return;
}

/**
 * \brief Helper function used by SCRadixPrintTree.  Prints the subtree with
 *        node as the root of the subtree
 *
 * \param node  Pointer to the node that is the root of the subtree to be printed
 * \param level Used for indentation purposes
 */
static void SCRadixPrintRadixSubtree(SCRadixNode *node, int level)
{
    if (node != NULL) {
        SCRadixPrintNodeInfo(node, level);
        SCRadixPrintRadixSubtree(node->left, level + 1);
        SCRadixPrintRadixSubtree(node->right, level + 1);
    }

    return;
}

/**
 * \brief Prints the Radix Tree. While printing the radix tree we use the
 *        following format
 *
 *        Parent_0
 *            Left_Child_1
 *                Left_Child_2
 *                Right_Child_2
 *            Right_Child_1
 *                Left_Child_2
 *                Right_Child_2     and so on
 *
 *        Each node printed out holds details on the next bit that differs
 *        amongst its children, and if the node holds a prefix, the perfix is
 *        printed as well.
 *
 * \param tree Pointer to the Radix tree that has to be printed
 */
void SCRadixPrintTree(SCRadixTree *tree)
{
    printf("Printing the Radix Tree: \n");

    SCRadixPrintRadixSubtree(tree->head, 0);

    return;
}

/*------------------------------------Unit_Tests------------------------------*/

#ifdef UNITTESTS

int SCRadixTestInsertion01(void)
{
    SCRadixTree *tree = NULL;
    SCRadixPrefix *prefix = NULL;
    SCRadixNode *node[2];

    int result = 1;

    tree = SCRadixCreateRadixTree();
    prefix = SCRadixCreatePrefix((uint8_t *)"abaa", 32);
    node[0] = SCRadixAddKey(prefix, tree);
    prefix = SCRadixCreatePrefix((uint8_t *)"abab", 32);
    node[1] = SCRadixAddKey(prefix, tree);

    result &= (tree->head->bit == 30);
    result &= (tree->head->right == node[0]);
    result &= (tree->head->left == node[1]);

    SCRadixReleaseRadixTree(tree);

    return 1;
}

int SCRadixTestInsertion02(void)
{
    SCRadixTree *tree = NULL;
    SCRadixPrefix *prefix = NULL;

    int result = 1;

    tree = SCRadixCreateRadixTree();
    prefix = SCRadixCreatePrefix((uint8_t *)"aaaaaa", 48);
    SCRadixAddKey(prefix, tree);
    prefix = SCRadixCreatePrefix((uint8_t *)"aaaaab", 48);
    SCRadixAddKey(prefix, tree);
    prefix = SCRadixCreatePrefix((uint8_t *)"aaaaaba", 56);
    SCRadixAddKey(prefix, tree);
    prefix = SCRadixCreatePrefix((uint8_t *)"abab", 32);
    SCRadixAddKey(prefix, tree);

    SCRadixReleaseRadixTree(tree);

    /* If we don't have a segfault till here we have succeeded */
    return result;
}

int SCRadixTestIPV4Insertion03(void)
{
    SCRadixTree *tree = NULL;
    SCRadixPrefix *prefix[10];
    SCRadixPrefix *temp_prefix = NULL;

    struct sockaddr_in servaddr;

    int result = 1;

    /* add the keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.1", &servaddr.sin_addr) <= 0)
        return 0;
    tree = SCRadixCreateRadixTree();
    prefix[0] = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    SCRadixAddKey(prefix[0], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    prefix[1] = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    SCRadixAddKey(prefix[1], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.3", &servaddr.sin_addr) <= 0)
        return 0;
    prefix[2] = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    SCRadixAddKey(prefix[2], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.4", &servaddr.sin_addr) <= 0)
        return 0;
    prefix[3] = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    SCRadixAddKey(prefix[3], tree);

    /* Try to add the prefix that already exists in the tree */
    SCRadixAddKey(prefix[2], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "220.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    prefix[4] = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    SCRadixAddKey(prefix[4], tree);

    if (inet_pton(AF_INET, "192.168.1.5", &servaddr.sin_addr) <= 0)
        return 0;
    prefix[5] = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    SCRadixAddKey(prefix[5], tree);

    if (inet_pton(AF_INET, "192.168.1.18", &servaddr.sin_addr) <= 0)
        return 0;
    prefix[6] = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    SCRadixAddKey(prefix[6], tree);

    /* test the existence of keys */
    result &= (SCRadixFindKey(prefix[0], tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.3", &servaddr.sin_addr) <= 0)
        return 0;
    temp_prefix = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    result &= (SCRadixFindKey(temp_prefix, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "127.234.2.62", &servaddr.sin_addr) <= 0)
        return 0;
    temp_prefix = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    result &= (SCRadixFindKey(temp_prefix, tree) == NULL);

    result &= (SCRadixFindKey(prefix[2], tree) != NULL);
    result &= (SCRadixFindKey(prefix[3], tree) != NULL);
    result &= (SCRadixFindKey(prefix[4], tree) != NULL);
    result &= (SCRadixFindKey(prefix[5], tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.6", &servaddr.sin_addr) <= 0)
        return 0;
    temp_prefix = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    result &= (SCRadixFindKey(temp_prefix, tree) == NULL);

    SCRadixReleaseRadixTree(tree);

    return result;
}

int SCRadixTestIPV4Removal04(void)
{
    SCRadixTree *tree = NULL;
    SCRadixPrefix *prefix[10];

    struct sockaddr_in servaddr;

    int result = 1;

    /* add the keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.1", &servaddr.sin_addr) <= 0)
        return 0;
    tree = SCRadixCreateRadixTree();
    prefix[0] = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    SCRadixAddKey(prefix[0], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    prefix[1] = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    SCRadixAddKey(prefix[1], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.3", &servaddr.sin_addr) <= 0)
        return 0;
    prefix[2] = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    SCRadixAddKey(prefix[2], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.4", &servaddr.sin_addr) <= 0)
        return 0;
    prefix[3] = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    SCRadixAddKey(prefix[3], tree);

    /* Try to add the prefix that already exists in the tree */
    SCRadixAddKey(prefix[2], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "220.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    prefix[4] = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    SCRadixAddKey(prefix[4], tree);

    if (inet_pton(AF_INET, "192.168.1.5", &servaddr.sin_addr) <= 0)
        return 0;
    prefix[5] = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    SCRadixAddKey(prefix[5], tree);

    if (inet_pton(AF_INET, "192.168.1.18", &servaddr.sin_addr) <= 0)
        return 0;
    prefix[6] = SCRadixCreateIPV4Prefix((uint8_t *)&servaddr.sin_addr);
    SCRadixAddKey(prefix[6], tree);

    /* test the existence of keys */
    SCRadixRemoveKey(prefix[0], tree);
    SCRadixRemoveKey(prefix[2], tree);
    SCRadixRemoveKey(prefix[5], tree);
    SCRadixRemoveKey(prefix[3], tree);

    result &= (SCRadixFindKey(prefix[3], tree) == NULL);
    result &= (SCRadixFindKey(prefix[6], tree) != NULL);

    SCRadixRemoveKey(prefix[1], tree);
    SCRadixRemoveKey(prefix[4], tree);
    SCRadixRemoveKey(prefix[6], tree);

    result &= (SCRadixFindKey(prefix[5], tree) == NULL);
    result &= (tree->head == NULL);

    SCRadixReleaseRadixTree(tree);

    return result;
}

int SCRadixTestCharacterInsertion05(void)
{
    SCRadixTree *tree = NULL;
    SCRadixPrefix *prefix[10];
    SCRadixPrefix *temp_prefix = NULL;

    int result = 1;

    tree = SCRadixCreateRadixTree();

    /* Let us have our team here ;-) */
    prefix[0] = SCRadixCreatePrefix((uint8_t *)"Victor", 48);
    SCRadixAddKey(prefix[0], tree);

    prefix[1] = SCRadixCreatePrefix((uint8_t *)"Matt", 32);
    SCRadixAddKey(prefix[1], tree);

    prefix[2] = SCRadixCreatePrefix((uint8_t *)"Josh", 56);
    SCRadixAddKey(prefix[2], tree);

    prefix[3] = SCRadixCreatePrefix((uint8_t *)"Margaret", 64);
    SCRadixAddKey(prefix[3], tree);

    prefix[4] = SCRadixCreatePrefix((uint8_t *)"Pablo", 40);
    SCRadixAddKey(prefix[4], tree);

    prefix[5] = SCRadixCreatePrefix((uint8_t *)"Brian", 40);
    SCRadixAddKey(prefix[5], tree);

    prefix[6] = SCRadixCreatePrefix((uint8_t *)"Jasonish", 64);
    SCRadixAddKey(prefix[6], tree);

    prefix[7] = SCRadixCreatePrefix((uint8_t *)"Jasonmc", 56);
    SCRadixAddKey(prefix[7], tree);

    prefix[8] = SCRadixCreatePrefix((uint8_t *)"Nathan", 48);
    SCRadixAddKey(prefix[8], tree);

    prefix[9] = SCRadixCreatePrefix((uint8_t *)"Anoop", 40);
    SCRadixAddKey(prefix[9], tree);

    result &= (SCRadixFindKey(prefix[0], tree) != NULL);
    result &= (SCRadixFindKey(prefix[1], tree) != NULL);
    result &= (SCRadixFindKey(prefix[2], tree) != NULL);
    result &= (SCRadixFindKey(prefix[3], tree) != NULL);
    result &= (SCRadixFindKey(prefix[4], tree) != NULL);
    result &= (SCRadixFindKey(prefix[5], tree) != NULL);
    result &= (SCRadixFindKey(prefix[6], tree) != NULL);
    result &= (SCRadixFindKey(prefix[7], tree) != NULL);
    result &= (SCRadixFindKey(prefix[8], tree) != NULL);
    result &= (SCRadixFindKey(prefix[9], tree) != NULL);

    temp_prefix = SCRadixCreatePrefix((uint8_t *)"bamboo", 48);
    result &= (SCRadixFindKey(temp_prefix, tree) == NULL);

    temp_prefix = SCRadixCreatePrefix((uint8_t *)"bool", 32);
    result &= (SCRadixFindKey(temp_prefix, tree) == NULL);

    temp_prefix = SCRadixCreatePrefix((uint8_t *)"meerkat", 56);
    result &= (SCRadixFindKey(temp_prefix, tree) == NULL);

    temp_prefix = SCRadixCreatePrefix((uint8_t *)"Victor", 48);
    result &= (SCRadixFindKey(temp_prefix, tree) == NULL);


    SCRadixReleaseRadixTree(tree);

    return 1;
}

int SCRadixTestCharacterRemoval06(void)
{
    SCRadixTree *tree = NULL;
    SCRadixPrefix *prefix[10];

    int result = 1;

    tree = SCRadixCreateRadixTree();

    /* Let us have our team here ;-) */
    prefix[0] = SCRadixCreatePrefix((uint8_t *)"Victor", 48);
    SCRadixAddKey(prefix[0], tree);

    prefix[1] = SCRadixCreatePrefix((uint8_t *)"Matt", 32);
    SCRadixAddKey(prefix[1], tree);

    prefix[2] = SCRadixCreatePrefix((uint8_t *)"Josh", 56);
    SCRadixAddKey(prefix[2], tree);

    prefix[3] = SCRadixCreatePrefix((uint8_t *)"Margaret", 64);
    SCRadixAddKey(prefix[3], tree);

    prefix[4] = SCRadixCreatePrefix((uint8_t *)"Pablo", 40);
    SCRadixAddKey(prefix[4], tree);

    prefix[5] = SCRadixCreatePrefix((uint8_t *)"Brian", 40);
    SCRadixAddKey(prefix[5], tree);

    prefix[6] = SCRadixCreatePrefix((uint8_t *)"Jasonish", 64);
    SCRadixAddKey(prefix[6], tree);

    prefix[7] = SCRadixCreatePrefix((uint8_t *)"Jasonmc", 56);
    SCRadixAddKey(prefix[7], tree);

    prefix[8] = SCRadixCreatePrefix((uint8_t *)"Nathan", 48);
    SCRadixAddKey(prefix[8], tree);

    prefix[9] = SCRadixCreatePrefix((uint8_t *)"Anoop", 40);
    SCRadixAddKey(prefix[9], tree);

    SCRadixRemoveKey(prefix[8], tree);
    SCRadixRemoveKey(prefix[5], tree);
    SCRadixRemoveKey(prefix[3], tree);

    result &= (SCRadixFindKey(prefix[0], tree) != NULL);
    result &= (SCRadixFindKey(prefix[1], tree) != NULL);
    result &= (SCRadixFindKey(prefix[2], tree) != NULL);
    result &= (SCRadixFindKey(prefix[3], tree) == NULL);
    result &= (SCRadixFindKey(prefix[5], tree) == NULL);
    result &= (SCRadixFindKey(prefix[8], tree) == NULL);

    SCRadixRemoveKey(prefix[0], tree);
    SCRadixRemoveKey(prefix[2], tree);
    SCRadixRemoveKey(prefix[7], tree);
    SCRadixRemoveKey(prefix[1], tree);

    result &= (SCRadixFindKey(prefix[4], tree) != NULL);
    result &= (SCRadixFindKey(prefix[6], tree) != NULL);
    result &= (SCRadixFindKey(prefix[9], tree) != NULL);

    SCRadixRemoveKey(prefix[4], tree);
    SCRadixRemoveKey(prefix[6], tree);
    SCRadixRemoveKey(prefix[9], tree);

    result &= (SCRadixFindKey(prefix[4], tree) == NULL);
    result &= (SCRadixFindKey(prefix[6], tree) == NULL);
    result &= (SCRadixFindKey(prefix[9], tree) == NULL);

    result &= (tree->head == NULL);

    SCRadixReleaseRadixTree(tree);

    return 1;
}

int SCRadixTestIPV6Insertion07(void)
{
    SCRadixTree *tree = NULL;
    SCRadixPrefix *prefix[10];
    SCRadixPrefix *temp_prefix = NULL;

    struct sockaddr_in6 servaddr;

    int result = 1;

    /* add the keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    tree = SCRadixCreateRadixTree();
    prefix[0] = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    SCRadixAddKey(prefix[0], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "BD15:9791:5346:6223:AADB:8713:9882:2432",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    prefix[1] = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    SCRadixAddKey(prefix[1], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "1111:A21B:6221:BDEA:BBBA::DBAA:9861",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    prefix[2] = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    SCRadixAddKey(prefix[2], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "4444:0BF7:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    prefix[3] = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    SCRadixAddKey(prefix[3], tree);

    /* Try to add the prefix that already exists in the tree */
    SCRadixAddKey(prefix[2], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "5555:0BF1:ABCD:ADEA:7922:ABCD:9124:2375",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    prefix[4] = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    SCRadixAddKey(prefix[4], tree);

    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBCA:1245:2342:1111:2212",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    prefix[5] = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    SCRadixAddKey(prefix[5], tree);

    if (inet_pton(AF_INET6, "2003:0BF1:5346:1251:7422:1112:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    prefix[6] = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    SCRadixAddKey(prefix[6], tree);

    /* test the existence of keys */
    result &= (SCRadixFindKey(prefix[0], tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "8888:0BF1:5346:BDEA:6422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    temp_prefix = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    result &= (SCRadixFindKey(temp_prefix, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2006:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    temp_prefix = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    result &= (SCRadixFindKey(temp_prefix, tree) == NULL);

    result &= (SCRadixFindKey(prefix[0], tree) != NULL);
    result &= (SCRadixFindKey(prefix[1], tree) != NULL);
    result &= (SCRadixFindKey(prefix[2], tree) != NULL);
    result &= (SCRadixFindKey(prefix[3], tree) != NULL);
    result &= (SCRadixFindKey(prefix[4], tree) != NULL);
    result &= (SCRadixFindKey(prefix[5], tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:DDDD:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    temp_prefix = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    result &= (SCRadixFindKey(temp_prefix, tree) == NULL);

    SCRadixReleaseRadixTree(tree);

    return result;
}

int SCRadixTestIPV6Removal08(void)
{
    SCRadixTree *tree = NULL;
    SCRadixPrefix *prefix[10];
    SCRadixPrefix *temp_prefix = NULL;

    struct sockaddr_in6 servaddr;

    int result = 1;

    /* add the keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    tree = SCRadixCreateRadixTree();
    prefix[0] = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    SCRadixAddKey(prefix[0], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "BD15:9791:5346:6223:AADB:8713:9882:2432",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    prefix[1] = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    SCRadixAddKey(prefix[1], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "1111:A21B:6221:BDEA:BBBA::DBAA:9861",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    prefix[2] = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    SCRadixAddKey(prefix[2], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "4444:0BF7:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    prefix[3] = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    SCRadixAddKey(prefix[3], tree);

    /* Try to add the prefix that already exists in the tree */
    SCRadixAddKey(prefix[2], tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "5555:0BF1:ABCD:ADEA:7922:ABCD:9124:2375",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    prefix[4] = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    SCRadixAddKey(prefix[4], tree);

    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBCA:1245:2342:1111:2212",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    prefix[5] = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    SCRadixAddKey(prefix[5], tree);

    if (inet_pton(AF_INET6, "2003:0BF1:5346:1251:7422:1112:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    prefix[6] = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    SCRadixAddKey(prefix[6], tree);

    /* test the existence of keys */
    result &= (SCRadixFindKey(prefix[0], tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "8888:0BF1:5346:BDEA:6422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    temp_prefix = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    result &= (SCRadixFindKey(temp_prefix, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2006:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    temp_prefix = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    result &= (SCRadixFindKey(temp_prefix, tree) == NULL);

    result &= (SCRadixFindKey(prefix[0], tree) != NULL);
    result &= (SCRadixFindKey(prefix[1], tree) != NULL);
    result &= (SCRadixFindKey(prefix[2], tree) != NULL);
    result &= (SCRadixFindKey(prefix[3], tree) != NULL);
    result &= (SCRadixFindKey(prefix[4], tree) != NULL);
    result &= (SCRadixFindKey(prefix[5], tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:DDDD:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    temp_prefix = SCRadixCreateIPV6Prefix((uint8_t *)&servaddr.sin6_addr);
    result &= (SCRadixFindKey(temp_prefix, tree) == NULL);

    SCRadixRemoveKey(prefix[0], tree);
    SCRadixRemoveKey(prefix[1], tree);

    result &= (SCRadixFindKey(prefix[0], tree) == NULL);
    result &= (SCRadixFindKey(prefix[1], tree) == NULL);
    result &= (SCRadixFindKey(prefix[2], tree) != NULL);
    result &= (SCRadixFindKey(prefix[3], tree) != NULL);
    result &= (SCRadixFindKey(prefix[4], tree) != NULL);
    result &= (SCRadixFindKey(prefix[5], tree) != NULL);

    SCRadixRemoveKey(prefix[2], tree);
    SCRadixRemoveKey(prefix[3], tree);
    SCRadixRemoveKey(prefix[4], tree);
    SCRadixRemoveKey(prefix[5], tree);

    result &= (SCRadixFindKey(prefix[0], tree) == NULL);
    result &= (SCRadixFindKey(prefix[1], tree) == NULL);
    result &= (SCRadixFindKey(prefix[2], tree) == NULL);
    result &= (SCRadixFindKey(prefix[3], tree) == NULL);
    result &= (SCRadixFindKey(prefix[4], tree) == NULL);
    result &= (SCRadixFindKey(prefix[5], tree) == NULL);

    SCRadixReleaseRadixTree(tree);

    return result;
}


#endif

void SCRadixRegisterTests(void)
{

#ifdef UNITTESTS

    UtRegisterTest("SCRadixTestInsertion01", SCRadixTestInsertion01, 1);
    UtRegisterTest("SCRadixTestInsertion02", SCRadixTestInsertion02, 1);
    UtRegisterTest("SCRadixTestIPV4Insertion03", SCRadixTestIPV4Insertion03, 1);
    UtRegisterTest("SCRadixTestIPV4Removal04", SCRadixTestIPV4Removal04, 1);
    UtRegisterTest("SCRadixTestCharacterInsertion05",
                   SCRadixTestCharacterInsertion05, 1);
    UtRegisterTest("SCRadixTestCharacterRemoval06",
                   SCRadixTestCharacterRemoval06, 1);
    UtRegisterTest("SCRadixTestIPV6Insertion07", SCRadixTestIPV6Insertion07, 1);
    UtRegisterTest("SCRadixTestIPV6Removal08", SCRadixTestIPV6Removal08, 1);

#endif

    return;
}
