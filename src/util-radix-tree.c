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

#ifdef OS_FREEBSD
#include <netinet/in.h>
#endif /* OS_FREEBSD */
#ifdef OS_DARWIN
#include <netinet/in.h>
#endif /* OS_FREEBSD */

#include "util-radix-tree.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-unittest.h"

/**
 * \brief Creates a new Prefix for a key.  Used internally by the API.
 *
 * \param key_stream Data that has to be wrapped in a SCRadixPrefix instance to
 *                   be processed for insertion/lookup/removal of a node by the
 *                   radix tree
 * \param key_bitlen The bitlen of the the above stream.  For example if the
 *                   stream holds the ipv4 address(4 bytes), bitlen would be 32
 * \param user       Pointer to the user data that has to be associated with
 *                   this key
 *
 * \retval prefix The newly created prefix instance on success; NULL on failure
 */
static SCRadixPrefix *SCRadixCreatePrefix(uint8_t *key_stream,
                                          uint16_t key_bitlen, void *user,
                                          uint8_t netmask)
{
    SCRadixPrefix *prefix = NULL;

    if ((key_bitlen % 8 != 0) || key_bitlen == 0) {
        SCLogError(SC_INVALID_ARGUMENT, "Invalid argument bitlen - %d",
                   key_bitlen);
        return NULL;
    }

    if (key_stream == NULL) {
        SCLogError(SC_INVALID_ARGUMENT, "Argument \"stream\" NULL");
        return NULL;
    }

    if ( (prefix = malloc(sizeof(SCRadixPrefix))) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(prefix, 0, sizeof(SCRadixPrefix));

    if ( (prefix->stream = malloc(key_bitlen / 8)) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(prefix->stream, 0, key_bitlen / 8);

    memcpy(prefix->stream, key_stream, key_bitlen / 8);
    prefix->bitlen = key_bitlen;
    prefix->user = user;
    prefix->netmask = netmask;

    return prefix;
}

/**
 * \brief Frees a SCRadixPrefix instance
 *
 * \param prefix Pointer to a prefix instance
 * \param tree   Pointer to the Radix tree to which this prefix belongs
 */
static void SCRadixReleasePrefix(SCRadixPrefix *prefix, SCRadixTree *tree)
{
    if (prefix != NULL) {
        if (tree->Free != NULL)
            tree->Free(prefix->user);
        if (prefix->stream != NULL)
            free(prefix->stream);
        free(prefix);
    }

    return;
}

/**
 * \brief Creates a new node for the Radix tree
 *
 * \retval node The newly created node for the radix tree
 */
static inline SCRadixNode *SCRadixCreateNode()
{
    SCRadixNode *node = NULL;

    if ( (node = malloc(sizeof(SCRadixNode))) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(node, 0, sizeof(SCRadixNode));

    return node;
}

/**
 * \brief Frees a Radix tree node
 *
 * \param node Pointer to a Radix tree node
 * \param tree Pointer to the Radix tree to which this node belongs
 */
static inline void SCRadixReleaseNode(SCRadixNode *node, SCRadixTree *tree)
{
    if (node != NULL) {
        SCRadixReleasePrefix(node->prefix, tree);
        free(node);
    }

    return;
}

/**
 * \brief Creates a new Radix tree
 *
 * \param Free Function pointer supplied by the user to be used by the Radix
 *             cleanup API to free the user suppplied data
 *
 * \retval tree The newly created radix tree on success
 */
SCRadixTree *SCRadixCreateRadixTree(void (*Free)(void*))
{
    SCRadixTree *tree = NULL;

    if ( (tree = malloc(sizeof(SCRadixTree))) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(tree, 0, sizeof(SCRadixTree));

    tree->Free = Free;

    return tree;
}

/**
 * \brief Internal helper function used by SCRadixReleaseRadixTree to free a
 *        subtree
 *
 * \param node Pointer to the root of the subtree that has to be freed
 * \param tree Pointer to the Radix tree to which this subtree belongs
 */
static void SCRadixReleaseRadixSubtree(SCRadixNode *node, SCRadixTree *tree)
{
    if (node != NULL) {
        SCRadixReleaseRadixSubtree(node->left, tree);
        SCRadixReleaseRadixSubtree(node->right, tree);
        SCRadixReleaseNode(node, tree);
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
    SCRadixReleaseRadixSubtree(tree->head, tree);

    tree->head = NULL;

    return;
}

/**
 * \brief Adds a key to the Radix tree.  Used internally by the API.
 *
 * \param key_stream Data that has to added to the Radix tree
 * \param key_bitlen The bitlen of the the above stream.  For example if the
 *                   stream is the string "abcd", the bitlen would be 32.  If
 *                   the stream is an IPV6 address bitlen would be 128
 * \param tree       Pointer to the Radix tree
 * \param user       Pointer to the user data that has to be associated with
 *                   this key
 * \param netmask    The netmask if we are adding an IP netblock; 255 if we are
 *                   not adding an IP netblock
 *
 * \retval node Pointer to the newly created node
 */
static SCRadixNode *SCRadixAddKey(uint8_t *key_stream, uint16_t key_bitlen,
                                  SCRadixTree *tree, void *user, uint8_t netmask)
{
    SCRadixNode *node = NULL;
    SCRadixNode *new_node = NULL;
    SCRadixNode *parent = NULL;
    SCRadixNode *inter_node = NULL;
    SCRadixNode *bottom_node = NULL;

    SCRadixPrefix *prefix = NULL;

    uint8_t *stream = NULL;
    uint8_t bitlen = 0;

    int check_bit = 0;
    int differ_bit = 0;

    int i = 0;
    int j = 0;
    int temp = 0;

    if ( (prefix = SCRadixCreatePrefix(key_stream, key_bitlen, user,
                                       netmask)) == NULL) {
        return NULL;
    }

    if (tree == NULL) {
        SCLogError(SC_INVALID_ARGUMENT, "Argument \"tree\" NULL");
        return NULL;
    }

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
         * faster, but at the cost of being larger.  But with larger caches
         * these days we don't have to worry about cache misses */
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

        node->prefix = SCRadixCreatePrefix(prefix->stream, prefix->bitlen, NULL,
                                           255);
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

        if (node->netmasks != NULL) {
            if ((node->netmasks[0] - 1) < differ_bit) {
                inter_node->netmask_cnt++;
                if ( (inter_node->netmasks = malloc(sizeof(int))) == NULL) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                    exit(EXIT_FAILURE);
                }
                inter_node->netmasks[0] = node->netmasks[0];
                free(node->netmasks);
                node->netmasks = NULL;
                node->netmask_cnt--;
            }
        }

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

    if (netmask != 255) {
        node = new_node;
        parent = new_node->parent;
        while (parent != NULL && netmask < (parent->bit + 1)) {
            node = parent;
            parent = parent->parent;
        }

        node->netmask_cnt++;
        if ( (node->netmasks = realloc(node->netmasks, (node->netmask_cnt *
                                                        sizeof(int)))) == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }

        if (node->netmask_cnt == 1) {
            node->netmasks[0] = netmask;
            return new_node;
        }

        node->netmasks[node->netmask_cnt - 1] = netmask;

        for (i = node->netmask_cnt - 2; i >= 0; i--) {
            if (netmask < node->netmasks[i]) {
                node->netmasks[i + 1] = netmask;
                break;
            }

            node->netmasks[i + 1] = node->netmasks[i];
            node->netmasks[i] = netmask;
        }
    }

    return new_node;
}

/**
 * \brief Adds a new generic key to the Radix tree
 *
 * \param key_stream Data that has to be added to the Radix tree
 * \param key_bitlen The bitlen of the the above stream.  For example if the
 *                   stream is the string "abcd", the bitlen would be 32
 * \param tree       Pointer to the Radix tree
 * \param user       Pointer to the user data that has to be associated with the
 *                   key
 *
 * \retval node Pointer to the newly created node
 */
SCRadixNode *SCRadixAddKeyGeneric(uint8_t *key_stream, uint16_t key_bitlen,
                                  SCRadixTree *tree, void *user)
{
    SCRadixNode *node = SCRadixAddKey(key_stream, key_bitlen, tree, user, 255);

    return node;
}

/**
 * \brief Adds a new IPV4 address to the Radix tree
 *
 * \param key_stream Data that has to be added to the Radix tree.  In this case
 *                   a pointer to an IPV4 address
 * \param tree       Pointer to the Radix tree
 * \param user       Pointer to the user data that has to be associated with the
 *                   key
 *
 * \retval node Pointer to the newly created node
 */
SCRadixNode *SCRadixAddKeyIPV4(uint8_t *key_stream, SCRadixTree *tree,
                               void *user)
{
    SCRadixNode *node = SCRadixAddKey(key_stream, 32, tree, user, 255);

    return node;
}

/**
 * \brief Adds a new IPV6 address to the Radix tree
 *
 * \param key_stream Data that has to be added to the Radix tree.  In this case
 *                   the pointer to an IPV6 address
 * \param tree       Pointer to the Radix tree
 * \param user       Pointer to the user data that has to be associated with the
 *                   key
 *
 * \retval node Pointer to the newly created node
 */
SCRadixNode *SCRadixAddKeyIPV6(uint8_t *key_stream, SCRadixTree *tree,
                               void *user)
{
    SCRadixNode *node = SCRadixAddKey(key_stream, 128, tree, user, 255);

    return node;
}

/**
 * \brief Adds a new IPV4 netblock to the Radix tree
 *
 * \param key_stream Data that has to be added to the Radix tree.  In this case
 *                   a pointer to an IPV4 netblock
 * \param tree       Pointer to the Radix tree
 * \param user       Pointer to the user data that has to be associated with the
 *                   key
 * \param netmask    The netmask if we are adding a netblock
 *
 * \retval node Pointer to the newly created node
 */
SCRadixNode *SCRadixAddKeyIPV4Netblock(uint8_t *key_stream, SCRadixTree *tree,
                                       void *user, uint8_t netmask)
{
    SCRadixNode *node = SCRadixAddKey(key_stream, 32, tree, user, netmask);

    return node;
}

/**
 * \brief Adds a new IPV6 netblock to the Radix tree
 *
 * \param key_stream Data that has to be added to the Radix tree.  In this case
 *                   a pointer to an IPV6 netblock
 * \param tree       Pointer to the Radix tree
 * \param user       Pointer to the user data that has to be associated with the
 *                   key
 * \param netmask    The netmask if we are adding a netblock
 *
 * \retval node Pointer to the newly created node
 */
SCRadixNode *SCRadixAddKeyIPV6Netblock(uint8_t *key_stream, SCRadixTree *tree,
                                       void *user, uint8_t netmask)
{
    SCRadixNode *node = SCRadixAddKey(key_stream, 128, tree, user, netmask);

    return node;
}

/**
 * \brief Removes a key from the Radix tree
 *
 * \param key_stream Data that has to be removed from the Radix tree
 * \param key_bitlen The bitlen of the the above stream.  For example if the
 *                   stream holds an IPV4 address(4 bytes), bitlen would be 32
 * \param tree       Pointer to the Radix tree from which the key has to be
 *                   removed
 */
static void SCRadixRemoveKey(uint8_t *key_stream, uint16_t key_bitlen,
                             SCRadixTree *tree)
{
    SCRadixNode *node = tree->head;
    SCRadixNode *parent = NULL;
    SCRadixNode *temp = NULL;

    SCRadixPrefix *prefix = NULL;

    int mask = 0;
    int i = 0;

    if (node == NULL)
        return;

    if ( (prefix = SCRadixCreatePrefix(key_stream, key_bitlen, NULL, 255)) == NULL)
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
    } else {
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
        SCRadixReleaseNode(parent, tree);
        SCRadixReleaseNode(node, tree);
    } else {
        temp = tree->head;
        if (parent->left == node) {
            tree->head->right->parent = NULL;
            tree->head = tree->head->right;
        } else {
            tree->head->left->parent = NULL;
            tree->head = tree->head->left;
        }
        SCRadixReleaseNode(temp, tree);
        SCRadixReleaseNode(node, tree);
    }
    return;
}

/**
 * \brief Removes a key from the Radix tree
 *
 * \param key_stream Data that has to be removed from the Radix tree
 * \param key_bitlen The bitlen of the the above stream.
 * \param tree       Pointer to the Radix tree from which the key has to be
 *                   removed
 */
void SCRadixRemoveKeyGeneric(uint8_t *key_stream, uint16_t key_bitlen,
                             SCRadixTree *tree)
{
    return SCRadixRemoveKey(key_stream, key_bitlen, tree);
}

/**
 * \brief Removes an IPV4 address key from the Radix tree
 *
 * \param key_stream Data that has to be removed from the Radix tree.  In this
 *                   case an IPV4 address
 * \param tree       Pointer to the Radix tree from which the key has to be
 *                   removed
 */
void SCRadixRemoveKeyIPV4(uint8_t *key_stream, SCRadixTree *tree)
{
    return SCRadixRemoveKey(key_stream, 32, tree);
}

/**
 * \brief Removes an IPV6 address key from the Radix tree
 *
 * \param key_stream Data that has to be removed from the Radix tree.  In this
 *                   case an IPV6 address
 * \param tree       Pointer to the Radix tree from which the key has to be
 *                   removed
 */
void SCRadixRemoveKeyIPV6(uint8_t *key_stream, SCRadixTree *tree)
{
    return SCRadixRemoveKey(key_stream, 128, tree);
}

/**
 * \brief Checks if an IP prefix falls under a netblock, in the path to the root
 *        of the tree, from the node.  Used internally by SCRadixFindKey()
 *
 * \param prefix Pointer to the prefix that contains the ip address
 * \param node   Pointer to the node from where we have to climb the tree
 */
static inline SCRadixNode *SCRadixFindKeyIPNetblock(SCRadixPrefix *prefix,
                                                    SCRadixNode *node)
{
    SCRadixNode *netmask_node = NULL;
    int mask = 0;
    int bytes = 0;
    int i = 0;
    int j = 0;

    while (node != NULL && node->netmasks == NULL)
        node = node->parent;

    if (node == NULL)
        return NULL;

    /* hold the node found containing a netmask.  We will need it when we call
     * this function recursively */
    netmask_node = node;

    for (j = 0; j < node->netmask_cnt; j++) {
        bytes = prefix->bitlen / 8;
        for (i = 0; i < bytes; i++) {
            mask = -1;
            if ( ((i + 1) * 8) > node->netmasks[j]) {
                if ( ((i + 1) * 8 - node->netmasks[j]) < 8)
                    mask = -1 << ((i + 1) * 8 - node->netmasks[j]);
                else
                    mask = 0;
            }
            prefix->stream[i] &= mask;
        }

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

        if (memcmp(node->prefix->stream, prefix->stream, bytes) == 0) {
            mask = -1 << (8 - prefix->bitlen % 8);

            if (prefix->bitlen % 8 == 0 ||
                (node->prefix->stream[bytes] & mask) == (prefix->stream[bytes] & mask))
                return node;
        }
    }

    return SCRadixFindKeyIPNetblock(prefix, netmask_node->parent);
}

/**
 * \brief Checks if an IP address key is present in the tree.  The function
 *        apart from handling any normal data, also handles ipv4/ipv6 netblocks
 *
 * \param key_stream Data that has to be found in the Radix tree
 * \param key_bitlen The bitlen of the above stream.
 * \param tree       Pointer to the Radix tree
 * \param is_ip_key  The key to be searched is an ip address
 */
static SCRadixNode *SCRadixFindKey(uint8_t *key_stream, uint16_t key_bitlen,
                                   SCRadixTree *tree, int is_ip_key)
{
    SCRadixNode *node = tree->head;
    SCRadixPrefix *prefix = NULL;
    int mask = 0;
    int bytes = 0;

    if (tree->head == NULL)
        return NULL;

    if ( (prefix = SCRadixCreatePrefix(key_stream, key_bitlen, NULL, 255)) == NULL)
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

    bytes = prefix->bitlen / 8;
    if (memcmp(node->prefix->stream, prefix->stream, bytes) == 0) {
        mask = -1 << (8 - prefix->bitlen % 8);

        if (prefix->bitlen % 8 == 0 ||
            (node->prefix->stream[bytes] & mask) == (prefix->stream[bytes] & mask))
            return node;
    }

    /* if you are not an ip key, get out of here */
    if (is_ip_key == 0)
        return NULL;

    return SCRadixFindKeyIPNetblock(prefix, node);
}

/**
 * \brief Checks if a key is present in the tree
 *
 * \param key_stream Data that has to be found in the Radix tree
 * \param key_bitlen The bitlen of the the above stream.
 * \param tree       Pointer to the Radix tree instance
 */
SCRadixNode *SCRadixFindKeyGeneric(uint8_t *key_stream, uint16_t key_bitlen,
                                   SCRadixTree *tree)
{
    return SCRadixFindKey(key_stream, key_bitlen, tree, 0);
}

/**
 * \brief Checks if an IPV4 address is present in the tree
 *
 * \param key_stream Data that has to be found in the Radix tree.  In this case
 *                   an IPV4 address
 * \param tree       Pointer to the Radix tree instance
 */
SCRadixNode *SCRadixFindKeyIPV4(uint8_t *key_stream, SCRadixTree *tree)
{
    return SCRadixFindKey(key_stream, 32, tree, 1);
}

/**
 * \brief Checks if an IPV6 address is present in the tree
 *
 * \param key_stream Data that has to be found in the Radix tree.  In this case
 *                   an IPV6 address
 * \param tree       Pointer to the Radix tree instance
 */
SCRadixNode *SCRadixFindKeyIPV6(uint8_t *key_stream, SCRadixTree *tree)
{
    return SCRadixFindKey(key_stream, 128, tree, 1);
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
        printf("   ");

    printf("%d [", node->bit);

    if (node->netmasks == NULL)
        printf("%d, ", -1);

    for (i = 0; i < node->netmask_cnt; i++)
        printf("%d, ", node->netmasks[i]);

    printf("] (");
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
    SCRadixNode *node[2];

    int result = 1;

    tree = SCRadixCreateRadixTree(NULL);

    node[0] = SCRadixAddKeyGeneric((uint8_t *)"abaa", 32, tree, NULL);
    node[1] = SCRadixAddKeyGeneric((uint8_t *)"abab", 32, tree, NULL);

    result &= (tree->head->bit == 30);
    result &= (tree->head->right == node[0]);
    result &= (tree->head->left == node[1]);

    SCRadixReleaseRadixTree(tree);

    return 1;
}

int SCRadixTestInsertion02(void)
{
    SCRadixTree *tree = NULL;
    int result = 1;

    tree = SCRadixCreateRadixTree(NULL);

    SCRadixAddKeyGeneric((uint8_t *)"aaaaaa", 48, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"aaaaab", 48, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"aaaaaba", 56, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"abab", 32, tree, NULL);
    SCRadixReleaseRadixTree(tree);

    /* If we don't have a segfault till here we have succeeded :) */
    return result;
}

int SCRadixTestIPV4Insertion03(void)
{
    SCRadixTree *tree = NULL;
    struct sockaddr_in servaddr;
    int result = 1;

    tree = SCRadixCreateRadixTree(NULL);

    /* add the keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.1", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.3", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.4", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    /* add a key that already exists in the tree */
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    /* test for the existance of a key */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.6", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == NULL);

    /* test for the existance of a key */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.4", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    /* continue adding keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "220.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.5", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.18", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    /* test the existence of keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.3", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "127.234.2.62", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.1", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.5", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.3", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.4", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "220.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.18", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    SCRadixReleaseRadixTree(tree);

    return result;
}

int SCRadixTestIPV4Removal04(void)
{
    SCRadixTree *tree = NULL;
    struct sockaddr_in servaddr;
    int result = 1;

    tree = SCRadixCreateRadixTree(NULL);

    /* add the keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.1", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.3", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.4", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "220.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.5", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.18", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    /* remove the keys from the tree */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.1", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixRemoveKeyIPV4((uint8_t *)&servaddr.sin_addr, tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.3", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixRemoveKeyIPV4((uint8_t *)&servaddr.sin_addr, tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.4", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixRemoveKeyIPV4((uint8_t *)&servaddr.sin_addr, tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.18", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixRemoveKeyIPV4((uint8_t *)&servaddr.sin_addr, tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.1", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.3", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixRemoveKeyIPV4((uint8_t *)&servaddr.sin_addr, tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "220.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixRemoveKeyIPV4((uint8_t *)&servaddr.sin_addr, tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.5", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixRemoveKeyIPV4((uint8_t *)&servaddr.sin_addr, tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.5", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixRemoveKeyIPV4((uint8_t *)&servaddr.sin_addr, tree);

    result &= (tree->head == NULL);

    SCRadixReleaseRadixTree(tree);

    return result;
}

int SCRadixTestCharacterInsertion05(void)
{
    SCRadixTree *tree = NULL;
    int result = 1;

    tree = SCRadixCreateRadixTree(NULL);

    /* Let us have our team here ;-) */
    SCRadixAddKeyGeneric((uint8_t *)"Victor", 48, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Matt", 32, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Josh", 32, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Margaret", 64, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Pablo", 40, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Brian", 40, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Jasonish", 64, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Jasonmc", 56, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Nathan", 48, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Anoop", 40, tree, NULL);

    result &= (SCRadixFindKeyGeneric((uint8_t *)"Victor", 48, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Matt", 32, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Josh", 32, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Margaret", 64, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Pablo", 40, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Brian", 40, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Jasonish", 64, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Jasonmc", 56, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Nathan", 48, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Anoop", 40, tree) != NULL);

    result &= (SCRadixFindKeyGeneric((uint8_t *)"bamboo", 48, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"bool", 32, tree) == NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"meerkat", 56, tree) == NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Victor", 48, tree) == NULL);

    SCRadixReleaseRadixTree(tree);

    return 1;
}

int SCRadixTestCharacterRemoval06(void)
{
    SCRadixTree *tree = NULL;
    int result = 1;

    tree = SCRadixCreateRadixTree(NULL);

    /* Let us have our team here ;-) */
    SCRadixAddKeyGeneric((uint8_t *)"Victor", 48, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Matt", 32, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Josh", 32, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Margaret", 64, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Pablo", 40, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Brian", 40, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Jasonish", 64, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Jasonmc", 56, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Nathan", 48, tree, NULL);
    SCRadixAddKeyGeneric((uint8_t *)"Anoop", 40, tree, NULL);

    SCRadixRemoveKeyGeneric((uint8_t *)"Nathan", 48, tree);
    SCRadixRemoveKeyGeneric((uint8_t *)"Brian", 40, tree);
    SCRadixRemoveKeyGeneric((uint8_t *)"Margaret", 64, tree);

    result &= (SCRadixFindKeyGeneric((uint8_t *)"Victor", 48, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Matt", 32, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Josh", 32, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Margaret", 64, tree) == NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Brian", 40, tree) == NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Nathan", 48, tree) == NULL);

    SCRadixRemoveKeyGeneric((uint8_t *)"Victor", 48, tree);
    SCRadixRemoveKeyGeneric((uint8_t *)"Josh", 32, tree);
    SCRadixRemoveKeyGeneric((uint8_t *)"Jasonmc", 56, tree);
    SCRadixRemoveKeyGeneric((uint8_t *)"Matt", 32, tree);

    result &= (SCRadixFindKeyGeneric((uint8_t *)"Pablo", 40, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Jasonish", 64, tree) != NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Anoop", 40, tree) != NULL);

    SCRadixRemoveKeyGeneric((uint8_t *)"Pablo", 40, tree);
    SCRadixRemoveKeyGeneric((uint8_t *)"Jasonish", 64, tree);
    SCRadixRemoveKeyGeneric((uint8_t *)"Anoop", 40, tree);

    result &= (SCRadixFindKeyGeneric((uint8_t *)"Pablo", 40, tree) == NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Jasonish", 64, tree) == NULL);
    result &= (SCRadixFindKeyGeneric((uint8_t *)"Anoop", 40, tree) == NULL);

    result &= (tree->head == NULL);

    SCRadixReleaseRadixTree(tree);

    return 1;
}

int SCRadixTestIPV6Insertion07(void)
{
    SCRadixTree *tree = NULL;
    struct sockaddr_in6 servaddr;
    int result = 1;

    tree = SCRadixCreateRadixTree(NULL);

    /* add the keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "BD15:9791:5346:6223:AADB:8713:9882:2432",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "1111:A21B:6221:BDEA:BBBA::DBAA:9861",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "4444:0BF7:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    /* Try to add the prefix that already exists in the tree */
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "5555:0BF1:ABCD:ADEA:7922:ABCD:9124:2375",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBCA:1245:2342:1111:2212",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:1251:7422:1112:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    /* test the existence of keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "BD15:9791:5346:6223:AADB:8713:9882:2432",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "1111:A21B:6221:BDEA:BBBA::DBAA:9861",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "4444:0BF7:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABC2:ABCD:DBCA:1245:2342:1111:2212",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF5:5346:1251:7422:1112:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "5555:0BF1:ABCD:ADEA:7922:ABCD:9124:2375",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBCA:1245:2342:1111:2212",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:1251:7422:1112:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    SCRadixReleaseRadixTree(tree);

    return result;
}

int SCRadixTestIPV6Removal08(void)
{
    SCRadixTree *tree = NULL;
    struct sockaddr_in6 servaddr;
    int result = 1;

    tree = SCRadixCreateRadixTree(NULL);

    /* add the keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "BD15:9791:5346:6223:AADB:8713:9882:2432",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "1111:A21B:6221:BDEA:BBBA::DBAA:9861",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "4444:0BF7:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    /* Try to add the prefix that already exists in the tree */
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "5555:0BF1:ABCD:ADEA:7922:ABCD:9124:2375",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBCA:1245:2342:1111:2212",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:1251:7422:1112:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    /* test the existence of keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "8888:0BF1:5346:BDEA:6422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2006:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "BD15:9791:5346:6223:AADB:8713:9882:2432",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    /* test for existance */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "1111:A21B:6221:BDEA:BBBA::DBAA:9861",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "4444:0BF7:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "5555:0BF1:ABCD:ADEA:7922:ABCD:9124:2375",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBCA:1245:2342:1111:2212",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:1251:7422:1112:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:DDDD:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    /* remove keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixRemoveKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "BD15:9791:5346:6223:AADB:8713:9882:2432",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixRemoveKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree);

    /* test for existance */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "BD15:9791:5346:6223:AADB:8713:9882:2432",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "1111:A21B:6221:BDEA:BBBA::DBAA:9861",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "4444:0BF7:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "5555:0BF1:ABCD:ADEA:7922:ABCD:9124:2375",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBCA:1245:2342:1111:2212",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    /* remove keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "1111:A21B:6221:BDEA:BBBA::DBAA:9861",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixRemoveKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "4444:0BF7:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixRemoveKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "5555:0BF1:ABCD:ADEA:7922:ABCD:9124:2375",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixRemoveKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBCA:1245:2342:1111:2212",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixRemoveKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree);

    /* test for existance */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "BD15:9791:5346:6223:AADB:8713:9882:2432",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "1111:A21B:6221:BDEA:BBBA::DBAA:9861",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "4444:0BF7:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "5555:0BF1:ABCD:ADEA:7922:ABCD:9124:2375",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBCA:1245:2342:1111:2212",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    SCRadixReleaseRadixTree(tree);

    return result;
}

int SCRadixTestIPV4NetblockInsertion09(void)
{
    SCRadixTree *tree = NULL;
    struct sockaddr_in servaddr;
    int result = 1;

    tree = SCRadixCreateRadixTree(NULL);

    /* add the keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.1", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.3", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.4", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "220.168.1.2", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.5", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.18", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 24);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.192.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 18);

    if (inet_pton(AF_INET, "192.175.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    /* test for the existance of a key */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.1.6", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.170.1.6", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.145", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.64.6", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.191.6", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.224.6", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.174.224.6", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.175.224.6", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    SCRadixReleaseRadixTree(tree);

    return result;
}

int SCRadixTestIPV4NetblockInsertion10(void)
{
    SCRadixTree *tree = NULL;
    SCRadixNode *node[2];
    struct sockaddr_in servaddr;
    int result = 1;

    tree = SCRadixCreateRadixTree(NULL);

    /* add the keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "253.192.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "253.192.235.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 24);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.4", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "220.168.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "253.224.1.5", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.0", &servaddr.sin_addr) <= 0)
        return 0;
    node[0] = SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL,
                                        24);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.45", &servaddr.sin_addr) <= 0)
        return 0;
    node[1] = SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 18);

    if (inet_pton(AF_INET, "192.175.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    /* test for the existance of a key */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.53", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == node[0]);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.45", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == node[1]);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.78", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == node[0]);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.127.78", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == NULL);

    SCRadixReleaseRadixTree(tree);

    return result;
}

int SCRadixTestIPV4NetblockInsertion11(void)
{
    SCRadixTree *tree = NULL;
    SCRadixNode *node = NULL;
    struct sockaddr_in servaddr;
    int result = 1;

    tree = SCRadixCreateRadixTree(NULL);

    /* add the keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "253.192.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "253.192.235.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 24);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.4", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "220.168.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "253.224.1.5", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 24);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.45", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 18);

    if (inet_pton(AF_INET, "192.175.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    if (inet_pton(AF_INET, "0.0.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    node = SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 0);

    /* test for the existance of a key */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.53", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.45", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.78", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.127.78", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == node);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "1.1.1.1", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == node);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.255.254.25", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == node);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "169.255.254.25", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == node);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "0.0.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == node);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "253.224.1.5", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL &&
               SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != node);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "245.63.62.121", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL &&
               SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == node);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "253.224.1.6", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL &&
               SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == node);

    SCRadixReleaseRadixTree(tree);

    return result;
}

int SCRadixTestIPV4NetblockInsertion12(void)
{
    SCRadixTree *tree = NULL;
    SCRadixNode *node[2];
    struct sockaddr_in servaddr;
    int result = 1;

    tree = SCRadixCreateRadixTree(NULL);

    /* add the keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "253.192.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "253.192.235.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 24);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.167.1.4", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "220.168.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "253.224.1.5", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.168.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 16);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.0", &servaddr.sin_addr) <= 0)
        return 0;
    node[0] = SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 24);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.45", &servaddr.sin_addr) <= 0)
        return 0;
    node[1] = SCRadixAddKeyIPV4((uint8_t *)&servaddr.sin_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.0.0", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 18);

    if (inet_pton(AF_INET, "225.175.21.228", &servaddr.sin_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV4Netblock((uint8_t *)&servaddr.sin_addr, tree, NULL, 32);

    /* test for the existance of a key */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.53", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == node[0]);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.45", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == node[1]);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.128.78", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == node[0]);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "192.171.127.78", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "225.175.21.228", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "225.175.21.224", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "225.175.21.229", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET, "225.175.21.230", &servaddr.sin_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV4((uint8_t *)&servaddr.sin_addr, tree) == NULL);

    SCRadixReleaseRadixTree(tree);

    return result;
}

int SCRadixTestIPV6NetblockInsertion13(void)
{
    SCRadixTree *tree = NULL;
    struct sockaddr_in6 servaddr;
    int result = 1;

    tree = SCRadixCreateRadixTree(NULL);

    /* add the keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "BD15:9791:5346:6223:AADB:8713:9882:2432",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "1111:A21B:6221:BDEA:BBBA::DBAA:9861",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "4444:0BF7:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "5555:0BF1:ABCD:ADEA:7922:ABCD:9124:2375",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DB00:0000:0000:0000:0000",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6Netblock((uint8_t *)&servaddr.sin6_addr, tree, NULL, 56);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBAA:1245:2342:1145:6241",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    /* test the existence of keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "BD15:9791:5346:6223:AADB:8713:9882:2432",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "1111:A21B:6221:BDEA:BBBA::DBAA:9861",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "4444:0BF7:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABC2:ABCD:DBCA:1245:2342:1111:2212",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF5:5346:1251:7422:1112:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "5555:0BF1:ABCD:ADEA:7922:ABCD:9124:2375",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBCA:1245:2342:1111:2212",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBAA:1245:2342:1146:6241",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBAA:1245:2342:1356:1241",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DAAA:1245:2342:1146:6241",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == NULL);


    SCRadixReleaseRadixTree(tree);

    return result;
}

int SCRadixTestIPV6NetblockInsertion14(void)
{
    SCRadixTree *tree = NULL;
    SCRadixNode *node = NULL;
    struct sockaddr_in6 servaddr;
    int result = 1;

    tree = SCRadixCreateRadixTree(NULL);

    /* add the keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2003:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "BD15:9791:5346:6223:AADB:8713:9882:2432",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "1111:A21B:6221:BDEA:BBBA::DBAA:9861",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "4444:0BF7:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "5555:0BF1:ABCD:ADEA:7922:ABCD:9124:2375",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DB00:0000:0000:0000:0000",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6Netblock((uint8_t *)&servaddr.sin6_addr, tree, NULL, 56);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBAA:1245:2342:1145:6241",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    SCRadixAddKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree, NULL);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "::", &servaddr.sin6_addr) <= 0)
        return 0;
    node = SCRadixAddKeyIPV6Netblock((uint8_t *)&servaddr.sin6_addr, tree, NULL,
                                     0);

    /* test the existence of keys */
    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2004:0BF1:5346:BDEA:7422:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == node);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2004:0BF1:5346:B116:2362:8713:9124:2315",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == node);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "2004:0B23:3252:BDEA:7422:8713:9124:2341",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) == node);

    bzero(&servaddr, sizeof(servaddr));
    if (inet_pton(AF_INET6, "DBCA:ABCD:ABCD:DBAA:1245:2342:1145:6241",
                  &servaddr.sin6_addr) <= 0)
        return 0;
    result &= (SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != NULL &&
               SCRadixFindKeyIPV6((uint8_t *)&servaddr.sin6_addr, tree) != node);

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
    UtRegisterTest("SCRadixTestIPV4NetblockInsertion09",
                   SCRadixTestIPV4NetblockInsertion09, 1);
    UtRegisterTest("SCRadixTestIPV4NetblockInsertion10",
                   SCRadixTestIPV4NetblockInsertion10, 1);
    UtRegisterTest("SCRadixTestIPV4NetblockInsertion11",
                   SCRadixTestIPV4NetblockInsertion11, 1);
    UtRegisterTest("SCRadixTestIPV4NetblockInsertion12",
                   SCRadixTestIPV4NetblockInsertion12, 1);
    UtRegisterTest("SCRadixTestIPV6NetblockInsertion13",
                   SCRadixTestIPV6NetblockInsertion13, 1);
    UtRegisterTest("SCRadixTestIPV6NetblockInsertion14",
                   SCRadixTestIPV6NetblockInsertion14, 1);

#endif

    return;
}
