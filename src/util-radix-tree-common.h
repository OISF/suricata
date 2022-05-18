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

#include "util-validate.h"

#ifndef ADDRESS_BYTES
#error "define ADDRESS_BYTES"
#endif
#ifndef NETMASK_MAX
#error "define NETMASK_MAX"
#endif

#define RADIX_BITTEST(x, y) ((x) & (y))

/**
 * \brief Structure that hold the user data and the netmask associated with it.
 */
typedef struct RadixUserData {
    /* holds a pointer to the user data associated with the particular netmask */
    void *user;
    /* pointer to the next user data in the list */
    struct RadixUserData *next;
    /* holds the netmask value that corresponds to this user data pointer */
    uint8_t netmask;
} RadixUserData;

/**
 * \brief Allocates and returns a new instance of SCRadixUserData.
 *
 * \param netmask The netmask entry (cidr) that has to be made in the new
 *                SCRadixUserData instance
 * \param user    The user data that has to be set for the above
 *                netmask in the newly created SCRadixUserData instance.
 *
 * \retval user_data Pointer to a new instance of SCRadixUserData.
 */
static RadixUserData *AllocUserData(uint8_t netmask, void *user)
{
    RadixUserData *user_data = SCCalloc(1, sizeof(RadixUserData));
    if (unlikely(user_data == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        return NULL;
    }
    user_data->netmask = netmask;
    user_data->user = user;
    return user_data;
}

/**
 * \brief Deallocates an instance of SCRadixUserData.
 *
 * \param user_data Pointer to the instance of SCRadixUserData that has to be
 *                  freed.
 */
static void FreeUserData(RadixUserData *user_data)
{
    SCFree(user_data);
}

/**
 * \brief Appends a user_data instance(RadixUserData) to a
 *        user_data(RadixUserData) list.  We add the new entry in descending
 *        order with respect to the netmask contained in the SCRadixUserData.
 *
 * \param new  Pointer to the RadixUserData to be added to the list.
 * \param list Pointer to the RadixUserData list head, to which "new" has to
 *             be appended.
 */
static void AppendToUserDataList(RadixUserData *add, RadixUserData **list)
{
    RadixUserData *temp = NULL;

    BUG_ON(add == NULL || list == NULL);

    /* add to the list in descending order.  The reason we do this is for
     * optimizing key retrieval for a ip key under a netblock */
    RadixUserData *prev = temp = *list;
    while (temp != NULL) {
        if (add->netmask > temp->netmask)
            break;
        prev = temp;
        temp = temp->next;
    }

    if (temp == *list) {
        add->next = *list;
        *list = add;
    } else {
        add->next = prev->next;
        prev->next = add;
    }
}

/**
 * \brief Adds a netmask and its user_data for a particular prefix stream.
 *
 * \param prefix  The prefix stream to which the netmask and its corresponding
 *                user data has to be added.
 * \param netmask The netmask value (cidr) that has to be added to the prefix.
 * \param user    The pointer to the user data corresponding to the above
 *                netmask.
 */
static void AddNetmaskUserDataToNode(RADIX_NODE_TYPE *node, uint8_t netmask, void *user)
{
    BUG_ON(!node);
    AppendToUserDataList(AllocUserData(netmask, user), &node->user_data);
}

/**
 * \brief Removes a particular user_data corresponding to a particular netmask
 *        entry, from a prefix.
 *
 * \param prefix  Pointer to the prefix from which the user_data/netmask entry
 *                has to be removed.
 * \param netmask The netmask value (cidr) whose user_data has to be deleted.
 */
static void RemoveNetmaskUserDataFromNode(RADIX_NODE_TYPE *node, uint8_t netmask)
{
    BUG_ON(!node);

    RadixUserData *temp = NULL, *prev = NULL;
    prev = temp = node->user_data;
    while (temp != NULL) {
        if (temp->netmask == netmask) {
            if (temp == node->user_data)
                node->user_data = temp->next;
            else
                prev->next = temp->next;

            FreeUserData(temp);
            break;
        }
        prev = temp;
        temp = temp->next;
    }
}

/**
 * \brief Indicates if prefix contains an entry for an ip with a specific netmask.
 *
 * \param prefix  Pointer to the ip prefix that is being checked.
 * \param netmask The netmask value (cidr) that has to be checked for
 *                presence in the prefix.
 *
 * \retval 1 On match.
 * \retval 0 On no match.
 */
static int ContainNetmask(RADIX_NODE_TYPE *node, uint8_t netmask)
{
    BUG_ON(!node);
    RadixUserData *user_data = node->user_data;
    while (user_data != NULL) {
        if (user_data->netmask == netmask)
            return 1;
        user_data = user_data->next;
    }
    return 0;
}

/**
 * \brief Returns the total netmask count for this prefix.
 *
 * \param prefix Pointer to the prefix
 *
 * \retval count The total netmask count for this prefix.
 */
static int NetmaskCount(RADIX_NODE_TYPE *node)
{
    BUG_ON(!node);
    uint32_t count = 0;
    RadixUserData *user_data = node->user_data;
    while (user_data != NULL) {
        count++;
        user_data = user_data->next;
    }
    return count;
}

/**
 * \brief Indicates if prefix contains an entry for an ip with a specific netmask
 *        and if it does, it sets `user_data_result` to the netmask user_data entry.
 *
 * \param prefix      Pointer to the ip prefix that is being checked.
 * \param netmask     The netmask value for which we will have to return the user_data
 * \param exact_match Bool flag which indicates if we should check if the prefix
 *                    holds proper netblock  or not.
 * \param[out] user_data_result user data pointer
 *
 * \retval 1 On match.
 * \retval 0 On no match.
 */
static int ContainNetmaskAndSetUserData(
        RADIX_NODE_TYPE *node, uint8_t netmask, bool exact_match, void **user_data_result)
{
    BUG_ON(!node);

    RadixUserData *user_data = node->user_data;
    /* Check if we have a match for an exact ip.  An exact ip as in not a proper
     * netblock, i.e. an ip with a netmask of 32. */
    if (exact_match) {
        if (user_data->netmask == netmask) {
            if (user_data_result)
                *user_data_result = user_data->user;
            return 1;
        } else {
            goto no_match;
        }
    }

    /* Check for the user_data entry for this netmask_value */
    while (user_data != NULL) {
        if (user_data->netmask == netmask) {
            if (user_data_result)
                *user_data_result = user_data->user;
            return 1;
        }
        user_data = user_data->next;
    }

no_match:
    if (user_data_result != NULL)
        *user_data_result = NULL;
    return 0;
}

/**
 * \brief Creates a new node for the Radix tree
 *
 * \retval node The newly created node for the radix tree
 */
static inline RADIX_NODE_TYPE *RadixCreateNode(void)
{
    RADIX_NODE_TYPE *node = NULL;

    if ((node = SCCalloc(1, sizeof(RADIX_NODE_TYPE))) == NULL) {
        SCLogError(SC_ERR_FATAL,
                "Fatal error encountered in SCRadix4CreateNode. Mem not allocated...");
        return NULL;
    }
    node->bit = NETMASK_MAX;
    return node;
}

/**
 * \brief Frees a Radix tree node
 *
 * \param node Pointer to a Radix tree node
 * \param tree Pointer to the Radix tree to which this node belongs
 */
static void ReleaseNode(
        RADIX_NODE_TYPE *node, RADIX_TREE_TYPE *tree, const RADIX_CONFIG_TYPE *config)
{
    DEBUG_VALIDATE_BUG_ON(config == NULL);
    if (node != NULL) {
        RadixUserData *ud = node->user_data;
        while (ud != NULL) {
            RadixUserData *next = ud->next;
            if (config->Free != NULL && ud->user) {
                config->Free(ud->user);
            }
            FreeUserData(ud);
            ud = next;
        }
        SCFree(node);
    }
}

/**
 * \brief Internal helper function used by TreeRelease to free a subtree
 *
 * \param node Pointer to the root of the subtree that has to be freed
 * \param tree Pointer to the Radix tree to which this subtree belongs
 */
static void ReleaseSubtree(
        RADIX_NODE_TYPE *node, RADIX_TREE_TYPE *tree, const RADIX_CONFIG_TYPE *config)
{
    DEBUG_VALIDATE_BUG_ON(config == NULL);
    if (node != NULL) {
        ReleaseSubtree(node->left, tree, config);
        ReleaseSubtree(node->right, tree, config);
        ReleaseNode(node, tree, config);
    }
}

/**
 * \brief frees a Radix tree and all its nodes
 *
 * \param tree Pointer to the Radix tree that has to be freed
 */
static void TreeRelease(RADIX_TREE_TYPE *tree, const RADIX_CONFIG_TYPE *config)
{
    DEBUG_VALIDATE_BUG_ON(config == NULL);
    if (tree == NULL)
        return;

    ReleaseSubtree(tree->head, tree, config);
    tree->head = NULL;
    return;
}

/**
 * \brief Adds a key to the Radix tree. Used internally by the API.
 *
 * \param tree       Pointer to the Radix tree
 * \param key_stream Data that has to added to the Radix tree
 * \param user       Pointer to the user data that has to be associated with
 *                   this key
 * \param netmask    The netmask (cidr)
 * \param negated    The key is negated.
 *
 * \retval node Pointer to the newly created node
 */
static RADIX_NODE_TYPE *AddKey(RADIX_TREE_TYPE *tree, const RADIX_CONFIG_TYPE *config,
        const uint8_t *key_stream, uint8_t netmask, void *user)
{
    DEBUG_VALIDATE_BUG_ON(config == NULL);
    RADIX_NODE_TYPE *node = NULL;
    RADIX_NODE_TYPE *parent = NULL;
    RADIX_NODE_TYPE *bottom_node = NULL;

    uint8_t tmp_stream[ADDRESS_BYTES];
    memcpy(tmp_stream, key_stream, sizeof(tmp_stream));

    int check_bit = 0;
    int differ_bit = 0;

    int i = 0;
    int j = 0;
    int temp = 0;

    if (tree == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Argument \"tree\" NULL");
        return NULL;
    }

    /* chop the ip address against a netmask */
    MaskIPNetblock(tmp_stream, netmask, NETMASK_MAX);

    /* the very first element in the radix tree */
    if (tree->head == NULL) {
        node = RadixCreateNode();
        if (node == NULL)
            return NULL;
        memcpy(node->prefix_stream, tmp_stream, sizeof(tmp_stream));
        node->has_prefix = true;
        node->user_data = AllocUserData(netmask, user);
        if (node->user_data == NULL) {
            ReleaseNode(node, tree, config);
            return NULL;
        }
        tree->head = node;
        if (netmask == NETMASK_MAX)
            return node;

        AddNetmaskToMasks(node, netmask);
        return node;
    }
    node = tree->head;

    /* we walk down the tree only when we satisfy 2 conditions.  The first one
     * being the incoming prefix is shorter than the differ bit of the current
     * node.  In case we fail in this aspect, we walk down to the tree, till we
     * arrive at a node that ends in a prefix */
    while (node->bit < NETMASK_MAX || node->has_prefix == false) {
        /* if the bitlen isn't long enough to handle the bit test, we just walk
         * down along one of the paths, since either paths should end up with a
         * node that has a common prefix whose differ bit is greater than the
         * bitlen of the incoming prefix */
        if (NETMASK_MAX <= node->bit) {
            if (node->right == NULL)
                break;
            node = node->right;
        } else {
            if (RADIX_BITTEST(tmp_stream[node->bit >> 3], (0x80 >> (node->bit % 8)))) {
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

    /* get the first bit position where the ips differ */
    check_bit = MIN(node->bit, NETMASK_MAX);
    for (i = 0; (i * 8) < check_bit; i++) {
        if ((temp = (tmp_stream[i] ^ bottom_node->prefix_stream[i])) == 0) {
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
    BUG_ON(differ_bit == NETMASK_MAX && node->bit != NETMASK_MAX);

    /* We already have the node in the tree with the same differing bit position */
    if (differ_bit == NETMASK_MAX && node->bit == NETMASK_MAX) {
        if (node->has_prefix) {
            /* Check if we already have this netmask entry covered by this prefix */
            if (ContainNetmask(node, netmask)) {
                /* Basically we already have this stream prefix, as well as the
                 * netblock entry for this.  A perfect duplicate. */
                SCLogDebug("Duplicate entry for this ip address/netblock");
            } else {
                /* Basically we already have this stream prefix, but we don't
                 * have an entry for this particular netmask value for this
                 * prefix.  For example, we have an entry for 192.168.0.0 and
                 * 192.168.0.0/16 and now we are trying to enter 192.168.0.0/20 */
                AddNetmaskUserDataToNode(node, netmask, user);

                /* if we are adding a netmask of 32 it indicates we are adding
                 * an exact host ip into the radix tree, in which case we don't
                 * need to add the netmask value into the tree */
                if (netmask == NETMASK_MAX)
                    return node;

                /* looks like we have a netmask which is != 32, in which
                 * case we walk up the tree to insert this netmask value in the
                 * correct node */
                parent = node->parent;
                while (parent != NULL && netmask < (parent->bit + 1)) {
                    node = parent;
                    parent = parent->parent;
                }

                AddNetmaskToMasks(node, netmask);
                if (NetmaskEqualsMask(node, netmask)) {
                    return node;
                }
            }
        }
        return node;
    }

    /* create the leaf node for the new key */
    RADIX_NODE_TYPE *new_node = RadixCreateNode();
    if (new_node == NULL)
        return NULL;
    memcpy(new_node->prefix_stream, tmp_stream, sizeof(tmp_stream));
    new_node->has_prefix = true;
    new_node->user_data = AllocUserData(netmask, user);
    if (new_node->user_data == NULL) {
        ReleaseNode(new_node, tree, config);
        return NULL;
    }

    /* stick our new_node into the tree.  Create a node that holds the
     * differing bit position and break the branch.  Also handle the
     * tranfer of netmasks between node and inter_node(explained in more
     * detail below) */
    RADIX_NODE_TYPE *inter_node = RadixCreateNode();
    if (inter_node == NULL) {
        ReleaseNode(new_node, tree, config);
        return NULL;
    }
    inter_node->has_prefix = false;
    inter_node->bit = differ_bit;
    inter_node->parent = node->parent;
    SCLogDebug("inter_node: differ_bit %u", differ_bit);

    /* update netmasks for node and set them for inter_node */
    ProcessInternode(node, inter_node);

    if (RADIX_BITTEST(tmp_stream[differ_bit >> 3], (0x80 >> (differ_bit % 8)))) {
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

    /* insert the netmask into the tree */
    if (netmask != NETMASK_MAX) {
        node = new_node;
        parent = new_node->parent;
        while (parent != NULL && netmask < (parent->bit + 1)) {
            node = parent;
            parent = parent->parent;
        }
        AddNetmaskToMasks(node, netmask);
    }
    return new_node;
}

/**
 * \brief Removes a netblock entry from an ip node.  The function first
 *        deletes the netblock/user_data entry for the prefix and then
 *        removes the netmask entry that has been made in the tree, by
 *        walking up the tree and deleting the entry from the specific node.
 *
 * \param node    The node from which the netblock entry has to be removed.
 * \param netmask The netmask entry (cidr) that has to be removed.
 */
static void RemoveNetblockEntry(RADIX_NODE_TYPE *node, uint8_t netmask)
{
    BUG_ON(!node);

    RemoveNetmaskUserDataFromNode(node, netmask);

    if (netmask == NETMASK_MAX) {
        SCLogDebug("%d == %d", netmask, NETMASK_MAX);
        return;
    }

    RemoveNetmaskFromMasks(node, netmask);
    if (node->parent != NULL)
        RemoveNetmaskFromMasks(node->parent, netmask);
    return;
}

/**
 * \brief Removes a key from the Radix tree
 *
 * \param key_stream Data that has to be removed from the Radix tree
 * \param tree       Pointer to the Radix tree from which the key has to be
 *                   removed
 */
static void RemoveKey(RADIX_TREE_TYPE *tree, const RADIX_CONFIG_TYPE *config,
        const uint8_t *key_stream, const uint8_t netmask)
{
    RADIX_NODE_TYPE *node = tree->head;
    RADIX_NODE_TYPE *parent = NULL;
    RADIX_NODE_TYPE *temp_dest = NULL;

    if (node == NULL) {
        SCLogDebug("tree is empty");
        return;
    }

    uint8_t tmp_stream[ADDRESS_BYTES];
    memcpy(tmp_stream, key_stream, sizeof(tmp_stream));

    while (node->bit < NETMASK_MAX) {
        if (RADIX_BITTEST(tmp_stream[node->bit >> 3], (0x80 >> (node->bit % 8)))) {
            node = node->right;
        } else {
            node = node->left;
        }

        if (node == NULL) {
            SCLogDebug("no matching node found");
            return;
        }
    }

    if (node->bit != NETMASK_MAX || node->has_prefix == false) {
        SCLogDebug("node %p bit %d != %d, or not has_prefix %s", node, node->bit, NETMASK_MAX,
                node->has_prefix ? "true" : "false");
        return;
    }

    if (SCMemcmp(node->prefix_stream, tmp_stream, sizeof(tmp_stream)) == 0) {
        if (!ContainNetmask(node, netmask)) {
            SCLogDebug("key exists in the tree, but this (%d) "
                       "netblock entry doesn't exist",
                    netmask);
            return;
        }
    } else {
        SCLogDebug("You are trying to remove a key that doesn't exist in the "
                   "Radix Tree");
        return;
    }

    /* The ip node does exist, and the netblock entry does exist in this node, if
     * we have reached this point.  If we have more than one netblock entry, it
     * indicates we have multiple entries for this key.  So we delete that
     * particular netblock entry, and make our way out of this function */
    if (NetmaskCount(node) > 1) { // || !NoneNegated(node)) {
        RemoveNetblockEntry(node, netmask);
        SCLogDebug("NetmaskCount");
        return;
    }
    SCLogDebug("not netmask cnt");

    /* we are deleting the root of the tree.  This would be the only node left
     * in the tree */
    if (tree->head == node) {
        ReleaseNode(node, tree, config);
        tree->head = NULL;
        SCLogDebug("tree->head == node");
        return;
    }

    parent = node->parent;
    /* parent->parent is not the root of the tree */
    if (parent->parent != NULL) {
        if (parent->parent->left == parent) {
            if (node->parent->left == node) {
                temp_dest = parent->right;
                parent->parent->left = parent->right;
                parent->right->parent = parent->parent;
            } else {
                temp_dest = parent->left;
                parent->parent->left = parent->left;
                parent->left->parent = parent->parent;
            }
        } else {
            if (node->parent->left == node) {
                temp_dest = parent->right;
                parent->parent->right = parent->right;
                parent->right->parent = parent->parent;
            } else {
                temp_dest = parent->left;
                parent->parent->right = parent->left;
                parent->left->parent = parent->parent;
            }
        }
        /* parent is the root of the tree */
    } else {
        if (parent->left == node) {
            temp_dest = tree->head->right;
            tree->head->right->parent = NULL;
            tree->head = tree->head->right;
        } else {
            temp_dest = tree->head->left;
            tree->head->left->parent = NULL;
            tree->head = tree->head->left;
        }
    }
    /* We need to shift the netmask entries from the node that would be
     * deleted to its immediate descendant */
    AddNetmasksFromNode(temp_dest, parent);
    RemoveNetmaskFromMasks(temp_dest, netmask);
    /* release the nodes */
    ReleaseNode(parent, tree, config);
    ReleaseNode(node, tree, config);

    SCLogDebug("end (netmask %d)", netmask);
    return;
}

/**
 * \brief Checks if an IP prefix falls under a netblock, in the path to the root
 *        of the tree, from the node.  Used internally by FindKey()
 *
 * \param prefix Pointer to the prefix that contains the ip address
 * \param node   Pointer to the node from where we have to climb the tree
 */
static inline RADIX_NODE_TYPE *FindKeyIPNetblock(const uint8_t *key_stream, RADIX_NODE_TYPE *node,
        void **user_data_result, uint8_t *out_netmask)
{
    while (node != NULL && NetmasksEmpty(node))
        node = node->parent;
    if (node == NULL)
        return NULL;

    uint8_t tmp_stream[ADDRESS_BYTES];
    memcpy(tmp_stream, key_stream, sizeof(tmp_stream));

    /* hold the node found containing a netmask.  We will need it when we call
     * this function recursively */
    RADIX_NODE_TYPE *netmask_node = node;

    for (int j = 0; j <= NETMASK_MAX; j++) {
        int m = NETMASK_MAX - j;

        if (!(NetmaskIssetInMasks(netmask_node, m)))
            continue;

        for (int i = 0; i < ADDRESS_BYTES; i++) {
            uint32_t mask = UINT_MAX;
            if (((i + 1) * 8) > m) {
                if (((i + 1) * 8 - m) < 8)
                    mask = UINT_MAX << ((i + 1) * 8 - m);
                else
                    mask = 0;
            }
            tmp_stream[i] &= mask;
        }

        while (node->bit < NETMASK_MAX) {
            if (RADIX_BITTEST(tmp_stream[node->bit >> 3], (0x80 >> (node->bit % 8)))) {
                node = node->right;
            } else {
                node = node->left;
            }

            if (node == NULL)
                return NULL;
        }

        if (node->bit != NETMASK_MAX || node->has_prefix == false)
            return NULL;

        if (SCMemcmp(node->prefix_stream, tmp_stream, sizeof(tmp_stream)) == 0) {
            if (ContainNetmaskAndSetUserData(node, m, false, user_data_result)) {
                *out_netmask = m;
                return node;
            }
        }
    }

    return FindKeyIPNetblock(tmp_stream, netmask_node->parent, user_data_result, out_netmask);
}

/**
 * \brief Checks if an IP address key is present in the tree.  The function
 *        apart from handling any normal data, also handles ipv4/ipv6 netblocks
 *
 * \param key_stream  Data that has to be found in the Radix tree
 * \param tree        Pointer to the Radix tree
 * \param exact_match The key to be searched is an ip address
 */
static RADIX_NODE_TYPE *FindKey(const RADIX_TREE_TYPE *tree, const uint8_t *key_stream,
        const uint8_t netmask, bool exact_match, void **user_data_result, uint8_t *out_netmask)
{
    if (tree == NULL || tree->head == NULL)
        return NULL;

    RADIX_NODE_TYPE *node = tree->head;
    uint8_t tmp_stream[ADDRESS_BYTES];
    memcpy(tmp_stream, key_stream, sizeof(tmp_stream));

    while (node->bit < NETMASK_MAX) {
        if (RADIX_BITTEST(tmp_stream[node->bit >> 3], (0x80 >> (node->bit % 8)))) {
            node = node->right;
        } else {
            node = node->left;
        }

        if (node == NULL) {
            return NULL;
        }
    }

    if (node->bit != NETMASK_MAX || node->has_prefix == false) {
        return NULL;
    }

    if (SCMemcmp(node->prefix_stream, tmp_stream, sizeof(tmp_stream)) == 0) {
        SCLogDebug("stream match");
        if (ContainNetmaskAndSetUserData(node, netmask, true, user_data_result)) {
            SCLogDebug("contains netmask etc");
            *out_netmask = netmask;
            return node;
        }
    }

    /* if you are not an ip key, get out of here */
    if (exact_match) {
        SCLogDebug("no node found and need exact match, so failed");
        return NULL;
    }

    RADIX_NODE_TYPE *ret = FindKeyIPNetblock(tmp_stream, node, user_data_result, out_netmask);
    return ret;
}

/**
 * \brief Checks if an IPV4 address is present in the tree
 *
 * \param key_stream Data that has to be found in the Radix tree.  In this case
 *                   an IPV4 address
 * \param tree       Pointer to the Radix tree instance
 */
static RADIX_NODE_TYPE *FindExactMatch(
        const RADIX_TREE_TYPE *tree, const uint8_t *key_stream, void **user_data_result)
{
    uint8_t unused = 0;
    return FindKey(tree, key_stream, NETMASK_MAX, true, user_data_result, &unused);
}

/**
 * \brief Checks if an IPV4 address is present in the tree under a netblock
 *
 * \param key_stream Data that has to be found in the Radix tree.  In this case
 *                   an IPV4 address
 * \param tree       Pointer to the Radix tree instance
 */
static RADIX_NODE_TYPE *FindBestMatch(
        const RADIX_TREE_TYPE *tree, const uint8_t *key_stream, void **user_data_result)
{
    uint8_t unused = 0;
    return FindKey(tree, key_stream, NETMASK_MAX, false, user_data_result, &unused);
}

static RADIX_NODE_TYPE *FindBestMatch2(const RADIX_TREE_TYPE *tree, const uint8_t *key_stream,
        void **user_data_result, uint8_t *out_netmask)
{
    return FindKey(tree, key_stream, NETMASK_MAX, false, user_data_result, out_netmask);
}

/**
 * \brief Checks if an IPV4 Netblock address is present in the tree
 *
 * \param key_stream Data that has to be found in the Radix tree.  In this case
 *                   an IPV4  netblock address
 * \param tree       Pointer to the Radix tree instance
 */
static RADIX_NODE_TYPE *FindNetblock(const RADIX_TREE_TYPE *tree, const uint8_t *key_stream,
        const uint8_t netmask, void **user_data_result)
{
    uint8_t unused = 0;
    RADIX_NODE_TYPE *node = FindKey(tree, key_stream, netmask, true, user_data_result, &unused);
    return node;
}

/**
 * \brief Helper function used by PrintTree.  Prints the subtree with
 *        node as the root of the subtree
 *
 * \param node  Pointer to the node that is the root of the subtree to be printed
 * \param level Used for indentation purposes
 */
static void PrintSubtree(RADIX_NODE_TYPE *node, int level, void (*PrintData)(void *))
{
    if (node != NULL) {
        PrintNodeInfo(node, level, PrintData);
        PrintSubtree(node->left, level + 1, PrintData);
        PrintSubtree(node->right, level + 1, PrintData);
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
static void PrintTree(RADIX_TREE_TYPE *tree, const RADIX_CONFIG_TYPE *config)
{
    printf("Printing the Radix Tree: \n");
    PrintSubtree(tree->head, 0, config->PrintData);
}

static bool CompareTreesSub(
        RADIX_NODE_TYPE *n1, RADIX_NODE_TYPE *n2, RADIX_TREE_COMPARE_CALLBACK Callback)
{
    // compare nodes
    bool n1_has_left = n1->left != NULL;
    bool n2_has_left = n2->left != NULL;
    if (n1_has_left != n2_has_left)
        return false;

    bool n1_has_right = n1->right != NULL;
    bool n2_has_right = n2->right != NULL;
    if (n1_has_right != n2_has_right)
        return false;

    if (SCMemcmp(n1->prefix_stream, n2->prefix_stream, ADDRESS_BYTES) != 0)
        return false;

    RadixUserData *u1 = n1->user_data;
    RadixUserData *u2 = n2->user_data;
    while (1) {
        if (u1 == NULL && u2 == NULL)
            break;
        if ((u1 != NULL && u2 == NULL) || (u1 == NULL && u2 != NULL))
            return false;
        if (u1->netmask != u2->netmask)
            return false;

        if (Callback != NULL) {
            if (Callback(u1->user, u2->user) == false)
                return false;
        }

        u1 = u1->next;
        u2 = u2->next;
    }

    if (n1->left && n2->left)
        if (CompareTreesSub(n1->left, n2->left, Callback) == false)
            return false;
    if (n1->right && n2->right)
        if (CompareTreesSub(n1->right, n2->right, Callback) == false)
            return false;

    return true;
}

static bool CompareTrees(
        const RADIX_TREE_TYPE *t1, const RADIX_TREE_TYPE *t2, RADIX_TREE_COMPARE_CALLBACK Callback)
{
    if (t1->head == NULL && t2->head == NULL)
        return true;
    if ((t1->head == NULL && t2->head != NULL) || (t1->head != NULL && t2->head == NULL))
        return false;
    return CompareTreesSub(t1->head, t2->head, Callback);
}
