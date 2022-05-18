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
 * Based on util-radix-tree.[ch] by:
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __UTIL_RADIX6_TREE_H__
#define __UTIL_RADIX6_TREE_H__

struct RadixUserData;

/**
 * \brief Structure for the node in the radix tree
 */
typedef struct SCRadix6Node_ {
    /* the key that has been stored in the tree */
    uint8_t prefix_stream[16];

    /* holds bitmap of netmasks that come under this node in the tree */
    uint8_t masks[17];

    /* the bit position where the bits differ in the nodes children.  Used
     * to determine the path to be taken during a lookup */
    uint8_t bit;
    /** bool to see if prefix_stream is filled */
    bool has_prefix;

    /* any user data that has to be associated with this key.  We need a user
     * data field for each netblock value possible since one ip can be associated
     * with any of the the 128 netblocks. */
    struct RadixUserData *user_data;

    /* the left and the right children of a node */
    struct SCRadix6Node_ *left, *right;

    /* the parent node for this tree */
    struct SCRadix6Node_ *parent;
} SCRadix6Node;

/**
 * \brief Structure for the radix tree
 */
typedef struct SCRadix6Tree_ {
    /* the root node in the radix tree */
    SCRadix6Node *head;
} SCRadix6Tree;

typedef struct SCRadix6Config_ {
    void (*Free)(void *);
    /* function pointer that is supplied by the user to free the user data
     * held by the user field of SCRadix6Node */
    void (*PrintData)(void *);
} SCRadix6Config;

#define SC_RADIX6_TREE_INITIALIZER                                                                 \
    {                                                                                              \
        .head = NULL                                                                               \
    }
SCRadix6Tree SCRadix6TreeInitialize(void);
void SCRadix6TreeRelease(SCRadix6Tree *, const SCRadix6Config *);

SCRadix6Node *SCRadix6AddKeyIPV6(SCRadix6Tree *, const SCRadix6Config *, const uint8_t *, void *);
SCRadix6Node *SCRadix6AddKeyIPV6Netblock(
        SCRadix6Tree *, const SCRadix6Config *, const uint8_t *, uint8_t, void *);
SCRadix6Node *SCRadix6AddKeyIPV6String(
        SCRadix6Tree *, const SCRadix6Config *, const char *, void *);

void SCRadix6RemoveKeyIPV6Netblock(
        SCRadix6Tree *, const SCRadix6Config *, const uint8_t *, uint8_t);
void SCRadix6RemoveKeyIPV6(SCRadix6Tree *, const SCRadix6Config *, const uint8_t *);

SCRadix6Node *SCRadix6TreeFindExactMatch(const SCRadix6Tree *, const uint8_t *, void **);
SCRadix6Node *SCRadix6TreeFindNetblock(
        const SCRadix6Tree *, const uint8_t *, const uint8_t, void **);
SCRadix6Node *SCRadix6TreeFindBestMatch(const SCRadix6Tree *, const uint8_t *, void **);
SCRadix6Node *SCRadix6TreeFindBestMatch2(const SCRadix6Tree *, const uint8_t *, void **, uint8_t *);

void SCRadix6PrintTree(SCRadix6Tree *, const SCRadix6Config *);
void SCRadix6PrintNodeInfo(SCRadix6Node *, int, void (*PrintData)(void *));

void SCRadix6RegisterTests(void);

typedef int (*SCRadix6ForEachNodeFunc)(
        const SCRadix6Node *node, void *user_data, const uint8_t netmask, void *data);

int SCRadix6ForEachNode(SCRadix6Tree *tree, SCRadix6ForEachNodeFunc Callback, void *data);

/** \brief compare content of 2 user data entries
 *  \retval true equal
 *  \retval false not equal
 */
typedef bool (*SCRadix6TreeCompareFunc)(const void *ud1, const void *ud2);
bool SCRadix6CompareTrees(
        const SCRadix6Tree *t1, const SCRadix6Tree *t2, SCRadix6TreeCompareFunc Callback);

#endif /* __UTIL_RADIX4_TREE_H__ */
