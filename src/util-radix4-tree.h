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

#ifndef __UTIL_RADIX4_TREE_H__
#define __UTIL_RADIX4_TREE_H__

struct RadixUserData;

/**
 * \brief Structure for the node in the radix tree
 */
typedef struct SCRadix4Node_ {
    /* holds bitmap of netmasks that come under this node in the tree */
    uint64_t masks : 33;
    uint64_t pad1 : 31;

    /* the bit position where the bits differ in the nodes children.  Used
     * to determine the path to be taken during a lookup */
    uint8_t bit;

    /** bool to see if prefix_stream is filled */
    bool has_prefix;

    /* the key that has been stored in the tree */
    uint8_t prefix_stream[4];

    /* any user data that has to be associated with this key.  We need a user
     * data field for each netblock value possible since one ip can be associated
     * with any of the the 32 netblocks. */
    struct RadixUserData *user_data;

    /* the left and the right children of a node */
    struct SCRadix4Node_ *left, *right;

    /* the parent node for this tree */
    struct SCRadix4Node_ *parent;
} SCRadix4Node;

/**
 * \brief Structure for the radix tree
 */
typedef struct SCRadix4Tree_ {
    /* the root node in the radix tree */
    SCRadix4Node *head;

} SCRadix4Tree;

typedef struct SCRadix4Config_ {
    void (*Free)(void *); // pass in when actually freeing?
    /* function pointer that is supplied by the user to free the user data
     * held by the user field of SCRadix4Node */
    void (*PrintData)(void *); // debug only?
} SCRadix4Config;

#define SC_RADIX4_TREE_INITIALIZER                                                                 \
    {                                                                                              \
        .head = NULL                                                                               \
    }
SCRadix4Tree SCRadix4TreeInitialize(void);
void SCRadix4TreeRelease(SCRadix4Tree *, const SCRadix4Config *);

SCRadix4Node *SCRadix4AddKeyIPV4(SCRadix4Tree *, const SCRadix4Config *, const uint8_t *, void *);
SCRadix4Node *SCRadix4AddKeyIPV4Netblock(
        SCRadix4Tree *, const SCRadix4Config *, const uint8_t *, uint8_t, void *);
SCRadix4Node *SCRadix4AddKeyIPV4String(
        SCRadix4Tree *, const SCRadix4Config *, const char *, void *);

void SCRadix4RemoveKeyIPV4Netblock(
        SCRadix4Tree *, const SCRadix4Config *, const uint8_t *, uint8_t);
void SCRadix4RemoveKeyIPV4(SCRadix4Tree *, const SCRadix4Config *, const uint8_t *);

SCRadix4Node *SCRadix4TreeFindExactMatch(const SCRadix4Tree *, const uint8_t *, void **);
SCRadix4Node *SCRadix4TreeFindNetblock(
        const SCRadix4Tree *, const uint8_t *, const uint8_t, void **);
SCRadix4Node *SCRadix4TreeFindBestMatch(const SCRadix4Tree *, const uint8_t *, void **);
SCRadix4Node *SCRadix4TreeFindBestMatch2(const SCRadix4Tree *, const uint8_t *, void **, uint8_t *);

void SCRadix4PrintTree(SCRadix4Tree *, const SCRadix4Config *config);
void SCRadix4PrintNodeInfo(SCRadix4Node *, int, void (*PrintData)(void *));

void SCRadix4RegisterTests(void);

typedef int (*SCRadix4ForEachNodeFunc)(
        const SCRadix4Node *node, void *user_data, const uint8_t netmask, void *data);

int SCRadix4ForEachNode(SCRadix4Tree *tree, SCRadix4ForEachNodeFunc Callback, void *data);

/** \brief compare content of 2 user data entries
 *  \retval true equal
 *  \retval false not equal
 */
typedef bool (*SCRadix4TreeCompareFunc)(const void *ud1, const void *ud2);
bool SCRadix4CompareTrees(
        const SCRadix4Tree *t1, const SCRadix4Tree *t2, SCRadix4TreeCompareFunc Callback);

#endif /* __UTIL_RADIX4_TREE_H__ */
