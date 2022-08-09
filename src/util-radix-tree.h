/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __UTIL_RADIX_TREE_H__
#define __UTIL_RADIX_TREE_H__

#define SC_RADIX_BITTEST(x, y) ((x) & (y))

/**
 * \brief Structure that hold the user data and the netmask associated with it.
 */
typedef struct SCRadixUserData_ {
    /* holds a pointer to the user data associated with the particular netmask */
    void *user;
    /* pointer to the next user data in the list */
    struct SCRadixUserData_ *next;
    /* holds the netmask value that corresponds to this user data pointer */
    uint8_t netmask;
} SCRadixUserData;

/**
 * \brief Structure for the prefix/key in the radix tree
 */
typedef struct SCRadixPrefix_ {
    /* length of the stream */
    uint16_t bitlen;

    /* the key that has been stored in the tree */
    uint8_t *stream;

    /* any user data that has to be associated with this key.  We need a user
     * data field for each netblock value possible since one ip can be associated
     * with any of the 32 or 128 netblocks.  Also for non-ips, we store the
     * netmask as 255 in SCRadixUserData->netmask */
    SCRadixUserData *user_data;
} SCRadixPrefix;

/**
 * \brief Structure for the node in the radix tree
 */
typedef struct SCRadixNode_ {
    /* the bit position where the bits differ in the nodes children.  Used
     * to determine the path to be taken during a lookup*/
    uint16_t bit;

    uint16_t pad0;

    /* total no of netmasks that are registered under this node */
    uint16_t netmask_cnt;
    /* holds a list of netmasks that come under this node in the tree */
    uint8_t *netmasks;

    /* holds the prefix that the path to this node holds */
    SCRadixPrefix *prefix;

    /* the left and the right children of a node */
    struct SCRadixNode_ *left, *right;

    /* the parent node for this tree */
    struct SCRadixNode_ *parent;
} SCRadixNode;

/**
 * \brief Structure for the radix tree
 */
typedef struct SCRadixTree_ {
    /* the root node in the radix tree */
    SCRadixNode *head;

    /* function pointer that is supplied by the user to free the user data
     * held by the user field of SCRadixNode */
    void (*PrintData)(void *);
    void (*Free)(void *);
} SCRadixTree;


struct in_addr *SCRadixValidateIPV4Address(const char *);
struct in6_addr *SCRadixValidateIPV6Address(const char *);
void SCRadixChopIPAddressAgainstNetmask(uint8_t *, uint8_t, uint16_t);

SCRadixTree *SCRadixCreateRadixTree(void (*Free)(void*), void (*PrintData)(void*));
void SCRadixReleaseRadixTree(SCRadixTree *);

SCRadixNode *SCRadixAddKeyIPV4(uint8_t *, SCRadixTree *, void *);
SCRadixNode *SCRadixAddKeyIPV6(uint8_t *, SCRadixTree *, void *);
SCRadixNode *SCRadixAddKeyIPV4Netblock(uint8_t *, SCRadixTree *, void *,
                                       uint8_t);
SCRadixNode *SCRadixAddKeyIPV6Netblock(uint8_t *, SCRadixTree *, void *,
                                       uint8_t);
SCRadixNode *SCRadixAddKeyIPV4String(const char *, SCRadixTree *, void *);
SCRadixNode *SCRadixAddKeyIPV6String(const char *, SCRadixTree *, void *);

void SCRadixRemoveKeyGeneric(uint8_t *, uint16_t, SCRadixTree *);
void SCRadixRemoveKeyIPV4Netblock(uint8_t *, SCRadixTree *, uint8_t);
void SCRadixRemoveKeyIPV4(uint8_t *, SCRadixTree *);
void SCRadixRemoveKeyIPV6Netblock(uint8_t *, SCRadixTree *, uint8_t);
void SCRadixRemoveKeyIPV6(uint8_t *, SCRadixTree *);

SCRadixNode *SCRadixFindKeyIPV4ExactMatch(uint8_t *, SCRadixTree *, void **);
SCRadixNode *SCRadixFindKeyIPV4Netblock(uint8_t *, SCRadixTree *, uint8_t, void **);
SCRadixNode *SCRadixFindKeyIPV4BestMatch(uint8_t *, SCRadixTree *, void **);

SCRadixNode *SCRadixFindKeyIPV6ExactMatch(uint8_t *, SCRadixTree *, void **);
SCRadixNode *SCRadixFindKeyIPV6Netblock(uint8_t *, SCRadixTree *, uint8_t, void **);
SCRadixNode *SCRadixFindKeyIPV6BestMatch(uint8_t *, SCRadixTree *, void **);

void SCRadixPrintTree(SCRadixTree *);
void SCRadixPrintNodeInfo(SCRadixNode *, int,  void (*PrintData)(void*));

void SCRadixRegisterTests(void);

#endif /* __UTIL_RADIX_TREE_H__ */
