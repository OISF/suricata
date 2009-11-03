/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __UTIL_RADIX_TREE_H__
#define __UTIL_RADIX_TREE_H__

#define SC_RADIX_BITTEST(x, y) ((x) & (y))

/**
 * \brief Structure for the prefix/key in the radix tree
 */
typedef struct SCRadixPrefix_ {
    /* length of the stream */
    uint16_t bitlen;

    /* the key that has been stored in the tree */
    uint8_t *stream;

    /* if this is a prefix that holds a netblock, this field holds the
     * netmask, 255 otherwise */
    uint8_t netmask;

    /* any user data that has to be associated with this key */
    void *user;
} SCRadixPrefix;

/**
 * \brief Structure for the node in the radix tree
 */
typedef struct SCRadixNode_ {
    /* the bit position where the bits differ in the nodes children.  Used
     * to determine the path to be taken during a lookup*/
    uint16_t bit;

    /* holds a list of netmaks that come under this node in the tree */
    uint8_t *netmasks;
    /* total no of netmasks that are registered under this node */
    int netmask_cnt;

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
    void (*Free)(void *);
} SCRadixTree;


SCRadixTree *SCRadixCreateRadixTree(void (*Free)(void*));
void SCRadixReleaseRadixTree(SCRadixTree *);

SCRadixNode *SCRadixAddKeyGeneric(uint8_t *, uint16_t, SCRadixTree *, void *);
SCRadixNode *SCRadixAddKeyIPV4(uint8_t *, SCRadixTree *, void *);
SCRadixNode *SCRadixAddKeyIPV6(uint8_t *, SCRadixTree *, void *);
SCRadixNode *SCRadixAddKeyIPV4Netblock(uint8_t *, SCRadixTree *, void *,
                                       uint8_t);
SCRadixNode *SCRadixAddKeyIPV6Netblock(uint8_t *, SCRadixTree *, void *,
                                       uint8_t);

void SCRadixRemoveKeyGeneric(uint8_t *, uint16_t, SCRadixTree *);
void SCRadixRemoveKeyIPV4(uint8_t *, SCRadixTree *);
void SCRadixRemoveKeyIPV6(uint8_t *, SCRadixTree *);

SCRadixNode *SCRadixFindKeyGeneric(uint8_t *, uint16_t, SCRadixTree *);
SCRadixNode *SCRadixFindKeyIPV4(uint8_t *, SCRadixTree *);
SCRadixNode *SCRadixFindKeyIPV6(uint8_t *, SCRadixTree *);

void SCRadixPrintTree(SCRadixTree *);

void SCRadixRegisterTests(void);


#endif /* __UTIL_RADIX_TREE_H__ */
