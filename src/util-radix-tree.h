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
} SCRadixPrefix;

/**
 * \brief Structure for the node in the radix tree
 */
typedef struct SCRadixNode_ {
    /* the bit position where the bits differ in the nodes children.  Used
     * to determine the path to be taken during a lookup*/
    uint16_t bit;

    /* Holds the prefix that the path to this node holds */
    SCRadixPrefix *prefix;

    /* the left and the right children of a node */
    struct SCRadixNode_ *left, *right;

    /* the parent node for this tree */
    struct SCRadixNode_ *parent;

    /* any user data that has to be associated with this node */
    void *user;
} SCRadixNode;

/**
 * \brief Structure for the radix tree
 */
typedef struct SCRadixTree_ {
    /* the root node in the radix tree */
    SCRadixNode *head;
} SCRadixTree;


SCRadixTree *SCRadixCreateRadixTree();
void SCRadixReleaseRadixTree(SCRadixTree *);

SCRadixPrefix *SCRadixCreatePrefix(uint8_t *, uint16_t);
SCRadixPrefix *SCRadixCreateIPV4Prefix(uint8_t *);
SCRadixPrefix *SCRadixCreateIPV6Preix(uint8_t *);
void SCRadixReleasePrefix(SCRadixPrefix *prefix);

SCRadixNode *SCRadixAddKey(SCRadixPrefix *, SCRadixTree *);
void SCRadixRemoveKey(SCRadixPrefix *, SCRadixTree *);

SCRadixNode *SCRadixFindKey(SCRadixPrefix *, SCRadixTree *);

void SCRadixPrintTree(SCRadixTree *);

void SCRadixRegisterTests(void);


#endif /* __UTIL_RADIX_TREE_H__ */

