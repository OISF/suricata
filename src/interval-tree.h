/*	$NetBSD: interval-tree.h,v 1.8 2004/03/28 19:38:30 provos Exp $	*/
/*	$OpenBSD: interval-tree.h,v 1.7 2002/10/17 21:51:54 art Exp $	*/
/* $FreeBSD$ */

/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SYS_INTERVALTREE_H_
#define _SYS_INTERVALTREE_H_

#if defined(__clang_analyzer__)
#define _T_ASSERT(a) assert((a))
#else
#define _T_ASSERT(a)
#endif

/*
 * This file defines data structures for interval trees which are
 * implemented using red-black trees.
 *
 * A red-black tree is a binary search tree with the node color as an
 * extra attribute.  It fulfills a set of conditions:
 *	- every search path from the root to a leaf consists of the
 *	  same number of black nodes,
 *	- each red node (except for the root) has a black parent,
 *	- each leaf node is black.
 *
 * Every operation on a red-black tree is bounded as O(lg n).
 * The maximum height of a red-black tree is 2lg (n+1).
 */

/* Macros that define a red-black tree */
#define IRB_HEAD(name, type)                                                                       \
    struct name {                                                                                  \
        struct type *rbh_root; /* root of the tree */                                              \
    }

#define IRB_INITIALIZER(root)                                                                      \
    {                                                                                              \
        NULL                                                                                       \
    }

#define IRB_INIT(root)                                                                             \
    do {                                                                                           \
        (root)->rbh_root = NULL;                                                                   \
    } while (/*CONSTCOND*/ 0)

#define IRB_BLACK 0
#define IRB_RED   1
#define IRB_ENTRY(type)                                                                            \
    struct {                                                                                       \
        struct type *rbe_left;   /* left element */                                                \
        struct type *rbe_right;  /* right element */                                               \
        struct type *rbe_parent; /* parent element */                                              \
        int rbe_color;           /* node color */                                                  \
    }

#define IRB_LEFT(elm, field)   (elm)->field.rbe_left
#define IRB_RIGHT(elm, field)  (elm)->field.rbe_right
#define IRB_PARENT(elm, field) (elm)->field.rbe_parent
#define IRB_COLOR(elm, field)  (elm)->field.rbe_color
#define IRB_ROOT(head)         (head)->rbh_root
#define IRB_EMPTY(head)        (IRB_ROOT(head) == NULL)

#define IRB_SET(elm, parent, field)                                                                \
    do {                                                                                           \
        IRB_PARENT(elm, field) = parent;                                                           \
        IRB_LEFT(elm, field) = IRB_RIGHT(elm, field) = NULL;                                       \
        IRB_COLOR(elm, field) = IRB_RED;                                                           \
    } while (/*CONSTCOND*/ 0)

#define IRB_SET_BLACKRED(black, red, field)                                                        \
    do {                                                                                           \
        IRB_COLOR(black, field) = IRB_BLACK;                                                       \
        IRB_COLOR(red, field) = IRB_RED;                                                           \
    } while (/*CONSTCOND*/ 0)

/*
 * The implementation of the following macro has been updated.
 * In order to incorporte it properly, the call sites of this
 * function have also been updated compared to the standard
 * Red Black tree implementation in tree.h of BSD */
#ifndef IRB_AUGMENT
#define IRB_AUGMENT(x, field)                                                                      \
    do {                                                                                           \
        if (x != NULL) {                                                                           \
            x->max = x->port2;                                                                     \
            if (IRB_LEFT(x, field) != NULL) {                                                      \
                x->max = MAX(x->max, IRB_LEFT(x, field)->max);                                     \
            }                                                                                      \
            if (IRB_RIGHT(x, field) != NULL) {                                                     \
                x->max = MAX(x->max, IRB_RIGHT(x, field)->max);                                    \
            }                                                                                      \
        }                                                                                          \
    } while (0)
#endif

#define IRB_ROTATE_LEFT(head, elm, tmp, field)                                                     \
    do {                                                                                           \
        (tmp) = IRB_RIGHT(elm, field);                                                             \
        if ((IRB_RIGHT(elm, field) = IRB_LEFT(tmp, field)) != NULL) {                              \
            IRB_PARENT(IRB_LEFT(tmp, field), field) = (elm);                                       \
        }                                                                                          \
        if ((IRB_PARENT(tmp, field) = IRB_PARENT(elm, field)) != NULL) {                           \
            if ((elm) == IRB_LEFT(IRB_PARENT(elm, field), field))                                  \
                IRB_LEFT(IRB_PARENT(elm, field), field) = (tmp);                                   \
            else                                                                                   \
                IRB_RIGHT(IRB_PARENT(elm, field), field) = (tmp);                                  \
        } else                                                                                     \
            (head)->rbh_root = (tmp);                                                              \
        IRB_LEFT(tmp, field) = (elm);                                                              \
        IRB_PARENT(elm, field) = (tmp);                                                            \
        IRB_AUGMENT(elm, field);                                                                   \
        IRB_AUGMENT(tmp, field);                                                                   \
        if ((IRB_PARENT(tmp, field)))                                                              \
            IRB_AUGMENT(IRB_PARENT(tmp, field), field);                                            \
    } while (/*CONSTCOND*/ 0)

#define IRB_ROTATE_RIGHT(head, elm, tmp, field)                                                    \
    do {                                                                                           \
        (tmp) = IRB_LEFT(elm, field);                                                              \
        if ((IRB_LEFT(elm, field) = IRB_RIGHT(tmp, field)) != NULL) {                              \
            IRB_PARENT(IRB_RIGHT(tmp, field), field) = (elm);                                      \
        }                                                                                          \
        if ((IRB_PARENT(tmp, field) = IRB_PARENT(elm, field)) != NULL) {                           \
            if ((elm) == IRB_LEFT(IRB_PARENT(elm, field), field))                                  \
                IRB_LEFT(IRB_PARENT(elm, field), field) = (tmp);                                   \
            else                                                                                   \
                IRB_RIGHT(IRB_PARENT(elm, field), field) = (tmp);                                  \
        } else                                                                                     \
            (head)->rbh_root = (tmp);                                                              \
        IRB_RIGHT(tmp, field) = (elm);                                                             \
        IRB_PARENT(elm, field) = (tmp);                                                            \
        IRB_AUGMENT(elm, field);                                                                   \
        IRB_AUGMENT(tmp, field);                                                                   \
        if ((IRB_PARENT(tmp, field)))                                                              \
            IRB_AUGMENT(IRB_PARENT(tmp, field), field);                                            \
    } while (/*CONSTCOND*/ 0)

/* Generates prototypes and inline functions */
#define IRB_PROTOTYPE(name, type, field, cmp) IRB_PROTOTYPE_INTERNAL(name, type, field, cmp, )
#define IRB_PROTOTYPE_STATIC(name, type, field, cmp)                                               \
    IRB_PROTOTYPE_INTERNAL(name, type, field, cmp, __unused static)
#define IRB_PROTOTYPE_INTERNAL(name, type, field, cmp, attr)                                       \
    IRB_PROTOTYPE_INSERT_COLOR(name, type, attr);                                                  \
    IRB_PROTOTYPE_REMOVE_COLOR(name, type, attr);                                                  \
    IRB_PROTOTYPE_INSERT(name, type, attr);                                                        \
    IRB_PROTOTYPE_REMOVE(name, type, attr);                                                        \
    IRB_PROTOTYPE_FIND(name, type, attr);                                                          \
    IRB_PROTOTYPE_NFIND(name, type, attr);                                                         \
    IRB_PROTOTYPE_NEXT(name, type, attr);                                                          \
    IRB_PROTOTYPE_PREV(name, type, attr);                                                          \
    IRB_PROTOTYPE_MINMAX(name, type, attr);
#define IRB_PROTOTYPE_INSERT_COLOR(name, type, attr)                                               \
    attr void name##_IRB_INSERT_COLOR(struct name *, struct type *)
#define IRB_PROTOTYPE_REMOVE_COLOR(name, type, attr)                                               \
    attr void name##_IRB_REMOVE_COLOR(struct name *, struct type *, struct type *)
#define IRB_PROTOTYPE_REMOVE(name, type, attr)                                                     \
    attr struct type *name##_IRB_REMOVE(struct name *, struct type *)
#define IRB_PROTOTYPE_INSERT(name, type, attr)                                                     \
    attr struct type *name##_IRB_INSERT(struct name *, struct type *)
#define IRB_PROTOTYPE_FIND(name, type, attr)                                                       \
    attr struct type *name##_IRB_FIND(struct name *, struct type *)
#define IRB_PROTOTYPE_NFIND(name, type, attr)                                                      \
    attr struct type *name##_IRB_NFIND(struct name *, struct type *)
#define IRB_PROTOTYPE_NEXT(name, type, attr) attr struct type *name##_IRB_NEXT(struct type *)
#define IRB_PROTOTYPE_PREV(name, type, attr) attr struct type *name##_IRB_PREV(struct type *)
#define IRB_PROTOTYPE_MINMAX(name, type, attr)                                                     \
    attr struct type *name##_IRB_MINMAX(struct name *, int)

/* Main rb operation.
 * Moves node close to the key of elm to top
 */
#define IRB_GENERATE(name, type, field, cmp) IRB_GENERATE_INTERNAL(name, type, field, cmp, )
#define IRB_GENERATE_STATIC(name, type, field, cmp)                                                \
    IRB_GENERATE_INTERNAL(name, type, field, cmp, __unused static)
#define IRB_GENERATE_INTERNAL(name, type, field, cmp, attr)                                        \
    IRB_GENERATE_INSERT_COLOR(name, type, field, attr)                                             \
    IRB_GENERATE_REMOVE_COLOR(name, type, field, attr)                                             \
    IRB_GENERATE_INSERT(name, type, field, cmp, attr)                                              \
    IRB_GENERATE_REMOVE(name, type, field, attr)                                                   \
    IRB_GENERATE_FIND(name, type, field, cmp, attr)                                                \
    IRB_GENERATE_NFIND(name, type, field, cmp, attr)                                               \
    IRB_GENERATE_NEXT(name, type, field, attr)                                                     \
    IRB_GENERATE_PREV(name, type, field, attr)                                                     \
    IRB_GENERATE_MINMAX(name, type, field, attr)

#define IRB_GENERATE_INSERT_COLOR(name, type, field, attr)                                         \
    attr void name##_IRB_INSERT_COLOR(struct name *head, struct type *elm)                         \
    {                                                                                              \
        struct type *parent, *gparent, *tmp;                                                       \
        while ((parent = IRB_PARENT(elm, field)) != NULL && IRB_COLOR(parent, field) == IRB_RED) { \
            gparent = IRB_PARENT(parent, field);                                                   \
            _T_ASSERT(gparent);                                                                    \
            if (parent == IRB_LEFT(gparent, field)) {                                              \
                tmp = IRB_RIGHT(gparent, field);                                                   \
                if (tmp && IRB_COLOR(tmp, field) == IRB_RED) {                                     \
                    IRB_COLOR(tmp, field) = IRB_BLACK;                                             \
                    IRB_SET_BLACKRED(parent, gparent, field);                                      \
                    elm = gparent;                                                                 \
                    continue;                                                                      \
                }                                                                                  \
                if (IRB_RIGHT(parent, field) == elm) {                                             \
                    IRB_ROTATE_LEFT(head, parent, tmp, field);                                     \
                    tmp = parent;                                                                  \
                    parent = elm;                                                                  \
                    elm = tmp;                                                                     \
                }                                                                                  \
                IRB_SET_BLACKRED(parent, gparent, field);                                          \
                IRB_ROTATE_RIGHT(head, gparent, tmp, field);                                       \
            } else {                                                                               \
                tmp = IRB_LEFT(gparent, field);                                                    \
                if (tmp && IRB_COLOR(tmp, field) == IRB_RED) {                                     \
                    IRB_COLOR(tmp, field) = IRB_BLACK;                                             \
                    IRB_SET_BLACKRED(parent, gparent, field);                                      \
                    elm = gparent;                                                                 \
                    continue;                                                                      \
                }                                                                                  \
                if (IRB_LEFT(parent, field) == elm) {                                              \
                    IRB_ROTATE_RIGHT(head, parent, tmp, field);                                    \
                    tmp = parent;                                                                  \
                    parent = elm;                                                                  \
                    elm = tmp;                                                                     \
                }                                                                                  \
                IRB_SET_BLACKRED(parent, gparent, field);                                          \
                IRB_ROTATE_LEFT(head, gparent, tmp, field);                                        \
            }                                                                                      \
        }                                                                                          \
        IRB_COLOR(head->rbh_root, field) = IRB_BLACK;                                              \
    }

#define IRB_GENERATE_REMOVE_COLOR(name, type, field, attr)                                         \
    attr void name##_IRB_REMOVE_COLOR(struct name *head, struct type *parent, struct type *elm)    \
    {                                                                                              \
        struct type *tmp;                                                                          \
        while ((elm == NULL || IRB_COLOR(elm, field) == IRB_BLACK) && elm != IRB_ROOT(head)) {     \
            if (IRB_LEFT(parent, field) == elm) {                                                  \
                tmp = IRB_RIGHT(parent, field);                                                    \
                if (IRB_COLOR(tmp, field) == IRB_RED) {                                            \
                    IRB_SET_BLACKRED(tmp, parent, field);                                          \
                    IRB_ROTATE_LEFT(head, parent, tmp, field);                                     \
                    tmp = IRB_RIGHT(parent, field);                                                \
                }                                                                                  \
                _T_ASSERT(tmp);                                                                    \
                if ((IRB_LEFT(tmp, field) == NULL ||                                               \
                            IRB_COLOR(IRB_LEFT(tmp, field), field) == IRB_BLACK) &&                \
                        (IRB_RIGHT(tmp, field) == NULL ||                                          \
                                IRB_COLOR(IRB_RIGHT(tmp, field), field) == IRB_BLACK)) {           \
                    IRB_COLOR(tmp, field) = IRB_RED;                                               \
                    elm = parent;                                                                  \
                    parent = IRB_PARENT(elm, field);                                               \
                } else {                                                                           \
                    if (IRB_RIGHT(tmp, field) == NULL ||                                           \
                            IRB_COLOR(IRB_RIGHT(tmp, field), field) == IRB_BLACK) {                \
                        struct type *oleft;                                                        \
                        if ((oleft = IRB_LEFT(tmp, field)) != NULL)                                \
                            IRB_COLOR(oleft, field) = IRB_BLACK;                                   \
                        IRB_COLOR(tmp, field) = IRB_RED;                                           \
                        IRB_ROTATE_RIGHT(head, tmp, oleft, field);                                 \
                        tmp = IRB_RIGHT(parent, field);                                            \
                    }                                                                              \
                    IRB_COLOR(tmp, field) = IRB_COLOR(parent, field);                              \
                    IRB_COLOR(parent, field) = IRB_BLACK;                                          \
                    if (IRB_RIGHT(tmp, field))                                                     \
                        IRB_COLOR(IRB_RIGHT(tmp, field), field) = IRB_BLACK;                       \
                    IRB_ROTATE_LEFT(head, parent, tmp, field);                                     \
                    elm = IRB_ROOT(head);                                                          \
                    break;                                                                         \
                }                                                                                  \
            } else {                                                                               \
                tmp = IRB_LEFT(parent, field);                                                     \
                if (IRB_COLOR(tmp, field) == IRB_RED) {                                            \
                    IRB_SET_BLACKRED(tmp, parent, field);                                          \
                    IRB_ROTATE_RIGHT(head, parent, tmp, field);                                    \
                    tmp = IRB_LEFT(parent, field);                                                 \
                }                                                                                  \
                _T_ASSERT(tmp);                                                                    \
                if ((IRB_LEFT(tmp, field) == NULL ||                                               \
                            IRB_COLOR(IRB_LEFT(tmp, field), field) == IRB_BLACK) &&                \
                        (IRB_RIGHT(tmp, field) == NULL ||                                          \
                                IRB_COLOR(IRB_RIGHT(tmp, field), field) == IRB_BLACK)) {           \
                    IRB_COLOR(tmp, field) = IRB_RED;                                               \
                    elm = parent;                                                                  \
                    parent = IRB_PARENT(elm, field);                                               \
                } else {                                                                           \
                    if (IRB_LEFT(tmp, field) == NULL ||                                            \
                            IRB_COLOR(IRB_LEFT(tmp, field), field) == IRB_BLACK) {                 \
                        struct type *oright;                                                       \
                        if ((oright = IRB_RIGHT(tmp, field)) != NULL)                              \
                            IRB_COLOR(oright, field) = IRB_BLACK;                                  \
                        IRB_COLOR(tmp, field) = IRB_RED;                                           \
                        IRB_ROTATE_LEFT(head, tmp, oright, field);                                 \
                        tmp = IRB_LEFT(parent, field);                                             \
                    }                                                                              \
                    IRB_COLOR(tmp, field) = IRB_COLOR(parent, field);                              \
                    IRB_COLOR(parent, field) = IRB_BLACK;                                          \
                    if (IRB_LEFT(tmp, field))                                                      \
                        IRB_COLOR(IRB_LEFT(tmp, field), field) = IRB_BLACK;                        \
                    IRB_ROTATE_RIGHT(head, parent, tmp, field);                                    \
                    elm = IRB_ROOT(head);                                                          \
                    break;                                                                         \
                }                                                                                  \
            }                                                                                      \
        }                                                                                          \
        if (elm)                                                                                   \
            IRB_COLOR(elm, field) = IRB_BLACK;                                                     \
    }

#define IRB_GENERATE_REMOVE(name, type, field, attr)                                               \
    attr struct type *name##_IRB_REMOVE(struct name *head, struct type *elm)                       \
    {                                                                                              \
        struct type *child, *parent, *old = elm;                                                   \
        int color;                                                                                 \
        if (IRB_LEFT(elm, field) == NULL)                                                          \
            child = IRB_RIGHT(elm, field);                                                         \
        else if (IRB_RIGHT(elm, field) == NULL)                                                    \
            child = IRB_LEFT(elm, field);                                                          \
        else {                                                                                     \
            struct type *left;                                                                     \
            elm = IRB_RIGHT(elm, field);                                                           \
            while ((left = IRB_LEFT(elm, field)) != NULL)                                          \
                elm = left;                                                                        \
            child = IRB_RIGHT(elm, field);                                                         \
            parent = IRB_PARENT(elm, field);                                                       \
            color = IRB_COLOR(elm, field);                                                         \
            if (child)                                                                             \
                IRB_PARENT(child, field) = parent;                                                 \
            if (parent) {                                                                          \
                if (IRB_LEFT(parent, field) == elm)                                                \
                    IRB_LEFT(parent, field) = child;                                               \
                else                                                                               \
                    IRB_RIGHT(parent, field) = child;                                              \
                IRB_AUGMENT(parent, field);                                                        \
            } else                                                                                 \
                IRB_ROOT(head) = child;                                                            \
            if (IRB_PARENT(elm, field) == old)                                                     \
                parent = elm;                                                                      \
            _T_ASSERT((old));                                                                      \
            (elm)->field = (old)->field;                                                           \
            if (IRB_PARENT(old, field)) {                                                          \
                if (IRB_LEFT(IRB_PARENT(old, field), field) == old)                                \
                    IRB_LEFT(IRB_PARENT(old, field), field) = elm;                                 \
                else                                                                               \
                    IRB_RIGHT(IRB_PARENT(old, field), field) = elm;                                \
                IRB_AUGMENT(IRB_PARENT(old, field), field);                                        \
            } else                                                                                 \
                IRB_ROOT(head) = elm;                                                              \
            _T_ASSERT(old);                                                                        \
            _T_ASSERT(IRB_LEFT(old, field));                                                       \
            IRB_PARENT(IRB_LEFT(old, field), field) = elm;                                         \
            if (IRB_RIGHT(old, field))                                                             \
                IRB_PARENT(IRB_RIGHT(old, field), field) = elm;                                    \
            if (parent) {                                                                          \
                left = parent;                                                                     \
                do {                                                                               \
                    IRB_AUGMENT(left, field);                                                      \
                } while ((left = IRB_PARENT(left, field)) != NULL);                                \
            }                                                                                      \
            goto color;                                                                            \
        }                                                                                          \
        parent = IRB_PARENT(elm, field);                                                           \
        color = IRB_COLOR(elm, field);                                                             \
        if (child)                                                                                 \
            IRB_PARENT(child, field) = parent;                                                     \
        if (parent) {                                                                              \
            if (IRB_LEFT(parent, field) == elm)                                                    \
                IRB_LEFT(parent, field) = child;                                                   \
            else                                                                                   \
                IRB_RIGHT(parent, field) = child;                                                  \
            IRB_AUGMENT(parent, field);                                                            \
        } else                                                                                     \
            IRB_ROOT(head) = child;                                                                \
    color:                                                                                         \
        if (color == IRB_BLACK)                                                                    \
            name##_IRB_REMOVE_COLOR(head, parent, child);                                          \
        return (old);                                                                              \
    }

#define IRB_GENERATE_INSERT(name, type, field, cmp, attr)                                          \
    /* Inserts a node into the IRB tree */                                                         \
    attr struct type *name##_IRB_INSERT(struct name *head, struct type *elm)                       \
    {                                                                                              \
        struct type *tmp;                                                                          \
        struct type *parent = NULL;                                                                \
        int comp = 0;                                                                              \
        tmp = IRB_ROOT(head);                                                                      \
        while (tmp) {                                                                              \
            parent = tmp;                                                                          \
            comp = (cmp)(elm, parent);                                                             \
            if (comp < 0) {                                                                        \
                tmp = IRB_LEFT(tmp, field);                                                        \
            } else if (comp > 0) {                                                                 \
                tmp = IRB_RIGHT(tmp, field);                                                       \
            } else                                                                                 \
                return (tmp);                                                                      \
        }                                                                                          \
        IRB_SET(elm, parent, field);                                                               \
        if (parent != NULL) {                                                                      \
            if (comp < 0)                                                                          \
                IRB_LEFT(parent, field) = elm;                                                     \
            else                                                                                   \
                IRB_RIGHT(parent, field) = elm;                                                    \
        } else                                                                                     \
            IRB_ROOT(head) = elm;                                                                  \
        IRB_AUGMENT(elm, field);                                                                   \
        name##_IRB_INSERT_COLOR(head, elm);                                                        \
        return (NULL);                                                                             \
    }

#define IRB_GENERATE_FIND(name, type, field, cmp, attr)                                            \
    /* Finds the node with the same key as elm */                                                  \
    attr struct type *name##_IRB_FIND(struct name *head, struct type *elm)                         \
    {                                                                                              \
        struct type *tmp = IRB_ROOT(head);                                                         \
        int comp;                                                                                  \
        while (tmp) {                                                                              \
            comp = cmp(elm, tmp);                                                                  \
            if (comp < 0)                                                                          \
                tmp = IRB_LEFT(tmp, field);                                                        \
            else if (comp > 0)                                                                     \
                tmp = IRB_RIGHT(tmp, field);                                                       \
            else                                                                                   \
                return (tmp);                                                                      \
        }                                                                                          \
        return (NULL);                                                                             \
    }

#define IRB_GENERATE_NFIND(name, type, field, cmp, attr)                                           \
    /* Finds the first node greater than or equal to the search key */                             \
    attr struct type *name##_IRB_NFIND(struct name *head, struct type *elm)                        \
    {                                                                                              \
        struct type *tmp = IRB_ROOT(head);                                                         \
        struct type *res = NULL;                                                                   \
        int comp;                                                                                  \
        while (tmp) {                                                                              \
            comp = cmp(elm, tmp);                                                                  \
            if (comp < 0) {                                                                        \
                res = tmp;                                                                         \
                tmp = IRB_LEFT(tmp, field);                                                        \
            } else if (comp > 0)                                                                   \
                tmp = IRB_RIGHT(tmp, field);                                                       \
            else                                                                                   \
                return (tmp);                                                                      \
        }                                                                                          \
        return (res);                                                                              \
    }

#define IRB_GENERATE_NEXT(name, type, field, attr)                                                 \
    /* ARGSUSED */                                                                                 \
    attr struct type *name##_IRB_NEXT(struct type *elm)                                            \
    {                                                                                              \
        if (IRB_RIGHT(elm, field)) {                                                               \
            elm = IRB_RIGHT(elm, field);                                                           \
            while (IRB_LEFT(elm, field))                                                           \
                elm = IRB_LEFT(elm, field);                                                        \
        } else {                                                                                   \
            if (IRB_PARENT(elm, field) && (elm == IRB_LEFT(IRB_PARENT(elm, field), field)))        \
                elm = IRB_PARENT(elm, field);                                                      \
            else {                                                                                 \
                while (IRB_PARENT(elm, field) &&                                                   \
                        (elm == IRB_RIGHT(IRB_PARENT(elm, field), field)))                         \
                    elm = IRB_PARENT(elm, field);                                                  \
                elm = IRB_PARENT(elm, field);                                                      \
            }                                                                                      \
        }                                                                                          \
        return (elm);                                                                              \
    }

#define IRB_GENERATE_PREV(name, type, field, attr)                                                 \
    /* ARGSUSED */                                                                                 \
    attr struct type *name##_IRB_PREV(struct type *elm)                                            \
    {                                                                                              \
        if (IRB_LEFT(elm, field)) {                                                                \
            elm = IRB_LEFT(elm, field);                                                            \
            while (IRB_RIGHT(elm, field))                                                          \
                elm = IRB_RIGHT(elm, field);                                                       \
        } else {                                                                                   \
            if (IRB_PARENT(elm, field) && (elm == IRB_RIGHT(IRB_PARENT(elm, field), field)))       \
                elm = IRB_PARENT(elm, field);                                                      \
            else {                                                                                 \
                while (IRB_PARENT(elm, field) && (elm == IRB_LEFT(IRB_PARENT(elm, field), field))) \
                    elm = IRB_PARENT(elm, field);                                                  \
                elm = IRB_PARENT(elm, field);                                                      \
            }                                                                                      \
        }                                                                                          \
        return (elm);                                                                              \
    }

#define IRB_GENERATE_MINMAX(name, type, field, attr)                                               \
    attr struct type *name##_IRB_MINMAX(struct name *head, int val)                                \
    {                                                                                              \
        struct type *tmp = IRB_ROOT(head);                                                         \
        struct type *parent = NULL;                                                                \
        while (tmp) {                                                                              \
            parent = tmp;                                                                          \
            if (val < 0)                                                                           \
                tmp = IRB_LEFT(tmp, field);                                                        \
            else                                                                                   \
                tmp = IRB_RIGHT(tmp, field);                                                       \
        }                                                                                          \
        return (parent);                                                                           \
    }

#define IRB_NEGINF -1
#define IRB_INF    1

#define IRB_INSERT(name, x, y) name##_IRB_INSERT(x, y)
#define IRB_REMOVE(name, x, y) name##_IRB_REMOVE(x, y)
#define IRB_FIND(name, x, y)   name##_IRB_FIND(x, y)
#define IRB_NFIND(name, x, y)  name##_IRB_NFIND(x, y)
#define IRB_NEXT(name, x, y)   name##_IRB_NEXT(y)
#define IRB_PREV(name, x, y)   name##_IRB_PREV(y)
#define IRB_MIN(name, x)       name##_IRB_MINMAX(x, IRB_NEGINF)
#define IRB_MAX(name, x)       name##_IRB_MINMAX(x, IRB_INF)

#define IRB_FOREACH(x, name, head)                                                                 \
    for ((x) = IRB_MIN(name, head); (x) != NULL; (x) = name##_IRB_NEXT(x))

#define IRB_FOREACH_FROM(x, name, y)                                                               \
    for ((x) = (y); ((x) != NULL) && ((y) = name##_IRB_NEXT(x), (x) != NULL); (x) = (y))

#define IRB_FOREACH_SAFE(x, name, head, y)                                                         \
    for ((x) = IRB_MIN(name, head); ((x) != NULL) && ((y) = name##_IRB_NEXT(x), (x) != NULL);      \
            (x) = (y))

#define IRB_FOREACH_REVERSE(x, name, head)                                                         \
    for ((x) = IRB_MAX(name, head); (x) != NULL; (x) = name##_IRB_PREV(x))

#define IRB_FOREACH_REVERSE_FROM(x, name, y)                                                       \
    for ((x) = (y); ((x) != NULL) && ((y) = name##_IRB_PREV(x), (x) != NULL); (x) = (y))

#define IRB_FOREACH_REVERSE_SAFE(x, name, head, y)                                                 \
    for ((x) = IRB_MAX(name, head); ((x) != NULL) && ((y) = name##_IRB_PREV(x), (x) != NULL);      \
            (x) = (y))

#endif /* _SYS_INTERVALTREE_H_ */
