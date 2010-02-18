/*
 * LibHTP (http://www.libhtp.org)
 * Copyright 2009,2010 Ivan Ristic <ivanr@webkreator.com>
 *
 * LibHTP is an open source product, released under terms of the General Public Licence
 * version 2 (GPLv2). Please refer to the file LICENSE, which contains the complete text
 * of the license.
 *
 * In addition, there is a special exception that allows LibHTP to be freely
 * used with any OSI-approved open source licence. Please refer to the file
 * LIBHTP_LICENSING_EXCEPTION for the full text of the exception.
 *
 */

#ifndef _DSLIB_H
#define	_DSLIB_H

#include "bstr.h"

// IMPORTANT This library is used internally by the parser and you should
//           not rely on it in your code. The implementation may change at
//           some point in the future.

// What we have here is two implementations of a list structure (array- and link-list-based),
// and one implementation of a table (case-insensitive keys; multiple key values are allowed).
// The lists can be used as a stack.
//
// TODO The table element retrieval if very inefficient at the moment.

#define list_push(L, E) (L)->push(L, E)
#define list_pop(L) (L)->pop(L)
#define list_empty(L) (L)->empty(L)
#define list_get(L, N) (L)->get((list_t *)L, N)
#define list_replace(L, N, E) (L)->replace((list_t *)L, N, E)
#define list_add(L, N) (L)->push(L, N)
#define list_size(L) (L)->size(L)
#define list_iterator_reset(L) (L)->iterator_reset(L)
#define list_iterator_next(L) (L)->iterator_next(L)
#define list_destroy(L) (L)->destroy(L)

#define LIST_COMMON \
    int (*push)(list_t *, void *); \
    void *(*pop)(list_t *); \
    int (*empty)(list_t *); \
    void *(*get)(list_t *, size_t index); \
    int (*replace)(list_t *, size_t index, void *); \
    size_t (*size)(list_t *); \
    void (*iterator_reset)(list_t *); \
    void *(*iterator_next)(list_t *); \
    void (*destroy)(list_t *)

typedef struct list_t list_t;
typedef struct list_array_t list_array_t;
typedef struct list_linked_element_t list_linked_element_t;
typedef struct list_linked_t list_linked_t;

typedef struct table_t table_t;

struct list_t {
    LIST_COMMON;
};

struct list_linked_element_t {
    void *data;
    list_linked_element_t *next;
};

struct list_linked_t {
    LIST_COMMON;

    list_linked_element_t *first;
    list_linked_element_t *last;
};

struct list_array_t {
    LIST_COMMON;

    size_t first;
    size_t last;
    size_t max_size;
    size_t current_size;
    void **elements;

    size_t iterator_index;
};

list_t *list_linked_create(void);
list_t *list_array_create(size_t size);

struct table_t {
    list_t *list;
};

table_t *table_create(size_t size);
     int table_add(table_t *, bstr *, void *);
    void table_set(table_t *, bstr *, void *);
   void *table_get(table_t *, bstr *);
   void *table_getc(table_t *, char *);
    void table_iterator_reset(table_t *);
   bstr *table_iterator_next(table_t *, void **);
  size_t table_size(table_t *t);
    void table_destroy(table_t *);
    void table_clear(table_t *);

#endif	/* _DSLIB_H */

