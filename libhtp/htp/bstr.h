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

#ifndef _BSTR_H
#define	_BSTR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// IMPORTANT This binary string library is used internally by the parser and you should
//           not rely on it in your code. The implementation may change.
//
// TODO
//           - Add a function that wraps an existing data
//           - Support Unicode bstrings

typedef void * bstr;

bstr *bstr_alloc(size_t newsize);
void  bstr_free(bstr *s);
bstr *bstr_expand(bstr *s, size_t newsize);
bstr *bstr_cstrdup(char *);
bstr *bstr_memdup(char *data, size_t len);
bstr *bstr_strdup(bstr *b);
bstr *bstr_strdup_ex(bstr *b, size_t offset, size_t len);
char *bstr_tocstr(bstr *);

int bstr_chr(bstr *, int);
int bstr_rchr(bstr *, int);

int bstr_cmpc(bstr *, char *);
int bstr_cmp(bstr *, bstr *);
int bstr_cmp_nocase(bstr *, bstr *);

bstr *bstr_dup_lower(bstr *);
bstr *bstr_tolowercase(bstr *);

bstr *bstr_add_mem(bstr *, char *, size_t);
bstr *bstr_add_str(bstr *, bstr *);
bstr *bstr_add_cstr(bstr *, char *);

bstr *bstr_add_mem_noex(bstr *, char *, size_t);
bstr *bstr_add_str_noex(bstr *, bstr *);
bstr *bstr_add_cstr_noex(bstr *, char *);

int bstr_util_memtoip(char *data, size_t len, int base, size_t *lastlen);
char *bstr_memtocstr(char *data, size_t len);

int bstr_indexof(bstr *haystack, bstr *needle);
int bstr_indexofc(bstr *haystack, char *needle);
int bstr_indexof_nocase(bstr *haystack, bstr *needle);
int bstr_indexofc_nocase(bstr *haystack, char *needle);
int bstr_indexofmem(bstr *haystack, char *data, size_t len);
int bstr_indexofmem_nocase(bstr *haystack, char *data, size_t len);

void bstr_chop(bstr *b);
void bstr_len_adjust(bstr *s, size_t newlen);

char bstr_char_at(bstr *s, size_t pos);
 
typedef struct bstr_t bstr_t;

struct bstr_t {
    /** The length of the string stored in the buffer. */
    size_t len;
      
    /** The current size of the buffer. If the buffer is bigger than the
     *  string then it will be able to expand without having to reallocate.
     */
    size_t size;

    /** Optional buffer pointer. If this pointer is NUL (as it currently is
     *  in virtually all cases, the string buffer will immediatelly follow
     *  this structure. If the pointer is not NUL, it points to the actual
     *  buffer used, and there's no data following this structure.
     */
    char *ptr;
};

#define bstr_len(X) ((*(bstr_t *)(X)).len)
#define bstr_size(X) ((*(bstr_t *)(X)).size)
#define bstr_ptr(X) ( ((*(bstr_t *)(X)).ptr == NULL) ? (char *)((char *)(X) + sizeof(bstr_t)) : (char *)(*(bstr_t *)(X)).ptr )

#endif	/* _BSTR_H */

