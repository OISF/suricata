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

#include "bstr.h"
#include <ctype.h>

/**
 * Allocate a zero-length bstring, but reserving space for at least len bytes.
 *
 * @param len
 * @return New string
 */
bstr *bstr_alloc(size_t len) {
    unsigned char *s = malloc(sizeof (bstr_t) + len);
    if (s == NULL) return NULL;

    bstr_t *b = (bstr_t *) s;
    b->len = 0;
    b->size = len;
    b->ptr = NULL;

    return (bstr *) s;
}

/**
 * Deallocate a bstring. Allows a NULL bstring on input.
 *
 * @param b
 */
void bstr_free(bstr *b) {
    if (b == NULL) return;
    free(b);
}

/**
 * Append source bstring to destination bstring, growing
 * destination if necessary.
 *
 * @param destination
 * @param source
 * @return destination, at a potentially different memory location
 */
bstr *bstr_add_str(bstr *destination, bstr *source) {
    return bstr_add_mem(destination, bstr_ptr(source), bstr_len(source));
}

/**
 * Append a NUL-terminated source to destination, growing
 * destination if necessary.
 *
 * @param destination
 * @param source
 * @return destination, at a potentially different memory location
 */
bstr *bstr_add_cstr(bstr *destination, char *source) {
    return bstr_add_mem(destination, source, strlen(source));
}

/**
 * Append a memory region to destination, growing destination
 * if necessary.
 *
 * @param destination
 * @param data
 * @param len
 * @return destination, at a potentially different memory location
 */
bstr *bstr_add_mem(bstr *destination, char *data, size_t len) {    
    if (bstr_size(destination) < bstr_len(destination) + len) {        
        destination = bstr_expand(destination, bstr_len(destination) + len);
        if (destination == NULL) return NULL;        
    }    

    bstr_t *b = (bstr_t *) destination;
    memcpy(bstr_ptr(destination) + b->len, data, len);
    b->len = b->len + len;   

    return destination;
}

/**
 * Append source bstring to destination bstring, growing
 * destination if necessary.
 *
 * @param destination
 * @param source
 * @return destination, at a potentially different memory location
 */
bstr *bstr_add_str_noex(bstr *destination, bstr *source) {
    return bstr_add_mem_noex(destination, bstr_ptr(source), bstr_len(source));
}

/**
 * Append a NUL-terminated source to destination, growing
 * destination if necessary.
 *
 * @param destination
 * @param source
 * @return destination, at a potentially different memory location
 */
bstr *bstr_add_cstr_noex(bstr *destination, char *source) {
    return bstr_add_mem_noex(destination, source, strlen(source));
}

/**
 * Append a memory region to destination, growing destination
 * if necessary.
 *
 * @param destination
 * @param data
 * @param len
 * @return destination, at a potentially different memory location
 */
bstr *bstr_add_mem_noex(bstr *destination, char *data, size_t len) {
    size_t copylen = len;

    if (bstr_size(destination) < bstr_len(destination) + copylen) {
        copylen = bstr_size(destination) - bstr_len(destination);
        if (copylen <= 0) return destination;
    }

    bstr_t *b = (bstr_t *) destination;
    memcpy(bstr_ptr(destination) + b->len, data, copylen);
    b->len = b->len + copylen;

    return destination;
}

/**
 * Expand a string to support at least newsize bytes. The input bstring
 * is not changed if it is big enough to accommodate the desired size. If
 * the input bstring is smaller, however, it is expanded. The pointer to
 * the bstring may change. If the expansion fails, the original bstring
 * is left untouched (it is not freed).
 *
 * @param s
 * @param newsize
 * @return new bstring, or NULL if memory allocation failed
 */
bstr *bstr_expand(bstr *s, size_t newsize) {
    if (((bstr_t *) s)->ptr != NULL) {
        void * newblock = realloc(((bstr_t *) s)->ptr, newsize);
        if (newblock == NULL) {
            return NULL;
        } else {
            ((bstr_t *) s)->ptr = newblock;
        }
    } else {
        void *newblock = realloc(s, sizeof (bstr_t) + newsize);
        if (newblock == NULL) {
            return NULL;
        } else {
            s = newblock;
        }
    }

    ((bstr_t *) s)->size = newsize;

    return s;
}

/**
 * Create a new bstring by copying the provided NUL-terminated string.
 *
 * @param data
 * @return new bstring
 */
bstr *bstr_cstrdup(char *data) {
    return bstr_memdup(data, strlen(data));
}

/**
 * Create a new bstring by copying the provided memory region.
 *
 * @param data
 * @param len
 * @return new bstring
 */
bstr *bstr_memdup(char *data, size_t len) {
    bstr *b = bstr_alloc(len);
    if (b == NULL) return NULL;
    memcpy(bstr_ptr(b), data, len);
    ((bstr_t *) b)->len = len;
    return b;
}

/**
 * Create a new bstring by copying the provided bstring.
 *
 * @param b
 * @return new bstring
 */
bstr *bstr_strdup(bstr *b) {
    return bstr_strdup_ex(b, 0, bstr_len(b));
}

/**
 * Create a new bstring by copying a part of the provided
 * bstring.
 *
 * @param b
 * @param offset
 * @param len
 * @return new bstring
 */
bstr *bstr_strdup_ex(bstr *b, size_t offset, size_t len) {
    bstr *bnew = bstr_alloc(len);
    if (bnew == NULL) return NULL;
    memcpy(bstr_ptr(bnew), bstr_ptr(b) + offset, len);
    ((bstr_t *) bnew)->len = len;
    return bnew;
}

/**
 * Take the provided memory region and construct a NUL-terminated
 * string, replacing NUL bytes with "\0".
 *
 * @param data
 * @param len
 * @return new NUL-terminated string
 */
char *bstr_memtocstr(char *data, size_t len) {
    // Count how many NUL bytes we have in the string.
    size_t i, nulls = 0;
    for (i = 0; i < len; i++) {
        if (data[i] == '\0') {
            nulls++;
        }
    }

    // Now copy the string into a NUL-terminated buffer.
    char *r, *t;
    r = t = malloc(len + nulls + 1);
    if (t == NULL) return NULL;

    while (len--) {
        // Escape NUL bytes, but just copy everything else.
        if (*data == '\0') {
            data++;
            *t++ = '\\';
            *t++ = '0';
        } else {
            *t++ = *data++;
        }
    }

    // Terminate string.
    *t = '\0';

    return r;
}

/**
 * Create a new NUL-terminated string out of the provided bstring.
 *
 * @param b
 * @return new NUL-terminated string
 */
char *bstr_tocstr(bstr *b) {
    if (b == NULL) return NULL;
    return bstr_memtocstr(bstr_ptr(b), bstr_len(b));
}

/**
 * Return the first position of the provided character (byte).
 *
 * @param b
 * @param c
 * @return the first position of the character, or -1 if it could not be found
 */
int bstr_chr(bstr *b, int c) {
    char *data = bstr_ptr(b);
    size_t len = bstr_len(b);

    size_t i = 0;
    while (i < len) {
        if (data[i] == c) {
            return i;
        }

        i++;
    }

    return -1;
}

/**
 * Return the last position of a character (byte).
 *
 * @param b
 * @param c
 * @return the last position of the character, or -1 if it could not be found
 */
int bstr_rchr(bstr *b, int c) {
    char *data = bstr_ptr(b);
    size_t len = bstr_len(b);

    int i = len;
    while (i >= 0) {
        if (data[i] == c) {
            return i;
        }

        i--;
    }

    return -1;
}

/**
 * Compare two memory regions.
 *
 * @param s1
 * @param l1
 * @param s2
 * @param l2
 * @return 0 if the memory regions are identical, -1 or +1 if they're not
 */
int bstr_cmp_ex(char *s1, size_t l1, char *s2, size_t l2) {
    size_t p1 = 0, p2 = 0;

    while ((p1 < l1) && (p2 < l2)) {
        if (s1[p1] != s2[p2]) {
            // Difference
            return (s1[p1] < s2[p2]) ? -1 : 1;
        }

        p1++;
        p2++;
    }

    if ((p1 == l2) && (p2 == l1)) {
        // They're identical
        return 0;
    } else {
        // One string is shorter
        if (p1 == l1) return -1;
        else return 1;
    }
}

/**
 * Case-insensitive comparison of two memory regions.
 *
 * @param s1
 * @param l1
 * @param s2
 * @param l2
 * @return 0 if the memory regions are identical, -1 or +1 if they're not
 */
int bstr_cmp_nocase_ex(char *s1, size_t l1, char *s2, size_t l2) {
    size_t p1 = 0, p2 = 0;

    while ((p1 < l1) && (p2 < l2)) {
        if (tolower((int)s1[p1]) != tolower((int)s2[p2])) {
            // Difference
            return (tolower((int)s1[p1]) < tolower((int)s2[p2])) ? -1 : 1;
        }

        p1++;
        p2++;
    }

    if ((p1 == l2) && (p2 == l1)) {
        // They're identical
        return 0;
    } else {
        // One string is shorter
        if (p1 == l1) return -1;
        else return 1;
    }
}

/**
 * Compare a bstring with a NUL-terminated string.
 *
 * @param b
 * @param c
 * @return 0, -1 or +1
 */
int bstr_cmpc(bstr *b, char *c) {
    return bstr_cmp_ex(bstr_ptr(b), bstr_len(b), c, strlen(c));
}

/**
 * Compare two bstrings.
 *
 * @param b1
 * @param b2
 * @return 0, -1 or +1
 */
int bstr_cmp(bstr *b1, bstr *b2) {
    return bstr_cmp_ex(bstr_ptr(b1), bstr_len(b1), bstr_ptr(b2), bstr_len(b2));
}

/**
 * Case-insensitive comparison two bstrings.
 *
 * @param b1
 * @param b2
 * @return 0, -1 or +1
 */
int bstr_cmp_nocase(bstr *b1, bstr *b2) {
    return bstr_cmp_nocase_ex(bstr_ptr(b1), bstr_len(b1), bstr_ptr(b2), bstr_len(b2));
}

/**
 * Convert bstring to lowercase.
 *
 * @param b
 * @return b
 */
bstr *bstr_tolowercase(bstr *b) {
    if (b == NULL) return NULL;

    unsigned char *data = (unsigned char *)bstr_ptr(b);
    size_t len = bstr_len(b);

    size_t i = 0;
    while (i < len) {
        data[i] = tolower(data[i]);
        i++;
    }

    return b;
}

/**
 * Create a copy of the provided bstring, then convert it to lowercase.
 *
 * @param b
 * @return bstring copy
 */
bstr *bstr_dup_lower(bstr *b) {
    return bstr_tolowercase(bstr_strdup(b));
}

/**
 *
 */
int bstr_util_memtoip(char *data, size_t len, int base, size_t *lastlen) {
    int rval = 0, tval = 0, tflag = 0;

    size_t i = *lastlen = 0;
    for (i = 0; i < len; i++) {
        int d = data[i];

        *lastlen = i;

        // Convert character to digit.
        if ((d >= '0') && (d <= '9')) {
            d -= '0';
        } else if ((d >= 'a') && (d <= 'z')) {
            d -= 'a' - 10;
        } else if ((d >= 'A') && (d <= 'Z')) {
            d -= 'A' - 10;
        } else {
            d = -1;
        }

        // Check that the digit makes sense with the base
        // we are using.
        if ((d == -1) || (d >= base)) {
            if (tflag) {
                // Return what we have so far; lastlen points
                // to the first non-digit position.
                return rval;
            } else {
                // We didn't see a single digit.
                return -1;
            }
        }

        if (tflag) {
            rval *= base;

            if (tval > rval) {
                // Overflow
                return -2;
            }

            rval += d;

            if (tval > rval) {
                // Overflow
                return -2;
            }

            tval = rval;
        } else {
            tval = rval = d;
            tflag = 1;
        }
    }

    *lastlen = i + 1;

    return rval;
}

/**
 * Find needle in a haystack.
 *
 * @param haystack
 * @param needle
 * @return
 */
int bstr_indexof(bstr *haystack, bstr *needle) {
    return bstr_indexofmem(haystack, bstr_ptr(needle), bstr_len(needle));
}

/**
 * Find index in the haystack, with the needle being a NUL-terminated string.
 *
 * @param haystack
 * @param needle
 * @return
 */
int bstr_indexofc(bstr *haystack, char *needle) {
    return bstr_indexofmem(haystack, needle, strlen(needle));
}

/**
 * Find index in the haystack. Ignore case differences.
 *
 * @param haystack
 * @param needle
 * @return
 */
int bstr_indexof_nocase(bstr *haystack, bstr *needle) {
    return bstr_indexofmem_nocase(haystack, bstr_ptr(needle), bstr_len(needle));
}

/**
 * Find index in the haystack, with the needle being a NUL-terminated string.
 * Ignore case differences.
 *
 * @param haystack
 * @param needle
 * @return
 */
int bstr_indexofc_nocase(bstr *haystack, char *needle) {
    return bstr_indexofmem_nocase(haystack, needle, strlen(needle));
}

/**
 * Find index in the haystack, with the needle being a memory region.
 *
 * @param haystack
 * @param data2
 * @param len2
 * @return
 */
int bstr_indexofmem(bstr *haystack, char *data2, size_t len2) {
    unsigned char *data = (unsigned char *)bstr_ptr(haystack);
    size_t len = bstr_len(haystack);
    size_t i, j;

    // TODO Is an optimisation here justified?
    //      http://en.wikipedia.org/wiki/Knuth-Morris-Pratt_algorithm
    
    for (i = 0; i < len; i++) {
        size_t k = i;

        for (j = 0; ((j < len2) && (k < len)); j++) {
            if (data[k++] != data2[j]) break;
        }

        if ((k - i) == len2) {
            return i;
        }
    }

    return -1;
}

/**
 * Find index in the haystack, with the needle being a memory region.
 * Ignore case differences.
 *
 * @param haystack
 * @param data2
 * @param len2
 * @return
 */
int bstr_indexofmem_nocase(bstr *haystack, char *data2, size_t len2) {
    unsigned char *data = (unsigned char *)bstr_ptr(haystack);
    size_t len = bstr_len(haystack);
    size_t i, j;

    // TODO No need to inspect the last len2 - 1 bytes
    for (i = 0; i < len; i++) {
        size_t k = i;

        for (j = 0; ((j < len2) && (k < len)); j++) {
            if (toupper(data[k++]) != toupper((unsigned char)data2[j])) break;
        }

        if ((k - i) == len2) {
            return i;
        }
    }

    return -1;
}

/**
 * Remove one byte from the end of the string.
 *
 * @param s
 */
void bstr_chop(bstr *s) {
    bstr_t *b = (bstr_t *) s;
    if (b->len > 0) {
        b->len--;
    }
}

/**
 * Adjust bstring length. You will need to use this method whenever
 * you work directly with the string contents, and you end up changing
 * its length.
 *
 * @param s
 * @param newlen
 */
void bstr_len_adjust(bstr *s, size_t newlen) {
    bstr_t *b = (bstr_t *) s;
    b->len = newlen;
}

/**
 * Return the character (byte) at the given position.
 *
 * @param s
 * @param pos
 * @return the character, or -1 if the bstring is too short
 */
char bstr_char_at(bstr *s, size_t pos) {
    unsigned char *data = (unsigned char *)bstr_ptr(s);
    size_t len = bstr_len(s);

    if (pos > len) return -1;
    return data[pos];
}

