#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* XXX replace this by a better algo */

u_int8_t nocasetable[256];
#define _nc(c) nocasetable[(c)]

void BinSearchInit (void)
{
    /* create table for O(1) case conversion lookup */
    u_int8_t c = 0;
    for ( ; c < 255; c++) {
       if ( c >= 'a' && c <= 'z')
           nocasetable[c] = (c - ('a' - 'A'));
       else if (c >= 'A' && c <= 'Z')
           nocasetable[c] = (c + ('a' - 'A'));
       else
           nocasetable[c] = c;
    }
#ifdef DEBUG
    for (c = 0; c < 255; c++) {
        if (isprint(nocasetable[c]))
            printf("nocasetable[%c]: %c\n", c, nocasetable[c]);
    }
#endif /* DEBUG */
}

/* Binary search.
 *
 * Returns:
 *  - ptr to start of the match
 *  - null if no match
 */
/* simple bin search modelled loosely after strstr */
u_int8_t *
BinSearch(const u_int8_t *haystack, size_t haystack_len,
          const u_int8_t *needle, size_t needle_len)
{
    const u_int8_t *h, *n;
    const u_int8_t *hmax = haystack + haystack_len;
    const u_int8_t *nmax = needle + (needle_len - 1);

    if (needle_len == 0)
        return NULL;

    for (n = needle; haystack != hmax; haystack++) {
        if (*haystack != *n) {
            continue;
        }
        /* one byte needles */
        if (needle_len == 1)
            return haystack;

        for (h = haystack+1, n++; h != hmax; h++, n++) {
            //printf("h %c n %c\n", isprint(*h) ? *h : 'X', *n);
            if (*h != *n) {
                break;
            }
            /* if we run out of needle we fully matched */
            if (n == nmax) {
                return (u_int8_t *)haystack;
            }
        }
        n = needle;
    }
    return NULL;
}

/* Caseless binary search. More expensive that the one that
 * respects case.
 *
 * Returns:
 *  - ptr to start of the match
 *  - null if no match
 */
u_int8_t *
BinSearchNocase(const u_int8_t *haystack, size_t haystack_len,
                const u_int8_t *needle, size_t needle_len)
{
    const u_int8_t *h, *n;
    const u_int8_t *hmax = haystack + haystack_len;
    const u_int8_t *nmax = needle + (needle_len - 1);

    if (needle_len == 0)
        return NULL;

    for (n = needle; haystack != hmax; haystack++) {
        if (*haystack != *n && *haystack != _nc(*n)) {
            continue;
        }
        for (h = haystack+1, n++; h != hmax; h++, n++) {
            //printf("h %c n %c\n", isprint(*h) ? *h : 'X', *n);
            if (*h != *n && *h != _nc(*n)) {
                break;
            }
            /* if we run out of needle we fully matched */
            if (n == nmax) {
                return (u_int8_t *)haystack;
            }
        }
        n = needle;
    }
    return NULL;
}

