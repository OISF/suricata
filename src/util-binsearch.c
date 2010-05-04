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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Binary search utility functions
 *
 * \todo replace this by a better algo
 */

#include "suricata-common.h"
#include "suricata.h"

void BinSearchInit (void)
{
    /* nothing no more */
}

/* Binary search.
 *
 * Returns:
 *  - ptr to start of the match
 *  - null if no match
 */
/* simple bin search modelled loosely after strstr */
uint8_t *
BinSearch(const uint8_t *haystack, size_t haystack_len,
          const uint8_t *needle, size_t needle_len)
{
    const uint8_t *h, *n;
    const uint8_t *hmax = haystack + haystack_len;
    const uint8_t *nmax = needle + (needle_len - 1);

    if (needle_len == 0)
        return NULL;

    for (n = needle; haystack != hmax; haystack++) {
        if (*haystack != *n) {
            continue;
        }
        /* one byte needles */
        if (needle_len == 1)
            return (uint8_t *)haystack;

        for (h = haystack+1, n++; h != hmax; h++, n++) {
            //printf("h %c n %c\n", isprint(*h) ? *h : 'X', *n);
            if (*h != *n) {
                break;
            }
            /* if we run out of needle we fully matched */
            if (n == nmax) {
                return (uint8_t *)haystack;
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
uint8_t *
BinSearchNocase(const uint8_t *haystack, size_t haystack_len,
                const uint8_t *needle, size_t needle_len)
{
    const uint8_t *h, *n;
    const uint8_t *hmax = haystack + haystack_len;
    const uint8_t *nmax = needle + (needle_len - 1);

    if (needle_len == 0)
        return NULL;

    for (n = needle; haystack != hmax; haystack++) {
        if (*haystack != *n && *haystack != u8_tolower(*n)) {
            continue;
        }
        for (h = haystack+1, n++; h != hmax; h++, n++) {
            if (*h != *n && *h != u8_tolower(*n)) {
                break;
            }
            /* if we run out of needle we fully matched */
            if (n == nmax) {
                return (uint8_t *)haystack;
            }
        }
        n = needle;
    }
    return NULL;
}

