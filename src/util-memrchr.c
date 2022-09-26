/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "util-memrchr.h"

#ifdef UNITTESTS
#include "util-unittest.h"
#endif
#ifndef HAVE_MEMRCHR
void *memrchr (const void *s, int c, size_t n)
{
    const char *end = s + n;

    while (end > (const char *)s) {
        if (*end == (char)c)
            return (void *)end;
        end--;
    }
    return NULL;
}
#endif  /* HAVE_MEMRCHR */

#ifdef UNITTESTS
static int MemrchrTest01 (void)
{
    const char *haystack = "abcabc";
    char needle = 'b';

    char *ptr = memrchr(haystack, needle, strlen(haystack));
    if (ptr == NULL)
        return 0;

    if (strlen(ptr) != 2)
        return 0;

    if (strcmp(ptr, "bc") != 0)
        return 0;

    return 1;
}
#endif

void MemrchrRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("MemrchrTest01", MemrchrTest01);
#endif
}
