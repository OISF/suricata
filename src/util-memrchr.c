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
#include "util-unittest.h"
#include "util-memrchr.h"

#ifndef HAVE_MEMRCHR
void *memrchr (const void *s, int c, size_t n)
{
    const unsigned char *p = (const unsigned char *)s + n;
    const unsigned char uc = (unsigned char)c;

    while (p > (const unsigned char *)s) {
        p--;
        if (*p == uc)
            return (void *)p;
    }
    return NULL;
}
#endif  /* HAVE_MEMRCHR */

#ifdef UNITTESTS
static int MemrchrTest01 (void)
{
    char buf[] = { 'x', 'y', 'z' };
    char one_byte[] = { 'q' };
    char dup[] = { 'a', 'b', 'a' };

    FAIL_IF(memrchr(buf, 'x', sizeof(buf)) != &buf[0]);
    FAIL_IF(memrchr(buf, 'z', sizeof(buf)) != &buf[2]);
    FAIL_IF(memrchr(buf, 'y', sizeof(buf)) != &buf[1]);
    FAIL_IF(memrchr(buf, 'a', sizeof(buf)) != NULL);
    FAIL_IF(memrchr(one_byte, 'q', sizeof(one_byte)) != &one_byte[0]);
    FAIL_IF(memrchr(one_byte, 'q', 0) != NULL);
    FAIL_IF(memrchr(dup, 'a', sizeof(dup)) != &dup[2]);

    return 1;
}
#endif

void MemrchrRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("MemrchrTest01", MemrchrTest01);
#endif
}
