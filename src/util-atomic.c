/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "util-unittest.h"
#include "suricata.h"
#endif
#include "util-atomic.h"

#ifdef UNITTESTS

static int SCAtomicTest01(void)
{
    int result = 0;
    int a = 10;
    int b = 20;
    int *temp_int = NULL;

    SC_ATOMIC_DECLARE(void *, temp);
    SC_ATOMIC_INITPTR(temp);

    temp_int = SC_ATOMIC_GET(temp);
    if (temp_int != NULL)
        goto end;

    (void)SC_ATOMIC_SET(temp, &a);
    temp_int = SC_ATOMIC_GET(temp);
    if (temp_int == NULL)
        goto end;
    if (*temp_int != a)
        goto end;

    (void)SC_ATOMIC_SET(temp, &b);
    temp_int = SC_ATOMIC_GET(temp);
    if (temp_int == NULL)
        goto end;
    if (*temp_int != b)
        goto end;

    result = 1;

 end:
    return result;
}

#endif /* UNITTESTS */

void SCAtomicRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SCAtomicTest01", SCAtomicTest01);
#endif

    return;
}
