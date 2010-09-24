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
 * Memcmp implementations.
 */

#include "suricata-common.h"

#include "util-memcmp.h"
#include "util-unittest.h"

/* code is implemented in util-memcmp.h as it's all inlined */

/* UNITTESTS */
#ifdef UNITTESTS

static int MemcmpTest01 (void) {
    uint8_t a[] = "abcd";
    uint8_t b[] = "abcd";

    if (SCMemcmp(a, b, sizeof(a)-1) != 0)
        return 0;

    return 1;
}

static int MemcmpTest02 (void) {
    uint8_t a[] = "abcdabcdabcdabcd";
    uint8_t b[] = "abcdabcdabcdabcd";

    if (SCMemcmp(a, b, sizeof(a)-1) != 0)
        return 0;

    return 1;
}

static int MemcmpTest03 (void) {
    uint8_t a[] = "abcdabcd";
    uint8_t b[] = "abcdabcd";

    if (SCMemcmp(a, b, sizeof(a)-1) != 0)
        return 0;

    return 1;
}

static int MemcmpTest04 (void) {
    uint8_t a[] = "abcd";
    uint8_t b[] = "abcD";

    int r = SCMemcmp(a, b, sizeof(a)-1);
    if (r != 1) {
        printf("%s != %s, but memcmp returned %d: ", a, b, r);
        return 0;
    }

    return 1;
}

static int MemcmpTest05 (void) {
    uint8_t a[] = "abcdabcdabcdabcd";
    uint8_t b[] = "abcDabcdabcdabcd";

    if (SCMemcmp(a, b, sizeof(a)-1) != 1)
        return 0;

    return 1;
}

static int MemcmpTest06 (void) {
    uint8_t a[] = "abcdabcd";
    uint8_t b[] = "abcDabcd";

    if (SCMemcmp(a, b, sizeof(a)-1) != 1)
        return 0;

    return 1;
}

static int MemcmpTest07 (void) {
    uint8_t a[] = "abcd";
    uint8_t b[] = "abcde";

    if (SCMemcmp(a, b, sizeof(a)-1) != 0)
        return 0;

    return 1;
}

static int MemcmpTest08 (void) {
    uint8_t a[] = "abcdabcdabcdabcd";
    uint8_t b[] = "abcdabcdabcdabcde";

    if (SCMemcmp(a, b, sizeof(a)-1) != 0)
        return 0;

    return 1;
}

static int MemcmpTest09 (void) {
    uint8_t a[] = "abcdabcd";
    uint8_t b[] = "abcdabcde";

    if (SCMemcmp(a, b, sizeof(a)-1) != 0)
        return 0;

    return 1;
}

static int MemcmpTest10 (void) {
    uint8_t a[] = "abcd";
    uint8_t b[] = "Zbcde";

    if (SCMemcmp(a, b, sizeof(a)-1) != 1)
        return 0;

    return 1;
}

static int MemcmpTest11 (void) {
    uint8_t a[] = "abcdabcdabcdabcd";
    uint8_t b[] = "Zbcdabcdabcdabcde";

    if (SCMemcmp(a, b, sizeof(a)-1) != 1)
        return 0;

    return 1;
}

static int MemcmpTest12 (void) {
    uint8_t a[] = "abcdabcd";
    uint8_t b[] = "Zbcdabcde";

    if (SCMemcmp(a, b, sizeof(a)-1) != 1)
        return 0;

    return 1;
}

static int MemcmpTest13 (void) {
    uint8_t a[] = "abcdefgh";
    uint8_t b[] = "AbCdEfGhIjK";

    if (SCMemcmpLowercase(a, b, sizeof(a)-1) != 0)
        return 0;

    return 1;
}

#endif /* UNITTESTS */

void MemcmpRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("MemcmpTest01", MemcmpTest01, 1);
    UtRegisterTest("MemcmpTest02", MemcmpTest02, 1);
    UtRegisterTest("MemcmpTest03", MemcmpTest03, 1);
    UtRegisterTest("MemcmpTest04", MemcmpTest04, 1);
    UtRegisterTest("MemcmpTest05", MemcmpTest05, 1);
    UtRegisterTest("MemcmpTest06", MemcmpTest06, 1);
    UtRegisterTest("MemcmpTest07", MemcmpTest07, 1);
    UtRegisterTest("MemcmpTest08", MemcmpTest08, 1);
    UtRegisterTest("MemcmpTest09", MemcmpTest09, 1);
    UtRegisterTest("MemcmpTest10", MemcmpTest10, 1);
    UtRegisterTest("MemcmpTest11", MemcmpTest11, 1);
    UtRegisterTest("MemcmpTest12", MemcmpTest12, 1);
    UtRegisterTest("MemcmpTest13", MemcmpTest13, 1);
#endif /* UNITTESTS */
}

