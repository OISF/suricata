/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * \author Breno Silva <breno.silva@gmail.com>
 *
 * Unit test framework
 */

/**
 * \addtogroup Testing
 *
 * @{
 */

#ifndef SURICATA_UTIL_UNITTEST_H
#define SURICATA_UTIL_UNITTEST_H

#ifdef UNITTESTS

typedef struct UtTest_
{
    const char *name;
    int(*TestFn)(void);

    struct UtTest_ *next;

} UtTest;

void UtRegisterTest(const char *name, int(*TestFn)(void));
uint32_t UtRunTests(const char *regex_arg);
void UtInitialize(void);
void UtCleanup(void);
int UtRunSelftest (const char *regex_arg);
void UtListTests(const char *regex_arg);
void UtRunModeRegister(void);

extern int unittests_fatal;

/**
 * \brief Fail a test.
 */
#define FAIL do {                                      \
        if (unittests_fatal) {                         \
            BUG_ON(1);                                 \
        } else {                                       \
            return 0;                                  \
        }                                              \
    } while (0)

/**
 * \brief Fail a test if expression evaluates to true.
 */
#define FAIL_IF(expr) do {                             \
        if (unittests_fatal) {                         \
            BUG_ON(expr);                              \
        } else if (expr) {                             \
            return 0;                                  \
        }                                              \
    } while (0)

/**
 * \brief Fail a test if expression evaluates to false.
 */
#define FAIL_IF_NOT(expr) do { \
        FAIL_IF(!(expr));      \
    } while (0)

/**
 * \brief Fail a test if expression evaluates to NULL.
 */
#define FAIL_IF_NULL(expr) do {                 \
        FAIL_IF(NULL == expr);                  \
    } while (0)

/**
 * \brief Fail a test if expression evaluates to non-NULL.
 */
#define FAIL_IF_NOT_NULL(expr) do { \
        FAIL_IF(NULL != expr);      \
    } while (0)

/**
 * \brief Pass the test.
 *
 * Only to be used at the end of a function instead of "return 1."
 */
#define PASS do { \
        return 1; \
    } while (0)

/**
 * \brief Skip the test.
 *
 * Used to skip the tests that cannot be run in the current environment.
 * The aim is to keep this at 0.
 */
#define SKIP(reason)                                                                               \
    do {                                                                                           \
        SCLogInfo("Test skipped: %s", reason);                                                     \
        return 2;                                                                                  \
    } while (0)

#endif

#endif /* SURICATA_UTIL_UNITTEST_H */

/**
 * @}
 */
